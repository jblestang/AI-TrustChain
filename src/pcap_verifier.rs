//! Offline PCAP file parser, serializer, and forensic integrity verifier.
//!
//! This module supports:
//! 1. **Standard Libpcap (`.pcap`) Binary Format**:
//!    - 24-byte Global Header (`0xa1b2c3d4` microsecond magic, version 2.4, `LINKTYPE_ETHERNET = 1`).
//!    - 16-byte Packet Record Header (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`).
//!    - Ethernet II (`14` bytes, `EtherType = 0x0800` IPv4) + IPv4 Header (`20` bytes) +
//!      UDP (`8` bytes) or TCP (`20` bytes) header + Multi-PDU binary payload.
//! 2. **Multi-PDU Binary Wire Encoding**:
//!    - `pdu_count: u16` (big-endian) followed by `pdu_count` records of:
//!      `x: f64` (8B BE), `y: f64` (8B BE), `i: f64` (8B BE), `timestamp_us: u64` (8B BE),
//!      `non_critical_len: u16` (2B BE), and `non_critical: [u8; non_critical_len]`.
//! 3. **Offline Verification against Rotating Local Control Store**:
//!    - `verify_pcap_against_store` loads all intact `EncryptedControlFrame` records from a
//!      `RotatingControlStore` directory, parses all `IpPacket` flows from a `.pcap` file,
//!      runs the `EgressIps` verification engine, and returns the resulting `IntegrityAlert` list.

use crate::crypto::{decrypt_control_frame, CryptoError, TrustChainKeys};
use crate::egress_ips::{EgressIps, VerifierConfig};
use crate::model::{
    EncryptedControlFrame, FiveTuple, IntegrityAlert, IpPacket, Pdu, Protocol,
};
use crate::storage::{RotatingControlStore, StorageError};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use thiserror::Error;

/// Standard libpcap magic number (little-endian microsecond resolution).
const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;

/// Standard libpcap magic number (big-endian microsecond resolution).
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;

/// Link-layer header type for Ethernet (`LINKTYPE_ETHERNET`).
const LINKTYPE_ETHERNET: u32 = 1;

/// Ethernet II frame header length in bytes.
const ETHERNET_HEADER_LEN: usize = 14;

/// Minimum IPv4 header length in bytes (IHL = 5).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Standard UDP header length in bytes.
const UDP_HEADER_LEN: usize = 8;

/// Minimum TCP header length in bytes (Data Offset = 5).
const TCP_MIN_HEADER_LEN: usize = 20;

/// Fixed size of a single PDU's critical + length header (`x`, `y`, `i`, `timestamp_us`, `nc_len`).
const PDU_FIXED_HEADER_LEN: usize = 8 + 8 + 8 + 8 + 2;

/// Errors that can occur during PCAP parsing, writing, or offline verification.
#[derive(Debug, Error)]
pub enum PcapError {
    /// Underlying filesystem I/O error.
    #[error("PCAP I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Rotating control store error.
    #[error("control store error: {0}")]
    Storage(#[from] StorageError),
    /// Cryptographic verification error on a control frame.
    #[error("control frame crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// Invalid or unsupported `.pcap` global header or packet structure.
    #[error("malformed PCAP file or frame: {0}")]
    MalformedPcap(String),
}

/// Encodes a slice of `Pdu` items into the canonical multi-PDU transport payload format.
#[must_use]
pub fn encode_pdu_payload(pdus: &[Pdu]) -> Vec<u8> {
    let count = u16::try_from(pdus.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(2 + pdus.len() * PDU_FIXED_HEADER_LEN);
    buf.extend_from_slice(&count.to_be_bytes());
    for pdu in pdus.iter().take(usize::from(count)) {
        buf.extend_from_slice(&pdu.x.to_be_bytes());
        buf.extend_from_slice(&pdu.y.to_be_bytes());
        buf.extend_from_slice(&pdu.i.to_be_bytes());
        buf.extend_from_slice(&pdu.timestamp_us.to_be_bytes());
        let nc_len = u16::try_from(pdu.non_critical.len()).unwrap_or(u16::MAX);
        buf.extend_from_slice(&nc_len.to_be_bytes());
        buf.extend_from_slice(&pdu.non_critical[..usize::from(nc_len)]);
    }
    buf
}

/// Decodes a transport payload byte slice into a vector of `Pdu` records.
///
/// # Errors
/// Returns `PcapError::MalformedPcap` if the byte slice is truncated.
pub fn decode_pdu_payload(payload: &[u8]) -> Result<Vec<Pdu>, PcapError> {
    if payload.len() < 2 {
        return Err(PcapError::MalformedPcap(
            "transport payload shorter than 2-byte PDU count".to_string(),
        ));
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut offset = 2;
    let mut pdus = Vec::with_capacity(count);

    for _ in 0..count {
        if offset + PDU_FIXED_HEADER_LEN > payload.len() {
            return Err(PcapError::MalformedPcap(
                "truncated PDU fixed fields in transport payload".to_string(),
            ));
        }
        let x = f64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap_or([0; 8]));
        let y = f64::from_be_bytes(
            payload[offset + 8..offset + 16]
                .try_into()
                .unwrap_or([0; 8]),
        );
        let i = f64::from_be_bytes(
            payload[offset + 16..offset + 24]
                .try_into()
                .unwrap_or([0; 8]),
        );
        let timestamp_us = u64::from_be_bytes(
            payload[offset + 24..offset + 32]
                .try_into()
                .unwrap_or([0; 8]),
        );
        let nc_len = u16::from_be_bytes([payload[offset + 32], payload[offset + 33]]) as usize;
        offset += PDU_FIXED_HEADER_LEN;

        if offset + nc_len > payload.len() {
            return Err(PcapError::MalformedPcap(
                "truncated PDU non-critical bytes in transport payload".to_string(),
            ));
        }
        let non_critical = payload[offset..offset + nc_len].to_vec();
        offset += nc_len;

        pdus.push(Pdu::new(x, y, i, timestamp_us, non_critical));
    }

    Ok(pdus)
}

/// Writes a sequence of `IpPacket` records to a standard `.pcap` file (`LINKTYPE_ETHERNET`,
/// IPv4 + TCP/UDP headers + multi-PDU binary payload).
///
/// # Errors
/// Returns `PcapError` if an IPv6 address is passed to this IPv4 Ethernet writer or on I/O failure.
pub fn write_packets_to_pcap<P: AsRef<Path>>(
    pcap_path: P,
    packets: &[IpPacket],
) -> Result<(), PcapError> {
    let file = File::create(pcap_path)?;
    let mut writer = BufWriter::new(file);

    // 24-byte Libpcap Global Header (little-endian)
    let mut global_hdr = [0_u8; 24];
    global_hdr[0..4].copy_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
    global_hdr[4..6].copy_from_slice(&2_u16.to_le_bytes()); // version_major = 2
    global_hdr[6..8].copy_from_slice(&4_u16.to_le_bytes()); // version_minor = 4
    global_hdr[16..20].copy_from_slice(&65535_u32.to_le_bytes()); // snaplen
    global_hdr[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    writer.write_all(&global_hdr)?;

    for pkt in packets {
        let (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) = (pkt.flow.src_ip, pkt.flow.dst_ip) else {
            return Err(PcapError::MalformedPcap(
                "write_packets_to_pcap currently supports IPv4 flows".to_string(),
            ));
        };

        let app_payload = encode_pdu_payload(&pkt.pdus);
        let l4_hdr_len = match pkt.flow.protocol {
            Protocol::Udp => UDP_HEADER_LEN,
            Protocol::Tcp => TCP_MIN_HEADER_LEN,
        };
        let ip_total_len = IPV4_MIN_HEADER_LEN + l4_hdr_len + app_payload.len();
        let frame_len = ETHERNET_HEADER_LEN + ip_total_len;

        let pkt_ts_us = pkt.pdus.first().map_or(0, |p| p.timestamp_us);
        let ts_seconds = u32::try_from(pkt_ts_us / 1_000_000).unwrap_or(0);
        let ts_micros = u32::try_from(pkt_ts_us % 1_000_000).unwrap_or(0);
        let incl_len = u32::try_from(frame_len)
            .map_err(|_| PcapError::MalformedPcap("packet exceeds u32 max".to_string()))?;

        // 16-byte Libpcap Packet Record Header
        let mut rec_hdr = [0_u8; 16];
        rec_hdr[0..4].copy_from_slice(&ts_seconds.to_le_bytes());
        rec_hdr[4..8].copy_from_slice(&ts_micros.to_le_bytes());
        rec_hdr[8..12].copy_from_slice(&incl_len.to_le_bytes());
        rec_hdr[12..16].copy_from_slice(&incl_len.to_le_bytes());
        writer.write_all(&rec_hdr)?;

        // 14-byte Ethernet II Header (EtherType = 0x0800 IPv4)
        let mut eth_hdr = [0_u8; ETHERNET_HEADER_LEN];
        eth_hdr[12] = 0x08;
        eth_hdr[13] = 0x00;
        writer.write_all(&eth_hdr)?;

        // 20-byte IPv4 Header
        let mut ipv4_hdr = [0_u8; IPV4_MIN_HEADER_LEN];
        ipv4_hdr[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        let ip_len_u16 = u16::try_from(ip_total_len)
            .map_err(|_| PcapError::MalformedPcap("IPv4 packet exceeds 65535 bytes".to_string()))?;
        ipv4_hdr[2..4].copy_from_slice(&ip_len_u16.to_be_bytes());
        ipv4_hdr[8] = 64; // TTL
        ipv4_hdr[9] = match pkt.flow.protocol {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        };
        ipv4_hdr[12..16].copy_from_slice(&src_v4.octets());
        ipv4_hdr[16..20].copy_from_slice(&dst_v4.octets());
        writer.write_all(&ipv4_hdr)?;

        // Transport Header (UDP 8 bytes or TCP 20 bytes)
        match pkt.flow.protocol {
            Protocol::Udp => {
                let mut udp_hdr = [0_u8; UDP_HEADER_LEN];
                udp_hdr[0..2].copy_from_slice(&pkt.flow.src_port.to_be_bytes());
                udp_hdr[2..4].copy_from_slice(&pkt.flow.dst_port.to_be_bytes());
                let udp_len = u16::try_from(UDP_HEADER_LEN + app_payload.len()).unwrap_or(0);
                udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
                writer.write_all(&udp_hdr)?;
            }
            Protocol::Tcp => {
                let mut tcp_hdr = [0_u8; TCP_MIN_HEADER_LEN];
                tcp_hdr[0..2].copy_from_slice(&pkt.flow.src_port.to_be_bytes());
                tcp_hdr[2..4].copy_from_slice(&pkt.flow.dst_port.to_be_bytes());
                tcp_hdr[12] = 5 << 4; // Data offset = 5 (20 bytes)
                writer.write_all(&tcp_hdr)?;
            }
        }

        // Application Multi-PDU payload
        writer.write_all(&app_payload)?;
    }

    writer.flush()?;
    Ok(())
}

/// Reads all `IpPacket` records from a standard `.pcap` file (`LINKTYPE_ETHERNET`, IPv4 + TCP/UDP).
///
/// # Errors
/// Returns `PcapError` if the `.pcap` header is invalid or packet frames are malformed.
pub fn read_packets_from_pcap<P: AsRef<Path>>(pcap_path: P) -> Result<Vec<IpPacket>, PcapError> {
    let file = File::open(pcap_path)?;
    let mut reader = BufReader::new(file);

    let mut global_hdr = [0_u8; 24];
    reader.read_exact(&mut global_hdr)?;

    let magic = u32::from_le_bytes([global_hdr[0], global_hdr[1], global_hdr[2], global_hdr[3]]);
    let is_le = match magic {
        PCAP_MAGIC_LE => true,
        PCAP_MAGIC_BE => false,
        other => {
            return Err(PcapError::MalformedPcap(format!(
                "unsupported PCAP magic: 0x{other:08x}"
            )));
        }
    };

    let mut packets = Vec::new();
    loop {
        let mut rec_hdr = [0_u8; 16];
        match reader.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(PcapError::Io(e)),
        }

        let incl_bytes = [rec_hdr[8], rec_hdr[9], rec_hdr[10], rec_hdr[11]];
        let incl_len = if is_le {
            u32::from_le_bytes(incl_bytes)
        } else {
            u32::from_be_bytes(incl_bytes)
        } as usize;

        let mut frame = vec![0_u8; incl_len];
        reader.read_exact(&mut frame)?;

        if let Some(pkt) = parse_ethernet_ipv4_frame(&frame)? {
            packets.push(pkt);
        }
    }

    Ok(packets)
}

/// Parses a single Ethernet II frame into an `IpPacket` if it carries IPv4 (`0x0800`),
/// honoring IPv4 `Total Length` so Ethernet trailer padding (64-byte minimum frame) is stripped.
fn parse_ethernet_ipv4_frame(frame: &[u8]) -> Result<Option<IpPacket>, PcapError> {
    if frame.len() < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return Err(PcapError::MalformedPcap(
            "frame shorter than Ethernet + IPv4 header".to_string(),
        ));
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Ok(None);
    }

    let ip_slice = &frame[ETHERNET_HEADER_LEN..];
    let ihl_bytes = usize::from(ip_slice[0] & 0x0F) * 4;
    if ihl_bytes < IPV4_MIN_HEADER_LEN || ip_slice.len() < ihl_bytes {
        return Err(PcapError::MalformedPcap("invalid IPv4 IHL".to_string()));
    }
    let ip_total_len = usize::from(u16::from_be_bytes([ip_slice[2], ip_slice[3]]));
    if ip_total_len < ihl_bytes || ip_slice.len() < ip_total_len {
        return Err(PcapError::MalformedPcap(
            "invalid IPv4 total_length in PCAP".to_string(),
        ));
    }
    let ip_packet_slice = &ip_slice[..ip_total_len];

    let proto_byte = ip_packet_slice[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        ip_packet_slice[12],
        ip_packet_slice[13],
        ip_packet_slice[14],
        ip_packet_slice[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        ip_packet_slice[16],
        ip_packet_slice[17],
        ip_packet_slice[18],
        ip_packet_slice[19],
    ));

    let l4_slice = &ip_packet_slice[ihl_bytes..];
    let (protocol, src_port, dst_port, app_payload) = match proto_byte {
        17 => {
            if l4_slice.len() < UDP_HEADER_LEN {
                return Err(PcapError::MalformedPcap(
                    "truncated UDP header in PCAP".to_string(),
                ));
            }
            let sp = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
            let dp = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
            (Protocol::Udp, sp, dp, &l4_slice[UDP_HEADER_LEN..])
        }
        6 => {
            if l4_slice.len() < TCP_MIN_HEADER_LEN {
                return Err(PcapError::MalformedPcap(
                    "truncated TCP header in PCAP".to_string(),
                ));
            }
            let sp = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
            let dp = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
            let data_offset = usize::from(l4_slice[12] >> 4) * 4;
            if data_offset < TCP_MIN_HEADER_LEN || l4_slice.len() < data_offset {
                return Err(PcapError::MalformedPcap(
                    "invalid TCP data offset in PCAP".to_string(),
                ));
            }
            (Protocol::Tcp, sp, dp, &l4_slice[data_offset..])
        }
        other => {
            return Err(PcapError::MalformedPcap(format!(
                "unsupported IPv4 protocol number: {other}"
            )));
        }
    };

    let pdus = decode_pdu_payload(app_payload)?;
    let flow = FiveTuple::new(protocol, src_ip, dst_ip, src_port, dst_port);
    Ok(Some(IpPacket::new(flow, pdus)))
}

/// Verifies a captured `.pcap` file offline against the power-failure-safe rotating local
/// control store (`store_dir`), healing any torn tail record on disk first.
///
/// Use [`verify_pcap_against_live_store`] if the `RotatingControlStore` is actively running
/// and rotating in the background while verification takes place.
///
/// # Errors
/// Returns `PcapError` if reading the store, decrypting control frames, or parsing the `.pcap` fails.
pub fn verify_pcap_against_store<P1: AsRef<Path>, P2: AsRef<Path>>(
    store_dir: P1,
    pcap_path: P2,
    keys: TrustChainKeys,
    config: VerifierConfig,
) -> Result<Vec<IntegrityAlert>, PcapError> {
    let frames = RotatingControlStore::read_all_frames(store_dir)?;
    let packets = read_packets_from_pcap(pcap_path)?;
    verify_packets_with_frames(&frames, &packets, keys, config)
}

/// Verifies a `.pcap` file **while the algorithm and `RotatingControlStore` are actively running
/// and rotating segments**.
///
/// - Uses [`RotatingControlStore::read_all_frames_live`] (strictly read-only, non-truncating,
///   tolerant of concurrent segment rotation/deletion and in-flight tail writes).
/// - Automatically filters packets and control entries to the overlapping retained time window
///   so that packets captured *before* the oldest currently retained segment (which were rotated
///   out) or *after* the latest flushed control epoch (which are still buffered in memory at
///   Ingress) do not cause false `FlowAdded` or `PduAdded` alerts.
///
/// # Errors
/// Returns `PcapError` if reading the live store, decrypting control frames, or parsing the `.pcap` fails.
pub fn verify_pcap_against_live_store<P1: AsRef<Path>, P2: AsRef<Path>>(
    store_dir: P1,
    pcap_path: P2,
    keys: TrustChainKeys,
    config: VerifierConfig,
) -> Result<Vec<IntegrityAlert>, PcapError> {
    let frames = RotatingControlStore::read_all_frames_live(store_dir)?;
    let packets = read_packets_from_pcap(pcap_path)?;
    verify_packets_with_frames(&frames, &packets, keys, config)
}

/// Core verification helper that reconciles a slice of `EncryptedControlFrame` records against
/// a slice of decoded `.pcap` `IpPacket` records over their retained time horizon.
///
/// ## Hardened Horizon Filtering (DW-03 Fix)
/// - **Rogue Flow Preservation**: Packets belonging to flows that are **not** registered in
///   the retained control frames (`!known_flows.contains(&pkt.flow)`) are **never** filtered out,
///   ensuring `FlowAdded` is always detected even if the attacker sets a forged timestamp (`0` or `u64::MAX`).
/// - **Rotation-Only Lower Horizon Clipping**: Early PDUs on known flows are only clipped when
///   segment rotation actually evicted earlier frames (`first_frame.frame_seq > 0`). When
///   `first_frame.frame_seq == 0`, the entire history since boot is present, so even an injected
///   PDU with `timestamp_us = 0` on a known flow is caught as `PduAdded`.
fn verify_packets_with_frames(
    frames: &[EncryptedControlFrame],
    packets: &[IpPacket],
    keys: TrustChainKeys,
    config: VerifierConfig,
) -> Result<Vec<IntegrityAlert>, PcapError> {
    use std::collections::BTreeSet;

    if frames.is_empty() {
        return Ok(Vec::new());
    }

    let rotated_prefix_evicted = frames.first().is_some_and(|f| f.frame_seq > 0);
    let mut min_retained_ts_us = u64::MAX;
    let mut max_ts_us = 0_u64;
    let mut known_flows = BTreeSet::new();

    for frame in frames {
        let payload = decrypt_control_frame(&keys, frame)?;
        max_ts_us = max_ts_us.max(payload.emitted_at_us);
        for flow_summary in &payload.flows {
            known_flows.insert(flow_summary.flow);
            for entry in &flow_summary.entries {
                min_retained_ts_us = min_retained_ts_us.min(entry.timestamp_us);
                max_ts_us = max_ts_us.max(entry.timestamp_us);
            }
        }
    }

    let mut egress = EgressIps::new(keys, config);
    for frame in frames {
        egress.receive_control_frame(frame)?;
    }

    for pkt in packets {
        // Never filter out unknown/rogue flows: they must always be evaluated so FlowAdded triggers!
        let is_known_flow = known_flows.contains(&pkt.flow);
        let in_window_pdus: Vec<Pdu> = pkt
            .pdus
            .iter()
            .filter(|pdu| {
                if !is_known_flow || !rotated_prefix_evicted || min_retained_ts_us == u64::MAX {
                    true
                } else {
                    pdu.timestamp_us >= min_retained_ts_us
                }
            })
            .cloned()
            .collect();

        if in_window_pdus.is_empty() {
            continue;
        }

        for pdu in &in_window_pdus {
            max_ts_us = max_ts_us.max(pdu.timestamp_us);
        }
        egress.receive_data_packet(&IpPacket::new(pkt.flow, in_window_pdus));
    }

    let final_watermark_us = max_ts_us
        .saturating_add(config.grace_window_us)
        .saturating_add(config.control_skew_tolerance_us)
        .saturating_add(1_000_000);
    egress.evaluate_watermarks(final_watermark_us);

    Ok(egress.drain_alerts())
}
