//! Core domain models for the AI-TrustChain Dual-IPS Integrity System.
//!
//! This module defines the canonical representation of network flows (`FiveTuple`),
//! transport protocols (`Protocol`), protocol data units (`Pdu`), multi-PDU IP packets
//! (`IpPacket`), control stream descriptors (`PduControlEntry`, `ControlPayload`), and
//! structured security alerts (`IntegrityAlert`).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Transport layer protocol for a monitored network flow.
///
/// Both connection-oriented (`Tcp`) and connectionless (`Udp`) flows are supported.
/// Verification operates on extracted PDUs rather than raw packet boundaries so that
/// TCP segment coalescing or UDP packet loss does not desynchronize verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// Transmission Control Protocol (RFC 9293).
    Tcp,
    /// User Datagram Protocol (RFC 768).
    Udp,
}

/// Canonical 5-tuple uniquely identifying a unidirectional network flow.
///
/// Used as the primary partitioning key on both Ingress IPS and Egress IPS
/// to track per-flow sequence numbers, watermarks, and integrity windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    /// Transport protocol (`Tcp` or `Udp`).
    pub protocol: Protocol,
    /// Source IPv4 or IPv6 address.
    pub src_ip: IpAddr,
    /// Destination IPv4 or IPv6 address.
    pub dst_ip: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
}

impl FiveTuple {
    /// Constructs a new `FiveTuple` flow identifier.
    #[must_use]
    pub const fn new(
        protocol: Protocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}

/// A single Protocol Data Unit (PDU) embedded within a TCP or UDP packet.
///
/// Only the critical tuple `(x, y, i, timestamp_us)` is authenticated by the
/// control stream. The `non_critical` payload may be modified by intermediate
/// network equipment without triggering false-positive integrity alerts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pdu {
    /// Critical horizontal or Cartesian X coordinate.
    pub x: f64,
    /// Critical vertical or Cartesian Y coordinate.
    pub y: f64,
    /// Critical intensity, amplitude, or track identifier value.
    pub i: f64,
    /// Critical observation timestamp in microseconds since the Unix epoch.
    pub timestamp_us: u64,
    /// Non-critical ancillary fields or padding that are excluded from MAC calculation.
    pub non_critical: Vec<u8>,
}

impl Pdu {
    /// Creates a new `Pdu` with critical `[X, Y, I, Timestamp]` fields and optional non-critical bytes.
    #[must_use]
    pub const fn new(x: f64, y: f64, i: f64, timestamp_us: u64, non_critical: Vec<u8>) -> Self {
        Self {
            x,
            y,
            i,
            timestamp_us,
            non_critical,
        }
    }
}

/// An IP packet carrying one or more application PDUs over TCP or UDP.
///
/// A single `IpPacket` can encapsulate multiple `Pdu` records (`pdus.len() >= 1`),
/// and intermediate TCP stacks may split or coalesce `pdus` across packets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpPacket {
    /// The 5-tuple identifying the flow to which this packet belongs.
    pub flow: FiveTuple,
    /// Ordered list of PDUs extracted from this packet's transport payload.
    pub pdus: Vec<Pdu>,
}

impl IpPacket {
    /// Constructs a new multi-PDU `IpPacket` for a given `FiveTuple` flow.
    #[must_use]
    pub const fn new(flow: FiveTuple, pdus: Vec<Pdu>) -> Self {
        Self { flow, pdus }
    }
}

/// Compact per-PDU integrity record carried inside the ciphered Control Stream.
///
/// Pairing `timestamp_us` and `pdu_seq` with the 128-bit `xyi_mac` allows the Egress IPS to
/// distinguish an in-place alteration of `[X, Y, I]` (`PduAltered`) from a
/// dropped PDU (`PduDeleted`) or a spoofed injection (`PduAdded`) with 128-bit cryptographic
/// collision/forgery resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PduControlEntry {
    /// Monotonically increasing sequence number assigned to this PDU within its flow at Ingress.
    pub pdu_seq: u64,
    /// Critical PDU timestamp in microseconds.
    pub timestamp_us: u64,
    /// 128-bit keyed BLAKE3 MAC over `(flow, timestamp_us, canonical(x, y, i))`.
    pub xyi_mac: u128,
}

/// Summary of a single active flow within a Control Stream epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEpochSummary {
    /// The 5-tuple flow identifier.
    pub flow: FiveTuple,
    /// Total cumulative PDUs observed on this flow at Ingress since monitoring began.
    pub cumulative_pdu_count: u64,
    /// Number of PDUs observed in this specific epoch (`entries.len() as u64`).
    ///
    /// Carrying the per-epoch delta explicitly allows a late-joining or rebooted Egress IPS
    /// to detect whether a flow is actively transmitting in the current epoch (and thus
    /// detect `FlowDeleted` if 0 data packets arrive) without relying on historical
    /// `cumulative_pdu_count` accumulated while the Egress IPS was offline.
    pub epoch_pdu_count: u64,
    /// Individual PDU control descriptors observed during this epoch.
    pub entries: Vec<PduControlEntry>,
}

/// Decrypted payload of a Control Stream frame sent from Ingress IPS to Egress IPS.
///
/// Control frames are hash-chained via `prev_chain_hash` so that if any control frame
/// is dropped or suppressed in transit, the Egress IPS immediately detects the gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPayload {
    /// Per-boot 32-bit random/monotonic session identifier generated by the Ingress IPS.
    pub boot_session_id: u32,
    /// Monotonically increasing control frame sequence number.
    pub frame_seq: u64,
    /// BLAKE3 hash of the preceding serialized `ControlPayload` (all zeros for frame 0).
    pub prev_chain_hash: [u8; 32],
    /// Ingress wall-clock timestamp (in microseconds) when this control frame was emitted.
    pub emitted_at_us: u64,
    /// Per-flow batches and cumulative counters for all active flows at Ingress.
    pub flows: Vec<FlowEpochSummary>,
}

/// Outer wire representation of an AEAD-ciphered Control Stream frame.
///
/// The header fields (`sender_id`, `boot_session_id`, `frame_seq`) are authenticated as
/// Additional Associated Data (AAD) in `ChaCha20-Poly1305`, while `ciphertext` holds the
/// encrypted `ControlPayload` plus its 16-byte Poly1305 authentication tag.
///
/// In addition, `storage_auth_tag` is a 128-bit keyed `BLAKE3` MAC computed under the
/// dedicated `storage_verify` key (`StorageVerificationKey`) over the outer header and
/// `ciphertext`. This allows the **dedicated Storage VM** to cryptographically authenticate
/// incoming frames before persisting them to disk (preventing disk-exhaustion `DoS`) **without**
/// the Storage VM holding the `pdu_mac` or `control_aead` keys needed to decrypt the
/// control stream or forge PDU MACs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedControlFrame {
    /// Unique identifier of the Ingress IPS node that generated this control frame.
    pub sender_id: u32,
    /// Unique per-boot session identifier mixed into the AEAD key/nonce to guarantee
    /// zero AEAD nonce reuse even if the Ingress IPS reboots across power cycles.
    pub boot_session_id: u32,
    /// Strictly monotonic frame sequence number (used to derive the 96-bit AEAD nonce).
    pub frame_seq: u64,
    /// AEAD ciphertext and 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
    /// 128-bit outer authentication tag verifiable by the dedicated Storage VM via `StorageVerificationKey`.
    pub storage_auth_tag: u128,
}

/// Security and integrity alerts raised by the Egress IPS verification engine.
///
/// Covers all required detection categories: altered, deleted, and added flows or PDUs,
/// as well as tampering or loss on the control channel itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IntegrityAlert {
    /// A PDU arrived on a known flow matching an expected slot/timestamp, but its
    /// critical `[X, Y, I]` values were modified in transit.
    PduAltered {
        /// The affected 5-tuple flow.
        flow: FiveTuple,
        /// The expected Ingress PDU sequence number whose slot was altered.
        expected_pdu_seq: u64,
        /// Timestamp of the altered PDU.
        timestamp_us: u64,
        /// The tampered `(x, y, i)` values observed at Egress.
        observed_xyi: (f64, f64, f64),
    },
    /// An expected PDU observed at Ingress failed to arrive at Egress within the grace window.
    PduDeleted {
        /// The affected 5-tuple flow.
        flow: FiveTuple,
        /// The missing Ingress PDU sequence number.
        missing_pdu_seq: u64,
        /// Original timestamp of the deleted PDU.
        timestamp_us: u64,
    },
    /// An unexpected or replayed PDU arrived at Egress on a known flow with no matching
    /// Ingress control entry.
    PduAdded {
        /// The affected 5-tuple flow.
        flow: FiveTuple,
        /// Timestamp carried by the injected PDU.
        timestamp_us: u64,
        /// The injected `(x, y, i)` values observed at Egress.
        observed_xyi: (f64, f64, f64),
    },
    /// An entire legitimate flow announced by the Ingress Control Stream had zero packets
    /// reach Egress within the flow grace window (complete flow blackholing/deletion).
    FlowDeleted {
        /// The blackholed 5-tuple flow.
        flow: FiveTuple,
        /// Number of PDUs expected for this flow that were completely dropped.
        expected_pdu_count: u64,
    },
    /// Packets arrived at Egress for a 5-tuple flow that was never registered by the
    /// Ingress Control Stream (rogue/spoofed flow injection).
    FlowAdded {
        /// The unauthorized 5-tuple flow.
        flow: FiveTuple,
        /// Number of unauthorized PDUs observed before or upon alert emission.
        observed_pdu_count: usize,
    },
    /// One or more Control Stream frames were dropped, reordered, or failed hash-chain verification.
    ControlStreamGap {
        /// Expected control frame sequence number.
        expected_frame_seq: u64,
        /// Actually received control frame sequence number.
        received_frame_seq: u64,
    },
}

