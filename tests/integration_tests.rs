//! Comprehensive end-to-end integration tests for the AI-TrustChain Dual-IPS system.
//!
//! Validates all operational and adversarial scenarios across TCP and UDP multi-PDU flows:
//! 1. Nominal multi-PDU flow verification (TCP & UDP).
//! 2. Mutation of non-critical PDU data (ignored, zero false positives).
//! 3. TCP segment coalescing / re-framing across IP packets in transit.
//! 4. In-place modification of critical `(X, Y, I)` coordinates (`PduAltered`).
//! 5. Selective UDP packet loss / mid-flow PDU deletion (`PduDeleted`) without breaking
//!    subsequent valid PDUs on the same flow.
//! 6. Injection / replay of unauthorized PDUs into a legitimate flow (`PduAdded`).
//! 7. Complete deletion / blackholing of an entire flow (`FlowDeleted`).
//! 8. Injection of an unauthorized rogue 5-tuple flow (`FlowAdded`).
//! 9. Out-of-order arrival (data packet arrives before control frame) and Control Stream
//!    tampering / frame drop detection (`ControlStreamGap`).

use ai_trustchain::crypto::{CryptoError, TrustChainKeys};
use ai_trustchain::egress_ips::{EgressIps, VerifierConfig};
use ai_trustchain::ingress_ips::IngressIps;
use ai_trustchain::model::{FiveTuple, IntegrityAlert, IpPacket, Pdu, Protocol};
use std::net::{IpAddr, Ipv4Addr};

/// Helper to create deterministic test keys.
fn sample_keys() -> TrustChainKeys {
    TrustChainKeys::from_master_secret(&[0x42_u8; 32])
}

/// Helper to create a standard UDP radar flow 5-tuple.
fn udp_radar_flow(port: u16) -> FiveTuple {
    FiveTuple::new(
        Protocol::Udp,
        IpAddr::V4(Ipv4Addr::new(10, 10, 1, 10)),
        IpAddr::V4(Ipv4Addr::new(10, 20, 2, 20)),
        port,
        5000,
    )
}

/// Helper to create a standard TCP telemetry flow 5-tuple.
fn tcp_telemetry_flow(port: u16) -> FiveTuple {
    FiveTuple::new(
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 20, 9)),
        port,
        8443,
    )
}

#[test]
fn test_nominal_multi_pdu_and_non_critical_mutation_and_tcp_coalescing() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let tcp_flow = tcp_telemetry_flow(40001);

    // Ingress observes 2 separate TCP IP packets (2 PDUs each)
    let pkt1 = IpPacket::new(
        tcp_flow,
        vec![
            Pdu::new(100.5, 200.25, 10.0, 1_000_000, vec![0xAA, 0xBB]),
            Pdu::new(101.0, 201.75, 11.0, 1_010_000, vec![0xCC]),
        ],
    );
    let pkt2 = IpPacket::new(
        tcp_flow,
        vec![
            Pdu::new(102.0, -0.0, 12.0, 1_020_000, vec![0x01, 0x02]),
            Pdu::new(103.5, 205.0, 15.0, 1_030_000, vec![0xFF]),
        ],
    );

    ingress.observe_packet(&pkt1);
    ingress.observe_packet(&pkt2);
    let ctrl_frame = ingress.flush_control_frame(1_035_000).unwrap();

    // In transit:
    // 1. Middlebox coalesces the 2 TCP packets into 1 IP packet containing all 4 PDUs.
    // 2. Middlebox modifies `non_critical` bytes on all PDUs.
    // 3. `-0.0` is normalized to `+0.0`.
    let coalesced_egress_pkt = IpPacket::new(
        tcp_flow,
        vec![
            Pdu::new(100.5, 200.25, 10.0, 1_000_000, vec![0x99, 0x88, 0x77]),
            Pdu::new(101.0, 201.75, 11.0, 1_010_000, vec![]),
            Pdu::new(102.0, 0.0, 12.0, 1_020_000, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Pdu::new(103.5, 205.0, 15.0, 1_030_000, vec![0x00]),
        ],
    );

    egress.receive_control_frame(&ctrl_frame).unwrap();
    egress.receive_data_packet(&coalesced_egress_pkt);
    egress.evaluate_watermarks(2_000_000);

    let alerts = egress.drain_alerts();
    assert!(
        alerts.is_empty(),
        "Expected zero alerts for valid coalesced flow with non-critical mutations, got: {alerts:?}"
    );
}

#[test]
fn test_detect_altered_pdu_in_multi_pdu_packet() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let flow = udp_radar_flow(51000);
    let ingress_pkt = IpPacket::new(
        flow,
        vec![
            Pdu::new(10.0, 20.0, 1.0, 1_000_000, vec![1]),
            Pdu::new(30.0, 40.0, 2.0, 1_005_000, vec![2]),
            Pdu::new(50.0, 60.0, 3.0, 1_010_000, vec![3]),
        ],
    );

    ingress.observe_packet(&ingress_pkt);
    let ctrl_frame = ingress.flush_control_frame(1_012_000).unwrap();

    // Attacker modifies X coordinate of the second PDU (seq 1) from 30.0 -> 999.0
    let mut tampered_pkt = ingress_pkt.clone();
    tampered_pkt.pdus[1].x = 999.0;

    egress.receive_control_frame(&ctrl_frame).unwrap();
    egress.receive_data_packet(&tampered_pkt);
    egress.evaluate_watermarks(1_500_000);

    let alerts = egress.drain_alerts();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0],
        IntegrityAlert::PduAltered {
            flow,
            expected_pdu_seq: 1,
            timestamp_us: 1_005_000,
            observed_xyi: (999.0, 40.0, 2.0),
        }
    );
}

#[test]
fn test_udp_packet_loss_detects_deleted_pdu_without_desynchronizing_subsequent_packets() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let flow = udp_radar_flow(52000);
    let pkt1 = IpPacket::new(flow, vec![Pdu::new(1.0, 1.0, 10.0, 1_000_000, vec![])]);
    let pkt2_dropped = IpPacket::new(
        flow,
        vec![
            Pdu::new(2.0, 2.0, 20.0, 1_010_000, vec![]),
            Pdu::new(3.0, 3.0, 30.0, 1_015_000, vec![]),
        ],
    );
    let pkt3 = IpPacket::new(flow, vec![Pdu::new(4.0, 4.0, 40.0, 1_020_000, vec![])]);

    ingress.observe_packet(&pkt1);
    ingress.observe_packet(&pkt2_dropped);
    ingress.observe_packet(&pkt3);
    let ctrl_frame = ingress.flush_control_frame(1_025_000).unwrap();

    // Egress receives control frame, pkt1, and pkt3 (pkt2_dropped is lost in UDP network)
    egress.receive_control_frame(&ctrl_frame).unwrap();
    egress.receive_data_packet(&pkt1);
    egress.receive_data_packet(&pkt3);

    // Advance watermark past grace window (200ms)
    egress.evaluate_watermarks(1_500_000);

    let alerts = egress.drain_alerts();
    assert_eq!(
        alerts,
        vec![
            IntegrityAlert::PduDeleted {
                flow,
                missing_pdu_seq: 1,
                timestamp_us: 1_010_000,
            },
            IntegrityAlert::PduDeleted {
                flow,
                missing_pdu_seq: 2,
                timestamp_us: 1_015_000,
            },
        ]
    );
}

#[test]
fn test_detect_added_pdu_and_replay_attack() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let flow = udp_radar_flow(53000);
    let legit_pdu = Pdu::new(12.0, 34.0, 56.0, 2_000_000, vec![]);
    let injected_pdu = Pdu::new(77.0, 88.0, 99.0, 2_005_000, vec![]);

    let ingress_pkt = IpPacket::new(flow, vec![legit_pdu.clone()]);
    ingress.observe_packet(&ingress_pkt);
    let ctrl_frame = ingress.flush_control_frame(2_010_000).unwrap();

    // Attacker injects a fake PDU and also replays `legit_pdu` a second time
    let egress_pkt = IpPacket::new(flow, vec![legit_pdu.clone(), injected_pdu, legit_pdu]);

    egress.receive_control_frame(&ctrl_frame).unwrap();
    egress.receive_data_packet(&egress_pkt);
    egress.evaluate_watermarks(2_200_000);

    let alerts = egress.drain_alerts();
    assert_eq!(
        alerts,
        vec![
            IntegrityAlert::PduAdded {
                flow,
                timestamp_us: 2_005_000,
                observed_xyi: (77.0, 88.0, 99.0),
            },
            IntegrityAlert::PduAdded {
                flow,
                timestamp_us: 2_000_000,
                observed_xyi: (12.0, 34.0, 56.0),
            },
        ]
    );
}

#[test]
fn test_detect_deleted_flow_and_added_flow() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let deleted_flow = udp_radar_flow(54001);
    let rogue_flow = tcp_telemetry_flow(54002);

    // Ingress observes traffic on `deleted_flow`
    let legit_pkt = IpPacket::new(
        deleted_flow,
        vec![
            Pdu::new(1.0, 2.0, 3.0, 3_000_000, vec![]),
            Pdu::new(4.0, 5.0, 6.0, 3_010_000, vec![]),
        ],
    );
    ingress.observe_packet(&legit_pkt);
    let ctrl_frame = ingress.flush_control_frame(3_020_000).unwrap();

    // In transit: `deleted_flow` is completely blocked, while an attacker injects `rogue_flow`
    let rogue_pkt = IpPacket::new(
        rogue_flow,
        vec![Pdu::new(66.0, 66.0, 66.0, 3_015_000, vec![])],
    );

    egress.receive_control_frame(&ctrl_frame).unwrap();
    egress.receive_data_packet(&rogue_pkt);
    egress.evaluate_watermarks(3_500_000);

    let alerts = egress.drain_alerts();
    assert_eq!(alerts.len(), 2);
    assert!(alerts.contains(&IntegrityAlert::FlowDeleted {
        flow: deleted_flow,
        expected_pdu_count: 2,
    }));
    assert!(alerts.contains(&IntegrityAlert::FlowAdded {
        flow: rogue_flow,
        observed_pdu_count: 1,
    }));
}

#[test]
fn test_data_arriving_before_control_frame_and_control_stream_tampering() {
    let keys = sample_keys();
    let mut ingress = IngressIps::new(1, keys.clone());
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let flow = udp_radar_flow(55000);
    let pkt1 = IpPacket::new(flow, vec![Pdu::new(10.0, 20.0, 30.0, 4_000_000, vec![])]);
    ingress.observe_packet(&pkt1);
    let ctrl_frame_0 = ingress.flush_control_frame(4_005_000).unwrap();

    // Data packet beats the control frame to Egress IPS!
    egress.receive_data_packet(&pkt1);
    // Control frame arrives 10ms later (within 50ms skew tolerance)
    egress.receive_control_frame(&ctrl_frame_0).unwrap();
    egress.evaluate_watermarks(4_500_000);
    assert!(
        egress.drain_alerts().is_empty(),
        "Data arriving slightly ahead of control frame within skew window must verify cleanly"
    );

    // Now test Control Stream tampering & dropped control frame detection
    let pkt2 = IpPacket::new(flow, vec![Pdu::new(11.0, 21.0, 31.0, 5_000_000, vec![])]);
    ingress.observe_packet(&pkt2);
    let _dropped_ctrl_frame_1 = ingress.flush_control_frame(5_005_000).unwrap();

    let pkt3 = IpPacket::new(flow, vec![Pdu::new(12.0, 22.0, 32.0, 6_000_000, vec![])]);
    ingress.observe_packet(&pkt3);
    let ctrl_frame_2 = ingress.flush_control_frame(6_005_000).unwrap();

    // Tampered control frame must be rejected by AEAD
    let mut corrupted_frame = ctrl_frame_2.clone();
    corrupted_frame.ciphertext[0] ^= 0xFF;
    assert_eq!(
        egress.receive_control_frame(&corrupted_frame),
        Err(CryptoError::AuthenticationFailed)
    );

    // Receiving frame 2 when frame 1 was dropped triggers ControlStreamGap
    egress.receive_control_frame(&ctrl_frame_2).unwrap();
    let alerts = egress.drain_alerts();
    assert_eq!(
        alerts,
        vec![IntegrityAlert::ControlStreamGap {
            expected_frame_seq: 1,
            received_frame_seq: 2,
        }]
    );
}

#[test]
fn test_receiver_not_always_present_late_join_reboot_and_bounded_ingress() {
    use ai_trustchain::ingress_ips::IngressConfig;

    let keys = sample_keys();
    let ingress_cfg = IngressConfig {
        max_pending_entries_per_flow: 4,
        flow_idle_timeout_us: 1_000_000, // 1 second idle timeout
    };
    let mut ingress = IngressIps::with_config(1, keys.clone(), ingress_cfg);

    let historical_flow = udp_radar_flow(56001);
    let active_flow = udp_radar_flow(56002);

    // Phase 1: Egress IPS is completely OFFLINE.
    // Ingress observes traffic on both `historical_flow` and `active_flow` and flushes 3 epochs.
    for epoch in 0..3_u64 {
        let t = 1_000_000 + epoch * 100_000;
        ingress.observe_packet(&IpPacket::new(
            historical_flow,
            vec![Pdu::new(1.0, 2.0, 3.0, t, vec![])],
        ));
        ingress.observe_packet(&IpPacket::new(
            active_flow,
            vec![Pdu::new(10.0, 20.0, 30.0, t, vec![])],
        ));
        // Control frames 0, 1, 2 are emitted into the network while no receiver is present.
        let _unreceived_frame = ingress.flush_control_frame(t + 10_000).unwrap();
    }
    assert_eq!(ingress.active_flow_count(), 2);

    // Phase 2: Egress IPS boots up / joins late at frame_seq = 3!
    // Meanwhile `historical_flow` has stopped sending new packets (0 new PDUs in epoch 3,
    // though its cumulative_pdu_count is 3), while `active_flow` sends a new packet.
    let mut egress = EgressIps::new(keys, VerifierConfig::default());

    let pkt_epoch_3 = IpPacket::new(
        active_flow,
        vec![Pdu::new(50.0, 60.0, 70.0, 1_400_000, vec![])],
    );
    ingress.observe_packet(&pkt_epoch_3);
    let ctrl_frame_3 = ingress.flush_control_frame(1_410_000).unwrap();
    assert_eq!(ctrl_frame_3.frame_seq, 3);

    // Egress receives its very first control frame at seq 3 and the matching data packet
    egress.receive_control_frame(&ctrl_frame_3).unwrap();
    egress.receive_data_packet(&pkt_epoch_3);
    egress.evaluate_watermarks(1_800_000);

    // Neither ControlStreamGap (despite starting at frame 3) nor FlowDeleted on `historical_flow`
    // (which had 3 historical PDUs while Egress was offline, but 0 PDUs since Egress joined)
    // should be raised!
    assert!(
        egress.drain_alerts().is_empty(),
        "Late-joining Egress IPS must synchronize cleanly without false alarms on historical traffic"
    );

    // Phase 3: Now `historical_flow` stays idle past `flow_idle_timeout_us` (1s) and is pruned
    // by Ingress so Ingress memory stays strictly bounded.
    let pkt_epoch_4 = IpPacket::new(
        active_flow,
        vec![Pdu::new(51.0, 61.0, 71.0, 3_000_000, vec![])],
    );
    ingress.observe_packet(&pkt_epoch_4);
    let ctrl_frame_4 = ingress.flush_control_frame(3_010_000).unwrap();
    assert_eq!(
        ingress.active_flow_count(),
        1,
        "Idle historical flow must be pruned after flow_idle_timeout_us"
    );

    // Phase 4: Simulate Egress IPS temporarily disconnecting (missing frame 4) and re-anchoring
    // on frame 5 after `reset_sync_state()`.
    let _missed_by_disconnected_egress = ctrl_frame_4;
    egress.reset_sync_state();

    let pkt_epoch_5 = IpPacket::new(
        active_flow,
        vec![Pdu::new(52.0, 62.0, 72.0, 4_000_000, vec![])],
    );
    ingress.observe_packet(&pkt_epoch_5);
    let ctrl_frame_5 = ingress.flush_control_frame(4_010_000).unwrap();

    egress.receive_control_frame(&ctrl_frame_5).unwrap();
    egress.receive_data_packet(&pkt_epoch_5);
    egress.evaluate_watermarks(4_500_000);
    assert!(
        egress.drain_alerts().is_empty(),
        "Rebooted/reconnected Egress IPS must re-anchor cleanly on frame 5"
    );
}

#[test]
fn test_power_failure_safe_rotating_store_and_pcap_verification() {
    use ai_trustchain::pcap_verifier::{verify_pcap_against_store, write_packets_to_pcap};
    use ai_trustchain::storage::{StorageConfig, StorageVmNode};
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let keys = sample_keys();
    let storage_verify_key = keys.storage_verification_key();
    let temp_dir = std::env::temp_dir().join(format!(
        "ai_trustchain_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    let store_dir = temp_dir.join("control_store");
    let pcap_path = temp_dir.join("capture.pcap");

    // Configure small segments (250 bytes max per segment, max 3 retained segments)
    // so rotation happens rapidly and old segments are evicted deterministically.
    let storage_cfg = StorageConfig {
        max_segment_bytes: 250,
        max_segments: 3,
    };
    // Dedicated Storage VM holds ONLY `storage_verify_key` (never `TrustChainKeys`)
    let mut storage_vm =
        StorageVmNode::open(&store_dir, storage_cfg, storage_verify_key).unwrap();
    // Ingress IPS VM runs completely without local disk
    let mut ingress = IngressIps::new(1, keys.clone());

    let udp_flow = udp_radar_flow(57001);
    let tcp_flow = tcp_telemetry_flow(57002);

    // Phase 1: Ingress streams 2 early control epochs over the network to Storage VM
    // (which will be rotated out when frames 2, 3, 4 arrive)
    for i in 0..2_u64 {
        let early_pkt = IpPacket::new(
            udp_flow,
            vec![Pdu::new(1.0, 1.0, 1.0, 100_000 + i * 10_000, vec![])],
        );
        ingress.observe_packet(&early_pkt);
        let frame = ingress.flush_control_frame(105_000 + i * 10_000).unwrap();
        storage_vm.receive_and_persist_frame(&frame).unwrap();
    }

    // Phase 2: Ingress streams 3 active epochs (frames 2, 3, 4) to Storage VM
    let pkt_f2 = IpPacket::new(
        udp_flow,
        vec![
            Pdu::new(10.0, 20.0, 30.0, 1_000_000, vec![0xAA]),
            Pdu::new(15.0, 25.0, 35.0, 1_005_000, vec![0xBB]),
        ],
    );
    ingress.observe_packet(&pkt_f2);
    let frame_2 = ingress.flush_control_frame(1_010_000).unwrap();
    storage_vm.receive_and_persist_frame(&frame_2).unwrap();

    let pkt_f3 = IpPacket::new(
        tcp_flow,
        vec![Pdu::new(100.0, 200.0, 300.0, 1_020_000, vec![0xCC, 0xDD])],
    );
    ingress.observe_packet(&pkt_f3);
    let frame_3 = ingress.flush_control_frame(1_025_000).unwrap();
    storage_vm.receive_and_persist_frame(&frame_3).unwrap();

    let pkt_f4_dropped = IpPacket::new(
        udp_flow,
        vec![Pdu::new(50.0, 60.0, 70.0, 1_030_000, vec![])],
    );
    ingress.observe_packet(&pkt_f4_dropped);
    let frame_4 = ingress.flush_control_frame(1_035_000).unwrap();
    storage_vm.receive_and_persist_frame(&frame_4).unwrap();

    // Verify Storage VM rejects forged or replayed frames over the network (anti-DoS)
    let mut forged_frame = frame_4.clone();
    forged_frame.frame_seq = 99;
    assert!(
        storage_vm.receive_and_persist_frame(&forged_frame).is_err(),
        "Storage VM must reject unauthenticated frames before touching the disk"
    );
    assert!(
        storage_vm.receive_and_persist_frame(&frame_4).is_err(),
        "Storage VM must reject replayed frames so attackers cannot force premature rotation"
    );

    drop(storage_vm);

    // Verify rotation kept at most 3 segment files on disk
    let segment_files: Vec<_> = fs::read_dir(&store_dir)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        segment_files.len(),
        3,
        "Ring rotation must keep at most max_segments (3) files on disk"
    );

    // Phase 3: Simulate a mid-write POWER FAILURE by appending a torn/corrupted record
    // to the newest segment file on disk!
    let newest_segment = store_dir.join("segment_00000000000000000005.tclog");
    let size_before_crash = fs::metadata(&newest_segment).unwrap().len();
    {
        let mut f = OpenOptions::new().append(true).open(&newest_segment).unwrap();
        // Write a header claiming 500 bytes of payload + bogus checksum + only 7 bytes of torn data
        f.write_all(&500_u32.to_be_bytes()).unwrap();
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33])
            .unwrap();
        f.write_all(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
        f.sync_all().unwrap();
    }
    assert!(fs::metadata(&newest_segment).unwrap().len() > size_before_crash);

    // Phase 4: Build a .pcap file representing traffic captured on the network:
    // - `pkt_f2` has its first PDU's Y coordinate altered (20.0 -> 999.0) and second PDU intact
    // - `pkt_f3` is intact (with modified non_critical bytes, which are ignored)
    // - `pkt_f4_dropped` is missing from the PCAP (deleted in transit)
    // - `pkt_injected` is an added PDU on `tcp_flow`
    let mut pkt_f2_captured = pkt_f2.clone();
    pkt_f2_captured.pdus[0].y = 999.0;

    let mut pkt_f3_captured = pkt_f3.clone();
    pkt_f3_captured.pdus[0].non_critical = vec![0xFF, 0xEE, 0xDD];

    let pkt_injected = IpPacket::new(
        tcp_flow,
        vec![Pdu::new(888.0, 777.0, 666.0, 1_040_000, vec![])],
    );

    write_packets_to_pcap(
        &pcap_path,
        &[pkt_f2_captured, pkt_f3_captured, pkt_injected],
    )
    .unwrap();

    // Phase 5: Run offline PCAP verification against the crash-recovered rotating store
    let alerts = verify_pcap_against_store(
        &store_dir,
        &pcap_path,
        keys,
        VerifierConfig::default(),
    )
    .unwrap();

    // Confirm the torn tail record was automatically truncated/healed back to `size_before_crash`
    assert_eq!(
        fs::metadata(&newest_segment).unwrap().len(),
        size_before_crash,
        "Torn tail record from power failure must be truncated back to last valid frame boundary"
    );

    // Confirm all 3 expected anomalies in the PCAP are detected (Altered, Deleted, Added)
    assert_eq!(alerts.len(), 3, "Expected 3 alerts, got: {alerts:?}");
    assert!(alerts.contains(&IntegrityAlert::PduAltered {
        flow: udp_flow,
        expected_pdu_seq: 2,
        timestamp_us: 1_000_000,
        observed_xyi: (10.0, 999.0, 30.0),
    }));
    assert!(alerts.contains(&IntegrityAlert::PduDeleted {
        flow: udp_flow,
        missing_pdu_seq: 4,
        timestamp_us: 1_030_000,
    }));
    assert!(alerts.contains(&IntegrityAlert::PduAdded {
        flow: tcp_flow,
        timestamp_us: 1_040_000,
        observed_xyi: (888.0, 777.0, 666.0),
    }));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_live_pcap_checking_while_algorithm_is_running_with_rotation() {
    use ai_trustchain::pcap_verifier::{
        verify_pcap_against_live_store, write_packets_to_pcap,
    };
    use ai_trustchain::storage::{StorageConfig, StorageVmNode};
    use std::fs;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;

    let keys = sample_keys();
    let storage_verify_key = keys.storage_verification_key();
    let temp_dir = std::env::temp_dir().join(format!(
        "ai_trustchain_live_pcap_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    let store_dir = temp_dir.join("live_control_store");
    let pcap_path = temp_dir.join("live_capture.pcap");

    // Configure aggressive segment rotation (220 bytes per segment, 4 segments retained)
    let storage_cfg = StorageConfig {
        max_segment_bytes: 220,
        max_segments: 4,
    };
    let mut storage_vm =
        StorageVmNode::open(&store_dir, storage_cfg, storage_verify_key).unwrap();
    let mut ingress = IngressIps::new(1, keys.clone());
    let flow = udp_radar_flow(58000);

    // Step 1: Emit 3 early epochs (timestamps 100_000..120_000) that will get rotated out
    let mut all_captured_packets = Vec::new();
    for i in 0..3_u64 {
        let ts = 100_000 + i * 10_000;
        let pkt = IpPacket::new(flow, vec![Pdu::new(1.0, 2.0, 3.0, ts, vec![])]);
        ingress.observe_packet(&pkt);
        let frame = ingress.flush_control_frame(ts + 1_000).unwrap();
        storage_vm.receive_and_persist_frame(&frame).unwrap();
        all_captured_packets.push(pkt);
    }

    // Step 2: Emit 3 active epochs (timestamps 2_000_000..2_020_000) that remain in the rotating window
    let pkt_valid = IpPacket::new(flow, vec![Pdu::new(10.0, 20.0, 30.0, 2_000_000, vec![])]);
    let pkt_to_alter = IpPacket::new(flow, vec![Pdu::new(40.0, 50.0, 60.0, 2_010_000, vec![])]);
    let pkt_to_drop = IpPacket::new(flow, vec![Pdu::new(70.0, 80.0, 90.0, 2_020_000, vec![])]);

    ingress.observe_packet(&pkt_valid);
    let f1 = ingress.flush_control_frame(2_005_000).unwrap();
    storage_vm.receive_and_persist_frame(&f1).unwrap();

    ingress.observe_packet(&pkt_to_alter);
    let f2 = ingress.flush_control_frame(2_015_000).unwrap();
    storage_vm.receive_and_persist_frame(&f2).unwrap();

    ingress.observe_packet(&pkt_to_drop);
    let f3 = ingress.flush_control_frame(2_025_000).unwrap();
    storage_vm.receive_and_persist_frame(&f3).unwrap();

    // Build the PCAP file containing:
    // - The 3 older rotated-out packets (should be cleanly ignored because they predate the rotating window)
    // - `pkt_valid` (intact)
    // - `pkt_to_alter` with tampered X coordinate (40.0 -> 444.0)
    // - (`pkt_to_drop` is omitted -> should be detected as PduDeleted)
    let mut tampered = pkt_to_alter.clone();
    tampered.pdus[0].x = 444.0;
    all_captured_packets.push(pkt_valid);
    all_captured_packets.push(tampered);
    write_packets_to_pcap(&pcap_path, &all_captured_packets).unwrap();

    // Verify while `storage_vm` and `ingress` are still open and active in memory!
    let live_alerts = verify_pcap_against_live_store(
        &store_dir,
        &pcap_path,
        keys.clone(),
        VerifierConfig::default(),
    )
    .unwrap();

    assert_eq!(live_alerts.len(), 2, "Expected 2 alerts on live store, got: {live_alerts:?}");
    assert!(live_alerts.contains(&IntegrityAlert::PduAltered {
        flow,
        expected_pdu_seq: 4,
        timestamp_us: 2_010_000,
        observed_xyi: (444.0, 50.0, 60.0),
    }));
    assert!(live_alerts.contains(&IntegrityAlert::PduDeleted {
        flow,
        missing_pdu_seq: 5,
        timestamp_us: 2_020_000,
    }));

    // Step 3: Multi-threaded stress test — Ingress VM streams to Storage VM + segment rotation
    // on one thread while concurrently running `verify_pcap_against_live_store` on another thread.
    let writer_done = Arc::new(AtomicBool::new(false));
    let writer_done_clone = Arc::clone(&writer_done);
    let store_dir_writer = store_dir.clone();
    let keys_writer = keys.clone();

    let writer_handle = thread::spawn(move || {
        for step in 0..25_u64 {
            let ts = 3_000_000 + step * 10_000;
            let pkt = IpPacket::new(flow, vec![Pdu::new(1.0, 1.0, 1.0, ts, vec![])]);
            ingress.observe_packet(&pkt);
            let frame = ingress.flush_control_frame(ts + 1_000).unwrap();
            storage_vm.receive_and_persist_frame(&frame).unwrap();
        }
        writer_done_clone.store(true, Ordering::Release);
        // Keep `storage_vm` alive until thread exit
        assert!(store_dir_writer.exists());
        drop(keys_writer);
    });

    // Concurrently invoke `verify_pcap_against_live_store` repeatedly while segments rotate
    let mut concurrent_checks = 0;
    while !writer_done.load(Ordering::Acquire) || concurrent_checks < 5 {
        let res = verify_pcap_against_live_store(
            &store_dir,
            &pcap_path,
            keys.clone(),
            VerifierConfig::default(),
        );
        assert!(
            res.is_ok(),
            "Concurrent live PCAP verification failed during segment rotation: {res:?}"
        );
        concurrent_checks += 1;
    }

    writer_handle.join().unwrap();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_all_eight_design_weakness_fixes() {
    use ai_trustchain::ingress_ips::IngressConfig;
    use ai_trustchain::pcap_verifier::{verify_pcap_against_live_store, write_packets_to_pcap};
    use ai_trustchain::storage::{StorageConfig, StorageVmNode};
    use std::fs;

    let keys = sample_keys();
    let temp_dir = std::env::temp_dir().join(format!(
        "ai_trustchain_dw_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    let store_dir = temp_dir.join("dw_store");
    let pcap_path = temp_dir.join("dw_capture.pcap");

    // -------------------------------------------------------------------------
    // 1. DW-01 (AEAD Nonce Reuse across Power Cycle) & DW-06 (Ring-Buffer Eviction Sync)
    //    with Decoupled Storage VM (holding only StorageVerificationKey)
    // -------------------------------------------------------------------------
    let mut storage_vm = StorageVmNode::open(
        &store_dir,
        StorageConfig::default(),
        keys.storage_verification_key(),
    )
    .unwrap();
    let ingress_cfg = IngressConfig {
        max_pending_entries_per_flow: 2, // Tiny ring buffer to force eviction (DW-06)
        flow_idle_timeout_us: 5_000_000,
    };
    let mut ingress_boot1 = IngressIps::with_config(1, keys.clone(), ingress_cfg);
    let flow = udp_radar_flow(59001);

    // Observe 4 PDUs when max_pending_entries_per_flow = 2 (evicts first 2, keeps seq 2 and 3)
    let pkt_overflow = IpPacket::new(
        flow,
        vec![
            Pdu::new(1.0, 1.0, 1.0, 1_000_000, vec![]),
            Pdu::new(2.0, 2.0, 2.0, 1_001_000, vec![]),
            Pdu::new(3.0, 3.0, 3.0, 1_002_000, vec![]),
            Pdu::new(4.0, 4.0, 4.0, 1_003_000, vec![]),
        ],
    );
    ingress_boot1.observe_packet(&pkt_overflow);
    let frame_boot1 = ingress_boot1.flush_control_frame(1_005_000).unwrap();
    storage_vm.receive_and_persist_frame(&frame_boot1).unwrap();

    // Simulate Ingress IPS VM power cycle (completely stateless reboot without disk):
    // generates a fresh `boot_session_id` and starts at `frame_seq = 0` under a new session key!
    let mut ingress_boot2 = IngressIps::with_config(1, keys.clone(), ingress_cfg);
    assert_ne!(
        ingress_boot1.boot_session_id(),
        ingress_boot2.boot_session_id(),
        "DW-01: Rebooted Ingress VM must have a fresh boot_session_id to prevent AEAD nonce reuse"
    );

    let pkt_boot2 = IpPacket::new(flow, vec![Pdu::new(5.0, 5.0, 5.0, 1_010_000, vec![])]);
    ingress_boot2.observe_packet(&pkt_boot2);
    let frame_boot2 = ingress_boot2.flush_control_frame(1_015_000).unwrap();
    assert_eq!(frame_boot2.frame_seq, 0);
    storage_vm.receive_and_persist_frame(&frame_boot2).unwrap();

    // -------------------------------------------------------------------------
    // 2. DW-07 (Control Frame Anti-Replay)
    // -------------------------------------------------------------------------
    let mut egress = EgressIps::new(keys.clone(), VerifierConfig::default());
    egress.receive_control_frame(&frame_boot1).unwrap();
    // Replaying `frame_boot1` (same boot_session_id, frame_seq = 0 < expected 1) must be rejected!
    assert_eq!(
        egress.receive_control_frame(&frame_boot1),
        Err(CryptoError::ControlFrameReplay {
            expected: 1,
            received: 0,
        }),
        "DW-07: Replayed control frame must be rejected"
    );
    // Receiving `frame_boot2` (new boot_session_id, seq 1) succeeds cleanly
    egress.receive_control_frame(&frame_boot2).unwrap();

    // -------------------------------------------------------------------------
    // 3. DW-04 (Future-Timestamp Bypass `u64::MAX`) & DW-05 (Nudged Timestamp `PduAltered`)
    // -------------------------------------------------------------------------
    let mut ingress_live = IngressIps::new(1, keys.clone());
    let mut egress_live = EgressIps::new(
        keys.clone(),
        VerifierConfig {
            grace_window_us: 200_000,
            control_skew_tolerance_us: 50_000,
            max_tracked_flows: 4,
            max_pending_per_flow: 8,
            flow_idle_timeout_us: 1_000_000,
        },
    );

    let pkt_orig = IpPacket::new(flow, vec![Pdu::new(10.0, 20.0, 30.0, 2_000_000, vec![])]);
    ingress_live.observe_packet(&pkt_orig);
    let ctrl_live = ingress_live.flush_control_frame(2_005_000).unwrap();
    egress_live.receive_control_frame(&ctrl_live).unwrap();

    // Attacker modifies X (10.0 -> 99.0) AND nudges timestamp by +5us (2_000_000 -> 2_000_005) (DW-05),
    // AND injects a second PDU with `timestamp_us = u64::MAX` to try to bypass `saturating_sub` (DW-04)!
    let pkt_attack = IpPacket::new(
        flow,
        vec![
            Pdu::new(99.0, 20.0, 30.0, 2_000_005, vec![]),
            Pdu::new(77.0, 77.0, 77.0, u64::MAX, vec![]),
        ],
    );
    egress_live.receive_data_packet(&pkt_attack);
    egress_live.evaluate_watermarks(2_100_000);

    let live_alerts = egress_live.drain_alerts();
    assert_eq!(live_alerts.len(), 2, "Expected PduAltered + PduAdded, got: {live_alerts:?}");
    assert!(
        live_alerts.contains(&IntegrityAlert::PduAltered {
            flow,
            expected_pdu_seq: 0,
            timestamp_us: 2_000_005,
            observed_xyi: (99.0, 20.0, 30.0),
        }),
        "DW-05: Nudged timestamp + altered X must be correlated as PduAltered"
    );
    assert!(
        live_alerts.contains(&IntegrityAlert::PduAdded {
            flow,
            timestamp_us: u64::MAX,
            observed_xyi: (77.0, 77.0, 77.0),
        }),
        "DW-04: Forged future timestamp u64::MAX must immediately trigger PduAdded"
    );

    // -------------------------------------------------------------------------
    // 4. DW-02 (Bounded Egress Flow Table against Spoofed 5-Tuple Flood)
    // -------------------------------------------------------------------------
    for port in 60000..60010 {
        let spoofed_flow = udp_radar_flow(port);
        egress_live.receive_data_packet(&IpPacket::new(
            spoofed_flow,
            vec![Pdu::new(1.0, 1.0, 1.0, 2_100_000, vec![])],
        ));
    }
    assert!(
        egress_live.tracked_flow_count() <= 4,
        "DW-02: Egress tracked flow count must never exceed max_tracked_flows (4)"
    );
    let flood_alerts = egress_live.drain_alerts();
    assert!(
        !flood_alerts.is_empty(),
        "DW-02: Spoofed 5-tuple flood must emit FlowAdded alerts while staying bounded"
    );

    // -------------------------------------------------------------------------
    // 5. DW-03 (PCAP Verifier Detection of Rogue Flow & Out-of-Window Timestamp Injection)
    // -------------------------------------------------------------------------
    let rogue_pcap_flow = tcp_telemetry_flow(61000);
    let rogue_pcap_pkt = IpPacket::new(
        rogue_pcap_flow,
        // Attacker uses timestamp = 5 (far below `min_retained_ts_us = 1_002_000`)
        vec![Pdu::new(6.0, 6.0, 6.0, 5, vec![])],
    );
    let valid_boot1_2_pkt = IpPacket::new(
        flow,
        vec![
            Pdu::new(3.0, 3.0, 3.0, 1_002_000, vec![]),
            Pdu::new(4.0, 4.0, 4.0, 1_003_000, vec![]),
            Pdu::new(5.0, 5.0, 5.0, 1_010_000, vec![]),
        ],
    );
    write_packets_to_pcap(&pcap_path, &[valid_boot1_2_pkt, rogue_pcap_pkt]).unwrap();

    let pcap_alerts = verify_pcap_against_live_store(
        &store_dir,
        &pcap_path,
        keys,
        VerifierConfig::default(),
    )
    .unwrap();
    assert_eq!(
        pcap_alerts,
        vec![IntegrityAlert::FlowAdded {
            flow: rogue_pcap_flow,
            observed_pdu_count: 1,
        }],
        "DW-03: PCAP verifier must detect rogue FlowAdded even when attacker sets timestamp = 5"
    );

    // -------------------------------------------------------------------------
    // 6. Residual Fix Verification: Unsynchronized Sensor Clock Offset & Empty PCAP Blackhole
    // -------------------------------------------------------------------------
    let mut ingress_unsync = IngressIps::new(1, sample_keys());
    let mut egress_unsync = EgressIps::new(sample_keys(), VerifierConfig::default());
    let unsync_flow = udp_radar_flow(62000);

    // Sensor clock is 10 hours BEHIND the IPS wall clock (`timestamp_us = 500_000`,
    // while IPS `emitted_at_us = 36_000_500_000`!).
    let unsync_pkt = IpPacket::new(
        unsync_flow,
        vec![
            Pdu::new(1.0, 2.0, 3.0, 500_000, vec![]),
            Pdu::new(4.0, 5.0, 6.0, 510_000, vec![]),
        ],
    );
    ingress_unsync.observe_packet(&unsync_pkt);
    let ctrl_unsync = ingress_unsync
        .flush_control_frame(36_000_515_000)
        .unwrap();

    egress_unsync.receive_control_frame(&ctrl_unsync).unwrap();
    // Evaluate watermarks 50ms after control emission (still well inside 200ms grace window!)
    // Without dynamic sensor-to-IPS clock-offset normalization, `36_000_565_000 - 500_000`
    // would be ~36,000 seconds (> 200ms) and falsely trigger `PduDeleted` BEFORE the packet arrives!
    egress_unsync.evaluate_watermarks(36_000_565_000);
    assert!(
        egress_unsync.drain_alerts().is_empty(),
        "Dynamic sensor-to-IPS clock offset calibration must prevent premature PduDeleted when sensor clock lags IPS clock"
    );

    // Now the legitimate packet arrives 80ms after control frame and verifies cleanly!
    egress_unsync.receive_data_packet(&unsync_pkt);
    egress_unsync.evaluate_watermarks(36_001_000_000);
    assert!(egress_unsync.drain_alerts().is_empty());

    // -------------------------------------------------------------------------
    // 7. Zero-False-Positive Guarantee Verification (Remote & Local Storage):
    //    - New flow arriving before its first control frame when sensor clock lags IPS clock by 10 hours
    // -------------------------------------------------------------------------
    let mut egress_zero_fp = EgressIps::new(sample_keys(), VerifierConfig::default());
    let mut ingress_zero_fp = IngressIps::new(1, sample_keys());
    let flow_a = tcp_telemetry_flow(63001);
    let flow_b_new = tcp_telemetry_flow(63002);

    // Calibrate clock offset on `flow_a` (sensor clock = 500_000, IPS clock = 36_000_500_000)
    let pkt_a = IpPacket::new(flow_a, vec![Pdu::new(1.0, 2.0, 3.0, 500_000, vec![])]);
    ingress_zero_fp.observe_packet(&pkt_a);
    let ctrl_a = ingress_zero_fp.flush_control_frame(36_000_505_000).unwrap();
    egress_zero_fp.receive_control_frame(&ctrl_a).unwrap();
    egress_zero_fp.receive_data_packet(&pkt_a);

    // Now a brand-new flow `flow_b_new` (from the same lagging sensor clock = 520_000) has its data packet
    // beat its control frame by 10ms (`current_time_us = 36_000_525_000`).
    // Because `global_clock_offset_us` is applied to newly arriving flows, `evaluate_watermarks` does NOT
    // falsely flag `flow_b_new` as `FlowAdded` before its control frame arrives!
    let pkt_b = IpPacket::new(flow_b_new, vec![Pdu::new(9.0, 8.0, 7.0, 520_000, vec![])]);
    ingress_zero_fp.observe_packet(&pkt_b);
    egress_zero_fp.receive_data_packet(&pkt_b);
    egress_zero_fp.evaluate_watermarks(36_000_525_000);
    assert!(
        egress_zero_fp.drain_alerts().is_empty(),
        "Zero-FP: New flow from lagging sensor clock must not trigger false FlowAdded within skew window"
    );

    // Control frame for `flow_b_new` arrives 10ms later and reconciles cleanly
    let ctrl_b = ingress_zero_fp.flush_control_frame(36_000_530_000).unwrap();
    egress_zero_fp.receive_control_frame(&ctrl_b).unwrap();
    egress_zero_fp.evaluate_watermarks(36_001_000_000);
    assert!(
        egress_zero_fp.drain_alerts().is_empty(),
        "Zero-FP: Early-arriving lagging-clock flow must produce 0 false positives"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
