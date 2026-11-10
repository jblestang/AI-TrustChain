//! Egress IPS (Verifier & Sliding-Window Reconciliation Engine).
//!
//! The `EgressIps` receives both the unmodified legitimate traffic flow (`IpPacket` over TCP/UDP)
//! and the ciphered out-of-band Control Stream (`EncryptedControlFrame`). It applies the same
//! canonical PDU extraction and keyed `BLAKE3` algorithm to the legitimate flow and reconciles
//! observations over a sliding time window to detect:
//! - Altered PDUs (`IntegrityAlert::PduAltered`)
//! - Deleted PDUs (`IntegrityAlert::PduDeleted`)
//! - Added / Injected PDUs (`IntegrityAlert::PduAdded`)
//! - Deleted Flows (`IntegrityAlert::FlowDeleted`)
//! - Added / Rogue Flows (`IntegrityAlert::FlowAdded`)
//! - Dropped / Out-of-order Control Frames (`IntegrityAlert::ControlStreamGap`)
//!
//! ## Hardened Against Adversarial Design Weaknesses
//! - **Control Anti-Replay (DW-07)**: Rejects replayed or rolled-back control frames
//!   (`frame_seq < expected_frame_seq` within the same `boot_session_id`) with
//!   `CryptoError::ControlFrameReplay`.
//! - **Bounded Memory / Anti-DoS (DW-02)**: Enforces `max_tracked_flows`, `max_pending_per_flow`,
//!   and `flow_idle_timeout_us`, and stops buffering PDUs for flows already flagged as `FlowAdded`.
//! - **Future-Timestamp Bypass Immunity (DW-04)**: Rejects or immediately resolves PDUs carrying
//!   forged future timestamps (`timestamp_us > current_time_us + control_skew_tolerance_us`)
//!   so an attacker setting `timestamp_us = u64::MAX` cannot hide in `pending_egress`.
//! - **Two-Tier Slot Correlation for `PduAltered` (DW-05)**: Matches exact `timestamp_us` first,
//!   and falls back to correlating the closest unmatched slot within `control_skew_tolerance_us`
//!   if an attacker modified both `(X, Y, I)` and nudged `timestamp_us`.

use crate::crypto::{
    compute_control_chain_hash, compute_pdu_xyi_mac, decrypt_control_frame, CryptoError,
    TrustChainKeys,
};
use crate::model::{
    EncryptedControlFrame, FiveTuple, IntegrityAlert, IpPacket, Pdu, PduControlEntry,
};
use std::collections::{BTreeMap, VecDeque};

/// Tuning and resource-bound parameters for the Egress IPS sliding-window reconciliation engine.
#[derive(Debug, Clone, Copy)]
pub struct VerifierConfig {
    /// Maximum time (in microseconds) a legitimate PDU declared in the Control Stream
    /// may be delayed in the network before being declared `PduDeleted` (or `FlowDeleted`).
    pub grace_window_us: u64,
    /// Maximum time (in microseconds) an arriving legitimate data PDU will wait for a
    /// slightly delayed Control Frame before being judged as `PduAltered`, `PduAdded`, or `FlowAdded`.
    pub control_skew_tolerance_us: u64,
    /// Maximum number of concurrent 5-tuple flows tracked in memory (protects against spoofed 5-tuple floods).
    pub max_tracked_flows: usize,
    /// Maximum number of unmatched PDUs buffered per flow in `pending_ingress` or `pending_egress`.
    pub max_pending_per_flow: usize,
    /// Duration of inactivity (in microseconds) after which an idle flow with no pending items is evicted.
    pub flow_idle_timeout_us: u64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            // Default 200 ms grace window for transit delay / jitter.
            grace_window_us: 200_000,
            // Default 50 ms tolerance when data packets outrun the control stream.
            control_skew_tolerance_us: 50_000,
            // Default cap of 4,096 concurrent flows.
            max_tracked_flows: 4_096,
            // Default cap of 4,096 pending PDUs per flow.
            max_pending_per_flow: 4_096,
            // Default 10 seconds idle timeout before pruning an inactive flow.
            flow_idle_timeout_us: 10_000_000,
        }
    }
}

/// An observed data PDU at Egress waiting briefly for its corresponding Control Frame
/// (in case the data packet arrived slightly before the control frame).
#[derive(Debug, Clone)]
struct PendingEgressPdu {
    /// Critical `(x, y, i)` coordinates observed in the packet.
    observed_xyi: (f64, f64, f64),
    /// Critical PDU timestamp in microseconds.
    timestamp_us: u64,
    /// Computed 128-bit keyed BLAKE3 MAC.
    xyi_mac: u128,
}

/// Per-flow reconciliation state maintained by the Egress IPS.
#[derive(Debug, Default)]
struct EgressFlowState {
    /// Whether this flow has been legitimized by at least one authenticated Control Frame.
    known_in_control: bool,
    /// Whether Egress has already emitted a `FlowAdded` alert for an unauthorized flow.
    flow_added_alerted: bool,
    /// Whether Egress has already emitted a `FlowDeleted` alert for a blackholed flow.
    flow_deleted_alerted: bool,
    /// Total PDUs declared by Ingress for this flow since this Egress IPS instance synchronized.
    expected_pdus_since_sync: u64,
    /// Historical cumulative PDU count on the first Control Frame observed by this Egress IPS,
    /// used as a baseline when `epoch_pdu_count == 0` across subsequent frames.
    baseline_cumulative_pdus: Option<u64>,
    /// Total legitimate data PDUs actually received at Egress on this flow.
    observed_data_pdus: usize,
    /// Earliest timestamp (us) when active PDUs for this flow were declared in a Control Frame
    /// since Egress synchronized.
    first_active_control_seen_us: Option<u64>,
    /// Earliest timestamp (us) when data packets arrived on this flow at Egress.
    first_data_seen_us: Option<u64>,
    /// Latest timestamp (us) of any control or data activity on this flow (for idle eviction).
    last_activity_us: u64,
    /// Dynamic clock-offset estimate `emitted_at_us - entry.timestamp_us` (signed microseconds)
    /// learned from authenticated Control Frames so that sensors whose clocks differ from the
    /// IPS wall clock are automatically normalized into the IPS time domain.
    sensor_to_ips_clock_offset_us: Option<i64>,
    /// Unmatched Ingress PDU descriptors awaiting arrival of legitimate data packets.
    pending_ingress: VecDeque<PduControlEntry>,
    /// Unmatched Egress data PDUs awaiting a potentially slightly delayed Control Frame.
    pending_egress: VecDeque<PendingEgressPdu>,
}

/// Egress Intrusion Prevention System (IPS-2) that verifies flow and PDU integrity.
#[derive(Debug)]
pub struct EgressIps {
    /// Shared cryptographic keys for PDU MAC verification and Control Stream decryption.
    keys: TrustChainKeys,
    /// Sliding-window timing and resource-bound configuration.
    config: VerifierConfig,
    /// Active Ingress `boot_session_id` to which this verifier is currently anchored.
    active_boot_session_id: Option<u32>,
    /// Expected next control frame sequence number (`None` until the first valid frame is received).
    expected_frame_seq: Option<u64>,
    /// Hash of the last verified `ControlPayload` in the control chain.
    last_chain_hash: [u8; 32],
    /// Global fallback sensor-to-IPS clock offset (`emitted_at_us - entry.timestamp_us`)
    /// learned across authenticated flows, used to normalize newly arriving flows before
    /// their first per-flow control frame arrives.
    global_clock_offset_us: Option<i64>,
    /// Per-flow verification state table.
    flows: BTreeMap<FiveTuple, EgressFlowState>,
    /// Accumulated security alerts ready to be drained by the caller.
    alerts: Vec<IntegrityAlert>,
}

impl EgressIps {
    /// Constructs a new `EgressIps` verifier with shared keys and timing configuration.
    ///
    /// Starts in an unsynchronized state (`expected_frame_seq = None`) so it can join
    /// an already-running network at any point without false alarms.
    #[must_use]
    pub fn new(keys: TrustChainKeys, config: VerifierConfig) -> Self {
        Self {
            keys,
            config,
            active_boot_session_id: None,
            expected_frame_seq: None,
            last_chain_hash: [0_u8; 32],
            global_clock_offset_us: None,
            flows: BTreeMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Resets the control-chain synchronization state (e.g., after a planned Egress maintenance
    /// pause or network interface flap) so the verifier cleanly re-anchors on the next
    /// authenticated `EncryptedControlFrame`.
    pub fn reset_sync_state(&mut self) {
        self.active_boot_session_id = None;
        self.expected_frame_seq = None;
        self.last_chain_hash = [0_u8; 32];
        self.global_clock_offset_us = None;
        self.flows.clear();
    }

    /// Processes an incoming ciphered `EncryptedControlFrame` from the Control Stream.
    ///
    /// 1. Authenticates and decrypts the AEAD payload.
    /// 2. Rejects any replayed or rolled-back control frame (`frame_seq < expected_frame_seq`
    ///    within the same `boot_session_id`) with `CryptoError::ControlFrameReplay`.
    /// 3. If this Egress IPS just joined (or Ingress rebooted with a new `boot_session_id` at
    ///    `frame_seq == 0`), anchors `expected_frame_seq` and `last_chain_hash`. Otherwise,
    ///    verifies `frame_seq` continuity and `prev_chain_hash` integrity.
    /// 4. Registers active flows and reconciles newly announced `PduControlEntry` records
    ///    against any data PDUs already waiting in `pending_egress`.
    ///
    /// # Errors
    /// Returns `CryptoError` if AEAD authentication fails, deserialization fails, or a replay is detected.
    pub fn receive_control_frame(
        &mut self,
        frame: &EncryptedControlFrame,
    ) -> Result<(), CryptoError> {
        let payload = decrypt_control_frame(&self.keys, frame)?;

        // Check if Ingress rebooted into a new boot session
        if let Some(current_session) = self.active_boot_session_id {
            if payload.boot_session_id != current_session {
                // Reject rollback to an older frame sequence even if `boot_session_id` differs,
                // unless `frame_seq == 0` (a genuine cold reboot of Ingress without disk state)
                if let Some(expected_seq) = self.expected_frame_seq {
                    if payload.frame_seq != 0 && payload.frame_seq < expected_seq {
                        return Err(CryptoError::ControlFrameReplay {
                            expected: expected_seq,
                            received: payload.frame_seq,
                        });
                    }
                }
                self.active_boot_session_id = Some(payload.boot_session_id);
                if payload.frame_seq == 0 {
                    self.expected_frame_seq = None;
                }
                for state in self.flows.values_mut() {
                    state.baseline_cumulative_pdus = None;
                }
            }
        } else {
            self.active_boot_session_id = Some(payload.boot_session_id);
        }

        // Check control stream anti-replay, continuity, and hash chain
        if let Some(expected_seq) = self.expected_frame_seq {
            if payload.frame_seq < expected_seq {
                return Err(CryptoError::ControlFrameReplay {
                    expected: expected_seq,
                    received: payload.frame_seq,
                });
            }
            if payload.frame_seq != expected_seq
                || payload.prev_chain_hash != self.last_chain_hash
            {
                self.alerts.push(IntegrityAlert::ControlStreamGap {
                    expected_frame_seq: expected_seq,
                    received_frame_seq: payload.frame_seq,
                });
            }
        }

        self.last_chain_hash = compute_control_chain_hash(&payload)?;
        self.expected_frame_seq = Some(payload.frame_seq + 1);

        let max_pending = self.config.max_pending_per_flow.max(1);
        for flow_summary in payload.flows {
            let state = self.flows.entry(flow_summary.flow).or_default();
            state.known_in_control = true;
            state.last_activity_us = state.last_activity_us.max(payload.emitted_at_us);

            // Track activity strictly from the point this Egress IPS synchronized
            let base = *state.baseline_cumulative_pdus.get_or_insert(
                flow_summary
                    .cumulative_pdu_count
                    .saturating_sub(flow_summary.epoch_pdu_count),
            );
            state.expected_pdus_since_sync = flow_summary.cumulative_pdu_count.saturating_sub(base);

            if state.expected_pdus_since_sync > 0 && state.first_active_control_seen_us.is_none() {
                state.first_active_control_seen_us = Some(payload.emitted_at_us);
            }

            // Insert each control entry or immediately match against early-arriving egress PDUs
            for entry in flow_summary.entries {
                // Continuously calibrate the sensor-to-IPS clock offset from authenticated control frames
                let offset = i64::try_from(payload.emitted_at_us)
                    .unwrap_or(i64::MAX)
                    .saturating_sub(i64::try_from(entry.timestamp_us).unwrap_or(i64::MAX));
                state.sensor_to_ips_clock_offset_us = Some(offset);
                self.global_clock_offset_us = Some(offset);
                state.last_activity_us = state.last_activity_us.max(payload.emitted_at_us);

                if let Some(pos) = state.pending_egress.iter().position(|egress_pdu| {
                    egress_pdu.timestamp_us == entry.timestamp_us
                        && egress_pdu.xyi_mac == entry.xyi_mac
                }) {
                    // Exact match with a data PDU that arrived slightly before this control frame
                    state.pending_egress.remove(pos);
                } else {
                    if state.pending_ingress.len() >= max_pending {
                        state.pending_ingress.pop_front();
                    }
                    state.pending_ingress.push_back(entry);
                }
            }
        }

        Ok(())
    }

    /// Processes an incoming cleartext `IpPacket` from the legitimate network path.
    ///
    /// Extracts all PDUs in the packet, computes their canonical `[X, Y, I, Timestamp]`
    /// keyed MAC, and attempts immediate exact reconciliation against `pending_ingress`.
    pub fn receive_data_packet(&mut self, packet: &IpPacket) {
        let max_flows = self.config.max_tracked_flows.max(1);
        if !self.flows.contains_key(&packet.flow) && self.flows.len() >= max_flows {
            // If flow table is at capacity, evict an already-alerted unauthorized flow first
            if let Some(rogue_key) = self
                .flows
                .iter()
                .find(|(_, s)| !s.known_in_control && s.flow_added_alerted)
                .map(|(k, _)| *k)
            {
                self.flows.remove(&rogue_key);
            } else {
                // Immediately emit FlowAdded without allocating unbounded state
                self.alerts.push(IntegrityAlert::FlowAdded {
                    flow: packet.flow,
                    observed_pdu_count: packet.pdus.len(),
                });
                return;
            }
        }

        let max_pending = self.config.max_pending_per_flow.max(1);
        let state = self.flows.entry(packet.flow).or_default();
        for pdu in &packet.pdus {
            state.observed_data_pdus += 1;
            state.last_activity_us = state.last_activity_us.max(pdu.timestamp_us);
            if state.first_data_seen_us.is_none() {
                state.first_data_seen_us = Some(pdu.timestamp_us);
            }

            // Do not buffer PDUs if this flow was already flagged as an unauthorized FlowAdded
            if !state.known_in_control && state.flow_added_alerted {
                continue;
            }

            let xyi_mac = compute_pdu_xyi_mac(&self.keys, &packet.flow, pdu);

            // Fast path: exact match (timestamp + MAC) in pending_ingress
            if let Some(pos) = state.pending_ingress.iter().position(|entry| {
                entry.timestamp_us == pdu.timestamp_us && entry.xyi_mac == xyi_mac
            }) {
                state.pending_ingress.remove(pos);
            } else {
                if state.pending_egress.len() >= max_pending {
                    state.pending_egress.pop_front();
                }
                state
                    .pending_egress
                    .push_back(Self::build_pending_pdu(pdu, xyi_mac));
            }
        }
    }

    /// Helper to construct a `PendingEgressPdu` from an observed `Pdu` and its MAC.
    #[must_use]
    const fn build_pending_pdu(pdu: &Pdu, xyi_mac: u128) -> PendingEgressPdu {
        PendingEgressPdu {
            observed_xyi: (pdu.x, pdu.y, pdu.i),
            timestamp_us: pdu.timestamp_us,
            xyi_mac,
        }
    }

    /// Normalizes a sensor PDU timestamp into the IPS wall-clock domain using the learned
    /// per-flow `sensor_to_ips_clock_offset_us` (if present).
    #[must_use]
    const fn normalize_to_ips_clock(ts_us: u64, clock_offset_us: Option<i64>) -> u64 {
        if let Some(offset) = clock_offset_us {
            ts_us.saturating_add_signed(offset)
        } else {
            ts_us
        }
    }

    /// Returns `true` if a timestamp is either older than `current_time_us - tolerance_us`
    /// OR implausibly far in the future (`ts > current_time_us + tolerance_us`), preventing
    /// attackers from bypassing watermark checks with `timestamp_us = u64::MAX`.
    #[must_use]
    const fn is_past_skew_or_forged_future(
        current_time_us: u64,
        ts: u64,
        tolerance_us: u64,
    ) -> bool {
        if ts <= current_time_us {
            current_time_us - ts >= tolerance_us
        } else {
            ts - current_time_us > tolerance_us
        }
    }

    /// Advances the verification watermark to `current_time_us`, resolving any pending
    /// discrepancies into concrete `IntegrityAlert` events and evicting idle flows.
    pub fn evaluate_watermarks(&mut self, current_time_us: u64) {
        let skew_tol = self.config.control_skew_tolerance_us;
        let grace_win = self.config.grace_window_us;
        let idle_timeout = self.config.flow_idle_timeout_us;
        let global_offset = self.global_clock_offset_us;

        for (flow, state) in &mut self.flows {
            if state.sensor_to_ips_clock_offset_us.is_none() {
                state.sensor_to_ips_clock_offset_us = global_offset;
            }
            Self::evaluate_single_flow(
                *flow,
                state,
                &mut self.alerts,
                current_time_us,
                skew_tol,
                grace_win,
            );
        }

        // Evict completely idle flows with empty queues past `flow_idle_timeout_us`
        self.flows.retain(|_, state| {
            !state.pending_ingress.is_empty()
                || !state.pending_egress.is_empty()
                || current_time_us.saturating_sub(state.last_activity_us) < idle_timeout
        });
    }

    /// Evaluates watermark rules for a single `FiveTuple` flow.
    fn evaluate_single_flow(
        flow: FiveTuple,
        state: &mut EgressFlowState,
        alerts: &mut Vec<IntegrityAlert>,
        current_time_us: u64,
        skew_tol: u64,
        grace_win: u64,
    ) {
        // 1. Check for unauthorized / added flows (FlowAdded)
        if !state.known_in_control {
            if let Some(first_seen) = state.first_data_seen_us {
                let normalized_first_seen =
                    Self::normalize_to_ips_clock(first_seen, state.sensor_to_ips_clock_offset_us);
                if Self::is_past_skew_or_forged_future(
                    current_time_us,
                    normalized_first_seen,
                    skew_tol,
                ) && !state.flow_added_alerted
                {
                    state.flow_added_alerted = true;
                    state.pending_egress.clear();
                    alerts.push(IntegrityAlert::FlowAdded {
                        flow,
                        observed_pdu_count: state.observed_data_pdus,
                    });
                }
            }
            return;
        }

        // 2. Reconcile unmatched Egress PDUs once control skew tolerance has elapsed
        let mut remaining_egress = VecDeque::new();
        while let Some(egress_pdu) = state.pending_egress.pop_front() {
            if let Some(exact_pos) = state.pending_ingress.iter().position(|entry| {
                entry.timestamp_us == egress_pdu.timestamp_us
                    && entry.xyi_mac == egress_pdu.xyi_mac
            }) {
                state.pending_ingress.remove(exact_pos);
                continue;
            }

            let normalized_egress_ts = Self::normalize_to_ips_clock(
                egress_pdu.timestamp_us,
                state.sensor_to_ips_clock_offset_us,
            );
            if !Self::is_past_skew_or_forged_future(current_time_us, normalized_egress_ts, skew_tol)
            {
                remaining_egress.push_back(egress_pdu);
                continue;
            }

            let slot_pos = state
                .pending_ingress
                .iter()
                .position(|entry| entry.timestamp_us == egress_pdu.timestamp_us)
                .or_else(|| {
                    state.pending_ingress.iter().position(|entry| {
                        entry.timestamp_us.abs_diff(egress_pdu.timestamp_us) <= skew_tol
                    })
                });

            if let Some(pos) = slot_pos {
                if let Some(altered_slot) = state.pending_ingress.remove(pos) {
                    alerts.push(IntegrityAlert::PduAltered {
                        flow,
                        expected_pdu_seq: altered_slot.pdu_seq,
                        timestamp_us: egress_pdu.timestamp_us,
                        observed_xyi: egress_pdu.observed_xyi,
                    });
                }
            } else {
                alerts.push(IntegrityAlert::PduAdded {
                    flow,
                    timestamp_us: egress_pdu.timestamp_us,
                    observed_xyi: egress_pdu.observed_xyi,
                });
            }
        }
        state.pending_egress = remaining_egress;

        // 3. Check for complete flow deletion (FlowDeleted) since Egress synchronized
        if state.observed_data_pdus == 0
            && state.expected_pdus_since_sync > 0
            && !state.flow_deleted_alerted
        {
            if let Some(first_ctrl) = state.first_active_control_seen_us {
                if current_time_us.saturating_sub(first_ctrl) >= grace_win {
                    state.flow_deleted_alerted = true;
                    state.pending_ingress.clear();
                    alerts.push(IntegrityAlert::FlowDeleted {
                        flow,
                        expected_pdu_count: state.expected_pdus_since_sync,
                    });
                    return;
                }
            }
        }

        // 4. Check for individual deleted PDUs (PduDeleted) past grace_window_us (normalized to IPS clock)
        let mut remaining_ingress = VecDeque::new();
        while let Some(ingress_entry) = state.pending_ingress.pop_front() {
            let normalized_ingress_ts = Self::normalize_to_ips_clock(
                ingress_entry.timestamp_us,
                state.sensor_to_ips_clock_offset_us,
            );
            if current_time_us.saturating_sub(normalized_ingress_ts) >= grace_win {
                alerts.push(IntegrityAlert::PduDeleted {
                    flow,
                    missing_pdu_seq: ingress_entry.pdu_seq,
                    timestamp_us: ingress_entry.timestamp_us,
                });
            } else {
                remaining_ingress.push_back(ingress_entry);
            }
        }
        state.pending_ingress = remaining_ingress;
    }

    /// Drains and returns all accumulated `IntegrityAlert` events emitted so far.
    #[must_use]
    pub fn drain_alerts(&mut self) -> Vec<IntegrityAlert> {
        std::mem::take(&mut self.alerts)
    }

    /// Returns the number of currently tracked flows in the Egress table.
    #[must_use]
    pub fn tracked_flow_count(&self) -> usize {
        self.flows.len()
    }
}
