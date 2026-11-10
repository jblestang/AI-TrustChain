//! Ingress IPS (Observer & Control Stream Generator).
//!
//! The `IngressIps` runs on the **Ingress IPS VM**, inspecting outgoing legitimate IP packets
//! (both TCP and UDP), extracting all embedded `[X, Y, I, Timestamp]` PDUs while leaving the
//! original packet untouched and unencrypted, and aggregating compact per-PDU integrity
//! descriptors into hash-chained, AEAD-encrypted Control Stream frames.
//!
//! ## Decoupled Multi-VM Architecture (No Disk on the Ingress IPS VM)
//! - The **Ingress IPS VM** does **not** perform local disk storage; it operates purely in memory
//!   with bounded ring buffers (`IngressConfig`) and streams `EncryptedControlFrame` packets
//!   unidirectionally over the network to both the **Egress IPS VM** (`EgressIps`) and the
//!   **dedicated Storage VM** (`StorageVmNode`).
//! - Every instance generates a unique `boot_session_id` so power cycles on the Ingress IPS VM
//!   never reuse AEAD `(key, nonce)` pairs.
//! - Each `IngressFlowState` enforces a bounded ring buffer (`max_pending_entries_per_flow`)
//!   and increments `cumulative_pdu_count` strictly by the number of actually emitted entries.
//! - Inactive flows are automatically pruned after `flow_idle_timeout_us`.

use crate::crypto::{
    compute_control_chain_hash, compute_pdu_xyi_mac, encrypt_control_frame, CryptoError,
    TrustChainKeys,
};
use crate::model::{
    ControlPayload, EncryptedControlFrame, FiveTuple, FlowEpochSummary, IpPacket, PduControlEntry,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic counter mixed with system nanoseconds to guarantee unique `boot_session_id` values.
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Generates a unique non-zero 32-bit `boot_session_id`.
fn generate_boot_session_id() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u32, |d| d.subsec_nanos());
    let seq = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let combined = nanos.wrapping_add(seq.wrapping_mul(0x9E37_79B9));
    if combined == 0 {
        1
    } else {
        combined
    }
}

/// Configuration for `IngressIps` resource bounds and flow lifecycle management.
#[derive(Debug, Clone, Copy)]
pub struct IngressConfig {
    /// Maximum number of pending PDU descriptors buffered per flow before the oldest
    /// un-flushed entry is evicted (prevents unbounded memory growth).
    pub max_pending_entries_per_flow: usize,
    /// Duration of inactivity (in microseconds) after which an idle flow is pruned from
    /// the Ingress flow table during `flush_control_frame`.
    pub flow_idle_timeout_us: u64,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            max_pending_entries_per_flow: 4_096,
            // Default 10 seconds idle timeout before pruning an inactive flow.
            flow_idle_timeout_us: 10_000_000,
        }
    }
}

/// Per-flow tracking state maintained by the Ingress IPS.
#[derive(Debug, Default)]
struct IngressFlowState {
    /// Total number of PDUs actually emitted in control frames for this flow.
    cumulative_pdu_count: u64,
    /// Monotonically increasing sequence number assigned to observed PDUs on this flow.
    next_pdu_seq: u64,
    /// Timestamp (in microseconds) of the most recently observed PDU on this flow.
    last_seen_us: u64,
    /// Bounded queue of PDU descriptors collected during the current open control epoch.
    pending_entries: VecDeque<PduControlEntry>,
}

/// Ingress Intrusion Prevention System (IPS-1) that observes cleartext multi-PDU packets
/// and generates the authenticated/ciphered Control Stream for IPS-2 without assuming
/// that IPS-2 is always online or reachable.
#[derive(Debug)]
pub struct IngressIps {
    /// Unique identifier of this Ingress IPS node.
    sender_id: u32,
    /// Per-boot session identifier preventing AEAD nonce reuse across power cycles.
    boot_session_id: u32,
    /// Shared cryptographic keys for PDU MACs and Control Stream AEAD encryption.
    keys: TrustChainKeys,
    /// Resource bounds and idle-flow eviction configuration.
    config: IngressConfig,
    /// Next control frame sequence number to emit.
    next_frame_seq: u64,
    /// 256-bit BLAKE3 hash of the previously emitted `ControlPayload` (all zeros initially).
    last_chain_hash: [u8; 32],
    /// Deterministic map of active flows and their buffered epoch entries.
    flows: BTreeMap<FiveTuple, IngressFlowState>,
}

impl IngressIps {
    /// Creates a new `IngressIps` instance with default resource bounds (`IngressConfig::default()`).
    #[must_use]
    pub fn new(sender_id: u32, keys: TrustChainKeys) -> Self {
        Self::with_config(sender_id, keys, IngressConfig::default())
    }

    /// Creates a new `IngressIps` instance with custom `IngressConfig` bounds.
    #[must_use]
    pub fn with_config(sender_id: u32, keys: TrustChainKeys, config: IngressConfig) -> Self {
        Self {
            sender_id,
            boot_session_id: generate_boot_session_id(),
            keys,
            config,
            next_frame_seq: 0,
            last_chain_hash: [0_u8; 32],
            flows: BTreeMap::new(),
        }
    }

    /// Returns this instance's unique `boot_session_id`.
    #[must_use]
    pub const fn boot_session_id(&self) -> u32 {
        self.boot_session_id
    }

    /// Observes a legitimate cleartext `IpPacket` (carrying 1 or more PDUs over TCP or UDP)
    /// without altering the packet itself.
    ///
    /// For every PDU inside the packet, extracts the critical `(x, y, i, timestamp_us)` tuple,
    /// computes its keyed `BLAKE3` MAC, and appends it to the bounded epoch buffer.
    pub fn observe_packet(&mut self, packet: &IpPacket) {
        let max_entries = self.config.max_pending_entries_per_flow.max(1);
        let state = self.flows.entry(packet.flow).or_default();
        for pdu in &packet.pdus {
            let pdu_seq = state.next_pdu_seq;
            state.next_pdu_seq += 1;
            state.last_seen_us = state.last_seen_us.max(pdu.timestamp_us);
            let xyi_mac = compute_pdu_xyi_mac(&self.keys, &packet.flow, pdu);

            if state.pending_entries.len() >= max_entries {
                state.pending_entries.pop_front();
            }
            state.pending_entries.push_back(PduControlEntry {
                pdu_seq,
                timestamp_us: pdu.timestamp_us,
                xyi_mac,
            });
        }
    }

    /// Flushes the current control epoch into an AEAD-encrypted, hash-chained
    /// `EncryptedControlFrame` ready for unidirectional transmission on the Control Stream.
    ///
    /// - Any flow that has been completely idle for longer than `config.flow_idle_timeout_us`
    ///   and has no pending entries is automatically pruned first.
    /// - `cumulative_pdu_count` is incremented strictly by `epoch_pdu_count` (`entries.len()`)
    ///   so that even if the per-flow ring buffer evicted older entries prior to flush,
    ///   `cumulative_pdu_count` and `epoch_pdu_count` remain 100% consistent at Egress.
    ///
    /// # Errors
    /// Returns `CryptoError` if payload serialization or AEAD encryption fails.
    pub fn flush_control_frame(
        &mut self,
        emitted_at_us: u64,
    ) -> Result<EncryptedControlFrame, CryptoError> {
        let idle_timeout = self.config.flow_idle_timeout_us;
        self.flows.retain(|_, state| {
            !state.pending_entries.is_empty()
                || emitted_at_us.saturating_sub(state.last_seen_us) < idle_timeout
        });

        let mut flow_summaries = Vec::with_capacity(self.flows.len());
        for (flow, state) in &mut self.flows {
            let entries: Vec<PduControlEntry> = state.pending_entries.drain(..).collect();
            let epoch_pdu_count = entries.len() as u64;
            state.cumulative_pdu_count += epoch_pdu_count;
            flow_summaries.push(FlowEpochSummary {
                flow: *flow,
                cumulative_pdu_count: state.cumulative_pdu_count,
                epoch_pdu_count,
                entries,
            });
        }

        let payload = ControlPayload {
            boot_session_id: self.boot_session_id,
            frame_seq: self.next_frame_seq,
            prev_chain_hash: self.last_chain_hash,
            emitted_at_us,
            flows: flow_summaries,
        };

        let new_chain_hash = compute_control_chain_hash(&payload)?;
        let encrypted = encrypt_control_frame(&self.keys, self.sender_id, &payload)?;

        self.last_chain_hash = new_chain_hash;
        self.next_frame_seq += 1;

        Ok(encrypted)
    }

    /// Returns the number of currently tracked active flows at Ingress.
    #[must_use]
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }
}
