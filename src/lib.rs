//! # AI-TrustChain
//!
//! Out-of-band IPS flow and PDU integrity verification engine for multi-IPS networks.
//!
//! ## Overview
//! In networks where legitimate traffic flows (`TCP` or `UDP`) cannot be encrypted or
//! modified inline, `ai-trustchain` pairs an **Ingress IPS** ([`ingress_ips::IngressIps`])
//! with an **Egress IPS** ([`egress_ips::EgressIps`]) connected via a ciphered out-of-band
//! **Control Stream**:
//!
//! - **Selective Field Authentication**: Extracts `[X, Y, I, Timestamp]` from multiple
//!   PDUs per IP packet while ignoring non-critical metadata changes.
//! - **Loss & Re-segmentation Tolerance**: Uses per-PDU keyed `BLAKE3` digests inside
//!   AEAD-encrypted (`ChaCha20-Poly1305`), hash-chained Control Frames so UDP packet loss
//!   or TCP segment coalescing never causes cascading false alarms.
//! - **Full Anomaly Coverage**: Detects altered PDUs (`PduAltered`), dropped PDUs
//!   (`PduDeleted`), injected/replayed PDUs (`PduAdded`), blackholed flows (`FlowDeleted`),
//!   rogue flows (`FlowAdded`), and control stream gaps (`ControlStreamGap`).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod crypto;
pub mod egress_ips;
pub mod ingress_ips;
pub mod model;
pub mod pcap_verifier;
pub mod storage;

