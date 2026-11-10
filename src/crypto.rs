//! Cryptographic primitives for the AI-TrustChain Control Stream and PDU Integrity Engine.
//!
//! Although the legitimate data flow cannot be ciphered or modified in transit, the
//! out-of-band Control Stream *can* be ciphered and authenticated. This module provides:
//! 1. Deterministic IEEE-754 floating-point canonicalization so `-0.0` and `+0.0` (or NaNs)
//!    hash identically across heterogeneous IPS hardware architectures.
//! 2. Keyed `BLAKE3` 64-bit MAC generation over canonical `(flow, timestamp_us, x, y, i)`.
//! 3. Control frame hash chaining (`BLAKE3`) to detect dropped control frames.
//! 4. Authenticated Encryption with Associated Data (`ChaCha20-Poly1305`) for the Control Stream,
//!    using per-boot session subkey derivation (`derive_session_aead_key`) so that power cycles
//!    on the Ingress IPS can never cause AEAD `(key, nonce)` reuse.

use crate::model::{ControlPayload, EncryptedControlFrame, FiveTuple, Pdu, Protocol};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use std::net::IpAddr;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Domain-specific cryptographic and serialization errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Failed to serialize or deserialize a control payload via `bincode`.
    #[error("control payload serialization error: {0}")]
    Serialization(String),
    /// AEAD encryption or authentication tag verification failed on the control stream.
    #[error("control frame AEAD authentication/decryption failed")]
    AuthenticationFailed,
    /// Replay or out-of-order rollback attempt detected on the control stream.
    #[error("control frame replay or rollback rejected (expected >= {expected}, got {received})")]
    ControlFrameReplay {
        /// Minimum acceptable `frame_seq`.
        expected: u64,
        /// Received `frame_seq`.
        received: u64,
    },
}

/// Shared 256-bit cryptographic key material provisioned to the Ingress and Egress IPS pair.
///
/// Uses domain-separated subkeys derived via `BLAKE3::derive_key` so that:
/// 1. `pdu_mac` (per-PDU `[X, Y, I, Timestamp]` authentication),
/// 2. `control_aead` (`ChaCha20-Poly1305` encryption of `ControlPayload`), and
/// 3. `storage_verify` (outer `storage_auth_tag` verification for the dedicated Storage VM)
///
/// are cryptographically independent. Automatically scrubs key material from memory on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct TrustChainKeys {
    /// 32-byte subkey dedicated to computing per-PDU keyed `BLAKE3` MACs.
    pdu_mac: [u8; 32],
    /// 32-byte subkey dedicated to `ChaCha20-Poly1305` AEAD encryption of the Control Stream.
    control_aead: [u8; 32],
    /// 32-byte subkey dedicated to outer frame authentication on the separate Storage VM.
    storage_verify: [u8; 32],
}

impl std::fmt::Debug for TrustChainKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustChainKeys")
            .field("pdu_mac", &"[REDACTED]")
            .field("control_aead", &"[REDACTED]")
            .field("storage_verify", &"[REDACTED]")
            .finish()
    }
}

/// Restricted verification-only key provisioned to the **separate Storage VM**.
///
/// Allows the Storage VM to authenticate `EncryptedControlFrame::storage_auth_tag` before
/// writing frames to disk (preventing unauthenticated disk-fill `DoS` attacks over the network)
/// **without** granting the Storage VM the ability to decrypt `ControlPayload` or forge
/// `pdu_mac` / `control_aead` data.
#[derive(Clone, ZeroizeOnDrop)]
pub struct StorageVerificationKey {
    /// 32-byte storage authentication subkey.
    subkey: [u8; 32],
}

impl std::fmt::Debug for StorageVerificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageVerificationKey")
            .field("subkey", &"[REDACTED]")
            .finish()
    }
}

impl TrustChainKeys {
    /// Derives domain-separated PDU MAC, Control AEAD, and Storage Verification keys from a 32-byte master secret.
    #[must_use]
    pub fn from_master_secret(master_secret: &[u8; 32]) -> Self {
        let pdu_mac =
            blake3::derive_key("AI-TrustChain v1 PDU MAC Key", master_secret);
        let control_aead =
            blake3::derive_key("AI-TrustChain v1 Control Stream AEAD Key", master_secret);
        let storage_verify =
            blake3::derive_key("AI-TrustChain v1 Storage VM Verification Key", master_secret);
        Self {
            pdu_mac,
            control_aead,
            storage_verify,
        }
    }

    /// Exports the restricted `StorageVerificationKey` to be provisioned onto the separate Storage VM.
    #[must_use]
    pub const fn storage_verification_key(&self) -> StorageVerificationKey {
        StorageVerificationKey {
            subkey: self.storage_verify,
        }
    }
}

/// Canonicalizes an `f64` coordinate or intensity value into an 8-byte big-endian representation.
///
/// Normalizes `-0.0` to `+0.0` and all `NaN` bit patterns to a single quiet `NaN` bit pattern
/// (`0x7ff8_0000_0000_0000`) so that semantically equivalent floats always yield identical MACs.
#[must_use]
pub fn canonicalize_f64(value: f64) -> [u8; 8] {
    if value == 0.0 {
        0.0_f64.to_be_bytes()
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000_u64.to_be_bytes()
    } else {
        value.to_be_bytes()
    }
}

/// Feeds the canonical binary representation of a `FiveTuple` into a `blake3::Hasher`.
fn hash_five_tuple(hasher: &mut blake3::Hasher, flow: &FiveTuple) {
    let proto_byte = match flow.protocol {
        Protocol::Tcp => 6_u8,
        Protocol::Udp => 17_u8,
    };
    hasher.update(&[proto_byte]);
    match flow.src_ip {
        IpAddr::V4(v4) => {
            hasher.update(&[4_u8]);
            hasher.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update(&[6_u8]);
            hasher.update(&v6.octets());
        }
    }
    match flow.dst_ip {
        IpAddr::V4(v4) => {
            hasher.update(&[4_u8]);
            hasher.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update(&[6_u8]);
            hasher.update(&v6.octets());
        }
    }
    hasher.update(&flow.src_port.to_be_bytes());
    hasher.update(&flow.dst_port.to_be_bytes());
}

/// Computes the 128-bit keyed `BLAKE3` MAC over a PDU's critical `[X, Y, I, Timestamp]` tuple
/// bound to its `FiveTuple` flow.
///
/// Non-critical fields (`pdu.non_critical`) are deliberately excluded from this calculation
/// so that benign middlebox changes to non-critical metadata do not trigger false alarms.
#[must_use]
pub fn compute_pdu_xyi_mac(keys: &TrustChainKeys, flow: &FiveTuple, pdu: &Pdu) -> u128 {
    let mut hasher = blake3::Hasher::new_keyed(&keys.pdu_mac);
    hash_five_tuple(&mut hasher, flow);
    hasher.update(&pdu.timestamp_us.to_be_bytes());
    hasher.update(&canonicalize_f64(pdu.x));
    hasher.update(&canonicalize_f64(pdu.y));
    hasher.update(&canonicalize_f64(pdu.i));

    let digest = hasher.finalize();
    let mut mac_bytes = [0_u8; 16];
    mac_bytes.copy_from_slice(&digest.as_bytes()[..16]);
    u128::from_be_bytes(mac_bytes)
}

/// Computes the 256-bit `BLAKE3` chain hash of a `ControlPayload` for control-stream chaining.
///
/// # Errors
/// Returns `CryptoError::Serialization` if the payload cannot be encoded.
pub fn compute_control_chain_hash(payload: &ControlPayload) -> Result<[u8; 32], CryptoError> {
    let encoded = bincode::serialize(payload)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// Derives a per-session 256-bit AEAD key bound to `(sender_id, boot_session_id)` so that
/// even if an Ingress IPS reboots without disk state, a new `boot_session_id` produces an
/// entirely independent `ChaCha20-Poly1305` key, eliminating any possibility of AEAD nonce reuse.
#[must_use]
fn derive_session_aead_key(
    keys: &TrustChainKeys,
    sender_id: u32,
    boot_session_id: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&keys.control_aead);
    hasher.update(b"AI-TrustChain v1 Session AEAD Subkey");
    hasher.update(&sender_id.to_be_bytes());
    hasher.update(&boot_session_id.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Constructs the 96-bit (12-byte) AEAD nonce from `(boot_session_id, frame_seq)`.
#[must_use]
fn build_aead_nonce(boot_session_id: u32, frame_seq: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&boot_session_id.to_be_bytes());
    nonce[4..12].copy_from_slice(&frame_seq.to_be_bytes());
    nonce
}

/// Constructs the Additional Associated Data (AAD) binding the outer header to the ciphertext.
#[must_use]
fn build_aead_aad(sender_id: u32, boot_session_id: u32, frame_seq: u64) -> [u8; 18] {
    let mut aad = [0_u8; 18];
    // Magic "TC" (0x54, 0x43)
    aad[0] = 0x54;
    aad[1] = 0x43;
    aad[2..6].copy_from_slice(&sender_id.to_be_bytes());
    aad[6..10].copy_from_slice(&boot_session_id.to_be_bytes());
    aad[10..18].copy_from_slice(&frame_seq.to_be_bytes());
    aad
}

/// Computes the 128-bit outer storage authentication tag (`storage_auth_tag`) over the
/// frame's header (`sender_id`, `boot_session_id`, `frame_seq`) and `ciphertext`.
#[must_use]
fn compute_storage_auth_tag(
    storage_verify_key: &[u8; 32],
    sender_id: u32,
    boot_session_id: u32,
    frame_seq: u64,
    ciphertext: &[u8],
) -> u128 {
    let mut hasher = blake3::Hasher::new_keyed(storage_verify_key);
    hasher.update(&build_aead_aad(sender_id, boot_session_id, frame_seq));
    hasher.update(ciphertext);
    let digest = hasher.finalize();
    let mut tag_bytes = [0_u8; 16];
    tag_bytes.copy_from_slice(&digest.as_bytes()[..16]);
    u128::from_be_bytes(tag_bytes)
}

/// Verifies an `EncryptedControlFrame` on the **separate Storage VM** using only the
/// restricted `StorageVerificationKey` (without decrypting the `ControlPayload`).
///
/// # Errors
/// Returns `CryptoError::AuthenticationFailed` if the outer `storage_auth_tag` does not match.
pub fn verify_frame_for_storage(
    storage_key: &StorageVerificationKey,
    frame: &EncryptedControlFrame,
) -> Result<(), CryptoError> {
    let expected = compute_storage_auth_tag(
        &storage_key.subkey,
        frame.sender_id,
        frame.boot_session_id,
        frame.frame_seq,
        &frame.ciphertext,
    );
    if frame.storage_auth_tag != expected {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

/// Encrypts and authenticates a `ControlPayload` into an `EncryptedControlFrame` using
/// `ChaCha20-Poly1305` with a per-session derived key and unique `(boot_session_id, frame_seq)` nonce,
/// and attaches the outer `storage_auth_tag` for the separate Storage VM.
///
/// # Errors
/// Returns `CryptoError` if serialization or AEAD encryption fails.
pub fn encrypt_control_frame(
    keys: &TrustChainKeys,
    sender_id: u32,
    payload: &ControlPayload,
) -> Result<EncryptedControlFrame, CryptoError> {
    let plaintext = bincode::serialize(payload)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let session_key = derive_session_aead_key(keys, sender_id, payload.boot_session_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    let nonce_bytes = build_aead_nonce(payload.boot_session_id, payload.frame_seq);
    let aad = build_aead_aad(sender_id, payload.boot_session_id, payload.frame_seq);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let storage_auth_tag = compute_storage_auth_tag(
        &keys.storage_verify,
        sender_id,
        payload.boot_session_id,
        payload.frame_seq,
        &ciphertext,
    );

    Ok(EncryptedControlFrame {
        sender_id,
        boot_session_id: payload.boot_session_id,
        frame_seq: payload.frame_seq,
        ciphertext,
        storage_auth_tag,
    })
}

/// Authenticates and decrypts an `EncryptedControlFrame` back into a `ControlPayload`.
///
/// # Errors
/// Returns `CryptoError::AuthenticationFailed` if the outer storage tag, ciphertext, or AAD header
/// was tampered with, or `CryptoError::Serialization` if the decrypted payload is malformed.
pub fn decrypt_control_frame(
    keys: &TrustChainKeys,
    frame: &EncryptedControlFrame,
) -> Result<ControlPayload, CryptoError> {
    let expected_storage_tag = compute_storage_auth_tag(
        &keys.storage_verify,
        frame.sender_id,
        frame.boot_session_id,
        frame.frame_seq,
        &frame.ciphertext,
    );
    if frame.storage_auth_tag != expected_storage_tag {
        return Err(CryptoError::AuthenticationFailed);
    }

    let session_key = derive_session_aead_key(keys, frame.sender_id, frame.boot_session_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    let nonce_bytes = build_aead_nonce(frame.boot_session_id, frame.frame_seq);
    let aad = build_aead_aad(frame.sender_id, frame.boot_session_id, frame.frame_seq);

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &frame.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let decoded: ControlPayload = bincode::deserialize(&plaintext)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    if decoded.frame_seq != frame.frame_seq || decoded.boot_session_id != frame.boot_session_id {
        return Err(CryptoError::AuthenticationFailed);
    }

    Ok(decoded)
}
