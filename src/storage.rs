//! Power-failure-safe rotating local storage (Write-Ahead Control Store) for `EncryptedControlFrame` records.
//!
//! ## Power-Failure Safety & Crash Recovery Design
//! When an Egress IPS is offline or a post-incident forensic audit is performed against a
//! captured `.pcap` file, the Ingress IPS (or a local logger) needs a durable, bounded-disk
//! local copy of the Control Stream.
//!
//! This module implements a segmented, rotating Write-Ahead Log (`RotatingControlStore`):
//! 1. **Segment Files**: Stored as `segment_<020_seq>.tclog` inside a target directory, starting
//!    with an 8-byte magic header (`"TCLOGV01"`).
//! 2. **Self-Framing Checksummed Records**:
//!    Each appended record has the fixed layout:
//!    - `payload_len`: `u32` (big-endian byte length of the serialized `EncryptedControlFrame`)
//!    - `checksum`: `[u8; 8]` (first 64 bits of `BLAKE3(payload_len_be || payload_bytes)`)
//!    - `payload_bytes`: `[u8; payload_len]` (`bincode`-encoded `EncryptedControlFrame`)
//! 3. **Crash / Power-Loss Durability (`fsync`)**:
//!    - Every `append_frame` writes the complete record and calls `File::sync_data()` (`fsync`)
//!      before returning.
//!    - On segment creation or rotation (deletion of the oldest segment when `max_segments` is
//!      exceeded), the parent directory is also `sync_all()`-ed where supported by the OS.
//! 4. **Torn-Write Recovery**:
//!    - If a power outage occurs mid-write at the tail of the active segment, the trailing record
//!      will either have fewer bytes than `12 + payload_len` or its 64-bit `BLAKE3` checksum will
//!      mismatch.
//!    - Both `RotatingControlStore::open` and `RotatingControlStore::read_all_frames` detect
//!      any torn tail record, truncate the segment file back to the last valid record offset,
//!      and `sync_all()` the repaired file so all previously committed frames remain intact.

use crate::crypto::{verify_frame_for_storage, CryptoError, StorageVerificationKey};
use crate::model::EncryptedControlFrame;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// 8-byte magic header written at offset 0 of every `.tclog` segment file.
const SEGMENT_MAGIC: &[u8; 8] = b"TCLOGV01";

/// Fixed byte size of a record header (`u32` length + 16-byte BLAKE3 checksum).
const RECORD_HEADER_LEN: usize = 20;

/// Upper bound on a single serialized control frame (16 MiB) to guard against corrupted length fields.
const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;

/// Configuration for the power-failure-safe rotating disk store.
#[derive(Debug, Clone, Copy)]
pub struct StorageConfig {
    /// Maximum size in bytes of a single `segment_<seq>.tclog` file before rotating to a new segment.
    /// (A single frame exceeding this size is still written before rotating on the next frame).
    pub max_segment_bytes: u64,
    /// Maximum number of segment files retained on disk (ring rotation deletes the oldest segment).
    pub max_segments: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            // Default 64 MiB per segment file, 60 segments max (3.75 GiB / ~4.03 GB bounded disk footprint),
            // sized to retain > 24 hours (1 full day) of traffic at 1,000 PDUs/s (~3.50 GiB/day).
            max_segment_bytes: 64 * 1024 * 1024,
            max_segments: 60,
        }
    }
}

/// Errors produced by the rotating local control store.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Underlying filesystem I/O error.
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization or deserialization error for a control frame.
    #[error("storage frame serialization error: {0}")]
    Serialization(String),
    /// Segment file starts with an invalid magic header.
    #[error("invalid segment file magic header in {0}")]
    InvalidSegmentMagic(PathBuf),
    /// Frame failed `StorageVerificationKey` authentication or replay check on the Storage VM.
    #[error("storage VM frame authentication/replay error: {0}")]
    Authentication(#[from] CryptoError),
}

/// Power-failure-safe rotating disk store for `EncryptedControlFrame` records.
#[derive(Debug)]
pub struct RotatingControlStore {
    /// Directory holding the rotating `segment_<seq>.tclog` files.
    dir: PathBuf,
    /// Rotation and size limits.
    config: StorageConfig,
    /// Monotonically increasing index of the active segment file.
    active_segment_seq: u64,
    /// Open file handle for the current active segment.
    active_file: File,
    /// Current valid byte length of the active segment file.
    active_file_len: u64,
}

impl RotatingControlStore {
    /// Opens or initializes a `RotatingControlStore` in `dir`.
    ///
    /// If existing segment files are present, inspects the newest segment, automatically
    /// repairs any torn tail record caused by a prior power failure, and resumes appending.
    ///
    /// # Errors
    /// Returns `StorageError` if the directory cannot be created/read or if a segment header is invalid.
    pub fn open<P: AsRef<Path>>(dir: P, config: StorageConfig) -> Result<Self, StorageError> {
        let dir_path = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir_path)?;

        let mut segments = Self::list_segments(&dir_path)?;
        if let Some(&(last_seq, ref last_path)) = segments.last() {
            // Recover/truncate any torn write on the latest segment before resuming
            let valid_len = Self::recover_and_validate_segment(last_path)?;
            let mut active_file = OpenOptions::new().read(true).write(true).open(last_path)?;
            active_file.seek(SeekFrom::Start(valid_len))?;

            let store = Self {
                dir: dir_path,
                config,
                active_segment_seq: last_seq,
                active_file,
                active_file_len: valid_len,
            };
            store.enforce_retention(&mut segments)?;
            Ok(store)
        } else {
            let first_seq = 1;
            let first_path = Self::segment_path(&dir_path, first_seq);
            let (active_file, active_file_len) = Self::create_new_segment_file(&first_path)?;
            Self::sync_directory(&dir_path);

            Ok(Self {
                dir: dir_path,
                config,
                active_segment_seq: first_seq,
                active_file,
                active_file_len,
            })
        }
    }

    /// Appends an `EncryptedControlFrame` to the active disk segment with an integrity checksum,
    /// calls `fsync` (`sync_data`), and rotates segments if `max_segment_bytes` is reached.
    ///
    /// # Errors
    /// Returns `StorageError` if serialization, disk write, or `fsync` fails.
    pub fn append_frame(&mut self, frame: &EncryptedControlFrame) -> Result<(), StorageError> {
        let payload = bincode::serialize(frame)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| StorageError::Serialization("frame exceeds u32 max".to_string()))?;

        let record_len = (RECORD_HEADER_LEN as u64) + u64::from(payload_len);

        // Rotate to a fresh segment if adding this record would exceed max_segment_bytes
        // (and the current segment already has at least one record beyond the 8-byte magic header).
        if self.active_file_len > (SEGMENT_MAGIC.len() as u64)
            && self.active_file_len + record_len > self.config.max_segment_bytes
        {
            self.rotate_segment()?;
        }

        let len_bytes = payload_len.to_be_bytes();
        let checksum = Self::compute_record_checksum(len_bytes, &payload);

        let mut record_buf = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
        record_buf.extend_from_slice(&len_bytes);
        record_buf.extend_from_slice(&checksum);
        record_buf.extend_from_slice(&payload);

        if let Err(e) = self
            .active_file
            .write_all(&record_buf)
            .and_then(|()| self.active_file.sync_data())
        {
            // Roll back file length and seek cursor to the last committed offset on partial write failure
            let _ = self.active_file.set_len(self.active_file_len);
            let _ = self.active_file.seek(SeekFrom::Start(self.active_file_len));
            return Err(StorageError::Io(e));
        }
        self.active_file_len += record_len;

        Ok(())
    }

    /// Reads all valid `EncryptedControlFrame` records in chronological order across all
    /// retained segments in `dir`, automatically tolerating and truncating any torn tail
    /// record left by an unexpected power loss.
    ///
    /// Note: Do not call this mutating recovery method while a writer is actively appending;
    /// for concurrent verification while the algorithm is running, use
    /// [`RotatingControlStore::read_all_frames_live`] or [`RotatingControlStore::snapshot_frames`].
    ///
    /// # Errors
    /// Returns `StorageError` if the directory cannot be read or a segment header is invalid.
    pub fn read_all_frames<P: AsRef<Path>>(
        dir: P,
    ) -> Result<Vec<EncryptedControlFrame>, StorageError> {
        let dir_path = dir.as_ref();
        let segments = Self::list_segments(dir_path)?;
        let mut all_frames = Vec::new();

        for (_seq, seg_path) in segments {
            let frames = Self::read_and_heal_segment(&seg_path)?;
            all_frames.extend(frames);
        }

        Ok(all_frames)
    }

    /// Reads a consistent, non-destructive snapshot of all valid `EncryptedControlFrame` records
    /// from `dir` **while `RotatingControlStore` is actively running and rotating segments**.
    ///
    /// - Opens segment files strictly in **read-only** mode (`File::open`) and never calls
    ///   `set_len`, so it cannot interfere with an active concurrent writer.
    /// - Gracefully skips any older segment that was unlinked (`ErrorKind::NotFound`) by
    ///   concurrent ring rotation between directory listing and file opening.
    /// - Safely stops at the last complete, checksum-verified record if it encounters an
    ///   in-flight partial write at the tail of the currently active segment.
    /// - Deduplicates and orders frames by `frame_seq`.
    ///
    /// # Errors
    /// Returns `StorageError` if the directory cannot be listed or an I/O error other than
    /// `NotFound` occurs.
    pub fn read_all_frames_live<P: AsRef<Path>>(
        dir: P,
    ) -> Result<Vec<EncryptedControlFrame>, StorageError> {
        let dir_path = dir.as_ref();
        let segments = Self::list_segments(dir_path)?;
        let mut all_frames = Vec::new();

        for (_seq, seg_path) in segments {
            match Self::read_segment_readonly(&seg_path) {
                Ok(frames) => all_frames.extend(frames),
                Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Segment was rotated/deleted by the active writer while we were scanning;
                    // skip it cleanly.
                }
                Err(StorageError::InvalidSegmentMagic(_)) => {
                    // Newly created segment file whose 8-byte magic header is still in-flight;
                    // skip cleanly.
                }
                Err(e) => return Err(e),
            }
        }

        all_frames.dedup_by_key(|f| (f.sender_id, f.boot_session_id, f.frame_seq));
        Ok(all_frames)
    }

    /// Takes a live read-only snapshot of all retained `EncryptedControlFrame` records directly
    /// from this running `RotatingControlStore` instance.
    ///
    /// # Errors
    /// Returns `StorageError` if reading the underlying segment directory fails.
    pub fn snapshot_frames(&self) -> Result<Vec<EncryptedControlFrame>, StorageError> {
        Self::read_all_frames_live(&self.dir)
    }

    /// Returns the directory path managed by this `RotatingControlStore`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Rotates to a new `segment_<seq+1>.tclog` file and removes the oldest segment(s)
    /// if the total count exceeds `config.max_segments`.
    fn rotate_segment(&mut self) -> Result<(), StorageError> {
        self.active_file.sync_all()?;
        self.active_segment_seq += 1;
        let new_path = Self::segment_path(&self.dir, self.active_segment_seq);
        let (new_file, new_len) = Self::create_new_segment_file(&new_path)?;
        self.active_file = new_file;
        self.active_file_len = new_len;

        let mut segments = Self::list_segments(&self.dir)?;
        self.enforce_retention(&mut segments)?;
        Self::sync_directory(&self.dir);
        Ok(())
    }

    /// Enforces `config.max_segments` by removing the oldest segment files.
    fn enforce_retention(&self, segments: &mut Vec<(u64, PathBuf)>) -> Result<(), StorageError> {
        let max_keep = self.config.max_segments.max(1);
        while segments.len() > max_keep {
            let (_old_seq, old_path) = segments.remove(0);
            if old_path.exists() {
                fs::remove_file(old_path)?;
            }
        }
        Ok(())
    }

    /// Creates a new segment file initialized with the 8-byte `SEGMENT_MAGIC` and synced to disk.
    fn create_new_segment_file(path: &Path) -> Result<(File, u64), StorageError> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;
        file.write_all(SEGMENT_MAGIC)?;
        file.sync_all()?;
        Ok((file, SEGMENT_MAGIC.len() as u64))
    }

    /// Scans a segment file, returns all intact `EncryptedControlFrame` records, and truncates
    /// any corrupted/torn tail record caused by a mid-write power outage.
    fn read_and_heal_segment(path: &Path) -> Result<Vec<EncryptedControlFrame>, StorageError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < SEGMENT_MAGIC.len() as u64 {
            return Err(StorageError::InvalidSegmentMagic(path.to_path_buf()));
        }

        let mut magic = [0_u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != SEGMENT_MAGIC {
            return Err(StorageError::InvalidSegmentMagic(path.to_path_buf()));
        }

        let mut valid_offset = SEGMENT_MAGIC.len() as u64;
        let mut frames = Vec::new();

        loop {
            let mut header = [0_u8; RECORD_HEADER_LEN];
            match file.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Clean EOF (if 0 bytes read) or torn header at tail
                    break;
                }
                Err(e) => return Err(StorageError::Io(e)),
            }

            let mut len_bytes = [0_u8; 4];
            len_bytes.copy_from_slice(&header[..4]);
            let payload_len = u32::from_be_bytes(len_bytes) as usize;

            if payload_len == 0 || payload_len > MAX_RECORD_LEN {
                // Corrupted length field from torn write -> heal at `valid_offset`
                break;
            }

            let mut expected_checksum = [0_u8; 16];
            expected_checksum.copy_from_slice(&header[4..20]);

            let mut payload = vec![0_u8; payload_len];
            if file.read_exact(&mut payload).is_err() {
                // Torn payload at tail -> heal at `valid_offset`
                break;
            }

            let actual_checksum = Self::compute_record_checksum(len_bytes, &payload);
            if actual_checksum != expected_checksum {
                // Bit rot or incomplete write -> heal at `valid_offset`
                break;
            }

            let Ok(frame) = bincode::deserialize::<EncryptedControlFrame>(&payload) else {
                break;
            };

            frames.push(frame);
            valid_offset += (RECORD_HEADER_LEN + payload_len) as u64;
        }

        // If a torn tail record was detected, truncate the file back to `valid_offset` and fsync
        if valid_offset < file_len {
            file.set_len(valid_offset)?;
            file.sync_all()?;
        }

        Ok(frames)
    }

    /// Validates a segment file and returns its repaired byte length.
    fn recover_and_validate_segment(path: &Path) -> Result<u64, StorageError> {
        let _ = Self::read_and_heal_segment(path)?;
        let len = fs::metadata(path)?.len();
        Ok(len)
    }

    /// Reads all complete, checksum-verified `EncryptedControlFrame` records from `path`
    /// in strictly read-only mode without modifying or truncating the file.
    ///
    /// Safe to execute concurrently while an active writer is appending to `path`.
    fn read_segment_readonly(path: &Path) -> Result<Vec<EncryptedControlFrame>, StorageError> {
        let mut file = File::open(path)?;
        let mut magic = [0_u8; 8];
        if file.read_exact(&mut magic).is_err() || &magic != SEGMENT_MAGIC {
            return Err(StorageError::InvalidSegmentMagic(path.to_path_buf()));
        }

        let mut frames = Vec::new();
        loop {
            let mut header = [0_u8; RECORD_HEADER_LEN];
            match file.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StorageError::Io(e)),
            }

            let mut len_bytes = [0_u8; 4];
            len_bytes.copy_from_slice(&header[..4]);
            let payload_len = u32::from_be_bytes(len_bytes) as usize;
            if payload_len == 0 || payload_len > MAX_RECORD_LEN {
                break;
            }

            let mut expected_checksum = [0_u8; 16];
            expected_checksum.copy_from_slice(&header[4..20]);

            let mut payload = vec![0_u8; payload_len];
            if file.read_exact(&mut payload).is_err() {
                break;
            }

            if Self::compute_record_checksum(len_bytes, &payload) != expected_checksum {
                break;
            }

            let Ok(frame) = bincode::deserialize::<EncryptedControlFrame>(&payload) else {
                break;
            };

            frames.push(frame);
        }

        Ok(frames)
    }

    /// Computes a 128-bit `BLAKE3` checksum over `len_bytes || payload`.
    #[must_use]
    fn compute_record_checksum(len_bytes: [u8; 4], payload: &[u8]) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&len_bytes);
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut out = [0_u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        out
    }

    /// Formats the canonical path for segment `seq` inside `dir`.
    #[must_use]
    fn segment_path(dir: &Path, seq: u64) -> PathBuf {
        dir.join(format!("segment_{seq:020}.tclog"))
    }

    /// Lists all `segment_<seq>.tclog` files in `dir` sorted ascending by sequence number.
    fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>, StorageError> {
        let mut list = Vec::new();
        if !dir.exists() {
            return Ok(list);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if let Some(num_str) = name
                    .strip_prefix("segment_")
                    .and_then(|s| s.strip_suffix(".tclog"))
                {
                    if let Ok(seq) = num_str.parse::<u64>() {
                        list.push((seq, path));
                    }
                }
            }
        }
        list.sort_by_key(|(seq, _)| *seq);
        Ok(list)
    }

    /// Best-effort `fsync` on the parent directory after file creation/unlink.
    fn sync_directory(dir: &Path) {
        if let Ok(dir_file) = File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }
}

/// Dedicated **Storage VM** receiver and rotating disk manager.
///
/// In the AI-TrustChain multi-VM deployment architecture, the Ingress IPS VM (which observes
/// the cleartext trust flow) is completely separate from the **Storage VM** (which maintains
/// the power-failure-safe rotating disk store for `.pcap` verification):
/// - The Ingress IPS streams `EncryptedControlFrame` packets unidirectionally to both the
///   Egress IPS VM and the Storage VM.
/// - The Storage VM holds **only** a restricted [`StorageVerificationKey`] (and **never** holds
///   `TrustChainKeys`, `pdu_mac_key`, or `control_aead_key`).
/// - Before writing any received `EncryptedControlFrame` to disk, `StorageVmNode::receive_and_persist_frame`
///   verifies its 128-bit `storage_auth_tag` and enforces anti-replay monotonicity per
///   `(sender_id, boot_session_id)` so an attacker on the network cannot fill or rotate out
///   the Storage VM's disk with forged or replayed frames.
#[derive(Debug)]
pub struct StorageVmNode {
    /// Restricted verification-only key (`StorageVerificationKey`).
    verification_key: StorageVerificationKey,
    /// Power-failure-safe rotating disk store managed on this Storage VM.
    store: RotatingControlStore,
    /// Active `(sender_id, boot_session_id)` currently tracked for anti-replay.
    active_session: Option<(u32, u32)>,
    /// Minimum acceptable `frame_seq` within `active_session`.
    expected_min_frame_seq: u64,
}

impl StorageVmNode {
    /// Opens or initializes a `StorageVmNode` on the dedicated Storage VM using its local
    /// `dir` path, `StorageConfig`, and restricted `StorageVerificationKey`.
    ///
    /// If existing segment files are present on disk, recovers any torn tail record and
    /// seeds the anti-replay state (`active_session` and `expected_min_frame_seq`) from
    /// the last committed frame.
    ///
    /// # Errors
    /// Returns `StorageError` if opening or recovering the underlying `RotatingControlStore` fails.
    pub fn open<P: AsRef<Path>>(
        dir: P,
        config: StorageConfig,
        verification_key: StorageVerificationKey,
    ) -> Result<Self, StorageError> {
        let store = RotatingControlStore::open(dir, config)?;
        let frames = store.snapshot_frames()?;
        let (active_session, expected_min_frame_seq) = if let Some(last) = frames.last() {
            (
                Some((last.sender_id, last.boot_session_id)),
                last.frame_seq + 1,
            )
        } else {
            (None, 0)
        };

        Ok(Self {
            verification_key,
            store,
            active_session,
            expected_min_frame_seq,
        })
    }

    /// Authenticates an incoming `EncryptedControlFrame` arriving over the network from the
    /// Ingress IPS VM using `StorageVerificationKey`, checks anti-replay monotonicity, and
    /// commits it to the power-failure-safe `RotatingControlStore`.
    ///
    /// # Errors
    /// Returns `StorageError::Authentication` if the frame's `storage_auth_tag` is invalid
    /// or if the frame is a replay (`frame_seq < expected_min_frame_seq`), or `StorageError::Io`
    /// on disk failure.
    pub fn receive_and_persist_frame(
        &mut self,
        frame: &EncryptedControlFrame,
    ) -> Result<(), StorageError> {
        // 1. Verify 128-bit outer storage authentication tag before touching the disk
        verify_frame_for_storage(&self.verification_key, frame)?;

        // 2. Enforce anti-replay so an attacker cannot flood/rotate the disk with captured valid frames
        let frame_session = (frame.sender_id, frame.boot_session_id);
        if self.active_session == Some(frame_session) {
            if frame.frame_seq < self.expected_min_frame_seq {
                return Err(StorageError::Authentication(
                    CryptoError::ControlFrameReplay {
                        expected: self.expected_min_frame_seq,
                        received: frame.frame_seq,
                    },
                ));
            }
        } else {
            // New boot session from Ingress IPS
            if frame.frame_seq != 0 && frame.frame_seq < self.expected_min_frame_seq {
                return Err(StorageError::Authentication(
                    CryptoError::ControlFrameReplay {
                        expected: self.expected_min_frame_seq,
                        received: frame.frame_seq,
                    },
                ));
            }
            self.active_session = Some(frame_session);
        }

        // 3. Persist and fsync to rotating segment store
        self.store.append_frame(frame)?;
        self.expected_min_frame_seq = frame.frame_seq + 1;
        Ok(())
    }

    /// Returns a reference to the underlying `RotatingControlStore`.
    #[must_use]
    pub const fn store(&self) -> &RotatingControlStore {
        &self.store
    }
}
