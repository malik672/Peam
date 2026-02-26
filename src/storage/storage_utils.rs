//! Low-level storage utilities for the lean-ethereum disk backend.
//!
//! This module provides the building blocks used by [`super::FileStore`]:
//!
//! | Category          | Functions |
//! |-------------------|-----------|
//! | Blob codec        | [`encode_blob`], [`decode_blob`] |
//! | Safe SSZ decoding | [`decode_state_safe`], [`decode_block_safe`], [`decode_signed_block_safe`] |
//! | File I/O          | [`atomic_write`], [`ensure_schema_version`] |
//!
//! ## Blob format
//!
//! Every persisted object is wrapped in a blob envelope:
//!
//! ```text
//! ┌──────────────┬─────────┬──────┬──────────────┬───────────────┬─────────┐
//! │ LEANSTRG (8B)│ ver (1B)│ kind │  length (4B) │ SHA-256 (32B) │ payload │
//! │  magic bytes │  = 0x01 │ (1B) │   LE u32     │   checksum    │  (SSZ)  │
//! └──────────────┴─────────┴──────┴──────────────┴───────────────┴─────────┘
//! ```
//!
//! A missing magic prefix is treated as the legacy raw-SSZ format for
//! backwards compatibility.
//!
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::{BLOB_MAGIC, BLOB_VERSION, SCHEMA_FILE, SCHEMA_VERSION};
use crate::containers::block::{Block, SignedBlockWithAttestation};
use crate::containers::state::State;
use crate::ssz::SszDecode;
use crate::types::bytes::Bytes32;

/// Returns `true` if `root` appears in the `pinned` set.
///
/// Pinned roots are exempt from pruning regardless of their slot height.
#[inline]
pub(super) fn is_pinned(pinned: &[Option<Bytes32>; 3], root: &Bytes32) -> bool {
    pinned.iter().flatten().any(|p| p == root)
}

/// Decodes SSZ bytes into a [`State`], catching any panics from the decoder.
///
/// Returns `None` if decoding panics or returns an error.
pub(super) fn decode_state_safe(bytes: &[u8]) -> Option<State> {
    catch_unwind(AssertUnwindSafe(|| State::decode_ssz(bytes)))
        .ok()
        .and_then(Result::ok)
}

/// Decodes SSZ bytes into a [`Block`], catching any panics from the decoder.
///
/// Returns `None` if decoding panics or returns an error.
pub(super) fn decode_block_safe(bytes: &[u8]) -> Option<Block> {
    catch_unwind(AssertUnwindSafe(|| Block::decode_ssz(bytes)))
        .ok()
        .and_then(Result::ok)
}

/// Decodes SSZ bytes into a [`SignedBlockWithAttestation`], catching any
/// panics from the decoder.
///
/// Returns `None` if decoding panics or returns an error.
pub(super) fn decode_signed_block_safe(bytes: &[u8]) -> Option<SignedBlockWithAttestation> {
    catch_unwind(AssertUnwindSafe(|| {
        SignedBlockWithAttestation::decode_ssz(bytes)
    }))
    .ok()
    .and_then(Result::ok)
}

/// Encodes a payload into the lean-ethereum blob format.
///
/// The returned buffer layout is:
///
/// ```text
/// LEANSTRG (8B) | version (1B) | kind (1B) | length LE u32 (4B) | SHA-256 (32B) | payload
/// ```
///
/// `kind` identifies the blob type (e.g. `0x01` for state, `0x02` for block).
pub(super) fn encode_blob(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 1 + 1 + 4 + 32 + payload.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.push(BLOB_VERSION);
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let checksum = Sha256::digest(payload);
    out.extend_from_slice(&checksum);
    out.extend_from_slice(payload);
    out
}

/// Decodes a blob produced by [`encode_blob`], returning the inner payload.
///
/// Validation steps:
/// 1. Checks the `LEANSTRG` magic prefix.
/// 2. Verifies the version byte matches [`BLOB_VERSION`].
/// 3. Verifies the `kind` byte matches `expected_kind`.
/// 4. Reads the 4-byte LE payload length and verifies total file size.
/// 5. Verifies the SHA-256 checksum of the payload.
///
/// **Backward compatibility**: if the first 8 bytes are *not* the magic
/// string, the raw bytes are returned as-is (legacy raw-SSZ format).
///
/// Returns `None` on any format, version, kind, length, or checksum mismatch.
#[inline]
pub(super) fn decode_blob(expected_kind: u8, bytes: &[u8]) -> Option<Vec<u8>> {
    // Backward compatibility with previous raw-SSZ persistence format.
    if bytes.len() < 8 {
        return None;
    }
    if &bytes[0..8] != BLOB_MAGIC {
        return Some(bytes.to_vec());
    }
    if bytes.len() < 8 + 1 + 1 + 4 + 32 {
        return None;
    }
    if bytes[8] != BLOB_VERSION {
        return None;
    }
    if bytes[9] != expected_kind {
        return None;
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&bytes[10..14]);
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    let payload_offset = 14 + 32;
    if bytes.len() != payload_offset + payload_len {
        return None;
    }
    let expected_checksum = &bytes[14..46];
    let payload = &bytes[payload_offset..];
    let actual_checksum = Sha256::digest(payload);
    if actual_checksum.as_slice() != expected_checksum {
        return None;
    }
    Some(payload.to_vec())
}

/// Checks whether the schema version file at `root/SCHEMA_FILE` matches
/// [`SCHEMA_VERSION`].
///
/// If the file does not exist it is created with the current version. If it
/// exists with a different version an error is returned, indicating that the
/// data directory was written by an incompatible binary.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read, cannot be created, or contains a
/// schema version string that does not match [`SCHEMA_VERSION`].
#[inline]
pub(super) fn ensure_schema_version(root: &Path) -> Result<(), String> {
    let schema_path = root.join(SCHEMA_FILE);
    if !schema_path.exists() {
        return atomic_write(schema_path, SCHEMA_VERSION.as_bytes());
    }
    let value = fs::read_to_string(schema_path).map_err(|err| err.to_string())?;
    if value.trim() != SCHEMA_VERSION {
        return Err(format!(
            "unsupported storage schema version {}, expected {}",
            value.trim(),
            SCHEMA_VERSION
        ));
    }
    Ok(())
}

/// Writes `bytes` to `path` atomically using a write-then-rename strategy.
///
/// Steps:
/// 1. Creates parent directories with [`fs::create_dir_all`].
/// 2. Opens a uniquely named temporary file (`.{name}.tmp.{nanoseconds}`)
///    with `O_CREAT | O_EXCL | O_WRONLY`.
/// 3. Writes all bytes and calls `fsync` on the file descriptor.
/// 4. Renames the temporary file to the final `path` (atomic on POSIX).
/// 5. `fsync`s the parent directory (Unix only) to make the rename durable.
///
/// If any step fails the temporary file is removed and an error is returned.
///
/// # Errors
///
/// Returns `Err` if the parent directory cannot be determined or created, if
/// the temporary file cannot be opened, if writing or syncing fails, or if the
/// rename fails.
pub(super) fn atomic_write(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?
        .to_path_buf();
    fs::create_dir_all(&parent).map_err(|err| err.to_string())?;

    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| format!("invalid file name: {}", path.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let tmp_path = parent.join(format!(".{}.tmp.{stamp}", file_name));

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|err| err.to_string())?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.to_string());
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.to_string());
    }
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.to_string());
    }
    sync_parent_dir(&parent)
}

/// Calls `fsync` on the parent directory to make a preceding rename durable.
///
/// Only meaningful on Unix; the `#[cfg(not(unix))]` variant is a no-op.
///
/// # Errors
///
/// Returns `Err` if the directory cannot be opened or synced.
#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), String> {
    let dir = File::open(parent).map_err(|err| err.to_string())?;
    dir.sync_all().map_err(|err| err.to_string())
}

/// No-op on non-Unix targets where directory `fsync` is not required.
#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> Result<(), String> {
    Ok(())
}
