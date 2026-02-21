use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rapidhash::RapidHashMap;
use sha2::{Digest, Sha256};

use super::{BLOB_MAGIC, BLOB_VERSION, SCHEMA_FILE, SCHEMA_VERSION};
use crate::containers::block::{Block, SignedBlockWithAttestation};
use crate::containers::state::State;
use crate::ssz::SszDecode;
use crate::types::bytes::Bytes32;

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

#[inline]
pub(super) fn root_to_hex(root: Bytes32) -> String {
    let mut out = String::with_capacity(64);
    push_root_hex(&mut out, root);
    out
}

#[inline]
pub(super) fn root_from_hex(hex: &str) -> Result<Bytes32, String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars for root, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_value(bytes[2 * i])?;
        let lo = hex_value(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(Bytes32::from(out))
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte: {byte}")),
    }
}

#[inline]
pub(super) fn option_root_to_text(root: Option<Bytes32>) -> String {
    root.map(root_to_hex).unwrap_or_default()
}

#[inline]
pub(super) fn option_root_from_text(text: &str) -> Result<Option<Bytes32>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    root_from_hex(text.trim()).map(Some)
}

#[inline]
pub(super) fn is_pinned(pinned: &[Option<Bytes32>; 3], root: &Bytes32) -> bool {
    pinned.iter().flatten().any(|p| p == root)
}

pub(super) fn parse_index_line_bytes(line: &[u8]) -> Result<(u64, Bytes32), String> {
    let equals = line
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or_else(|| "index line must contain '='".to_string())?;
    let slot_raw = trim_ascii_whitespace(&line[..equals]);
    let root_raw = trim_ascii_whitespace(&line[equals + 1..]);
    let slot = parse_u64_ascii(slot_raw)?;
    let root = root_from_hex_bytes(root_raw)?;
    Ok((slot, root))
}

#[inline]
fn parse_u64_ascii(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() {
        return Err("missing slot in index line".to_string());
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err("invalid slot in index line".to_string());
        }
        let digit = (byte - b'0') as u64;
        value = value
            .checked_mul(10)
            .and_then(|acc| acc.checked_add(digit))
            .ok_or_else(|| "slot overflow in index line".to_string())?;
    }
    Ok(value)
}

#[inline]
fn root_from_hex_bytes(hex: &[u8]) -> Result<Bytes32, String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars for root, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_value(hex[2 * i])?;
        let lo = hex_value(hex[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(Bytes32::from(out))
}

#[inline]
pub(super) fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

#[inline]
pub(super) fn index_to_bytes(index: &RapidHashMap<u64, Bytes32>) -> Vec<u8> {
    let mut rows: Vec<(u64, Bytes32)> = Vec::with_capacity(index.len());
    let rows_len = index.len();
    // SAFETY: we fully initialize every slot before reading/sorting `rows`.
    unsafe { rows.set_len(rows_len) };
    // SAFETY:
    // - `rows_len` equals `index.len()`, and `rows` was set to that length.
    // - `dst.add(i)` is in-bounds for all enumerated items.
    unsafe {
        let dst = rows.as_mut_ptr();
        for (i, (slot, root)) in index.iter().enumerate() {
            *dst.add(i) = (*slot, *root);
        }
    }
    rows.sort_unstable_by_key(|(slot, _)| *slot);
    let bytes_capacity: usize = rows
        .iter()
        .map(|(slot, _)| decimal_len_u64(*slot) + 66)
        .sum();
    let mut out = Vec::with_capacity(bytes_capacity);
    for (slot, root) in rows {
        push_decimal_u64(&mut out, slot);
        push_byte(&mut out, b'=');
        push_root_hex_bytes(&mut out, root);
        push_byte(&mut out, b'\n');
    }
    debug_assert_eq!(out.len(), bytes_capacity);
    out
}

#[inline]
fn decimal_len_u64(mut value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut len = 0;
    while value > 0 {
        len += 1;
        value /= 10;
    }
    len
}

#[inline]
fn push_root_hex(out: &mut String, root: Bytes32) {
    let bytes = root.as_array();
    let start = out.len();
    out.reserve(64);
    // SAFETY:
    // - `reserve(64)` ensures enough capacity.
    // - We write exactly 64 ASCII bytes (valid UTF-8) into the newly reserved tail.
    // - We set the new length after all writes complete.
    unsafe {
        let vec = out.as_mut_vec();
        let dst = vec.as_mut_ptr().add(start);
        for (i, byte) in bytes.iter().copied().enumerate() {
            *dst.add(i * 2) = HEX_LOWER[(byte >> 4) as usize];
            *dst.add(i * 2 + 1) = HEX_LOWER[(byte & 0x0f) as usize];
        }
        vec.set_len(start + 64);
    }
}

#[inline]
fn push_root_hex_bytes(out: &mut Vec<u8>, root: Bytes32) {
    let start = out.len();
    debug_assert!(out.capacity().saturating_sub(start) >= 64);
    // SAFETY:
    // - Caller preallocates enough capacity.
    // - Every slot in [start, start + 64) is written before use.
    unsafe {
        out.set_len(start + 64);
    }
    // SAFETY:
    // - buffer is grown above; writing exactly 64 bytes is in-bounds.
    unsafe {
        let dst = out.as_mut_ptr().add(start);
        for (i, byte) in root.as_array().iter().copied().enumerate() {
            *dst.add(i * 2) = HEX_LOWER[(byte >> 4) as usize];
            *dst.add(i * 2 + 1) = HEX_LOWER[(byte & 0x0f) as usize];
        }
    }
}

#[inline]
fn push_decimal_u64(out: &mut Vec<u8>, mut value: u64) {
    let len = decimal_len_u64(value);
    let start = out.len();
    debug_assert!(out.capacity().saturating_sub(start) >= len);
    // SAFETY:
    // - Caller preallocates enough capacity.
    // - All bytes in [start, start + len) are initialized before set_len.
    unsafe {
        let ptr = out.as_mut_ptr().add(start);
        for i in (0..len).rev() {
            *ptr.add(i) = b'0' + (value % 10) as u8;
            value /= 10;
        }
        out.set_len(start + len);
    }
}

#[inline]
fn push_byte(out: &mut Vec<u8>, byte: u8) {
    let start = out.len();
    debug_assert!(out.capacity().saturating_sub(start) >= 1);
    // SAFETY:
    // - Caller preallocates enough capacity.
    // - We initialize the byte before exposing it.
    unsafe {
        *out.as_mut_ptr().add(start) = byte;
        out.set_len(start + 1);
    }
}

pub(super) fn decode_state_safe(bytes: &[u8]) -> Option<State> {
    catch_unwind(AssertUnwindSafe(|| State::decode_ssz(bytes)))
        .ok()
        .and_then(Result::ok)
}

pub(super) fn decode_block_safe(bytes: &[u8]) -> Option<Block> {
    catch_unwind(AssertUnwindSafe(|| Block::decode_ssz(bytes)))
        .ok()
        .and_then(Result::ok)
}

pub(super) fn decode_signed_block_safe(bytes: &[u8]) -> Option<SignedBlockWithAttestation> {
    catch_unwind(AssertUnwindSafe(|| {
        SignedBlockWithAttestation::decode_ssz(bytes)
    }))
    .ok()
    .and_then(Result::ok)
}

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

pub(super) fn remove_blob_file(root: &Path, dir: &str, key: Bytes32) {
    let path = root.join(dir).join(format!("{}.ssz", root_to_hex(key)));
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::error!(
                critical = true,
                path = %path.display(),
                error_kind = ?err.kind(),
                "storage prune delete failed: permission denied"
            );
        }
        Err(err) => {
            tracing::warn!(
                critical = false,
                path = %path.display(),
                error_kind = ?err.kind(),
                "storage prune delete failed"
            );
        }
    }
}

pub(super) fn blob_has_sane_shape(path: &Path, expected_kind: u8) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let file_len = meta.len() as usize;
    if file_len < 8 {
        return false;
    }

    let mut header = [0u8; 14];
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    if file.read_exact(&mut header).is_err() {
        return false;
    }

    if &header[0..8] != BLOB_MAGIC {
        // Legacy raw-SSZ fallback path.
        return true;
    }
    if file_len < 46 {
        return false;
    }
    if header[8] != BLOB_VERSION || header[9] != expected_kind {
        return false;
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&header[10..14]);
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    file_len == (46 + payload_len)
}

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

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), String> {
    let dir = File::open(parent).map_err(|err| err.to_string())?;
    dir.sync_all().map_err(|err| err.to_string())
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_from_u64(value: u64) -> Bytes32 {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&value.to_le_bytes());
        Bytes32::from(out)
    }

    #[test]
    fn index_bytes_roundtrip_sorted_and_exact() {
        let mut index = RapidHashMap::default();
        index.insert(42, root_from_u64(42));
        index.insert(0, root_from_u64(0));
        index.insert(u64::MAX, root_from_u64(u64::MAX));
        index.insert(7, root_from_u64(7));

        let bytes = index_to_bytes(&index);
        let mut prev = None::<u64>;
        let mut seen = 0usize;
        for raw_line in bytes.split(|byte| *byte == b'\n') {
            let line = trim_ascii_whitespace(raw_line);
            if line.is_empty() {
                continue;
            }
            let (slot, root) = parse_index_line_bytes(line).expect("parse line");
            if let Some(p) = prev {
                assert!(slot >= p);
            }
            prev = Some(slot);
            assert_eq!(index.get(&slot), Some(&root));
            seen += 1;
        }
        assert_eq!(seen, index.len());
    }

    #[test]
    fn index_bytes_stress_large() {
        let mut index = RapidHashMap::default();
        let entries = 200_000u64;
        for i in 0..entries {
            let slot = i.wrapping_mul(31_337) ^ (i << 17);
            index.insert(slot, root_from_u64(i ^ 0xdead_beef));
        }

        let bytes = index_to_bytes(&index);
        assert!(!bytes.is_empty());

        let mut count = 0usize;
        for raw_line in bytes.split(|byte| *byte == b'\n') {
            let line = trim_ascii_whitespace(raw_line);
            if line.is_empty() {
                continue;
            }
            let (_slot, _root) = parse_index_line_bytes(line).expect("parse stress line");
            count += 1;
        }
        assert_eq!(count, index.len());
    }
}
