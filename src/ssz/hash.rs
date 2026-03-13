use sha2::{Digest, Sha256};

use crate::types::bytes::Bytes32;
use crate::unsafe_vec::write_at;

include!(concat!(env!("OUT_DIR"), "/zero_hashes.rs"));

pub const BYTES_PER_CHUNK: usize = 32;

#[inline]
pub fn hash_nodes(left: &Bytes32, right: &Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(left.as_array());
    hasher.update(right.as_array());
    let out = hasher.finalize();
    // Extract the first 32 bytes and return it as Bytes32.
    // We can optimize this later with a direct wrap/ptr, if needed.
    Bytes32::from_slice(&out)
}

#[inline]
pub fn chunkify_fixed(data: &[u8]) -> Vec<Bytes32> {
    if data.is_empty() {
        return vec![Bytes32::zero()];
    }

    // This is at most 32
    let chunk_count = (data.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
    let mut out: Vec<Bytes32> = Vec::with_capacity(chunk_count);
    unsafe { out.set_len(chunk_count) };
    let mut i = 0usize;
    let mut out_idx = 0usize;
    while i < data.len() {
        let end = (i + BYTES_PER_CHUNK).min(data.len());
        let mut chunk = [0u8; 32];
        chunk[..end - i].copy_from_slice(&data[i..end]);
        unsafe { write_at(&mut out, out_idx, Bytes32::from(chunk)) };
        out_idx += 1;
        i = end;
    }
    out
}

#[inline]
pub fn merkleize(chunks: &[Bytes32]) -> Bytes32 {
    merkleize_with_limit(chunks, chunks.len()).unwrap()
}

#[inline]
//can definitely be optimized further, with some hard thinking
pub fn merkleize_unsafe(chunks: &[Bytes32]) -> Bytes32 {
    let limit = chunks.len();

    if limit == 0 {
        return Bytes32::zero();
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if width == 1 {
        return chunks[0];
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;

    while subtree_size < width {
        let next_len = (level.len() + 1) / 2;
        let mut next: Vec<Bytes32> = Vec::with_capacity(next_len);
        unsafe { next.set_len(next_len) };
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i < level.len() {
            let left = &level[i];
            i += 1;
            let right = if i < level.len() {
                let r = &level[i];
                i += 1;
                r
            } else {
                &zero_tree_root_no_check(subtree_size)
            };
            unsafe { write_at(&mut next, out_idx, hash_nodes(left, right)) };
            out_idx += 1;
        }
        level = next;
        subtree_size <<= 1;
    }

    level[0]
}

#[inline]
// Safety: assumes exactly 5 field roots (width fixed to 8).
pub fn merkleize_tree_root(chunks: &[Bytes32]) -> Bytes32 {
    // width fixed to 8 for 5 field roots
    let z0 = zero_tree_root_no_check(1);
    let z1: Bytes32 = zero_tree_root_no_check(2);

    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &chunks[3]);
    let c = hash_nodes(&chunks[4], &z0);
    let d = z1;

    let e = hash_nodes(&a, &b);
    let f = hash_nodes(&c, &d);
    hash_nodes(&e, &f)
}

// width fixed to 4 for 4 field roots
#[inline]
pub fn merkleize_tree_root_4(chunks: &[Bytes32]) -> Bytes32 {
    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &chunks[3]);
    hash_nodes(&a, &b)
}

// width fixed to 4 for 3 field roots
#[inline]
pub fn merkleize_tree_root_3(chunks: &[Bytes32]) -> Bytes32 {
    let z0 = zero_tree_root_no_check(1);

    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &z0);
    hash_nodes(&a, &b)
}

// width fixed to 16 for 11 field roots
#[inline]
pub fn merkleize_tree_root_11(chunks: &[Bytes32]) -> Bytes32 {
    let z0 = zero_tree_root_no_check(1);
    let z1 = zero_tree_root_no_check(2);

    let h0 = hash_nodes(&chunks[0], &chunks[1]);
    let h1 = hash_nodes(&chunks[2], &chunks[3]);
    let h2 = hash_nodes(&chunks[4], &chunks[5]);
    let h3 = hash_nodes(&chunks[6], &chunks[7]);
    let h4 = hash_nodes(&chunks[8], &chunks[9]);
    let h5 = hash_nodes(&chunks[10], &z0);
    let h6 = z1;
    let h7 = z1;

    let k0 = hash_nodes(&h0, &h1);
    let k1 = hash_nodes(&h2, &h3);
    let k2 = hash_nodes(&h4, &h5);
    let k3 = hash_nodes(&h6, &h7);

    let m0 = hash_nodes(&k0, &k1);
    let m1 = hash_nodes(&k2, &k3);
    hash_nodes(&m0, &m1)
}

#[inline]
pub fn merkleize_with_limit(chunks: &[Bytes32], limit: usize) -> Result<Bytes32, String> {
    if limit < chunks.len() {
        return Err("merkleize limit smaller than input".to_string());
    }
    if limit == 0 {
        return Ok(Bytes32::zero());
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if chunks.is_empty() {
        return Ok(zero_tree_root_no_check(width));
    }
    if width == 1 {
        return Ok(chunks[0]);
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;

    while subtree_size < width {
        let next_len = (level.len() + 1) / 2;
        let mut next: Vec<Bytes32> = Vec::with_capacity(next_len);
        unsafe { next.set_len(next_len) };
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i < level.len() {
            let left = &level[i];
            unsafe {
                i = i.unchecked_add(1);
            }
            let right = if i < level.len() {
                let r: &Bytes32 = &level[i];
                unsafe {
                    i = i.unchecked_add(1);
                }
                r
            } else {
                &zero_tree_root_no_check(subtree_size)
            };
            unsafe {
                write_at(&mut next, out_idx, hash_nodes(left, right));
                // safety: level.len() is bound by usize::MAX and based on the iteration pattern, out_idx will always be less than next_len.
                out_idx = out_idx.unchecked_add(1);
            };
        }
        level = next;
        subtree_size <<= 1;
    }

    Ok(level[0])
}

#[inline]
pub fn mix_in_length(root: &Bytes32, length: usize) -> Bytes32 {
    let mut length_bytes = [0u8; 32];
    let len_u64 = length as u64;
    length_bytes[..8].copy_from_slice(&len_u64.to_le_bytes());
    let length_node = Bytes32::from(length_bytes);
    hash_nodes(root, &length_node)
}

#[inline]
fn zero_tree_root_no_check(width: usize) -> Bytes32 {
    let depth = width.trailing_zeros() as usize;
    let bytes = ZERO_HASHES[depth];
    Bytes32::from(bytes)
}

#[inline]
fn _zero_tree_root(width: usize) -> Bytes32 {
    if width <= 1 {
        return Bytes32::zero();
    }
    let depth = width.trailing_zeros() as usize;
    let bytes = ZERO_HASHES[depth];
    Bytes32::from(bytes)
}
