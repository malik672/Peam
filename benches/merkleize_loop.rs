#![allow(clippy::uninit_vec)]
#![allow(clippy::manual_div_ceil)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use lean_eth::ssz::hash::{hash_nodes, merkleize_unsafe};
use lean_eth::types::bytes::Bytes32;

fn merkleize_with_limit_while(chunks: &[Bytes32], limit: usize) -> Bytes32 {
    if limit == 0 {
        return Bytes32::zero();
    }
    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }
    if chunks.is_empty() {
        return Bytes32::zero();
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
                &Bytes32::zero()
            };
            unsafe {
                let slot = next.as_mut_ptr().add(out_idx);
                core::ptr::write(slot, hash_nodes(left, right));
            }
            out_idx += 1;
        }
        level = next;
        subtree_size <<= 1;
    }

    level[0]
}

fn merkleize_with_limit_for(chunks: &[Bytes32], limit: usize) -> Bytes32 {
    if limit == 0 {
        return Bytes32::zero();
    }
    let mut width = 1usize;
    let mut depth = 0usize;
    while width < limit {
        width <<= 1;
        depth += 1;
    }
    if chunks.is_empty() {
        return Bytes32::zero();
    }
    if width == 1 {
        return chunks[0];
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;
    for _ in 0..depth {
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
                &Bytes32::zero()
            };
            unsafe {
                let slot = next.as_mut_ptr().add(out_idx);
                core::ptr::write(slot, hash_nodes(left, right));
            }
            out_idx += 1;
        }
        level = next;
        black_box(subtree_size);
        subtree_size <<= 1;
    }

    level[0]
}

fn sample_chunks(count: usize) -> Vec<Bytes32> {
    (0..count)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            Bytes32::from(bytes)
        })
        .collect()
}

fn bench_merkleize_loops(c: &mut Criterion) {
    let chunks = sample_chunks(64);
    let limit = 64;

    c.bench_function("merkleize_with_limit_while", |b| {
        b.iter(|| merkleize_with_limit_while(black_box(&chunks), black_box(limit)))
    });
    c.bench_function("merkleize_with_limit_for", |b| {
        b.iter(|| merkleize_with_limit_for(black_box(&chunks), black_box(limit)))
    });
    c.bench_function("merkleize_unsafe", |b| {
        b.iter(|| merkleize_unsafe(black_box(&chunks)))
    });
}

criterion_group!(benches, bench_merkleize_loops);
criterion_main!(benches);
