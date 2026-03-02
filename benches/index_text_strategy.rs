use std::fmt::Write as _;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use peam::types::bytes::Bytes32;
use rapidhash::RapidHashMap;

const ENTRIES: u64 = 100_000;

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

fn nibble_to_hex(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[value as usize] as char
}

fn root_to_hex(root: Bytes32) -> String {
    let mut out = String::with_capacity(64);
    for byte in root.as_array() {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

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

fn push_root_hex(out: &mut String, root: Bytes32) {
    const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";
    let bytes = root.as_array();
    let start = out.len();
    out.reserve(64);
    // SAFETY:
    // - `reserve(64)` ensures capacity.
    // - We write exactly 64 ASCII bytes into the new tail.
    // - We set_len after writes.
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

fn old_index_to_text(index: &RapidHashMap<u64, Bytes32>) -> String {
    let mut rows: Vec<(u64, Bytes32)> = index.iter().map(|(slot, root)| (*slot, *root)).collect();
    rows.sort_by_key(|(slot, _)| *slot);
    let mut text = String::with_capacity(rows.len());
    for (slot, root) in rows {
        text.push_str(&slot.to_string());
        text.push('=');
        text.push_str(&root_to_hex(root));
        text.push('\n');
    }
    text
}

fn new_index_to_text(index: &RapidHashMap<u64, Bytes32>) -> String {
    let mut rows: Vec<(u64, Bytes32)> = index.iter().map(|(slot, root)| (*slot, *root)).collect();
    rows.sort_by_key(|(slot, _)| *slot);
    let capacity: usize = rows
        .iter()
        .map(|(slot, _)| decimal_len_u64(*slot) + 66)
        .sum();
    let mut text = String::with_capacity(capacity);
    for (slot, root) in rows {
        write!(&mut text, "{}=", slot).expect("write to string");
        push_root_hex(&mut text, root);
        text.push('\n');
    }
    text
}

fn build_index() -> RapidHashMap<u64, Bytes32> {
    let mut index = RapidHashMap::default();
    for i in 0..ENTRIES {
        let slot = (i.wrapping_mul(5_357) + 97) % 250_000;
        index.insert(slot, root_from_u64(i));
    }
    index
}

fn bench_index_text_strategy(c: &mut Criterion) {
    let index = build_index();
    assert_eq!(old_index_to_text(&index), new_index_to_text(&index));

    let mut group = c.benchmark_group("index_text_strategy");
    group.bench_function("old_to_string_root_to_hex", |b| {
        b.iter(|| black_box(old_index_to_text(black_box(&index))));
    });
    group.bench_function("new_prealloc_write_push_hex", |b| {
        b.iter(|| black_box(new_index_to_text(black_box(&index))));
    });
    group.finish();
}

criterion_group!(benches, bench_index_text_strategy);
criterion_main!(benches);
