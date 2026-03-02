use criterion::{Criterion, black_box, criterion_group, criterion_main};
use peam::ssz::hash::chunkify_fixed;

fn bench_chunkify_fixed(c: &mut Criterion) {
    let empty: Vec<u8> = Vec::new();
    let small: Vec<u8> = (0u8..64u8).collect();
    let medium: Vec<u8> = (0u8..255u8).cycle().take(4 * 1024).collect();
    let large: Vec<u8> = (0u8..255u8).cycle().take(64 * 1024).collect();

    c.bench_function("chunkify_fixed_empty", |b| {
        b.iter(|| chunkify_fixed(black_box(&empty)))
    });
    c.bench_function("chunkify_fixed_64b", |b| {
        b.iter(|| chunkify_fixed(black_box(&small)))
    });
    c.bench_function("chunkify_fixed_4kb", |b| {
        b.iter(|| chunkify_fixed(black_box(&medium)))
    });
    c.bench_function("chunkify_fixed_64kb", |b| {
        b.iter(|| chunkify_fixed(black_box(&large)))
    });
}

criterion_group!(benches, bench_chunkify_fixed);
criterion_main!(benches);
