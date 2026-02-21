use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use lean_eth::storage::{FinalizedMmr, verify_mmr_inclusion_proof};
use lean_eth::types::bytes::Bytes32;

const HISTORY: usize = 16_384;
const TARGET: usize = HISTORY / 2;

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

fn finalized_roots() -> Vec<Bytes32> {
    (0..HISTORY as u64).map(|i| root_from_u64(i + 1)).collect()
}

fn bench_finalized_mmr(c: &mut Criterion) {
    let roots = finalized_roots();
    let mmr = FinalizedMmr::from_leaves(roots.clone());
    let mmr_root = mmr.root();
    let target_root = roots[TARGET];
    let proof = mmr
        .proof_by_root(target_root)
        .expect("proof for target root");

    let mut group = c.benchmark_group("finalized_history");

    group.bench_function("lean_mmr_append_commitment", |b| {
        b.iter_batched(
            || mmr.clone(),
            |mut local| {
                local.append(black_box(root_from_u64(99_999_999)));
                black_box(local.root())
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("lean_mmr_proof_by_root", |b| {
        b.iter(|| black_box(mmr.proof_by_root(black_box(target_root))))
    });

    group.bench_function("lean_mmr_proof_by_index", |b| {
        b.iter(|| black_box(mmr.proof_by_index(black_box(TARGET))))
    });

    group.bench_function("lean_mmr_verify_inclusion", |b| {
        b.iter(|| black_box(verify_mmr_inclusion_proof(mmr_root, black_box(&proof))))
    });

    group.bench_function("linear_scan_find_root", |b| {
        b.iter(|| {
            black_box(
                roots.iter()
                    .enumerate()
                    .rfind(|(_, root)| **root == target_root)
                    .map(|(idx, _)| idx),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_finalized_mmr);
criterion_main!(benches);
