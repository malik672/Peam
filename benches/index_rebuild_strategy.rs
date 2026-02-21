use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use lean_eth::types::bytes::Bytes32;
use rapidhash::RapidHashMap;

const ENTRIES: u64 = 200_000;
const SLOT_MOD: u64 = 8192;

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

fn build_roots_to_slot() -> RapidHashMap<Bytes32, u64> {
    let mut map = RapidHashMap::default();
    for i in 0..ENTRIES {
        // Many collisions by slot to exercise duplicate-slot handling.
        map.insert(root_from_u64(i), (i.wrapping_mul(17)) % SLOT_MOD);
    }
    map
}

fn old_sorted_rebuild(states: &RapidHashMap<Bytes32, u64>) -> RapidHashMap<u64, Bytes32> {
    let mut rows: Vec<(u64, Bytes32)> = states.iter().map(|(root, slot)| (*slot, *root)).collect();
    rows.sort_by(|(slot_a, root_a), (slot_b, root_b)| {
        slot_a
            .cmp(slot_b)
            .then_with(|| root_a.as_array().cmp(&root_b.as_array()))
    });
    let mut out = RapidHashMap::default();
    for (slot, root) in rows {
        out.insert(slot, root);
    }
    out
}

fn new_linear_rebuild(states: &RapidHashMap<Bytes32, u64>) -> RapidHashMap<u64, Bytes32> {
    let mut out: RapidHashMap<u64, Bytes32> = RapidHashMap::default();
    for (root, slot) in states.iter() {
        match out.get_mut(slot) {
            Some(existing) => {
                if root.as_array() > existing.as_array() {
                    *existing = *root;
                }
            }
            None => {
                out.insert(*slot, *root);
            }
        }
    }
    out
}

fn bench_index_rebuild_strategy(c: &mut Criterion) {
    let states = build_roots_to_slot();
    let expected = old_sorted_rebuild(&states);
    let got = new_linear_rebuild(&states);
    assert_eq!(expected, got, "linear rebuild semantics diverged");

    let mut group = c.benchmark_group("index_rebuild_strategy");
    group.bench_function("old_collect_sort_insert", |b| {
        b.iter_batched(
            || states.clone(),
            |m| black_box(old_sorted_rebuild(&m)),
            BatchSize::LargeInput,
        );
    });
    group.bench_function("new_linear_max_root", |b| {
        b.iter_batched(
            || states.clone(),
            |m| black_box(new_linear_rebuild(&m)),
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_index_rebuild_strategy);
criterion_main!(benches);
