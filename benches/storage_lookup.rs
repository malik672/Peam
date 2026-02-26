use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use lean_eth::containers::block::{Block, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::storage::{FileStore, MemoryStore, Store};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

const ENTRIES: u64 = 1_000;

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

fn fixture_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("lean_eth_bench_{name}_{stamp}"))
}

fn dummy_block(slot: u64) -> Block {
    Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body: BlockBody {
            attestations: SszList::new(vec![]).expect("attestations"),
        },
    }
}

fn dummy_state(slot: u64) -> State {
    let mut state =
        State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"));
    state.slot = Slot(Uint64(slot));
    state
}

fn create_memory_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    for slot in 0..ENTRIES {
        let state_root = root_from_u64(slot + 100_000);
        let block_root = root_from_u64(slot + 200_000);
        store.put_state(state_root, dummy_state(slot));
        store.put_block(block_root, dummy_block(slot));
    }
    store
}

fn create_file_store() -> FileStore {
    let dir = fixture_dir("lookup");
    let mut store = FileStore::open(&dir).expect("open file store");
    for slot in 0..ENTRIES {
        let state_root = root_from_u64(slot + 100_000);
        let block_root = root_from_u64(slot + 200_000);
        store.put_state(state_root, dummy_state(slot));
        store.put_block(block_root, dummy_block(slot));
    }
    store
}

fn bench_storage_lookup(c: &mut Criterion) {
    let memory = create_memory_store();
    let file = create_file_store();
    let mid_slot = ENTRIES / 2;
    let mid_state_root = root_from_u64(mid_slot + 100_000);
    let mid_block_root = root_from_u64(mid_slot + 200_000);

    let mut group = c.benchmark_group("storage_lookup");

    group.bench_function("memory_get_state_by_root", |b| {
        b.iter(|| black_box(memory.get_state(black_box(&mid_state_root))));
    });
    group.bench_function("memory_get_block_by_root", |b| {
        b.iter(|| black_box(memory.get_block(black_box(&mid_block_root))));
    });
    group.bench_function("memory_get_state_by_slot", |b| {
        b.iter(|| black_box(memory.get_state_by_slot(black_box(mid_slot))));
    });
    group.bench_function("memory_get_block_by_slot", |b| {
        b.iter(|| black_box(memory.get_block_by_slot(black_box(mid_slot))));
    });

    group.bench_function("file_get_state_by_root", |b| {
        b.iter(|| black_box(file.get_state(black_box(&mid_state_root))));
    });
    group.bench_function("file_get_block_by_root", |b| {
        b.iter(|| black_box(file.get_block(black_box(&mid_block_root))));
    });
    group.bench_function("file_get_state_by_slot", |b| {
        b.iter(|| black_box(file.get_state_by_slot(black_box(mid_slot))));
    });
    group.bench_function("file_get_block_by_slot", |b| {
        b.iter(|| black_box(file.get_block_by_slot(black_box(mid_slot))));
    });

    group.bench_function("memory_random_slot_mix", |b| {
        b.iter_batched(
            || 0u64,
            |mut idx| {
                for _ in 0..256 {
                    let slot = (idx.wrapping_mul(1_315_423_911) + 17) % ENTRIES;
                    let _ = black_box(memory.get_block_by_slot(slot));
                    idx = idx.wrapping_add(1);
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("file_random_slot_mix", |b| {
        b.iter_batched(
            || 0u64,
            |mut idx| {
                for _ in 0..256 {
                    let slot = (idx.wrapping_mul(1_315_423_911) + 17) % ENTRIES;
                    let _ = black_box(file.get_block_by_slot(slot));
                    idx = idx.wrapping_add(1);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_storage_lookup);
criterion_main!(benches);
