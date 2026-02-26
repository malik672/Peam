use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{Criterion, criterion_group, criterion_main};
use lean_eth::containers::block::{Block, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::storage::{FileStore, Store};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

const FIXTURE_BLOCKS: u64 = 1_000;
const FIXTURE_STATES: u64 = 1_000;

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

fn fixture_dir(name: &str) -> PathBuf {
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

fn create_fixture() -> PathBuf {
    let dir = fixture_dir("open");
    let mut store = FileStore::open(&dir).expect("open fixture store");
    for slot in 0..FIXTURE_STATES {
        let root = root_from_u64(slot + 10_000);
        store.put_state(root, dummy_state(slot));
    }
    for slot in 0..FIXTURE_BLOCKS {
        let root = root_from_u64(slot + 20_000);
        store.put_block(root, dummy_block(slot));
    }
    dir
}

fn bench_file_store_open(c: &mut Criterion) {
    let dir = create_fixture();
    let mut group = c.benchmark_group("storage_open");
    group.bench_function("file_store_open_1k_states_1k_blocks", |b| {
        b.iter(|| {
            let store = FileStore::open(&dir).expect("open file store");
            criterion::black_box(store);
        });
    });
    let mid_slot = FIXTURE_STATES / 2;
    let mid_state_root = root_from_u64(mid_slot + 10_000);
    let mid_block_root = root_from_u64(mid_slot + 20_000);
    group.bench_function("file_store_cold_read_state_by_root", |b| {
        b.iter(|| {
            let store = FileStore::open(&dir).expect("open file store");
            let state = store.get_state(&mid_state_root);
            criterion::black_box(state);
        });
    });
    group.bench_function("file_store_cold_read_block_by_root", |b| {
        b.iter(|| {
            let store = FileStore::open(&dir).expect("open file store");
            let block = store.get_block(&mid_block_root);
            criterion::black_box(block);
        });
    });
    group.bench_function("file_store_cold_read_state_by_slot", |b| {
        b.iter(|| {
            let store = FileStore::open(&dir).expect("open file store");
            let state = store.get_state_by_slot(mid_slot);
            criterion::black_box(state);
        });
    });
    group.bench_function("file_store_cold_read_block_by_slot", |b| {
        b.iter(|| {
            let store = FileStore::open(&dir).expect("open file store");
            let block = store.get_block_by_slot(mid_slot);
            criterion::black_box(block);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_file_store_open);
criterion_main!(benches);
