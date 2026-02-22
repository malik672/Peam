use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use lean_eth::containers::block::{Block, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::storage::{FileStore, Store};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

const FIXTURE_ROWS: u64 = 1_000;
const ITERATIONS: usize = 100;

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
    std::env::temp_dir().join(format!("lean_eth_{name}_{stamp}"))
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
    let mut state = State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"));
    state.slot = Slot(Uint64(slot));
    state
}

fn create_fixture(dir: &PathBuf) {
    let mut store = FileStore::open(dir).expect("open fixture store");
    for slot in 0..FIXTURE_ROWS {
        let root = root_from_u64(slot + 10_000);
        store.put_state(root, dummy_state(slot));
    }
    for slot in 0..FIXTURE_ROWS {
        let root = root_from_u64(slot + 20_000);
        store.put_block(root, dummy_block(slot));
    }
}

fn avg_ms(total: Duration, iterations: usize) -> f64 {
    (total.as_secs_f64() * 1_000.0) / iterations as f64
}

fn main() {
    let dir = fixture_dir("storage_open_microbench");
    create_fixture(&dir);

    let mid_slot = FIXTURE_ROWS / 2;
    let mid_state_root = root_from_u64(mid_slot + 10_000);

    let mut open_total = Duration::ZERO;
    let mut cold_state_root_total = Duration::ZERO;
    let mut cold_block_slot_total = Duration::ZERO;
    let mut cold_state_slot_total = Duration::ZERO;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let store = FileStore::open(&dir).expect("open");
        std::hint::black_box(store);
        open_total += start.elapsed();
    }

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let store = FileStore::open(&dir).expect("open");
        let state = store.get_state(&mid_state_root);
        std::hint::black_box(state);
        cold_state_root_total += start.elapsed();
    }

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let store = FileStore::open(&dir).expect("open");
        let block = store.get_block_by_slot(mid_slot);
        std::hint::black_box(block);
        cold_block_slot_total += start.elapsed();
    }

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let store = FileStore::open(&dir).expect("open");
        let state = store.get_state_by_slot(mid_slot);
        std::hint::black_box(state);
        cold_state_slot_total += start.elapsed();
    }

    println!(
        "lean_eth_open_1k_states_1k_blocks avg: {:.3} ms",
        avg_ms(open_total, ITERATIONS)
    );
    println!(
        "lean_eth_cold_read_state_by_root avg: {:.3} ms",
        avg_ms(cold_state_root_total, ITERATIONS)
    );
    println!(
        "lean_eth_cold_read_block_by_slot avg: {:.3} ms",
        avg_ms(cold_block_slot_total, ITERATIONS)
    );
    println!(
        "lean_eth_cold_read_state_by_slot avg: {:.3} ms",
        avg_ms(cold_state_slot_total, ITERATIONS)
    );

    let _ = fs::remove_dir_all(&dir);
}
