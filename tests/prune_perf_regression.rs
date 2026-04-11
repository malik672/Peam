use std::path::PathBuf;
use std::time::Instant;

use peam::containers::block::{Block, BlockBody};
use peam::containers::state::{State, Validators};
use peam::containers::validator::ValidatorIndex;
use peam::slot::Slot;
use peam::storage::{FileStore, Store};
use peam::types::bytes::Bytes32;
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

const KEEP_RECENT_SLOTS: u64 = 64;
const SMALL_ROWS: u64 = 256;
const LARGE_ROWS: u64 = 512;
const RUNS: usize = 3;

fn temp_store_dir(tag: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("peam_perf_{tag}_{stamp}"))
}

fn root_from_u64(v: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v.to_le_bytes());
    Bytes32::from(out)
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

fn expected_removed(rows: u64, keep_recent: u64) -> usize {
    rows.saturating_sub(1).saturating_sub(keep_recent) as usize
}

fn measure_prune_ms(rows: u64) -> f64 {
    let mut samples = Vec::with_capacity(RUNS);
    let expected = expected_removed(rows, KEEP_RECENT_SLOTS);

    for _ in 0..RUNS {
        let dir = temp_store_dir("prune_regression");
        let mut store = FileStore::open(&dir).expect("open store");
        for slot in 0..rows {
            let block_root = root_from_u64(slot + 20_000);
            store.put_state(block_root, dummy_state(slot));
            store.put_block(block_root, dummy_block(slot));
        }

        let start = Instant::now();
        let report = store
            .prune(rows.saturating_sub(1), KEEP_RECENT_SLOTS)
            .expect("prune");
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        samples.push(elapsed_ms);

        // Sanity check: pruning work should be stable and deterministic.
        assert_eq!(report.removed_states, expected);
        assert_eq!(report.removed_blocks, expected);
        assert_eq!(report.removed_signed_blocks, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    samples[samples.len() / 2]
}

#[test]
#[ignore = "performance regression harness; run explicitly in perf jobs"]
fn prune_scales_near_linearly_for_small_deterministic_workload() {
    let small_ms = measure_prune_ms(SMALL_ROWS);
    let large_ms = measure_prune_ms(LARGE_ROWS);
    let ratio = large_ms / small_ms;

    eprintln!("prune-perf: small={small_ms:.3}ms large={large_ms:.3}ms ratio={ratio:.2}");

    // Guardrail: doubling rows should not trigger extreme super-linear blowup.
    // Threshold is intentionally loose to avoid host-specific flakiness.
    assert!(
        ratio <= 3.2,
        "prune scaling regression: small={small_ms:.3}ms large={large_ms:.3}ms ratio={ratio:.2}"
    );
}
