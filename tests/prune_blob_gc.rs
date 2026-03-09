use std::path::PathBuf;

use peam::containers::block::{Block, BlockBody};
use peam::containers::state::{State, Validators};
use peam::containers::validator::ValidatorIndex;
use peam::slot::Slot;
use peam::storage::{FileStore, Store};
use peam::types::bytes::Bytes32;
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

fn temp_store_dir(tag: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("peam_gc_{tag}_{stamp}"))
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

#[test]
fn prune_removes_unreferenced_state_and_block_blobs() {
    let rows = 12u64;
    let keep_recent_slots = 3u64;
    let expected_removed = rows.saturating_sub(1).saturating_sub(keep_recent_slots) as usize;

    let dir = temp_store_dir("blob_gc");
    let mut store = FileStore::open(&dir).expect("open store");

    for slot in 0..rows {
        store.put_state(root_from_u64(slot + 10_000), dummy_state(slot));
        store.put_block(root_from_u64(slot + 20_000), dummy_block(slot));
    }

    let report = store
        .prune(rows.saturating_sub(1), keep_recent_slots)
        .expect("prune");

    assert_eq!(report.removed_states, expected_removed);
    assert_eq!(report.removed_blocks, expected_removed);
    assert_eq!(report.removed_state_blobs, expected_removed);
    assert_eq!(report.removed_block_blobs, expected_removed);
    assert_eq!(report.removed_signed_blocks, 0);

    // Old blobs should be gone from root lookup.
    assert!(store.get_state(&root_from_u64(10_000)).is_none());
    assert!(store.get_block(&root_from_u64(20_000)).is_none());

    // Recent roots should still be available.
    let newest_slot = rows - 1;
    assert!(
        store
            .get_state(&root_from_u64(newest_slot + 10_000))
            .is_some()
    );
    assert!(
        store
            .get_block(&root_from_u64(newest_slot + 20_000))
            .is_some()
    );

    let _ = std::fs::remove_dir_all(dir);
}
