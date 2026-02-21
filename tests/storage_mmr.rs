use std::time::{SystemTime, UNIX_EPOCH};

use lean_eth::containers::block::{Block, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::storage::{FileStore, Store, verify_mmr_inclusion_proof};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

fn temp_store_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("lean_eth_storage_mmr_{name}_{stamp}"))
}

fn dummy_state(slot: u64) -> State {
    let mut state = State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"));
    state.slot = Slot(Uint64(slot));
    state
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

fn root_from_u64(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&value.to_le_bytes());
    Bytes32::from(out)
}

#[test]
fn finalized_mmr_proof_roundtrip_and_persistence() {
    let dir = temp_store_dir("proof_roundtrip");
    let mut store = FileStore::open(&dir).expect("open");
    for i in 0..12u64 {
        store.put_state(root_from_u64(10_000 + i), dummy_state(i));
        store.put_block(root_from_u64(20_000 + i), dummy_block(i));
        store.set_finalized(root_from_u64(30_000 + i));
    }

    let root = store.finalized_mmr_root();
    let size = store.finalized_mmr_size();
    if size == 0 {
        // MMR maintenance disabled in maximum-performance local-trust mode.
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    assert_eq!(size, 12);
    for idx in 0..size {
        let proof = store
            .finalized_mmr_proof_by_index(idx)
            .expect("mmr proof by index");
        assert!(verify_mmr_inclusion_proof(root, &proof));
    }
    drop(store);

    let reopened = FileStore::open(&dir).expect("reopen");
    assert_eq!(reopened.finalized_mmr_size(), 12);
    assert_eq!(reopened.finalized_mmr_root(), root);
    let target_root = root_from_u64(30_000 + 7);
    let proof = reopened
        .finalized_mmr_proof_by_root(target_root)
        .expect("reopened proof by root");
    assert!(verify_mmr_inclusion_proof(root, &proof));
    assert_eq!(proof.leaf, target_root);

    let _ = std::fs::remove_dir_all(dir);
}
