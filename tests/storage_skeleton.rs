use lean_eth::containers::block::{Block, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::storage::{MemoryStore, Store};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

fn dummy_block() -> Block {
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    Block {
        slot: Slot(Uint64(0)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body,
    }
}

fn dummy_state() -> State {
    State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"))
}

#[test]
fn memory_store_roundtrip() {
    let mut store = MemoryStore::new();
    let root = Bytes32::from([0x11u8; 32]);
    let block = dummy_block();
    let state_root = Bytes32::from([0x22u8; 32]);
    let state = dummy_state();

    store.put_block(root, block.clone());
    let fetched = store.get_block(&root).expect("block");
    assert_eq!(fetched, &block);
    let fetched_by_slot = store.get_block_by_slot(0).expect("block by slot");
    assert_eq!(fetched_by_slot, &block);

    store.put_state(state_root, state.clone());
    let fetched_state = store.get_state(&state_root).expect("state");
    assert_eq!(fetched_state, &state);
    let fetched_state_by_slot = store.get_state_by_slot(0).expect("state by slot");
    assert_eq!(fetched_state_by_slot, &state);

    store.set_head(root);
    assert_eq!(store.head(), Some(root));

    store.set_finalized(state_root);
    assert_eq!(store.finalized(), Some(state_root));

    store.set_justified(root);
    assert_eq!(store.justified(), Some(root));
}
