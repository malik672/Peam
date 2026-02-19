use lean_eth::containers::attestation::{Attestation, AttestationData};
use lean_eth::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::storage::{MemoryStore, Store};
use lean_eth::networking::{
    LeanRequestMessage, LeanResponseMessage, ReqRespHandler, StoreReqRespHandler,
};
use lean_eth::containers::req_resp::Status;
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::{Bytes3112, Bytes32, Bytes52};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;
use lean_eth::ssz::HashTreeRoot;
use std::sync::{Arc, RwLock};

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

fn build_signed_block(state: &State, slot: u64) -> SignedBlockWithAttestation {

    // clone again
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot))).expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());

    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(slot)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(slot)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let signature = BlockSignatures {
        attestation_signatures: SszList::new(vec![]).expect("attestation sigs"),
        proposer_signature: Bytes3112::zero(),
    };
    SignedBlockWithAttestation { message, signature }
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

#[test]
fn put_signed_block_updates_forkchoice_roots() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let signed = build_signed_block(&state, 1);
    let root = Bytes32::from([0x33u8; 32]);
    let mut store = MemoryStore::new();
    store
        .put_signed_block(root, signed, &mut state)
        .expect("put signed block");

    assert_eq!(store.head(), Some(root));
    assert_eq!(store.justified(), Some(state.latest_justified.root));
    assert_eq!(store.finalized(), Some(state.latest_finalized.root));
}

#[test]
fn status_prefers_store_head_and_finalized() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let signed = build_signed_block(&state, 1);
    let head_root = Bytes32::from([0x44u8; 32]);
    let mut store = MemoryStore::new();
    store
        .put_signed_block(head_root, signed, &mut state)
        .expect("put signed block");

    let store = Arc::new(RwLock::new(store));
    let state = Arc::new(RwLock::new(state));
    let handler = StoreReqRespHandler::new(state.clone(), store);

    let resp = handler
        .on_request(LeanRequestMessage::Status(Status {
            fork_digest: Bytes32::zero(),
            finalized_root: Bytes32::zero(),
            finalized_epoch: Uint64(0),
            head_root: Bytes32::zero(),
            head_slot: Uint64(0),
        }))
        .expect("status response");
    let LeanResponseMessage::Status(status) = resp else {
        panic!("expected status");
    };

    assert_eq!(status.head_root, head_root);
    let finalized_root = state.read().expect("state lock").latest_finalized.root;
    assert_eq!(status.finalized_root, finalized_root);
}
