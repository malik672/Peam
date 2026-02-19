use lean_eth::containers::attestation::{Attestation, AttestationData};
use lean_eth::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::fork_choice::ForkChoiceStore;
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::{Bytes3112, Bytes32, Bytes52};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

fn build_signed_block(
    base_state: &State,
    slot: u64,
    include_attestation: bool,
) -> (SignedBlockWithAttestation, State, Bytes32) {
    let mut temp = base_state.clone();
    temp.process_slots(Slot(Uint64(slot))).expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let attestations = if include_attestation {
        let att = Attestation {
            aggregation_bits: BitList::new(vec![true]).expect("participants"),
            data: AttestationData {
                slot: Slot(Uint64(slot)),
                head: Checkpoint {
                    root: Bytes32::zero(),
                    slot: Slot(Uint64(slot)),
                },
                target: Checkpoint {
                    root: parent_root,
                    slot: Slot(Uint64(slot)),
                },
                source: Checkpoint {
                    root: Bytes32::zero(),
                    slot: Slot(Uint64(0)),
                },
            },
        };
        SszList::new(vec![att]).expect("attestations")
    } else {
        SszList::new(vec![]).expect("attestations")
    };
    let body = BlockBody { attestations };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let mut post = base_state.clone();
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
    let root = Bytes32::from(message.block.hash_tree_root());
    (SignedBlockWithAttestation { message, signature }, post, root)
}

#[test]
fn fork_choice_updates_head_on_new_block() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let (anchor_block, anchor_state, anchor_root) = build_signed_block(&state, 1, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");
    assert_eq!(store.head(), anchor_root);

    let (next_block, next_state, next_root) = build_signed_block(&anchor_state, 2, true);
    store.on_block(next_block, next_state).expect("on block");

    assert_eq!(store.head(), next_root);
}

#[test]
fn fork_choice_uses_votes_to_pick_head() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let (anchor_block, anchor_state, anchor_root) = build_signed_block(&state, 1, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");
    assert_eq!(store.head(), anchor_root);

    let (fork_a, state_a, _root_a) = build_signed_block(&anchor_state, 2, false);
    let (fork_b, state_b, root_b) = build_signed_block(&anchor_state, 2, true);

    store.on_block(fork_a, state_a).expect("fork a");
    store.on_block(fork_b, state_b).expect("fork b");

    let vote = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(2)),
            },
            target: Checkpoint {
                root: root_b,
                slot: Slot(Uint64(2)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    store.on_attestation(&vote);
    assert_eq!(store.head(), root_b);
}
