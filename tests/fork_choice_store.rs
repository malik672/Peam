use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::fork_choice::ForkChoiceStore;
use peam::node::proposal_head_from_pending;
use peam::slot::Slot;
use peam::ssz::HashTreeRoot;
use peam::types::bitlist::BitList;
use peam::types::bytes::{Bytes32, Bytes52, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;
use std::sync::{Arc, RwLock};

fn build_signed_block(
    base_state: &State,
    slot: u64,
    include_attestation: bool,
) -> (SignedBlockWithAttestation, State, Bytes32) {
    let validator_count = base_state.validators.data.len() as u64;
    let proposer = if validator_count == 0 {
        0
    } else {
        slot % validator_count
    };
    let mut temp = base_state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
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
        proposer_index: ValidatorIndex(Uint64(proposer)),
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
        aggregation_bits: BitList::new({
            let mut bits = vec![false; proposer as usize + 1];
            bits[proposer as usize] = true;
            bits
        })
        .expect("participants"),
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
    (
        SignedBlockWithAttestation { message, signature },
        post,
        root,
    )
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
    store.accept_new_votes();
    assert_eq!(store.head(), root_b);
}

#[test]
fn proposal_head_applies_pending_votes_before_returning_head() {
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

    let pending_vote = Attestation {
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

    let proposal_head = store.get_proposal_head_with_pending([&pending_vote]);
    assert_eq!(proposal_head, root_b);
}

#[test]
fn node_proposal_helper_drains_pending_and_returns_head() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let (anchor_block, anchor_state, _anchor_root) = build_signed_block(&state, 1, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");

    let (fork_a, state_a, _root_a) = build_signed_block(&anchor_state, 2, false);
    let (fork_b, state_b, root_b) = build_signed_block(&anchor_state, 2, true);
    store.on_block(fork_a, state_a).expect("fork a");
    store.on_block(fork_b, state_b).expect("fork b");

    let pending_vote = Attestation {
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

    let fc = Arc::new(RwLock::new(Some(store)));
    let pending = Arc::new(RwLock::new(vec![pending_vote]));
    let head = proposal_head_from_pending(&fc, &pending).expect("proposal head");
    assert_eq!(head, root_b);
    assert!(pending.read().expect("pending lock").is_empty());
}

#[test]
fn safe_target_advances_after_supermajority_votes() {
    let validators = Validators::new(vec![
        Validator {
            pubkey: Bytes52::from([0x01u8; 52]),
            index: ValidatorIndex(Uint64(0)),
            balance: Uint64(0),
        },
        Validator {
            pubkey: Bytes52::from([0x02u8; 52]),
            index: ValidatorIndex(Uint64(1)),
            balance: Uint64(0),
        },
        Validator {
            pubkey: Bytes52::from([0x03u8; 52]),
            index: ValidatorIndex(Uint64(2)),
            balance: Uint64(0),
        },
    ])
    .expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);
    let (anchor_block, anchor_state, _anchor_root) = build_signed_block(&state, 1, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");
    let (next_block, next_state, next_root) = build_signed_block(&anchor_state, 2, false);
    store.on_block(next_block, next_state).expect("on block");

    // 2 of 3 validators => supermajority.
    let vote = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: next_root,
                slot: Slot(Uint64(2)),
            },
            target: Checkpoint {
                root: next_root,
                slot: Slot(Uint64(2)),
            },
            source: Checkpoint {
                root: store.latest_finalized().root,
                slot: store.latest_finalized().slot,
            },
        },
    };
    store.on_attestation(&vote);
    store.accept_new_votes();
    assert_eq!(store.safe_target(), next_root);
}

#[test]
fn reorg_vote_shift_changes_head() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);
    let (anchor_block, anchor_state, _anchor_root) = build_signed_block(&state, 1, false);
    let mut store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");

    let (fork_a, state_a, root_a) = build_signed_block(&anchor_state, 2, false);
    let (fork_b, state_b, root_b) = build_signed_block(&anchor_state, 2, true);
    store.on_block(fork_a, state_a).expect("fork a");
    store.on_block(fork_b, state_b).expect("fork b");

    let vote_a = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: root_a,
                slot: Slot(Uint64(2)),
            },
            target: Checkpoint {
                root: root_a,
                slot: Slot(Uint64(2)),
            },
            source: Checkpoint {
                root: store.latest_finalized().root,
                slot: store.latest_finalized().slot,
            },
        },
    };
    store.on_attestation(&vote_a);
    // Votes are staged first and only become active after acceptance.
    assert_ne!(store.head(), root_a);
    store.accept_new_votes();
    assert_eq!(store.head(), root_a);

    let vote_b = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: root_b,
                slot: Slot(Uint64(2)),
            },
            target: Checkpoint {
                root: root_b,
                slot: Slot(Uint64(2)),
            },
            source: Checkpoint {
                root: store.latest_finalized().root,
                slot: store.latest_finalized().slot,
            },
        },
    };
    store.on_attestation(&vote_b);
    store.accept_new_votes();
    assert_eq!(store.head(), root_b);
    assert!(
        store.reorgs_total() >= 1,
        "vote-shift reorg should be counted"
    );
}

#[test]
fn head_slot_and_validator_count_getters() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let (anchor_block, anchor_state, _anchor_root) = build_signed_block(&state, 1, false);
    let store = ForkChoiceStore::new(anchor_block, anchor_state.clone()).expect("forkchoice");

    assert_eq!(store.head_slot(), 1);
    assert_eq!(store.validator_count(), 1);
    assert_eq!(store.reorgs_total(), 0);
    assert_eq!(
        store.previous_justified().slot,
        store.latest_justified().slot
    );
}
