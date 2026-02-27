use lean_eth::containers::attestation::{AggregatedSignatureProof, Attestation, AttestationData};
use lean_eth::containers::block::{
    AttestationSignatures, Attestations, Block, BlockBody, BlockHeader, BlockSignatures,
    BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::state::{SignatureVerifier, State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::ByteList;
use lean_eth::types::bytes::Bytes3112;
use lean_eth::types::bytes::{Bytes32, Bytes52};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

#[test]
fn process_slots_advances_state_and_sets_root() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    assert_eq!(state.balances.data.len(), 0);
    state.process_slots(Slot(Uint64(1))).expect("process slots");
    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_ne!(state.latest_block_header.state_root, Bytes32::zero());
}

#[test]
fn process_block_header_updates_latest_header() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };

    state.process_block_header(header).expect("process header");
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
}

fn build_block_for_slot(state: &State, slot: u64, proposer: u64) -> Block {
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(proposer)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    if state.validators.data.is_empty() {
        return block;
    }
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());
    block
}

fn build_block_with_attestations_for_slot(
    state: &State,
    slot: u64,
    proposer: u64,
    attestations: Vec<Attestation>,
) -> Block {
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: Attestations::new(attestations).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(proposer)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    if state.validators.data.is_empty() {
        return block;
    }
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());
    block
}

#[test]
fn lean_spec_process_first_block_after_genesis() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 0);

    state.state_transition(&block).expect("transition");

    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.state_root, block.state_root);
    assert_eq!(state.historical_block_hashes.data.len(), 1);
}

#[test]
fn lean_spec_linear_chain_multiple_blocks() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    for slot in 1..=5u64 {
        let block = build_block_for_slot(&state, slot, 0);
        state.state_transition(&block).expect("transition");
    }

    assert_eq!(state.slot, Slot(Uint64(5)));
}

#[test]
fn lean_spec_blocks_with_gaps() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let slots = [1u64, 4u64, 8u64];
    for slot in slots {
        let block = build_block_for_slot(&state, slot, 0);
        state.state_transition(&block).expect("transition");
    }

    assert_eq!(state.slot, Slot(Uint64(8)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(8)));
    assert_ne!(state.latest_block_header.state_root, Bytes32::zero());
    assert_eq!(state.historical_block_hashes.data.len(), 8);
}

#[test]
fn lean_spec_block_at_large_slot_number() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 100, 0);
    state.state_transition(&block).expect("transition");

    assert_eq!(state.slot, Slot(Uint64(100)));
}

#[test]
fn lean_spec_block_with_invalid_proposer() {
    let v0 = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let mut block = build_block_for_slot(&state, 1, 1);
    block.proposer_index = ValidatorIndex(Uint64(0)); // wrong: expected 1

    let err = state.state_transition(&block).unwrap_err();
    assert!(err.contains("proposer"));
}

#[test]
fn lean_spec_block_with_invalid_parent_root() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let mut block = build_block_for_slot(&state, 1, 0);
    block.parent_root = Bytes32::from([0xDEu8; 32]);

    let err = state.state_transition(&block).unwrap_err();
    assert!(err.contains("parent root"));
}

#[test]
fn signed_block_signature_count_mismatch() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 0);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
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
    let proof = AggregatedSignatureProof {
        participants: BitList::new(vec![]).expect("participants"),
        proof_data: ByteList::new(vec![]).expect("proof"),
    };
    let sigs: AttestationSignatures = SszList::new(vec![proof]).expect("signatures");
    let signed = SignedBlockWithAttestation {
        message,
        signature: BlockSignatures {
            attestation_signatures: sigs,
            proposer_signature: lean_eth::types::bytes::Bytes3112::zero(),
        },
    };

    let err = state.process_signed_block(&signed).unwrap_err();
    assert!(err.contains("attestation signatures count"));
}

#[test]
fn signed_block_proposer_attestation_slot_mismatch() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 0);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
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
    let signed = SignedBlockWithAttestation {
        message,
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("signatures"),
            proposer_signature: lean_eth::types::bytes::Bytes3112::zero(),
        },
    };

    let err = state.process_signed_block(&signed).unwrap_err();
    assert!(err.contains("proposer attestation slot"));
}

#[test]
fn signed_block_proposer_attestation_participant_mismatch() {
    let v0 = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 1);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true, false]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
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
    let signed = SignedBlockWithAttestation {
        message,
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    };

    let err = state.process_signed_block(&signed).unwrap_err();
    assert!(err.contains("proposer attestation does not match proposer index"));
}

#[test]
fn signed_block_attestation_proof_participants_mismatch() {
    let v0 = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from([0x11u8; 32]),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    let block = build_block_with_attestations_for_slot(&state, 1, 1, vec![att]);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![false, true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![AggregatedSignatureProof {
                participants: BitList::new(vec![true, false]).expect("participants"),
                proof_data: ByteList::new(vec![0xAB]).expect("proof"),
            }])
            .expect("signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    };

    let err = state.process_signed_block(&signed).unwrap_err();
    assert!(err.contains("participants do not match aggregation bits"));
}

#[test]
fn signed_block_signature_verifier_error() {
    struct FailVerifier;

    impl SignatureVerifier for FailVerifier {
        fn verify_signed_block(
            &self,
            _signed: &SignedBlockWithAttestation,
            _state: &State,
        ) -> Result<(), String> {
            Err("sig verify failed".to_string())
        }
    }

    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 0);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
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
    let signed = SignedBlockWithAttestation {
        message,
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    };

    let err = state
        .process_signed_block_with_verifier(&signed, &FailVerifier)
        .unwrap_err();
    assert!(err.contains("sig verify failed"));
}

#[test]
fn process_block_header_pushes_historical_hashes() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(2))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(2)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };

    state.process_block_header(header).expect("process header");
    assert_eq!(state.historical_block_hashes.data.len(), 2);
    assert_eq!(state.historical_block_hashes.data[0], parent_root);
    assert_eq!(state.historical_block_hashes.data[1], Bytes32::zero());
}

#[test]
fn first_post_genesis_block_keeps_seeded_justified_and_finalized_root() {
    let v = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);
    let seeded_root = state.latest_justified.root;
    assert_eq!(seeded_root, state.latest_finalized.root);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state.process_block_header(header).expect("process header");

    assert_eq!(state.latest_justified.root, seeded_root);
    assert_eq!(state.latest_finalized.root, seeded_root);
}

#[test]
fn attestations_update_latest_justified() {
    let v0 = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        pubkey: Bytes52::from([0x03u8; 52]),
        index: ValidatorIndex(Uint64(2)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1, v2]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(1)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state.process_block_header(header).expect("process header");

    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::from(state.latest_block_header.hash_tree_root()),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from(state.latest_block_header.hash_tree_root()),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    let attestations = Attestations::new(vec![att]).expect("attestations");
    state
        .process_attestations(&attestations)
        .expect("process attestations");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(1)));
    assert!(state.justified_slots.len() >= 1);
    let idx = 0usize;
    let byte = idx / 8;
    let bit = idx % 8;
    assert!((state.justified_slots.data[byte] & (1u8 << bit)) != 0);
}

#[test]
fn attestations_with_zero_validators_do_not_justify() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");

    let att = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from([0x22u8; 32]),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    let attestations = Attestations::new(vec![att]).expect("attestations");
    state
        .process_attestations(&attestations)
        .expect("process attestations");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));
    assert_eq!(state.justified_slots.len(), 0);
}

#[test]
fn process_block_header_fills_empty_slots_with_zero_hashes() {
    let v = Validator {
        pubkey: Bytes52::from([0x03u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(4))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(4)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };

    state.process_block_header(header).expect("process header");
    assert_eq!(state.historical_block_hashes.data.len(), 4);
    assert_eq!(state.historical_block_hashes.data[0], parent_root);
    assert_eq!(state.historical_block_hashes.data[1], Bytes32::zero());
    assert_eq!(state.historical_block_hashes.data[2], Bytes32::zero());
    assert_eq!(state.historical_block_hashes.data[3], Bytes32::zero());
}

#[test]
fn historical_block_hashes_count_matches_expected() {
    let v = Validator {
        pubkey: Bytes52::from([0x04u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(3))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(3)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };

    state.process_block_header(header).expect("process header");
    assert_eq!(state.historical_block_hashes.data.len(), 3);
}

#[test]
fn process_block_delegates_to_header() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let parent_root = Bytes32::from(state.latest_block_header.hash_tree_root());

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    let block = Block {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root: header.parent_root,
        state_root: header.state_root,
        body,
    };

    state.process_block(&block).expect("process block");
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
}

#[test]
fn state_transition_processes_slots_then_block() {
    let v = Validator {
        pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);
    let mut temp_state = state.clone();
    temp_state
        .process_slots(Slot(Uint64(1)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp_state.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    let mut block = Block {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root: header.parent_root,
        state_root: header.state_root,
        body,
    };
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());

    state.state_transition(&block).expect("transition");
    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
}
