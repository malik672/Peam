use lean_eth::containers::block::{
    AttestationSignatures, Attestations, Block, BlockBody, BlockHeader, BlockSignatures,
    BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::attestation::{AggregatedSignatureProof, Attestation, AttestationData};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::state::{State, Validators, SignatureVerifier};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::types::bytes::{Bytes32, Bytes52};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::ByteList;
use lean_eth::types::bytes::Bytes3112;

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
    temp.process_slots(Slot(Uint64(slot))).expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(proposer)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    }
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
    assert_eq!(state.latest_block_header.state_root, Bytes32::zero());
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
    assert_eq!(state.latest_block_header.state_root, Bytes32::zero());
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
        proposer_attestation: SszList::new(vec![proposer_attestation])
            .expect("proposer attestations"),
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
        proposer_attestation: SszList::new(vec![proposer_attestation])
            .expect("proposer attestations"),
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
        proposer_attestation: SszList::new(vec![proposer_attestation])
            .expect("proposer attestations"),
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
fn first_post_genesis_block_sets_justified_and_finalized_root() {
    let v = Validator {
        pubkey: Bytes52::from([0x02u8; 52]),
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

    assert_eq!(state.latest_justified.root, parent_root);
    assert_eq!(state.latest_finalized.root, parent_root);
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
    let block = Block {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root: header.parent_root,
        state_root: header.state_root,
        body,
    };

    state.state_transition(&block).expect("transition");
    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
}
