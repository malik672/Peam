use peam::containers::attestation::{AggregatedSignatureProof, Attestation, AttestationData};
use peam::containers::block::{
    AttestationSignatures, Attestations, Block, BlockBody, BlockHeader, BlockSignatures,
    BlockWithAttestation, SignedBlockWithAttestation, MAX_ATTESTATIONS_DATA,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{
    NoopSignatureVerifier, PqSignatureVerifier, SignatureVerifier, State, Validators,
};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::crypto::pq;
use peam::slot::Slot;
use peam::ssz::HashTreeRoot;
use peam::types::bitlist::BitList;
use peam::types::bytes::ByteList;
use peam::types::bytes::Bytes3112;
use peam::types::bytes::{Bytes32, Bytes52};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

#[test]
fn process_slots_advances_state_and_sets_root() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);
    let original_header_root = state.latest_block_header.state_root;

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.state_root, original_header_root);
}

#[test]
fn process_slots_caches_zeroed_latest_header_state_root() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);
    state.latest_block_header.state_root = Bytes32::zero();

    let expected_root = Bytes32::from(state.hash_tree_root());

    state.process_slots(Slot(Uint64(1))).expect("process slots");

    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.state_root, expected_root);
}

#[test]
fn process_block_header_updates_latest_header() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
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

#[test]
fn state_root_mismatch_error_does_not_mutate_state() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);
    let original = state.clone();

    let mut block = build_block_for_slot(&state, 1, 0);
    block.state_root = Bytes32::from([0xabu8; 32]);
    let signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation {
                aggregation_bits: BitList::new(vec![true]).expect("participants"),
                data: AttestationData {
                    slot: Slot(Uint64(1)),
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
            },
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    };

    let err = state
        .process_signed_block_with_verifier(&signed, &NoopSignatureVerifier)
        .expect_err("state-root mismatch should reject block");
    assert!(err.contains("block state root does not match computed state root"));
    assert_eq!(
        state, original,
        "rejected state-root mismatch must leave state unchanged"
    );
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
    if state.validators.is_empty() {
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
    if state.validators.is_empty() {
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

fn apply_state_transition_for_test(state: &mut State, block: &Block) -> Result<(), String> {
    state.process_slots(block.slot)?;

    let header = block.header();
    state.process_block_header(header)?;
    state.process_block_body(&block.body, header.body_root)?;

    let computed_root = Bytes32::from(state.hash_tree_root());
    if computed_root != block.state_root {
        return Err("block state root does not match computed state root".to_string());
    }
    state.latest_block_header.state_root = computed_root;

    Ok(())
}

#[test]
fn lean_spec_process_first_block_after_genesis() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 1, 0);

    apply_state_transition_for_test(&mut state, &block).expect("transition");

    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.state_root, block.state_root);
    assert_eq!(state.historical_block_hashes.len(), 1);
}

#[test]
fn lean_spec_linear_chain_multiple_blocks() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    for slot in 1..=5u64 {
        let block = build_block_for_slot(&state, slot, 0);
        apply_state_transition_for_test(&mut state, &block).expect("transition");
    }

    assert_eq!(state.slot, Slot(Uint64(5)));
}

#[test]
fn lean_spec_blocks_with_gaps() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let slots = [1u64, 4u64, 8u64];
    for slot in slots {
        let block = build_block_for_slot(&state, slot, 0);
        apply_state_transition_for_test(&mut state, &block).expect("transition");
    }

    assert_eq!(state.slot, Slot(Uint64(8)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(8)));
    assert_ne!(state.latest_block_header.state_root, Bytes32::zero());
    assert_eq!(state.historical_block_hashes.len(), 8);
}

#[test]
fn lean_spec_block_at_large_slot_number() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let block = build_block_for_slot(&state, 100, 0);
    apply_state_transition_for_test(&mut state, &block).expect("transition");

    assert_eq!(state.slot, Slot(Uint64(100)));
}

#[test]
fn lean_spec_block_with_invalid_proposer() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x02u8; 52]),
        proposal_pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let mut block = build_block_for_slot(&state, 1, 1);
    block.proposer_index = ValidatorIndex(Uint64(0)); // wrong: expected 1

    let err = apply_state_transition_for_test(&mut state, &block).unwrap_err();
    assert!(err.contains("proposer"));
}

#[test]
fn lean_spec_block_with_invalid_parent_root() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let mut block = build_block_for_slot(&state, 1, 0);
    block.parent_root = Bytes32::from([0xDEu8; 32]);

    let err = apply_state_transition_for_test(&mut state, &block).unwrap_err();
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
            proposer_signature: peam::types::bytes::Bytes3112::zero(),
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
            proposer_signature: peam::types::bytes::Bytes3112::zero(),
        },
    };

    let err = state.process_signed_block(&signed).unwrap_err();
    assert!(err.contains("proposer attestation slot"));
}

#[test]
fn signed_block_rejects_too_many_distinct_attestation_data_entries() {
    let validators: Validators = SszList::new(vec![]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let attestations = (0..=MAX_ATTESTATIONS_DATA)
        .map(|slot| Attestation {
            aggregation_bits: BitList::new(vec![true]).expect("participants"),
            data: AttestationData {
                slot: Slot(Uint64(slot as u64)),
                head: Checkpoint {
                    root: Bytes32::from([slot as u8; 32]),
                    slot: Slot(Uint64(slot as u64)),
                },
                target: Checkpoint {
                    root: Bytes32::from([slot as u8; 32]),
                    slot: Slot(Uint64(slot as u64)),
                },
                source: Checkpoint {
                    root: Bytes32::from([slot.saturating_sub(1) as u8; 32]),
                    slot: Slot(Uint64(slot.saturating_sub(1) as u64)),
                },
            },
        })
        .collect::<Vec<_>>();
    let block = build_block_with_attestations_for_slot(&state, 1, 0, attestations.clone());
    let proofs = attestations
        .iter()
        .map(|attestation| AggregatedSignatureProof {
            participants: attestation.aggregation_bits.clone(),
            proof_data: ByteList::new(vec![]).expect("proof"),
        })
        .collect::<Vec<_>>();
    let signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation {
                aggregation_bits: BitList::new(vec![true]).expect("participants"),
                data: AttestationData {
                    slot: Slot(Uint64(1)),
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
            },
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(proofs).expect("signatures"),
            proposer_signature: Bytes3112::zero(),
        },
    };

    let err = state
        .process_signed_block_with_verifier(&signed, &NoopSignatureVerifier)
        .expect_err("too many distinct attestation-data entries should be rejected");
    assert!(err.contains("distinct attestation data entries"));
}

#[test]
fn signed_block_proposer_attestation_participant_mismatch() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x02u8; 52]),
        proposal_pubkey: Bytes52::from([0x02u8; 52]),
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
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x02u8; 52]),
        proposal_pubkey: Bytes52::from([0x02u8; 52]),
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
    assert!(err.contains("attestation aggregate participants mismatch"));
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
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
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
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
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
    assert_eq!(state.historical_block_hashes.len(), 2);
    assert_eq!(state.historical_block_hashes.get(0), Some(&parent_root));
    assert_eq!(state.historical_block_hashes.get(1), Some(&Bytes32::zero()));
}

#[test]
fn first_post_genesis_block_seeds_checkpoint_roots_from_parent() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x02u8; 52]),
        proposal_pubkey: Bytes52::from([0x02u8; 52]),
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
    assert_eq!(state.latest_justified.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));
}

#[test]
fn attestations_update_latest_justified() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x02u8; 52]),
        proposal_pubkey: Bytes52::from([0x02u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        attestation_pubkey: Bytes52::from([0x03u8; 52]),
        proposal_pubkey: Bytes52::from([0x03u8; 52]),
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
    state.latest_justified.root = parent_root;
    state.latest_finalized.root = parent_root;

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
    assert!(state.justified_slots.len >= 1);
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
    assert_eq!(state.justified_slots.len, 0);
}

#[test]
fn attestations_accumulate_votes_across_calls_for_justification_and_finalization() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x11u8; 52]),
        proposal_pubkey: Bytes52::from([0x11u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x22u8; 52]),
        proposal_pubkey: Bytes52::from([0x22u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        attestation_pubkey: Bytes52::from([0x33u8; 52]),
        proposal_pubkey: Bytes52::from([0x33u8; 52]),
        index: ValidatorIndex(Uint64(2)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1, v2]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header_1 = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(1)),
        parent_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state
        .process_block_header(header_1)
        .expect("process header slot 1");
    state.latest_block_header.state_root = Bytes32::from(state.hash_tree_root());
    state.latest_justified.root = header_1.parent_root;
    state.latest_finalized.root = header_1.parent_root;

    let target_1 = Checkpoint {
        root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        slot: Slot(Uint64(1)),
    };
    let source_0 = state.latest_justified;
    let att_1a = Attestation {
        aggregation_bits: BitList::new(vec![true, false, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: target_1,
            target: target_1,
            source: source_0,
        },
    };
    state
        .process_attestations(&Attestations::new(vec![att_1a]).expect("attestations"))
        .expect("process first vote for slot 1");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(0)));
    assert_eq!(state.justifications_roots.len(), 1);

    let att_1b = Attestation {
        aggregation_bits: BitList::new(vec![false, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: target_1,
            target: target_1,
            source: source_0,
        },
    };
    state
        .process_attestations(&Attestations::new(vec![att_1b]).expect("attestations"))
        .expect("process second vote for slot 1");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(1)));
    assert_eq!(state.justifications_roots.len(), 0);

    state.process_slots(Slot(Uint64(2))).expect("process slots");
    let header_2 = BlockHeader {
        slot: Slot(Uint64(2)),
        proposer_index: ValidatorIndex(Uint64(2)),
        parent_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state
        .process_block_header(header_2)
        .expect("process header slot 2");
    state.latest_block_header.state_root = Bytes32::from(state.hash_tree_root());

    let target_2 = Checkpoint {
        root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        slot: Slot(Uint64(2)),
    };
    let source_1 = state.latest_justified;
    let att_2a = Attestation {
        aggregation_bits: BitList::new(vec![true, false, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: target_2,
            target: target_2,
            source: source_1,
        },
    };
    let att_2b = Attestation {
        aggregation_bits: BitList::new(vec![false, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: target_2,
            target: target_2,
            source: source_1,
        },
    };

    state
        .process_attestations(&Attestations::new(vec![att_2a]).expect("attestations"))
        .expect("process first vote for slot 2");
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));

    state
        .process_attestations(&Attestations::new(vec![att_2b]).expect("attestations"))
        .expect("process second vote for slot 2");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(2)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(1)));
}

#[test]
fn attestations_with_mismatched_target_slot_root_are_ignored() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x11u8; 52]),
        proposal_pubkey: Bytes52::from([0x11u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x22u8; 52]),
        proposal_pubkey: Bytes52::from([0x22u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        attestation_pubkey: Bytes52::from([0x33u8; 52]),
        proposal_pubkey: Bytes52::from([0x33u8; 52]),
        index: ValidatorIndex(Uint64(2)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1, v2]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header_1 = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(1)),
        parent_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state
        .process_block_header(header_1)
        .expect("process header slot 1");
    state.latest_justified.root = header_1.parent_root;
    state.latest_finalized.root = header_1.parent_root;

    let source_0 = state.latest_justified;
    let head_1 = Checkpoint {
        root: Bytes32::from(state.latest_block_header.hash_tree_root()),
        slot: Slot(Uint64(1)),
    };
    // Mismatch on purpose: target.slot points to slot 1, but target.root is slot 0 root.
    let bad_target_1 = Checkpoint {
        root: source_0.root,
        slot: Slot(Uint64(1)),
    };
    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: head_1,
            target: bad_target_1,
            source: source_0,
        },
    };

    state
        .process_attestations(&Attestations::new(vec![att]).expect("attestations"))
        .expect("process attestations");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));
}

#[test]
fn finalizes_when_target_is_next_valid_justifiable_slot_not_adjacent_slot() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x41u8; 52]),
        proposal_pubkey: Bytes52::from([0x41u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x42u8; 52]),
        proposal_pubkey: Bytes52::from([0x42u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        attestation_pubkey: Bytes52::from([0x43u8; 52]),
        proposal_pubkey: Bytes52::from([0x43u8; 52]),
        index: ValidatorIndex(Uint64(2)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1, v2]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };

    for slot in 1..=9u64 {
        state
            .process_slots(Slot(Uint64(slot)))
            .expect("process slots");
        let header = BlockHeader {
            slot: Slot(Uint64(slot)),
            proposer_index: ValidatorIndex(Uint64(slot % 3)),
            parent_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
            state_root: Bytes32::zero(),
            body_root: Bytes32::from(body.hash_tree_root()),
        };
        state.process_block_header(header).expect("process header");
    }

    let source_slot = Slot(Uint64(6));
    let source_root = state.historical_block_hashes.as_slice()[6];
    state.justified_slots.len = 6;
    state.justified_slots.data = vec![0u8; 1];
    state.justified_slots.data[0] |= 1u8 << 5;

    let target_slot = Slot(Uint64(9));
    let target_root = Bytes32::from(state.latest_block_header.hash_tree_root());
    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: target_slot,
            head: Checkpoint {
                root: target_root,
                slot: target_slot,
            },
            target: Checkpoint {
                root: target_root,
                slot: target_slot,
            },
            source: Checkpoint {
                root: source_root,
                slot: source_slot,
            },
        },
    };
    state
        .process_attestations(&Attestations::new(vec![att]).expect("attestations"))
        .expect("process attestations");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(9)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(6)));
}

#[test]
fn duplicate_historical_roots_keep_pending_justifications_after_prune() {
    let v0 = Validator {
        attestation_pubkey: Bytes52::from([0x51u8; 52]),
        proposal_pubkey: Bytes52::from([0x51u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let v1 = Validator {
        attestation_pubkey: Bytes52::from([0x52u8; 52]),
        proposal_pubkey: Bytes52::from([0x52u8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let v2 = Validator {
        attestation_pubkey: Bytes52::from([0x53u8; 52]),
        proposal_pubkey: Bytes52::from([0x53u8; 52]),
        index: ValidatorIndex(Uint64(2)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v0, v1, v2]).expect("validators");
    let mut state = State::generate_genesis(Uint64(0), validators);

    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    for slot in 1..=8u64 {
        state
            .process_slots(Slot(Uint64(slot)))
            .expect("process slots");
        let header = BlockHeader {
            slot: Slot(Uint64(slot)),
            proposer_index: ValidatorIndex(Uint64(slot % 3)),
            parent_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
            state_root: Bytes32::zero(),
            body_root: Bytes32::from(body.hash_tree_root()),
        };
        state.process_block_header(header).expect("process header");
    }

    // Create a duplicate non-zero root at an older and newer slot.
    let pending_root = state.historical_block_hashes.as_slice()[2];
    state.historical_block_hashes.as_mut_slice()[7] = pending_root;

    // Seed one pending vote for `pending_root`.
    state.justifications_roots = SszList::new(vec![pending_root]).expect("roots");
    state.justifications_validators = BitList {
        data: vec![0b0000_0001],
        len: 3,
    };

    // Mark source slot (5) justified so (source=5,target=6) can finalize source.
    state.justified_slots.len = 5;
    state.justified_slots.data = vec![0u8; 1];
    state.justified_slots.data[0] |= 1u8 << 4;

    let source_slot = Slot(Uint64(5));
    let target_slot = Slot(Uint64(6));
    let source_root = state.historical_block_hashes.as_slice()[5];
    let target_root = state.historical_block_hashes.as_slice()[6];
    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: target_slot,
            head: Checkpoint {
                root: target_root,
                slot: target_slot,
            },
            target: Checkpoint {
                root: target_root,
                slot: target_slot,
            },
            source: Checkpoint {
                root: source_root,
                slot: source_slot,
            },
        },
    };

    state
        .process_attestations(&Attestations::new(vec![att]).expect("attestations"))
        .expect("process attestations");

    assert_eq!(state.latest_finalized.slot, source_slot);
    assert_eq!(state.justifications_roots.as_slice(), &[pending_root]);
}

#[test]
fn process_block_header_fills_empty_slots_with_zero_hashes() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x03u8; 52]),
        proposal_pubkey: Bytes52::from([0x03u8; 52]),
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
    assert_eq!(state.historical_block_hashes.len(), 4);
    assert_eq!(state.historical_block_hashes.get(0), Some(&parent_root));
    assert_eq!(state.historical_block_hashes.get(1), Some(&Bytes32::zero()));
    assert_eq!(state.historical_block_hashes.get(2), Some(&Bytes32::zero()));
    assert_eq!(state.historical_block_hashes.get(3), Some(&Bytes32::zero()));
}

#[test]
fn historical_block_hashes_count_matches_expected() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x04u8; 52]),
        proposal_pubkey: Bytes52::from([0x04u8; 52]),
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
    assert_eq!(state.historical_block_hashes.len(), 3);
}

#[test]
fn process_block_delegates_to_header() {
    let v = Validator {
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
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
        attestation_pubkey: Bytes52::from([0x01u8; 52]),
        proposal_pubkey: Bytes52::from([0x01u8; 52]),
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

    apply_state_transition_for_test(&mut state, &block).expect("transition");
    assert_eq!(state.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(1)));
}

#[test]
#[ignore = "expensive pq verifier path; run explicitly when exercising malformed aggregate proof handling"]
fn pq_verifier_rejects_placeholder_aggregate_proof_for_block_attestation() {
    let (pubkey, secret_key) =
        pq::key_gen_for_devnet_validator_with_role(0, pq::DevnetValidatorKeyRole::Attestation)
            .expect("keygen");
    let validator = Validator {
        attestation_pubkey: pubkey,
        proposal_pubkey: pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![validator]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let checkpoint = Checkpoint {
        root: Bytes32::zero(),
        slot: Slot(Uint64(0)),
    };
    let proposer_data = AttestationData {
        slot: Slot(Uint64(1)),
        head: checkpoint,
        target: checkpoint,
        source: checkpoint,
    };
    let proposer_signature = pq::sign_message(&secret_key, 1, &proposer_data.hash_tree_root())
        .expect("proposer signature");

    let body_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("bits"),
        data: proposer_data.clone(),
    };
    let block = Block {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body: BlockBody {
            attestations: Attestations::new(vec![body_attestation]).expect("attestations"),
        },
    };
    let signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation {
                aggregation_bits: BitList::new(vec![true]).expect("proposer bits"),
                data: proposer_data,
            },
        },
        signature: BlockSignatures {
            attestation_signatures: AttestationSignatures::new(vec![AggregatedSignatureProof {
                participants: BitList::new(vec![true]).expect("participants"),
                proof_data: ByteList::new(Vec::new()).expect("proof bytes"),
            }])
            .expect("attestation signatures"),
            proposer_signature,
        },
    };

    let verifier = PqSignatureVerifier;
    assert!(verifier.verify_signed_block(&signed, &state).is_err());
}
