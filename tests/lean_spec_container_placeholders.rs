//! leanSpec parity placeholders and incremental ports.

use lean_eth::containers::attestation::{AggregatedSignatureProof, Attestation, AttestationData};
use lean_eth::containers::block::{
    Attestations, Block, BlockBody, BlockHeader, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::{ByteList, Bytes32, Bytes52, Bytes3112};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

fn aggregate_by_data(
    attestations: &[lean_eth::containers::attestation::SignedAttestation],
) -> Vec<Attestation> {
    let mut groups: Vec<(AttestationData, Vec<usize>)> = Vec::new();
    for att in attestations {
        if let Some((_, participants)) = groups.iter_mut().find(|(data, _)| *data == att.message) {
            participants.push(att.validator_id.0 as usize);
        } else {
            groups.push((att.message.clone(), vec![att.validator_id.0 as usize]));
        }
    }

    let mut aggregated = Vec::new();
    for (data, participants) in groups.into_iter() {
        let max_idx = participants.iter().copied().max().unwrap_or(0);
        let mut bits = vec![false; max_idx + 1];
        for idx in participants {
            bits[idx] = true;
        }
        aggregated.push(Attestation {
            aggregation_bits: BitList::new(bits).expect("aggregation bits"),
            data,
        });
    }
    aggregated
}

fn build_block_for_slot(
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
fn lean_spec_attestation_aggregation() {
    use lean_eth::containers::attestation::SignedAttestation;

    let data_a = AttestationData {
        slot: Slot(Uint64(5)),
        head: Checkpoint {
            root: Bytes32::from([0x11u8; 32]),
            slot: Slot(Uint64(4)),
        },
        target: Checkpoint {
            root: Bytes32::from([0x12u8; 32]),
            slot: Slot(Uint64(3)),
        },
        source: Checkpoint {
            root: Bytes32::from([0x13u8; 32]),
            slot: Slot(Uint64(2)),
        },
    };
    let data_b = AttestationData {
        slot: Slot(Uint64(6)),
        head: Checkpoint {
            root: Bytes32::from([0x21u8; 32]),
            slot: Slot(Uint64(5)),
        },
        target: Checkpoint {
            root: Bytes32::from([0x22u8; 32]),
            slot: Slot(Uint64(4)),
        },
        source: Checkpoint {
            root: Bytes32::from([0x23u8; 32]),
            slot: Slot(Uint64(3)),
        },
    };

    let attestations = vec![
        SignedAttestation {
            validator_id: Uint64(1),
            message: data_a.clone(),
            signature: Bytes3112::zero(),
        },
        SignedAttestation {
            validator_id: Uint64(3),
            message: data_a.clone(),
            signature: Bytes3112::zero(),
        },
        SignedAttestation {
            validator_id: Uint64(5),
            message: data_b.clone(),
            signature: Bytes3112::zero(),
        },
    ];
    let aggregated = aggregate_by_data(&attestations);

    assert_eq!(aggregated.len(), 2);
    let a = aggregated
        .iter()
        .find(|att| att.data == data_a)
        .expect("group a");
    let b = aggregated
        .iter()
        .find(|att| att.data == data_b)
        .expect("group b");
    assert_eq!(a.aggregation_bits.len(), 4);
    assert_eq!(b.aggregation_bits.len(), 6);
    assert!(a.aggregation_bits.data[0] & (1u8 << 1) != 0);
    assert!(a.aggregation_bits.data[0] & (1u8 << 3) != 0);
    assert!(b.aggregation_bits.data[0] & (1u8 << 5) != 0);
}

#[test]
fn lean_spec_state_aggregation() {
    let validators: Validators = SszList::new(vec![
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
    let mut state = State::generate_genesis(Uint64(0), validators);

    let att = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from([0x31u8; 32]),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };

    let block = build_block_for_slot(&state, 1, 1, vec![att.clone()]);
    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![false, true, false]).expect("bits"),
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

    let mismatched_proof = AggregatedSignatureProof {
        participants: BitList::new(vec![true, false, false]).expect("participants"),
        proof_data: ByteList::new(vec![0xAA]).expect("proof"),
    };
    let signed_bad = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block.clone(),
            proposer_attestation: proposer_attestation.clone(),
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![mismatched_proof]).expect("sigs"),
            proposer_signature: Bytes3112::zero(),
        },
    };
    let err = state.process_signed_block(&signed_bad).unwrap_err();
    assert!(err.contains("participants do not match aggregation bits"));

    let good_proof = AggregatedSignatureProof {
        participants: att.aggregation_bits.clone(),
        proof_data: ByteList::new(vec![0xBB]).expect("proof"),
    };
    let signed_good = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![good_proof]).expect("sigs"),
            proposer_signature: Bytes3112::zero(),
        },
    };
    state
        .process_signed_block(&signed_good)
        .expect("process block");
    assert_eq!(state.latest_justified.slot, Slot(Uint64(1)));
}

#[test]
fn lean_spec_state_justified_slots() {
    let validators: Validators = SszList::new(vec![
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
    let mut state = State::generate_genesis(Uint64(0), validators);

    state.process_slots(Slot(Uint64(1))).expect("process slots");
    let parent_root_1 = Bytes32::from(state.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    let header_1 = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(1)),
        parent_root: parent_root_1,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state
        .process_block_header(header_1)
        .expect("process header");
    let att_1 = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from([0xA1u8; 32]),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    state
        .process_attestations(&Attestations::new(vec![att_1]).expect("attestations"))
        .expect("process attestations");
    assert_eq!(state.latest_justified.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));
    assert_eq!(state.justified_slots.len(), 1);

    state.process_slots(Slot(Uint64(2))).expect("process slots");
    let parent_root_2 = Bytes32::from(state.latest_block_header.hash_tree_root());
    let header_2 = BlockHeader {
        slot: Slot(Uint64(2)),
        proposer_index: ValidatorIndex(Uint64(2)),
        parent_root: parent_root_2,
        state_root: Bytes32::zero(),
        body_root: Bytes32::from(body.hash_tree_root()),
    };
    state
        .process_block_header(header_2)
        .expect("process header");
    let att_2 = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(2)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(2)),
            },
            target: Checkpoint {
                root: Bytes32::from([0xA2u8; 32]),
                slot: Slot(Uint64(2)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    state
        .process_attestations(&Attestations::new(vec![att_2]).expect("attestations"))
        .expect("process attestations");

    // Finalization advanced to slot 1, so justified window rebased by 1 slot.
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(1)));
    assert_eq!(state.latest_justified.slot, Slot(Uint64(2)));
    assert_eq!(state.justified_slots.len(), 1);
}

#[test]
fn lean_spec_state_process_attestations() {
    let validators: Validators = SszList::new(vec![
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

    let attestation = Attestation {
        aggregation_bits: BitList::new(vec![true, true, false]).expect("aggregation bits"),
        data: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root: Bytes32::from([0xAAu8; 32]),
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: state.latest_justified.root,
                slot: state.latest_justified.slot,
            },
        },
    };
    let attestations = Attestations::new(vec![attestation]).expect("attestations");
    state
        .process_attestations(&attestations)
        .expect("process attestations");

    assert_eq!(state.latest_justified.slot, Slot(Uint64(1)));
    assert!(state.justified_slots.len() >= 1);
}
