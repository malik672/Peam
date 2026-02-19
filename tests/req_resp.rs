use lean_eth::containers::req_resp::{
    BlocksByRangeRequest, BlocksByRangeResponse, BlocksByRootRequest, BlocksByRootResponse, Ping,
    Pong, Status, MAX_BLOCKS_PER_REQUEST, MAX_BLOCKS_PER_ROOT_REQUEST,
};
use lean_eth::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::ssz::{HashTreeRoot, SszDecode, SszEncode};
use lean_eth::storage::{MemoryStore, Store};
use lean_eth::containers::state::{State, Validators};
use lean_eth::types::uint::Uint64 as U64;
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

fn dummy_signed_block() -> SignedBlockWithAttestation {
    let block = dummy_block();
    let proposer_attestation = {
        let data = lean_eth::containers::attestation::AttestationData {
            slot: block.slot,
            head: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            source: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        };
        let att = lean_eth::containers::attestation::Attestation {
            aggregation_bits: lean_eth::types::bitlist::BitList::new(vec![true])
                .expect("bits"),
            data,
        };
        SszList::new(vec![att]).expect("proposer attestations")
    };
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let attestation_signatures = SszList::new(vec![]).expect("attestation sigs");
    let signature = BlockSignatures {
        attestation_signatures,
        proposer_signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    SignedBlockWithAttestation { message, signature }
}

fn signed_block_for_state(state: &State, slot: u64) -> SignedBlockWithAttestation {
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot))).expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    let block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let proposer_attestation = {
        let data = lean_eth::containers::attestation::AttestationData {
            slot: block.slot,
            head: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            source: lean_eth::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        };
        let att = lean_eth::containers::attestation::Attestation {
            aggregation_bits: lean_eth::types::bitlist::BitList::new(vec![true])
                .expect("bits"),
            data,
        };
        SszList::new(vec![att]).expect("proposer attestations")
    };
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let attestation_signatures = SszList::new(vec![]).expect("attestation sigs");
    let signature = BlockSignatures {
        attestation_signatures,
        proposer_signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    SignedBlockWithAttestation { message, signature }
}

#[test]
fn blocks_by_root_processes_signed_blocks() {
    let v = lean_eth::containers::validator::Validator {
        pubkey: lean_eth::types::bytes::Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).unwrap();
    let mut state = State::generate_genesis(U64(0), validators);
    let signed = signed_block_for_state(&state, 1);
    let blocks = SszList::<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>::new(vec![signed])
        .expect("blocks");
    let resp = BlocksByRootResponse { blocks };
    let decoded = BlocksByRootResponse::decode_ssz(&resp.encode_ssz()).unwrap();

    let mut store = MemoryStore::new();
    for (idx, block) in decoded.blocks.data.iter().enumerate() {
        let root = Bytes32::from([idx as u8; 32]);
        store
            .put_signed_block(root, block.clone(), &mut state)
            .expect("process signed block");
    }

    assert_eq!(store.get_block_by_slot(1).is_some(), true);
}

#[test]
fn status_roundtrip() {
    let status = Status {
        fork_digest: Bytes32::from([1u8; 32]),
        finalized_root: Bytes32::from([2u8; 32]),
        finalized_epoch: Uint64(3),
        head_root: Bytes32::from([4u8; 32]),
        head_slot: Uint64(5),
    };
    let encoded = status.encode_ssz();
    let decoded = Status::decode_ssz(&encoded).expect("decode");
    assert_eq!(decoded, status);
    let _ = status.hash_tree_root();
}

#[test]
fn ping_pong_roundtrip() {
    let ping = Ping { seq_number: Uint64(7) };
    let pong = Pong { seq_number: Uint64(7) };
    assert_eq!(Ping::decode_ssz(&ping.encode_ssz()).unwrap(), ping);
    assert_eq!(Pong::decode_ssz(&pong.encode_ssz()).unwrap(), pong);
}

#[test]
fn blocks_by_range_roundtrip() {
    let req = BlocksByRangeRequest {
        start_slot: Uint64(10),
        count: Uint64(2),
        step: Uint64(1),
    };
    let encoded = req.encode_ssz();
    let decoded = BlocksByRangeRequest::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, req);

    let blocks =
        SszList::<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>::new(vec![
            dummy_signed_block(),
        ])
        .expect("blocks");
    let resp = BlocksByRangeResponse { blocks };
    let encoded = resp.encode_ssz();
    let decoded = BlocksByRangeResponse::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, resp);
}

#[test]
fn blocks_by_root_roundtrip() {
    let roots = SszList::<Bytes32, MAX_BLOCKS_PER_ROOT_REQUEST>::new(vec![Bytes32::zero()])
        .expect("roots");
    let req = BlocksByRootRequest { roots };
    let encoded = req.encode_ssz();
    let decoded = BlocksByRootRequest::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, req);

    let blocks =
        SszList::<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>::new(vec![
            dummy_signed_block(),
        ])
        .expect("blocks");
    let resp = BlocksByRootResponse { blocks };
    let encoded = resp.encode_ssz();
    let decoded = BlocksByRootResponse::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, resp);
}
