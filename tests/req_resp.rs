use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::req_resp::{
    BlocksByRangeRequest, BlocksByRangeResponse, BlocksByRootRequest, MAX_BLOCKS_PER_REQUEST,
    MAX_BLOCKS_PER_ROOT_REQUEST, Ping, Pong, Status,
};
use peam::containers::state::{State, Validators};
use peam::containers::validator::ValidatorIndex;
use peam::slot::Slot;
use peam::ssz::{HashTreeRoot, SszDecode, SszEncode};
use peam::types::bytes::Bytes32;
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

fn compute_state_root_for_block(state: &State, block: &Block) -> Bytes32 {
    let mut temp = state.clone();
    if block.slot > temp.slot {
        temp.process_slots(block.slot).expect("process slots");
    }
    let header = block.header();
    temp.process_block_header(header).expect("process header");
    temp.process_block_body(&block.body, header.body_root)
        .expect("process body");
    Bytes32::from(temp.hash_tree_root())
}

fn dummy_signed_block() -> SignedBlockWithAttestation {
    let v = peam::containers::validator::Validator {
        attestation_pubkey: peam::types::bytes::Bytes52::from([0x01u8; 52]),
        proposal_pubkey: peam::types::bytes::Bytes52::from([0x01u8; 52]),
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let state = State::generate_genesis(Uint64(0), Validators::new(vec![v]).unwrap());
    signed_block_for_state(&state, 1)
}

fn signed_block_for_state(state: &State, slot: u64) -> SignedBlockWithAttestation {
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
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
    block.state_root = compute_state_root_for_block(state, &block);
    let proposer_attestation = {
        let data = peam::containers::attestation::AttestationData {
            slot: block.slot,
            head: peam::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: peam::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            source: peam::containers::checkpoint::Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        };
        peam::containers::attestation::Attestation {
            aggregation_bits: peam::types::bitlist::BitList::new(vec![true]).expect("bits"),
            data,
        }
    };
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let attestation_signatures = SszList::new(vec![]).expect("attestation sigs");
    let signature = BlockSignatures {
        attestation_signatures,
        proposer_signature: peam::types::bytes::Bytes3112::zero(),
    };
    SignedBlockWithAttestation { message, signature }
}

#[test]
fn status_roundtrip() {
    let status = Status {
        finalized_root: Bytes32::from([2u8; 32]),
        finalized_slot: Uint64(3),
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
    let ping = Ping {
        seq_number: Uint64(7),
    };
    let pong = Pong {
        seq_number: Uint64(7),
    };
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

    let blocks = SszList::<SignedBlockWithAttestation, MAX_BLOCKS_PER_REQUEST>::new(vec![
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
    let roots =
        SszList::<Bytes32, MAX_BLOCKS_PER_ROOT_REQUEST>::new(vec![Bytes32::zero()]).expect("roots");
    let req = BlocksByRootRequest { roots };
    let encoded = req.encode_ssz();
    let decoded = BlocksByRootRequest::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, req);
}
