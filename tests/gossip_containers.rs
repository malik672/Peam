use lean_eth::containers::attestation::{AttestationData, SignedAttestation};
use lean_eth::containers::block::{
    Block, BlockBody, BlockHeader, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use lean_eth::containers::gossip::{GossipAttestation, GossipBlock, GossipBlockHeader, VoluntaryExit};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::slot::Slot;
use lean_eth::ssz::{HashTreeRoot, SszDecode, SszEncode};
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
    let proposer_attestation = SszList::new(vec![]).expect("proposer attestations");
    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let signature = BlockSignatures {
        attestation_signatures: SszList::new(vec![]).expect("attestation sigs"),
        proposer_signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    SignedBlockWithAttestation { message, signature }
}

#[test]
fn gossip_block_roundtrip() {
    let msg = GossipBlock {
        block: dummy_signed_block(),
    };
    let encoded = msg.encode_ssz();
    let decoded = GossipBlock::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn gossip_block_header_roundtrip() {
    let header = BlockHeader {
        slot: Slot(Uint64(1)),
        proposer_index: ValidatorIndex(Uint64(2)),
        parent_root: Bytes32::from([3u8; 32]),
        state_root: Bytes32::from([4u8; 32]),
        body_root: Bytes32::from([5u8; 32]),
    };
    let msg = GossipBlockHeader { header };
    let encoded = msg.encode_ssz();
    let decoded = GossipBlockHeader::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn gossip_attestation_roundtrip() {
    let data = AttestationData {
        slot: Slot(Uint64(0)),
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
    };
    let attestation = SignedAttestation {
        validator_id: Uint64(1),
        message: data,
        signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    let msg = GossipAttestation { attestation };
    let encoded = msg.encode_ssz();
    let decoded = GossipAttestation::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn voluntary_exit_roundtrip() {
    let exit = VoluntaryExit {
        validator_index: ValidatorIndex(Uint64(10)),
        epoch: Uint64(3),
    };
    let encoded = exit.encode_ssz();
    let decoded = VoluntaryExit::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, exit);
    let _ = exit.hash_tree_root();
}
