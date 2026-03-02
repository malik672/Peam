use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    AttestationSignatures, Block, BlockBody, BlockSignatures, BlockWithAttestation,
    BlockWithSignatures, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::validator::ValidatorIndex;
use peam::slot::Slot;
use peam::ssz::{SszDecode, SszEncode};
use peam::types::bytes::{Bytes32, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

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

fn dummy_proposer_attestation(slot: Slot) -> Attestation {
    Attestation {
        aggregation_bits: peam::types::bitlist::BitList::new(vec![true]).expect("bits"),
        data: AttestationData {
            slot,
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
    }
}

#[test]
fn block_with_attestation_roundtrip_checked() {
    let block = dummy_block();
    let proposer_attestation = dummy_proposer_attestation(block.slot);
    let msg = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let encoded = msg.encode_ssz();
    let decoded = BlockWithAttestation::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, msg);
    let checked = BlockWithAttestation::decode_ssz_checked(&encoded).unwrap();
    assert_eq!(checked, msg);
}

#[test]
fn signed_block_with_attestation_roundtrip_checked() {
    let message = BlockWithAttestation {
        block: dummy_block(),
        proposer_attestation: dummy_proposer_attestation(Slot(Uint64(0))),
    };
    let signature = BlockSignatures {
        attestation_signatures: SszList::new(vec![]).expect("attestation sigs"),
        proposer_signature: Bytes3112::zero(),
    };
    let signed = SignedBlockWithAttestation { message, signature };
    let encoded = signed.encode_ssz();
    let decoded = SignedBlockWithAttestation::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, signed);
    let checked = SignedBlockWithAttestation::decode_ssz_checked(&encoded).unwrap();
    assert_eq!(checked, signed);
}

#[test]
fn block_with_signatures_roundtrip_checked() {
    let block = dummy_block();
    let signatures: AttestationSignatures = SszList::new(vec![]).expect("signatures");
    let msg = BlockWithSignatures { block, signatures };
    let encoded = msg.encode_ssz();
    let decoded = BlockWithSignatures::decode_ssz(&encoded).unwrap();
    assert_eq!(decoded, msg);
    let checked = BlockWithSignatures::decode_ssz_checked(&encoded).unwrap();
    assert_eq!(checked, msg);
}
