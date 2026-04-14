use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::slot::Slot;
use peam::ssz::hash::hash_nodes;
use peam::ssz::{HashTreeRoot, SszEncode};
use peam::types::bitlist::BitList;
use peam::types::bytes::{Bytes32, Bytes52};
use peam::types::uint::Uint64;

fn chunk_from_bytes(data: &[u8]) -> Bytes32 {
    let mut chunk = [0u8; 32];
    let len = data.len().min(32);
    chunk[..len].copy_from_slice(&data[..len]);
    Bytes32::from(chunk)
}

#[test]
fn checkpoint_encode_decode_roundtrip() {
    let mut root_bytes = [0u8; 32];
    for (i, b) in root_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let root = Bytes32::from(root_bytes);
    let slot = Slot(Uint64(42));
    let checkpoint = Checkpoint { root, slot };

    let encoded = checkpoint.encode_ssz();
    let mut expected = Vec::new();
    expected.extend_from_slice(root.as_ref());
    expected.extend_from_slice(&42u64.to_le_bytes());
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), 40);

    let decoded = Checkpoint::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, checkpoint);
}

#[test]
fn checkpoint_hash_tree_root_matches_manual_chunks() {
    let root = Bytes32::from([0x11u8; 32]);
    let slot = Slot(Uint64(7));
    let checkpoint = Checkpoint { root, slot };

    let slot_chunk = chunk_from_bytes(&7u64.to_le_bytes());
    let expected = hash_nodes(&root, &slot_chunk);

    assert_eq!(checkpoint.hash_tree_root(), expected.as_array());
}

#[test]
fn validator_encode_decode_roundtrip() {
    let mut attestation_pubkey_bytes = [0u8; 52];
    for (i, b) in attestation_pubkey_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let attestation_pubkey = Bytes52::from(attestation_pubkey_bytes);
    let proposal_pubkey = Bytes52::from([0xABu8; 52]);
    let index = ValidatorIndex(Uint64(5));
    let balance = Uint64(0);
    let validator = Validator {
        attestation_pubkey,
        proposal_pubkey,
        index,
        balance,
    };

    let encoded = validator.encode_ssz();
    let mut expected = Vec::new();
    expected.extend_from_slice(attestation_pubkey.as_ref());
    expected.extend_from_slice(proposal_pubkey.as_ref());
    expected.extend_from_slice(&5u64.to_le_bytes());
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), 112);

    let decoded = Validator::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, validator);
}

#[test]
fn validator_hash_tree_root_matches_manual_chunks() {
    let attestation_pubkey = Bytes52::from([0x22u8; 52]);
    let proposal_pubkey = Bytes52::from([0x33u8; 52]);
    let index = ValidatorIndex(Uint64(12));
    let balance = Uint64(0);
    let validator = Validator {
        attestation_pubkey,
        proposal_pubkey,
        index,
        balance,
    };

    let att = attestation_pubkey.as_array();
    let att_chunk0 = Bytes32::from_slice(&att[0..32]);
    let att_chunk1 = chunk_from_bytes(&att[32..52]);
    let attestation_pubkey_root = hash_nodes(&att_chunk0, &att_chunk1);

    let prop = proposal_pubkey.as_array();
    let prop_chunk0 = Bytes32::from_slice(&prop[0..32]);
    let prop_chunk1 = chunk_from_bytes(&prop[32..52]);
    let proposal_pubkey_root = hash_nodes(&prop_chunk0, &prop_chunk1);

    let pubkeys_root = hash_nodes(&attestation_pubkey_root, &proposal_pubkey_root);

    let index_chunk = chunk_from_bytes(&12u64.to_le_bytes());
    let expected = hash_nodes(&pubkeys_root, &index_chunk);

    assert_eq!(validator.hash_tree_root(), expected.as_array());
}

#[test]
fn attestation_encode_decode_roundtrip() {
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
    let attestation = Attestation {
        aggregation_bits: BitList::new(vec![]).expect("bits"),
        data,
    };

    let encoded = attestation.encode_ssz();
    let decoded = Attestation::decode_ssz_checked(&encoded).expect("decode");

    assert_eq!(decoded, attestation);
}
