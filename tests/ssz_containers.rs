use lean_eth::containers::attestation::{Attestation, AttestationData};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::hash::hash_nodes;
use lean_eth::ssz::{HashTreeRoot, SszEncode};
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::{Bytes32, Bytes52};
use lean_eth::types::uint::Uint64;

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
    let mut pubkey_bytes = [0u8; 52];
    for (i, b) in pubkey_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let pubkey = Bytes52::from(pubkey_bytes);
    let index = ValidatorIndex(Uint64(5));
    let balance = Uint64(0);
    let validator = Validator {
        pubkey,
        index,
        balance,
    };

    let encoded = validator.encode_ssz();
    let mut expected = Vec::new();
    expected.extend_from_slice(pubkey.as_ref());
    expected.extend_from_slice(&5u64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), 68);

    let decoded = Validator::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, validator);
}

#[test]
fn validator_hash_tree_root_matches_manual_chunks() {
    let pubkey = Bytes52::from([0x22u8; 52]);
    let index = ValidatorIndex(Uint64(12));
    let balance = Uint64(0);
    let validator = Validator {
        pubkey,
        index,
        balance,
    };

    let pk = pubkey.as_array();
    let chunk0 = Bytes32::from_slice(&pk[0..32]);
    let chunk1 = chunk_from_bytes(&pk[32..52]);
    let pubkey_root = hash_nodes(&chunk0, &chunk1);

    let index_chunk = chunk_from_bytes(&12u64.to_le_bytes());
    let balance_chunk = chunk_from_bytes(&0u64.to_le_bytes());
    let expected = {
        let roots = [pubkey_root, index_chunk, balance_chunk];
        lean_eth::ssz::hash::merkleize_unsafe(&roots)
    };

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
