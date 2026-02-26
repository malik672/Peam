use lean_eth::ssz::hash::{BYTES_PER_CHUNK, chunkify_fixed, merkleize_with_limit, mix_in_length};
use lean_eth::ssz::{HashTreeRoot, SszEncode};
use lean_eth::types::bitlist::{BitList, BitVector};
use lean_eth::types::bytes::Bytes32;

#[test]
fn bitlist_encode_decode_roundtrip() {
    let list = BitList::<16>::new(vec![true, false, true, true, false]).expect("list");
    let encoded = list.encode_ssz();
    let decoded = BitList::<16>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, list);
}

#[test]
fn bitlist_hash_tree_root_empty() {
    let list = BitList::<16>::new(vec![]).expect("list");
    let root = list.hash_tree_root();
    assert_ne!(root, Bytes32::zero().as_array());
}

#[test]
fn bitvector_encode_decode_roundtrip() {
    let vec = BitVector::<8>::new(vec![true, false, true, false, true, false, true, false])
        .expect("vector");
    let encoded = vec.encode_ssz();
    let decoded = BitVector::<8>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, vec);
}

#[test]
fn bitlist_hash_tree_root_matches_manual_packed_bits() {
    let list = BitList::<16>::new(vec![true, false, true, true, false]).expect("list");
    let packed = list.data.clone();
    let chunks = chunkify_fixed(&packed);
    let limit_chunks = 16_usize.div_ceil(BYTES_PER_CHUNK * 8);
    let root = merkleize_with_limit(&chunks, limit_chunks).expect("merkleize");
    let expected = mix_in_length(&root, list.len());

    assert_eq!(list.hash_tree_root(), expected.as_array());
}
