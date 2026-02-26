use lean_eth::ssz::hash::{merkleize_with_limit, mix_in_length};
use lean_eth::ssz::{HashTreeRoot, SszEncode};
use lean_eth::types::bitlist::BitList;
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::{SszList, SszVector};
use lean_eth::types::uint::Uint64;

fn chunk_from_u64s(values: &[u64]) -> Bytes32 {
    let mut chunk = [0u8; 32];
    for (i, v) in values.iter().enumerate() {
        let start = i * 8;
        chunk[start..start + 8].copy_from_slice(&v.to_le_bytes());
    }
    Bytes32::from(chunk)
}

#[test]
fn ssz_vector_uint64_roundtrip_and_root() {
    let vec = SszVector::<Uint64, 2>::new(vec![Uint64(1), Uint64(2)]).expect("vector");
    let encoded = vec.encode_ssz();
    assert_eq!(encoded.len(), 16);

    let decoded = SszVector::<Uint64, 2>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, vec);

    let expected = chunk_from_u64s(&[1, 2]);
    assert_eq!(vec.hash_tree_root(), expected.as_array());
}

#[test]
fn ssz_list_uint64_roundtrip_and_root() {
    let list = SszList::<Uint64, 4>::new(vec![Uint64(3), Uint64(4)]).expect("list");
    let encoded = list.encode_ssz();
    assert_eq!(encoded.len(), 16);

    let decoded = SszList::<Uint64, 4>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, list);

    let packed = chunk_from_u64s(&[3, 4]);
    let mixed = mix_in_length(&packed, 2);
    assert_eq!(list.hash_tree_root(), mixed.as_array());
}

#[test]
fn ssz_list_variable_offsets_roundtrip_and_root() {
    let a = BitList::<8>::new(vec![true, false, true]).expect("bitlist a");
    let b = BitList::<8>::new(vec![true, true, false, true, true]).expect("bitlist b");
    let list = SszList::<BitList<8>, 4>::new(vec![a.clone(), b.clone()]).expect("list");

    let encoded = list.encode_ssz();
    let a_enc = a.encode_ssz();
    let b_enc = b.encode_ssz();
    let first_off = 8u32;
    let second_off = first_off + a_enc.len() as u32;
    let mut expected = Vec::with_capacity(8 + a_enc.len() + b_enc.len());
    expected.extend_from_slice(&first_off.to_le_bytes());
    expected.extend_from_slice(&second_off.to_le_bytes());
    expected.extend_from_slice(&a_enc);
    expected.extend_from_slice(&b_enc);
    assert_eq!(encoded, expected);

    let decoded = SszList::<BitList<8>, 4>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, list);

    let chunks = vec![
        Bytes32::from(a.hash_tree_root()),
        Bytes32::from(b.hash_tree_root()),
    ];
    let root = merkleize_with_limit(&chunks, 4).expect("merkleize");
    let mixed = mix_in_length(&root, 2);
    assert_eq!(list.hash_tree_root(), mixed.as_array());
}

#[test]
fn ssz_vector_variable_offsets_roundtrip_and_root() {
    let a = BitList::<8>::new(vec![true, false, true]).expect("bitlist a");
    let b = BitList::<8>::new(vec![true, true, false, true, true]).expect("bitlist b");
    let vec = SszVector::<BitList<8>, 2>::new(vec![a.clone(), b.clone()]).expect("vector");

    let encoded = vec.encode_ssz();
    let a_enc = a.encode_ssz();
    let b_enc = b.encode_ssz();
    let first_off = 8u32;
    let second_off = first_off + a_enc.len() as u32;
    let mut expected = Vec::with_capacity(8 + a_enc.len() + b_enc.len());
    expected.extend_from_slice(&first_off.to_le_bytes());
    expected.extend_from_slice(&second_off.to_le_bytes());
    expected.extend_from_slice(&a_enc);
    expected.extend_from_slice(&b_enc);
    assert_eq!(encoded, expected);

    let decoded = SszVector::<BitList<8>, 2>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, vec);

    let chunks = vec![
        Bytes32::from(a.hash_tree_root()),
        Bytes32::from(b.hash_tree_root()),
    ];
    let root = merkleize_with_limit(&chunks, 2).expect("merkleize");
    assert_eq!(vec.hash_tree_root(), root.as_array());
}

#[test]
fn ssz_list_variable_offsets_empty_and_uneven() {
    let empty = SszList::<BitList<8>, 4>::new(vec![]).expect("list");
    let encoded = empty.encode_ssz();
    assert_eq!(encoded.len(), 0);
    let decoded = SszList::<BitList<8>, 4>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, empty);

    let a = BitList::<8>::new(vec![]).expect("bitlist a");
    let b = BitList::<8>::new(vec![true, false, true, true, false, true]).expect("bitlist b");
    let c = BitList::<8>::new(vec![true]).expect("bitlist c");
    let list = SszList::<BitList<8>, 4>::new(vec![a.clone(), b.clone(), c.clone()]).expect("list");

    let encoded = list.encode_ssz();
    let a_enc = a.encode_ssz();
    let b_enc = b.encode_ssz();
    let c_enc = c.encode_ssz();
    let first_off = 12u32;
    let second_off = first_off + a_enc.len() as u32;
    let third_off = second_off + b_enc.len() as u32;
    let mut expected = Vec::with_capacity(12 + a_enc.len() + b_enc.len() + c_enc.len());
    expected.extend_from_slice(&first_off.to_le_bytes());
    expected.extend_from_slice(&second_off.to_le_bytes());
    expected.extend_from_slice(&third_off.to_le_bytes());
    expected.extend_from_slice(&a_enc);
    expected.extend_from_slice(&b_enc);
    expected.extend_from_slice(&c_enc);
    assert_eq!(encoded, expected);

    let decoded = SszList::<BitList<8>, 4>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, list);
}

#[test]
fn ssz_list_variable_offsets_single_element() {
    let a = BitList::<8>::new(vec![true, false, true, true]).expect("bitlist a");
    let list = SszList::<BitList<8>, 4>::new(vec![a.clone()]).expect("list");

    let encoded = list.encode_ssz();
    let a_enc = a.encode_ssz();
    let first_off = 4u32;
    let mut expected = Vec::with_capacity(4 + a_enc.len());
    expected.extend_from_slice(&first_off.to_le_bytes());
    expected.extend_from_slice(&a_enc);
    assert_eq!(encoded, expected);

    let decoded = SszList::<BitList<8>, 4>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, list);
}

#[test]
fn ssz_vector_variable_offsets_with_empty_element() {
    let a = BitList::<8>::new(vec![]).expect("bitlist a");
    let b = BitList::<8>::new(vec![true, false, true]).expect("bitlist b");
    let vec = SszVector::<BitList<8>, 2>::new(vec![a.clone(), b.clone()]).expect("vector");

    let encoded = vec.encode_ssz();
    let a_enc = a.encode_ssz();
    let b_enc = b.encode_ssz();
    let first_off = 8u32;
    let second_off = first_off + a_enc.len() as u32;
    let mut expected = Vec::with_capacity(8 + a_enc.len() + b_enc.len());
    expected.extend_from_slice(&first_off.to_le_bytes());
    expected.extend_from_slice(&second_off.to_le_bytes());
    expected.extend_from_slice(&a_enc);
    expected.extend_from_slice(&b_enc);
    assert_eq!(encoded, expected);

    let decoded = SszVector::<BitList<8>, 2>::decode_ssz_checked(&encoded).expect("decode");
    assert_eq!(decoded, vec);
}
