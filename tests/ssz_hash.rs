use peam::ssz::hash::{merkleize_tree_root, merkleize_unsafe};
use peam::types::bytes::Bytes32;

#[test]
fn merkleize_tree_root_matches_merkleize_unsafe_for_5_fields() {
    let field_roots = [
        Bytes32::from([0x01u8; 32]),
        Bytes32::from([0x02u8; 32]),
        Bytes32::from([0x03u8; 32]),
        Bytes32::from([0x04u8; 32]),
        Bytes32::from([0x05u8; 32]),
    ];
    let fast = merkleize_tree_root(&field_roots);
    let general = merkleize_unsafe(&field_roots);
    assert_eq!(fast.as_array(), general.as_array());
}
