use lean_eth::slot::{Slot, is_justifiable_after, justified_index_after};
use lean_eth::types::uint::Uint64;

#[test]
fn justified_index_after_basic() {
    let finalized = Slot(Uint64(10));
    let candidate = Slot(Uint64(11));
    assert_eq!(justified_index_after(candidate, finalized), Some(0));
}

#[test]
fn is_justifiable_after_rules() {
    let finalized = Slot(Uint64(100));
    let candidate = Slot(Uint64(105));
    assert!(is_justifiable_after(candidate, finalized).unwrap());
}
