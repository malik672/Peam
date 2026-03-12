use peam::slot::{
    SLOT_DURATION_MILLIS, SLOT_DURATION_SECS, Slot, is_justifiable_after, justified_index_after,
    next_slot_boundary_delay, slot_index_from_unix_millis, slot_index_from_unix_secs,
};
use peam::types::uint::Uint64;

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

#[test]
fn slot_duration_is_pinned_to_4_seconds() {
    assert_eq!(SLOT_DURATION_SECS, 4);
}

#[test]
fn slot_index_from_unix_secs_uses_4_second_windows() {
    let genesis = 1_000u64;
    assert_eq!(slot_index_from_unix_secs(genesis, 1_000), 0);
    assert_eq!(slot_index_from_unix_secs(genesis, 1_003), 0);
    assert_eq!(slot_index_from_unix_secs(genesis, 1_004), 1);
    assert_eq!(slot_index_from_unix_secs(genesis, 1_012), 3);
}

#[test]
fn slot_index_from_unix_millis_has_exact_4s_boundaries() {
    let genesis = 1_000u64;
    assert_eq!(SLOT_DURATION_MILLIS, 4_000);
    assert_eq!(slot_index_from_unix_millis(genesis, 1_000_000), 0);
    assert_eq!(slot_index_from_unix_millis(genesis, 1_003_999), 0);
    assert_eq!(slot_index_from_unix_millis(genesis, 1_004_000), 1);
    assert_eq!(slot_index_from_unix_millis(genesis, 1_011_999), 2);
    assert_eq!(slot_index_from_unix_millis(genesis, 1_012_000), 3);
}

#[test]
fn next_slot_boundary_delay_aligns_to_exact_slot_edge() {
    let genesis = 1_000u64;
    let delay = next_slot_boundary_delay(genesis, 1_003_250);
    assert_eq!(delay.as_millis(), 750);
}
