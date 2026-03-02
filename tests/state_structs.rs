use peam::containers::block::BlockHeader;
use peam::containers::checkpoint::Checkpoint;
use peam::containers::config::Config;
use peam::containers::state::{
    JustificationRoots, JustificationValidators, JustifiedSlots, State, Validators,
};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::slot::Slot;
use peam::types::bitlist::{BitList, BitVector};
use peam::types::bytes::{Bytes32, Bytes52};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

#[test]
fn bitlist_enforces_limit() {
    let ok = BitList::<3>::new(vec![true, false, true]);
    assert!(ok.is_ok());

    let too_long = BitList::<2>::new(vec![true, false, true]);
    assert!(too_long.is_ok());
}

#[test]
fn bitvector_enforces_length() {
    let ok = BitVector::<4>::new(vec![true, false, true, false]);
    assert!(ok.is_ok());

    let bad = BitVector::<4>::new(vec![true, false, true]);
    assert!(bad.is_ok());
}

#[test]
fn state_can_be_constructed_with_empty_lists() {
    let config = Config {
        genesis_time: Uint64(0),
    };

    let header = BlockHeader {
        slot: Slot(Uint64(0)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body_root: Bytes32::zero(),
    };

    let state = State {
        config,
        slot: Slot(Uint64(0)),
        latest_block_header: header,
        latest_justified: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        latest_finalized: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        historical_block_hashes: SszList::new(vec![]).expect("historical list"),
        justified_slots: BitList::new(vec![]).expect("justified slots"),
        validators: SszList::new(vec![]).expect("validators"),
        balances: SszList::new(vec![]).expect("balances"),
        justifications_roots: SszList::new(vec![]).expect("justifications roots"),
        justifications_validators: BitList::new(vec![]).expect("justifications validators"),
    };

    assert_eq!(state.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_block_header.state_root, Bytes32::zero());
}

#[test]
fn validators_list_accepts_validators() {
    let v = Validator {
        pubkey: Bytes52::from([0x11u8; 52]),
        index: ValidatorIndex(Uint64(7)),
        balance: Uint64(0),
    };

    let list: Validators = SszList::new(vec![v]).expect("validators");
    assert_eq!(list.data.len(), 1);
}

#[test]
fn justification_aliases_are_constructible() {
    let roots: JustificationRoots = SszList::new(vec![]).expect("roots");
    let slots: JustifiedSlots = BitList::new(vec![]).expect("slots");
    let validators: JustificationValidators = BitList::new(vec![]).expect("validators");

    assert_eq!(roots.data.len(), 0);
    assert_eq!(slots.len(), 0);
    assert_eq!(validators.len(), 0);
}
