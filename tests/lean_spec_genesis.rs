use lean_eth::containers::block::{Attestations, BlockBody};
use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::HashTreeRoot;
use lean_eth::types::bytes::{Bytes32, Bytes52};
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

fn make_validators(n: usize) -> Validators {
    let mut vals: Vec<Validator> = Vec::with_capacity(n);
    unsafe { vals.set_len(n) };
    for i in 0..n {
        let v = Validator {
            pubkey: Bytes52::from([0u8; 52]),
            index: ValidatorIndex(Uint64(i as u64)),
            balance: Uint64(0),
        };
        unsafe {
            let slot = vals.as_mut_ptr().add(i);
            core::ptr::write(slot, v);
        }
    }
    SszList::new(vals).expect("validators")
}

fn empty_body_root() -> Bytes32 {
    let body = BlockBody {
        attestations: Attestations::new(vec![]).expect("attestations"),
    };
    Bytes32::from(body.hash_tree_root())
}

#[test]
fn genesis_default_configuration() {
    let validators = make_validators(4);
    let state = State::generate_genesis(Uint64(0), validators);

    assert_eq!(state.slot, Slot(Uint64(0)));
    assert_eq!(state.config.genesis_time, Uint64(0));
    assert_eq!(state.validators.data.len(), 4);
    assert_eq!(state.balances.data.len(), 4);
    assert_eq!(state.latest_justified.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_justified.root, Bytes32::zero());
    assert_eq!(state.latest_finalized.slot, Slot(Uint64(0)));
    assert_eq!(state.latest_finalized.root, Bytes32::zero());
    assert_eq!(state.latest_block_header.slot, Slot(Uint64(0)));
    assert_eq!(
        state.latest_block_header.proposer_index,
        ValidatorIndex(Uint64(0))
    );
    assert_eq!(state.latest_block_header.parent_root, Bytes32::zero());
    assert_eq!(state.latest_block_header.state_root, Bytes32::zero());
    assert_eq!(state.latest_block_header.body_root, empty_body_root());
    assert_eq!(state.historical_block_hashes.data.len(), 0);
    assert_eq!(state.justified_slots.len(), 0);
    assert_eq!(state.justifications_roots.data.len(), 0);
    assert_eq!(state.justifications_validators.len(), 0);
}

#[test]
fn genesis_custom_time() {
    let validators = make_validators(4);
    let state = State::generate_genesis(Uint64(1_234_567_890), validators);

    assert_eq!(state.config.genesis_time, Uint64(1_234_567_890));
    assert_eq!(state.latest_block_header.body_root, empty_body_root());
}

#[test]
fn genesis_custom_validator_set() {
    let validators = make_validators(8);
    let state = State::generate_genesis(Uint64(0), validators);

    assert_eq!(state.validators.data.len(), 8);
    assert_eq!(state.balances.data.len(), 8);
}
