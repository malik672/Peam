use peam::checkpoint_sync::{
    build_anchor_block, build_anchor_signed_block, verify_checkpoint_state,
};
use peam::containers::attestation::VALIDATOR_REGISTRY_LIMIT;
use peam::containers::checkpoint::Checkpoint;
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::slot::Slot;
use peam::ssz::HashTreeRoot;
use peam::types::bytes::{Bytes32, Bytes52};
use peam::types::uint::Uint64;

fn make_validators(n: usize) -> Validators {
    let mut vals = Vec::with_capacity(n);
    for i in 0..n {
        vals.push(Validator {
            pubkey: Bytes52::from([i as u8; 52]),
            index: ValidatorIndex(Uint64(i as u64)),
            balance: Uint64(0),
        });
    }
    Validators::new(vals).expect("validators")
}

fn base_state(genesis_time: u64, validator_count: usize) -> State {
    let validators = make_validators(validator_count);
    let mut state = State::generate_genesis(Uint64(genesis_time), validators);
    let header_root = Bytes32::from(state.latest_block_header.hash_tree_root());
    state.latest_finalized.root = header_root;
    state.latest_justified.root = header_root;
    state
}

#[test]
fn verify_checkpoint_state_accepts_valid_state() {
    let expected_genesis = base_state(42, 4);
    let state = expected_genesis.clone();
    assert!(verify_checkpoint_state(&state, &expected_genesis).is_ok());
}

#[test]
fn verify_checkpoint_state_rejects_empty_validators() {
    let expected_genesis = base_state(1, 1);
    let mut state = expected_genesis.clone();
    state.validators = Validators::new(vec![]).expect("validators");

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("empty validator registry"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_validator_count_mismatch() {
    let expected_genesis = base_state(1, 2);
    let state = base_state(1, 1);

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("validator count"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_genesis_time_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.config.genesis_time = Uint64(11);

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("genesis_time"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_validator_pubkey_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.validators.data[0].pubkey = Bytes52::from([9u8; 52]);

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("validator pubkey mismatch"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_validator_index_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.validators.data[1].index = ValidatorIndex(Uint64(7));

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("validator index mismatch"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_header_slot_ahead_of_state() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.latest_block_header.slot = Slot(Uint64(5));

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("header slot"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_finalized_slot_in_future() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.latest_finalized.slot = Slot(Uint64(1));

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("finalized slot is in the future"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_justified_before_finalized() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.slot = Slot(Uint64(2));
    state.latest_finalized = Checkpoint {
        root: state.latest_finalized.root,
        slot: Slot(Uint64(2)),
    };
    state.latest_justified = Checkpoint {
        root: state.latest_justified.root,
        slot: Slot(Uint64(1)),
    };

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("justified slot is before finalized"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_same_slot_root_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.latest_justified.root = Bytes32::from([1u8; 32]);

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("justified/finalized roots mismatch"), "{err}");
}

#[test]
fn verify_checkpoint_state_rejects_header_root_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.slot = Slot(Uint64(1));
    state.latest_justified = Checkpoint {
        root: state.latest_justified.root,
        slot: Slot(Uint64(1)),
    };
    state.latest_finalized.root = Bytes32::from([2u8; 32]);

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(
        err.contains("finalized root does not match header root"),
        "{err}"
    );
}

#[test]
fn verify_checkpoint_state_rejects_state_root_mismatch() {
    let expected_genesis = base_state(10, 2);
    let mut state = expected_genesis.clone();
    state.latest_block_header.state_root = Bytes32::from([7u8; 32]);
    let header_root = Bytes32::from(state.latest_block_header.hash_tree_root());
    state.latest_finalized.root = header_root;
    state.latest_justified.root = header_root;

    let err = verify_checkpoint_state(&state, &expected_genesis).unwrap_err();
    assert!(err.contains("state_root mismatch"), "{err}");
}

#[test]
fn build_anchor_block_uses_computed_state_root_when_header_is_zero() {
    let state = base_state(10, 2);
    let anchor = build_anchor_block(&state);
    let expected_root = Bytes32::from(state.hash_tree_root());
    assert_eq!(anchor.state_root, expected_root);
}

#[test]
fn build_anchor_block_uses_header_state_root_when_present() {
    let mut state = base_state(10, 2);
    state.latest_block_header.state_root = Bytes32::from([3u8; 32]);
    let anchor = build_anchor_block(&state);
    assert_eq!(anchor.state_root, state.latest_block_header.state_root);
}

#[test]
fn build_anchor_signed_block_rejects_proposer_out_of_range() {
    let state = base_state(10, 2);
    let mut anchor = build_anchor_block(&state);
    anchor.proposer_index = ValidatorIndex(Uint64(VALIDATOR_REGISTRY_LIMIT as u64));

    let err = build_anchor_signed_block(&state, &anchor).unwrap_err();
    assert!(err.contains("exceeds registry limit"), "{err}");
}

#[test]
fn build_anchor_signed_block_happy_path() {
    let state = base_state(10, 2);
    let anchor = build_anchor_block(&state);
    let signed = build_anchor_signed_block(&state, &anchor).expect("signed block");
    assert_eq!(signed.message.block, anchor);
    assert_eq!(signed.message.proposer_attestation.data.slot, anchor.slot);
}
