use lean_eth::containers::state::{State, Validators};
use lean_eth::containers::validator::{Validator, ValidatorIndex};
use lean_eth::slot::Slot;
use lean_eth::ssz::SszEncode;
use lean_eth::types::bytes::Bytes52;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;

#[test]
fn state_encode_decode_roundtrip() {
    let v = Validator {
        pubkey: Bytes52::from([0xAAu8; 52]),
        index: ValidatorIndex(Uint64(1)),
        balance: Uint64(0),
    };
    let validators: Validators = SszList::new(vec![v]).expect("validators");
    let state = State::generate_genesis(Uint64(0), validators);

    let encoded = state.encode_ssz();
    let decoded = State::decode_ssz_checked(&encoded).expect("decode");

    assert_eq!(decoded.slot, Slot(Uint64(0)));
    assert_eq!(decoded.validators.data.len(), 1);
    assert_eq!(decoded.balances.data.len(), 1);
    assert_eq!(decoded.balances.data[0], Uint64(0));
}
