use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::slot::Slot;
use peam::ssz::SszEncode;
use peam::types::bytes::Bytes52;
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

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
    assert_eq!(decoded.validators.len(), 1);
}
