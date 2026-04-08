use peam::app::build_genesis_with_validator_count;
use peam::containers::config::Config;
use peam::types::uint::Uint64;

#[test]
fn genesis_uses_requested_validator_count() {
    let config = Config {
        genesis_time: Uint64(0),
    };
    let state = build_genesis_with_validator_count(config, 400).expect("build genesis");
    assert_eq!(state.validators.len(), 400);
}

#[test]
fn genesis_rejects_zero_validator_count() {
    let config = Config {
        genesis_time: Uint64(0),
    };
    let err = build_genesis_with_validator_count(config, 0).expect_err("zero count must fail");
    assert!(err.contains("validator_count must be > 0"));
}
