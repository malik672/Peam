use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use peam::crypto::pq;
use peam::types::bytes::{Bytes52, Bytes3112};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

type LeanSigFastContractScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;

fn sample_message() -> [u8; 32] {
    [0xAB; 32]
}

#[test]
fn pq_verify_signature_rejects_invalid_material() {
    let err = pq::verify_signature(
        &Bytes52::from([0u8; 52]),
        0,
        &sample_message(),
        &Bytes3112::zero(),
    )
    .unwrap_err();
    assert!(
        err.contains("Failed to decode LeanSigPublicKey")
            || err.contains("Failed to decode LeanSigSignature")
            || err.contains("verification failed")
            || err.contains("Proposer signature verification failed")
    );
}

#[test]
fn pq_aggregate_verify_rejects_bad_lengths() {
    let err = pq::verify_aggregate_signature(
        &[Bytes52::from([0u8; 52])],
        &sample_message(),
        &[0x01, 0x02, 0x03],
        0,
    )
    .unwrap_err();
    assert!(err.contains("decode aggregate signature"));
}

#[test]
//CBTT
fn leansig_sign_panics_when_epoch_is_outside_key_interval_contract() {
    // Contract test for upstream behavior we rely on:
    // `leansig::sign` should guard key activation/preparation intervals.
    let mut rng = StdRng::from_seed([0x42u8; 32]);
    let (_pk, sk) = <LeanSigFastContractScheme as SignatureScheme>::key_gen(&mut rng, 0, 1);
    let message = sample_message();
    let activation = sk.get_activation_interval();
    let out_of_interval_epoch = activation.end as u32;

    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _ = <LeanSigFastContractScheme as SignatureScheme>::sign(
            &sk,
            out_of_interval_epoch,
            &message,
        );
    }))
    .is_err();

    assert!(
        panicked,
        "expected leansig::sign to panic for out-of-interval epoch; if this fails, upstream behavior changed and caller-side validation assumptions must be revisited"
    );
}
