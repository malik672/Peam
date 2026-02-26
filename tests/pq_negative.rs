use lean_eth::crypto::pq;
use lean_eth::types::bytes::{Bytes52, Bytes3112};

fn sample_message() -> [u8; 32] {
    [0xAB; 32]
}

#[cfg(not(feature = "pq_crypto"))]
#[test]
fn pq_verify_reports_feature_disabled_without_pq_crypto() {
    let err = pq::verify_signature(
        &Bytes52::from([0u8; 52]),
        0,
        &sample_message(),
        &Bytes3112::zero(),
    )
    .unwrap_err();
    assert!(err.contains("pq crypto feature disabled"));
}

#[cfg(feature = "pq_crypto")]
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

#[cfg(feature = "pq_crypto")]
#[test]
fn pq_aggregate_verify_reports_not_implemented() {
    let err = pq::verify_aggregate_signature(
        &[Bytes52::from([0u8; 52])],
        &sample_message(),
        &[0x01, 0x02, 0x03],
        0,
    )
    .unwrap_err();
    assert!(err.contains("not yet implemented"));
}
