#![cfg(feature = "pq_crypto")]

use leansig::{MESSAGE_LENGTH, serialization::Serializable, signature::SignatureScheme};
#[cfg(feature = "pq_multisig")]
use lean_multisig::{
    Devnet2XmssAggregateSignature, xmss_aggregation_setup_verifier,
    xmss_verify_aggregated_signatures,
};
#[cfg(feature = "pq_multisig")]
use ssz::Decode;

use crate::types::bytes::{Bytes3112, Bytes52};

pub type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanSigPublicKey = <LeanSigScheme as SignatureScheme>::PublicKey;
pub type LeanSigSignature = <LeanSigScheme as SignatureScheme>::Signature;

#[cfg(feature = "pq_multisig")]
pub fn setup_aggregate_verifier() {
    xmss_aggregation_setup_verifier();
}

#[cfg(not(feature = "pq_multisig"))]
pub fn setup_aggregate_verifier() {}

pub fn public_key_from_bytes(bytes: &Bytes52) -> Result<LeanSigPublicKey, String> {
    LeanSigPublicKey::from_bytes(bytes.as_ref())
        .map_err(|err| format!("Failed to decode LeanSigPublicKey: {err:?}"))
}

pub fn signature_from_bytes(bytes: &Bytes3112) -> Result<LeanSigSignature, String> {
    LeanSigSignature::from_bytes(bytes.as_ref())
        .map_err(|err| format!("Failed to decode LeanSigSignature: {err:?}"))
}

pub fn verify_signature(
    public_key: &Bytes52,
    epoch: u32,
    message: &[u8; MESSAGE_LENGTH],
    signature: &Bytes3112,
) -> Result<(), String> {
    let pk = public_key_from_bytes(public_key)?;
    let sig = signature_from_bytes(signature)?;
    let ok = <LeanSigScheme as SignatureScheme>::verify(&pk, epoch, message, &sig);
    if ok {
        Ok(())
    } else {
        Err("Proposer signature verification failed".to_string())
    }
}

// Attribution: aggregate verification flow is adapted from Ream's lean-multisig integration.
#[cfg(feature = "pq_multisig")]
pub fn verify_aggregate_signature(
    public_keys: &[Bytes52],
    message: &[u8; 32],
    aggregate_signature_bytes: &[u8],
    epoch: u32,
) -> Result<(), String> {
    let aggregate_signature =
        Devnet2XmssAggregateSignature::from_ssz_bytes(aggregate_signature_bytes)
            .map_err(|err| format!("Failed to decode aggregate signature: {err:?}"))?;

    let pubkeys = public_keys
        .iter()
        .map(public_key_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;

    xmss_verify_aggregated_signatures(&pubkeys, message, &aggregate_signature, epoch)
        .map_err(|err| format!("Aggregated signature verification failed: {err}"))
}

#[cfg(not(feature = "pq_multisig"))]
pub fn verify_aggregate_signature(
    _public_keys: &[Bytes52],
    _message: &[u8; 32],
    _aggregate_signature_bytes: &[u8],
    _epoch: u32,
) -> Result<(), String> {
    Err("pq_multisig feature disabled".to_string())
}
