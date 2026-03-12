//! Real post-quantum signature implementation.
//!
//! Uses `leansig` for single signatures.
//! Aggregate signing/verifying uses `lean-multisig` (devnet-2 target).

use lean_multisig::{
    Devnet2XmssAggregateSignature, xmss_aggregate_signatures, xmss_aggregation_setup_prover,
    xmss_aggregation_setup_verifier, xmss_verify_aggregated_signatures,
};
use leansig::{MESSAGE_LENGTH, serialization::Serializable, signature::SignatureScheme};
use rand::{SeedableRng, rngs::StdRng};
use ssz::{Decode, Encode};
use std::hash::Hasher;

use crate::types::bytes::{Bytes52, Bytes3112};

/// The concrete XMSS-based post-quantum signature scheme used throughout the node.
///
/// Instantiated with Poseidon hashing, optimized for hashing performance,
/// lifetime `2^32`, dimension 64, and base 8.
pub type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

/// Public key type for [`LeanSigScheme`].
pub type LeanSigPublicKey = <LeanSigScheme as SignatureScheme>::PublicKey;

/// Signature type for [`LeanSigScheme`].
pub type LeanSigSignature = <LeanSigScheme as SignatureScheme>::Signature;
/// Secret key type for [`LeanSigScheme`].
pub type LeanSigSecretKey = <LeanSigScheme as SignatureScheme>::SecretKey;

/// Narrow per-key active signing interval used for local devnet key material.
const DEVNET_KEY_ACTIVE_EPOCHS: usize = 8;

/// Pre-computes aggregation proving artifacts.
pub fn setup_aggregate_prover() {
    xmss_aggregation_setup_prover();
}

/// Pre-computes aggregation verification artifacts.
pub fn setup_aggregate_verifier() {
    xmss_aggregation_setup_verifier();
}

/// Deterministically derives a validator keypair for a devnet validator index.
///
/// This is used for local-devnet key material so every client can derive the
/// same validator registry without external key distribution.
#[inline]
pub fn key_gen_for_devnet_validator(
    validator_index: usize,
) -> Result<(Bytes52, LeanSigSecretKey), String> {
    let mut seed = [0u8; 32];
    seed[0..8]
        .copy_from_slice(&(0x4456_4E45_5431_0000u64 ^ (validator_index as u64)).to_le_bytes());
    let mut rng = StdRng::from_seed(seed);
    let (pk, sk) =
        <LeanSigScheme as SignatureScheme>::key_gen(&mut rng, 0, DEVNET_KEY_ACTIVE_EPOCHS);
    let pk_bytes = pk.to_bytes();
    if pk_bytes.len() != 52 {
        return Err(format!(
            "unexpected public key length {}, expected 52",
            pk_bytes.len()
        ));
    }
    Ok((Bytes52::from_slice(&pk_bytes), sk))
}

/// Signs a 32-byte message and returns the canonical 3112-byte signature.
#[inline]
pub fn sign_message(
    secret_key: &LeanSigSecretKey,
    epoch: u32,
    message: &[u8; MESSAGE_LENGTH],
) -> Result<Bytes3112, String> {
    let sig = <LeanSigScheme as SignatureScheme>::sign(secret_key, epoch, message)
        .map_err(|err| format!("failed to sign message: {err}"))?;
    let sig_bytes = sig.to_bytes();
    if sig_bytes.len() != Bytes3112::LEN {
        return Err(format!(
            "unexpected signature length {}, expected {}",
            sig_bytes.len(),
            Bytes3112::LEN
        ));
    }
    Ok(Bytes3112::from_slice(&sig_bytes))
}

/// Aggregates signatures using leanMultisig.
pub fn sign_aggregate(
    public_keys: &[Bytes52],
    secret_keys: &[&LeanSigSecretKey],
    epoch: u32,
    message: &[u8; MESSAGE_LENGTH],
) -> Result<Vec<u8>, String> {
    if public_keys.is_empty() {
        return Err("aggregate signature participants must be non-empty".to_string());
    }
    if public_keys.len() != secret_keys.len() {
        return Err(format!(
            "public key count ({}) does not match secret key count ({})",
            public_keys.len(),
            secret_keys.len()
        ));
    }
    let mut signatures = Vec::with_capacity(secret_keys.len());
    for secret_key in secret_keys {
        let signature = sign_message(secret_key, epoch, message)?;
        // SAFETY:
        // - `signatures` was preallocated with `secret_keys.len()`, and we perform
        //   exactly one insertion per loop iteration, so `len < capacity` always holds.
        // - `signature` is fully initialized before writing.
        unsafe {
            let idx = signatures.len();
            signatures.set_len(idx + 1);
            *signatures.get_unchecked_mut(idx) = signature;
        }
    }
    aggregate_signatures_impl(public_keys, &signatures, message, epoch)
}

#[inline]
fn hash_bytes_list<T: AsRef<[u8]>>(items: &[T]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write_usize(items.len());
    for item in items {
        hasher.write(item.as_ref());
    }
    hasher.finish()
}

#[inline]
fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

#[inline]
fn maybe_log_aggregate_io(
    phase: &'static str,
    public_keys: &[Bytes52],
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) {
    if std::env::var("LEAN_XMSS_IO_DEBUG").as_deref().ok() != Some("1") {
        return;
    }
    let pubkeys_hash = hash_bytes_list(public_keys);
    let message_hash = hash_bytes(message);
    tracing::info!(
        target: "xmss_io",
        phase,
        epoch,
        pubkeys_len = public_keys.len(),
        pubkeys_hash,
        message_hash,
        "xmss aggregate io"
    );
}

#[inline]
fn aggregate_signatures_impl(
    public_keys: &[Bytes52],
    signatures: &[Bytes3112],
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<u8>, String> {
    maybe_log_aggregate_io("prove", public_keys, message, epoch);
    let pub_keys = public_keys
        .iter()
        .map(public_key_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let sigs = signatures
        .iter()
        .map(signature_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate = xmss_aggregate_signatures(&pub_keys, &sigs, message, epoch)
        .map_err(|err| format!("failed to aggregate signatures: {err:?}"))?;
    Ok(aggregate.as_ssz_bytes())
}

/// Aggregates pre-existing signatures into a single SSZ-encoded leanMultisig proof.
#[inline]
pub fn aggregate_signatures(
    public_keys: &[Bytes52],
    signatures: &[Bytes3112],
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<u8>, String> {
    if public_keys.is_empty() {
        return Err("aggregate signature participants must be non-empty".to_string());
    }
    if public_keys.len() != signatures.len() {
        return Err(format!(
            "public key count ({}) does not match signature count ({})",
            public_keys.len(),
            signatures.len()
        ));
    }
    aggregate_signatures_impl(public_keys, signatures, message, epoch)
}

/// Deserializes a 52-byte public key into a [`LeanSigPublicKey`].
///
/// # Errors
///
/// Returns `Err` if the byte slice is not a valid encoded public key.
#[inline]
pub fn public_key_from_bytes(bytes: &Bytes52) -> Result<LeanSigPublicKey, String> {
    LeanSigPublicKey::from_bytes(bytes.as_ref())
        .map_err(|err| format!("Failed to decode LeanSigPublicKey: {err:?}"))
}

/// Deserializes a 3112-byte signature into a [`LeanSigSignature`].
///
/// # Errors
///
/// Returns `Err` if the byte slice is not a valid encoded signature.
#[inline]
pub fn signature_from_bytes(bytes: &Bytes3112) -> Result<LeanSigSignature, String> {
    LeanSigSignature::from_bytes(bytes.as_ref())
        .map_err(|err| format!("Failed to decode LeanSigSignature: {err:?}"))
}

/// Verifies a single post-quantum signature.
///
/// Decodes `public_key` and `signature` from their byte representations, then
/// checks the signature over `message` at the given `epoch`.
///
/// # Errors
///
/// Returns `Err` if key/signature deserialization fails or if verification does
/// not pass.
#[inline]
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

/// Verifies an SSZ-encoded leanMultisig aggregated signature proof.
#[inline]
pub fn verify_aggregate_signature(
    public_keys: &[Bytes52],
    message: &[u8; 32],
    aggregate_signature_bytes: &[u8],
    epoch: u32,
) -> Result<(), String> {
    if public_keys.is_empty() {
        return Err("aggregate signature participants must be non-empty".to_string());
    }
    if aggregate_signature_bytes.len() < 8 {
        return Err("failed to decode aggregate signature: proof too short".to_string());
    }
    maybe_log_aggregate_io("verify", public_keys, message, epoch);

    let aggregate = Devnet2XmssAggregateSignature::from_ssz_bytes(aggregate_signature_bytes)
        .map_err(|err| format!("failed to decode aggregate signature: {err:?}"))?;
    let pub_keys = public_keys
        .iter()
        .map(public_key_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    xmss_verify_aggregated_signatures(&pub_keys, message, &aggregate, epoch)
        .map_err(|err| format!("failed to verify aggregated signatures: {err}"))
}
