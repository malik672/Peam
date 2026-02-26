//! Real post-quantum signature implementation, compiled only with `pq_crypto`.
//!
//! Uses `leansig` for single signatures.
//! Aggregate / multi-signature verification (`verify_aggregate_signature`)
//! is a stub that always returns an error; a full multisig implementation
//! will be wired up in a future feature.
//!
//! # Feature gates
//!
//! | Feature       | Effect |
//! |---------------|--------|
//! | `pq_crypto`   | Enables this entire module |

use leansig::{MESSAGE_LENGTH, serialization::Serializable, signature::SignatureScheme};

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

/// No-op placeholder; a real aggregate verifier setup will be added with multisig support.
pub fn setup_aggregate_verifier() {}

/// Deserializes a 52-byte public key into a [`LeanSigPublicKey`].
///
/// # Errors
///
/// Returns `Err` if the byte slice is not a valid encoded public key.
pub fn public_key_from_bytes(bytes: &Bytes52) -> Result<LeanSigPublicKey, String> {
    LeanSigPublicKey::from_bytes(bytes.as_ref())
        .map_err(|err| format!("Failed to decode LeanSigPublicKey: {err:?}"))
}

/// Deserializes a 3112-byte signature into a [`LeanSigSignature`].
///
/// # Errors
///
/// Returns `Err` if the byte slice is not a valid encoded signature.
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

/// Stub: aggregate signature verification is not yet implemented.
///
/// Always returns `Err`. A full multisig implementation will be wired up in a
/// future release.
pub fn verify_aggregate_signature(
    _public_keys: &[Bytes52],
    _message: &[u8; 32],
    _aggregate_signature_bytes: &[u8],
    _epoch: u32,
) -> Result<(), String> {
    Err("aggregate signature verification not yet implemented".to_string())
}
