//! Real post-quantum signature implementation.
//!
//! Uses `leansig` for single signatures.
//! Aggregate signing/verifying uses `lean-multisig` (devnet-2 target).

use lean_multisig::{
    AggregatedXMSS, setup_prover, setup_verifier, xmss_aggregate, xmss_verify_aggregation,
};
use leansig::{
    MESSAGE_LENGTH,
    inc_encoding::target_sum::TargetSumEncoding,
    serialization::Serializable,
    signature::{
        SignatureScheme,
        generalized_xmss::{
            GeneralizedXMSSPublicKey, GeneralizedXMSSSecretKey, GeneralizedXMSSSignature,
            GeneralizedXMSSSignatureScheme,
        },
    },
    symmetric::{
        message_hash::aborting::AbortingHypercubeMessageHash,
        prf::shake_to_field::ShakePRFtoF,
        tweak_hash::poseidon::PoseidonTweakHash,
    },
};
use rand::{SeedableRng, rngs::StdRng};
use std::hash::Hasher;

use crate::types::bytes::{Bytes52, Bytes3112};

/// The concrete XMSS-based post-quantum signature scheme used throughout the node.
///
const PARAMETER_LEN: usize = 5;
const HASH_LEN_FE: usize = 8;
const TWEAK_LEN_FE: usize = 2;
const POSEIDON24_CAPACITY: usize = 9;
const V: usize = 46;
const BASE: usize = 8;
const Z: usize = 8;
const Q: usize = 127;
const MSG_LEN_FE: usize = 9;
const RAND_LEN_FE: usize = 7;
const TARGET_SUM: usize = 200;
const LOG_LIFETIME: usize = 32;

type MH =
    AbortingHypercubeMessageHash<PARAMETER_LEN, RAND_LEN_FE, HASH_LEN_FE, V, BASE, Z, Q, TWEAK_LEN_FE, MSG_LEN_FE>;
type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, POSEIDON24_CAPACITY, V>;
type PrF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
type IE = TargetSumEncoding<MH, TARGET_SUM>;

/// Instantiated with the devnet4 XMSS parameters used by lean-multisig.
pub type LeanSigScheme = GeneralizedXMSSSignatureScheme<PrF, IE, TH, LOG_LIFETIME>;

/// Public key type for [`LeanSigScheme`].
pub type LeanSigPublicKey = GeneralizedXMSSPublicKey<TH>;

/// Signature type for [`LeanSigScheme`].
pub type LeanSigSignature = GeneralizedXMSSSignature<IE, TH>;
/// Secret key type for [`LeanSigScheme`].
pub type LeanSigSecretKey = GeneralizedXMSSSecretKey<PrF, IE, TH, LOG_LIFETIME>;

/// Narrow per-key active signing interval used for local devnet key material.
const DEVNET_KEY_ACTIVE_EPOCHS: usize = 8;
/// Aggregation rate used when Peam proves fresh XMSS aggregate proofs.
///
/// Verification is encoded in the proof, so peers do not need to know this value.
const XMSS_AGGREGATION_LOG_INV_RATE: usize = 1;

pub struct AggregateChildProof<'a> {
    pub public_keys: &'a [Bytes52],
    pub proof_data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevnetValidatorKeyRole {
    Attestation,
    Proposal,
}

#[inline]
fn devnet_validator_seed(validator_index: usize, role: DevnetValidatorKeyRole) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let role_tag = match role {
        DevnetValidatorKeyRole::Attestation => 0x4456_4E45_5431_0000u64,
        DevnetValidatorKeyRole::Proposal => 0x4456_4E45_5431_5052u64,
    };
    seed[0..8].copy_from_slice(&(role_tag ^ (validator_index as u64)).to_le_bytes());
    seed
}

/// Pre-computes aggregation proving artifacts.
pub fn setup_aggregate_prover() {
    setup_prover();
}

/// Pre-computes aggregation verification artifacts.
pub fn setup_aggregate_verifier() {
    setup_verifier();
}

/// Deterministically derives a role-specific validator keypair for local devnets.
#[inline]
pub fn key_gen_for_devnet_validator_with_role(
    validator_index: usize,
    role: DevnetValidatorKeyRole,
) -> Result<(Bytes52, LeanSigSecretKey), String> {
    let seed = devnet_validator_seed(validator_index, role);
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
    aggregate_signatures_impl(&[], public_keys, &signatures, message, epoch)
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
    children: &[AggregateChildProof<'_>],
    public_keys: &[Bytes52],
    signatures: &[Bytes3112],
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<u8>, String> {
    maybe_log_aggregate_io("prove", public_keys, message, epoch);
    let mut child_pubkeys = Vec::with_capacity(children.len());
    let mut child_refs = Vec::with_capacity(children.len());
    // SAFETY:
    // - both vectors are preallocated to `children.len()`, so no reallocation occurs.
    // - each slot is written exactly once before the corresponding length is increased.
    // - `child_refs` stores slices into `child_pubkeys`, which stay valid because
    //   `child_pubkeys` never reallocates after capacity reservation.
    unsafe {
        for (idx, child) in children.iter().enumerate() {
            let pub_keys = child
                .public_keys
                .iter()
                .map(public_key_from_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            let aggregate = AggregatedXMSS::deserialize(child.proof_data)
                .ok_or_else(|| "failed to decode child aggregate signature".to_string())?;
            crate::unsafe_vec::write_at(&mut child_pubkeys, idx, pub_keys);
            let initialized_len = idx.unchecked_add(1);
            child_pubkeys.set_len(initialized_len);
            let pub_keys = (&*child_pubkeys.as_ptr().add(idx)).as_slice();
            crate::unsafe_vec::write_at(&mut child_refs, idx, (pub_keys, aggregate));
            child_refs.set_len(initialized_len);
        }
    }
    let mut raw_xmss = Vec::with_capacity(public_keys.len());
    // SAFETY:
    // - `raw_xmss` is preallocated to `public_keys.len()`.
    // - `public_keys.len() == signatures.len()` is an invariant of the callers.
    // - each slot is written exactly once before the vector length is increased.
    unsafe {
        for (idx, (public_key, signature)) in public_keys.iter().zip(signatures.iter()).enumerate()
        {
            crate::unsafe_vec::write_at(
                &mut raw_xmss,
                idx,
                (public_key_from_bytes(public_key)?, signature_from_bytes(signature)?),
            );
            raw_xmss.set_len(idx.unchecked_add(1));
        }
    }
    if child_refs.is_empty() && raw_xmss.is_empty() {
        return Err("aggregate signature participants must be non-empty".to_string());
    }
    let (_, aggregate) = xmss_aggregate(
        &child_refs,
        raw_xmss,
        message,
        epoch,
        XMSS_AGGREGATION_LOG_INV_RATE,
    );
    Ok(aggregate.serialize())
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
    aggregate_signatures_impl(&[], public_keys, signatures, message, epoch)
}

/// Recursively aggregates existing aggregate proofs together with optional raw signatures.
#[inline]
pub fn aggregate_proofs(
    children: &[AggregateChildProof<'_>],
    public_keys: &[Bytes52],
    signatures: &[Bytes3112],
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
) -> Result<Vec<u8>, String> {
    if public_keys.len() != signatures.len() {
        return Err(format!(
            "public key count ({}) does not match signature count ({})",
            public_keys.len(),
            signatures.len()
        ));
    }
    aggregate_signatures_impl(children, public_keys, signatures, message, epoch)
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

    let aggregate = AggregatedXMSS::deserialize(aggregate_signature_bytes)
        .ok_or_else(|| "failed to decode aggregate signature".to_string())?;
    let pub_keys = public_keys
        .iter()
        .map(public_key_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    xmss_verify_aggregation(pub_keys, &aggregate, message, epoch)
        .map(|_| ())
        .map_err(|err| format!("failed to verify aggregated signatures: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        AggregateChildProof, DevnetValidatorKeyRole, aggregate_proofs, devnet_validator_seed,
        key_gen_for_devnet_validator_with_role, sign_aggregate, sign_message,
        verify_aggregate_signature,
    };

    #[test]
    fn devnet_role_seeds_are_distinct_and_stable() {
        let attestation = devnet_validator_seed(0, DevnetValidatorKeyRole::Attestation);
        let proposal = devnet_validator_seed(0, DevnetValidatorKeyRole::Proposal);

        assert_ne!(attestation, proposal);
        assert_eq!(attestation[..8], [0, 0, 49, 84, 69, 78, 86, 68]);
        assert_eq!(proposal[..8], [82, 80, 49, 84, 69, 78, 86, 68]);
        assert!(attestation[8..].iter().all(|byte| *byte == 0));
        assert!(proposal[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    #[ignore = "recursive XMSS proof composition is slow; run explicitly when validating the path"]
    fn recursively_aggregates_child_proof_with_fresh_signature() {
        let (pk0, sk0) =
            key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Attestation)
                .expect("validator 0 key");
        let (pk1, sk1) =
            key_gen_for_devnet_validator_with_role(1, DevnetValidatorKeyRole::Attestation)
                .expect("validator 1 key");
        let message = [0x5Au8; 32];
        let child_proof = sign_aggregate(&[pk0], &[&sk0], 1, &message).expect("child proof");
        let sig1 = sign_message(&sk1, 1, &message).expect("signature");

        let aggregate = aggregate_proofs(
            &[AggregateChildProof {
                public_keys: &[pk0],
                proof_data: &child_proof,
            }],
            &[pk1],
            &[sig1],
            &message,
            1,
        )
        .expect("recursive aggregate");

        verify_aggregate_signature(&[pk0, pk1], &message, &aggregate, 1)
            .expect("verify recursive aggregate");
    }
}
