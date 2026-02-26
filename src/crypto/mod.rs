//! Post-quantum cryptography module.
//!
//! Exposes a unified `pq` sub-module whose implementation depends on feature flags:
//!
//! | Feature flags active          | Implementation                        |
//! |-------------------------------|---------------------------------------|
//! | `pq_crypto`                   | [`pq`] backed by `leansig` / `lean-multisig` |
//! | *(none)*                      | No-op stubs that always return `Err`  |
//!
//! Callers should import `crate::crypto::pq` and use
//! [`pq::verify_signature`] / [`pq::verify_aggregate_signature`] without
//! caring which backend is active.

/// Post-quantum signature primitives.
///
/// When compiled with `pq_crypto` this delegates to the real `leansig` /
/// `lean-multisig` implementation in `src/crypto/pq.rs`.
/// Without the feature, every function returns an `Err` immediately so that
/// the rest of the code compiles and the non-crypto path works correctly.
#[cfg(feature = "pq_crypto")]
pub mod pq;

#[cfg(not(feature = "pq_crypto"))]
pub mod pq {
    use crate::types::bytes::{Bytes52, Bytes3112};

    /// No-op verifier setup — does nothing when `pq_crypto` is disabled.
    pub fn setup_aggregate_verifier() {}

    /// Stub single-signature verifier.
    ///
    /// Always returns `Err("pq crypto feature disabled")` when the `pq_crypto`
    /// feature is not enabled.
    pub fn verify_signature(
        _public_key: &Bytes52,
        _epoch: u32,
        _message: &[u8; 32],
        _signature: &Bytes3112,
    ) -> Result<(), String> {
        Err("pq crypto feature disabled".to_string())
    }

    /// Stub aggregate-signature verifier.
    ///
    /// Always returns `Err("pq crypto feature disabled")` when the `pq_crypto`
    /// feature is not enabled.
    pub fn verify_aggregate_signature(
        _public_keys: &[Bytes52],
        _message: &[u8; 32],
        _aggregate_signature_bytes: &[u8],
        _epoch: u32,
    ) -> Result<(), String> {
        Err("pq crypto feature disabled".to_string())
    }
}
