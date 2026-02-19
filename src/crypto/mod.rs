#[cfg(feature = "pq_crypto")]
pub mod pq;

#[cfg(not(feature = "pq_crypto"))]
pub mod pq {
    use crate::types::bytes::{Bytes3112, Bytes52};

    pub fn setup_aggregate_verifier() {}

    pub fn verify_signature(
        _public_key: &Bytes52,
        _epoch: u32,
        _message: &[u8; 32],
        _signature: &Bytes3112,
    ) -> Result<(), String> {
        Err("pq crypto feature disabled".to_string())
    }

    pub fn verify_aggregate_signature(
        _public_keys: &[Bytes52],
        _message: &[u8; 32],
        _aggregate_signature_bytes: &[u8],
        _epoch: u32,
    ) -> Result<(), String> {
        Err("pq crypto feature disabled".to_string())
    }
}
