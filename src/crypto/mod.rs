//! Post-quantum cryptography module.
//!
//! Master tracks the latest devnet path; PQ signing and verification are always
//! enabled in this crate.

/// Devnet-1 fixed PQ activation horizon in epochs (`2^18`).
pub const PQ_ACTIVATION_TIME_EPOCHS: u32 = 1 << 18;

/// Post-quantum signature primitives implemented by `leansig`/`lean-multisig`.
pub mod pq;
