//! Gossip message validation: signature verification and structural checks.
//!
//! [`validate_gossip`] is the top-level entry point called per inbound gossip
//! message. It dispatches to kind-specific validators and invokes the
//! injected [`GossipSignatureVerifier`] for cryptographic checks.
//!
//! Two verifier implementations are provided:
//! - [`NoopGossipVerifier`] — accepts everything (tests / no-crypto mode).
//! - [`SimpleGossipVerifier`] — performs real PQ signature verification using
//!   the validator public-key registry.

use std::sync::Arc;

use crate::containers::attestation::{
    AggregatedSignatureProof, Attestation, SignedAttestation, VALIDATOR_REGISTRY_LIMIT,
};
use crate::containers::block::BlockWithAttestation;
use crate::containers::gossip::{GossipAttestation, GossipBlock, GossipBlockHeader, VoluntaryExit};
use crate::containers::validator::{Validator, ValidatorIndex};
use crate::crypto;
use crate::ssz::HashTreeRoot;
use crate::types::bitlist::BitList;
use crate::types::bytes::{Bytes52, Bytes3112};

/// Discriminant for selecting the gossip validator to run on a topic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GossipValidatorKind {
    /// No validation — accept unconditionally.
    None,
    /// Validate a full signed block with proposer and attestation signatures.
    Block,
    /// Validate a bare block header (SSZ decode only).
    BlockHeader,
    /// Validate a single signed attestation.
    Attestation,
    /// Validate a voluntary-exit message (SSZ decode only).
    VoluntaryExit,
}

/// Cryptographic signature verifier for gossip messages.
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// networking tasks.
pub trait GossipSignatureVerifier: Send + Sync {
    /// Verify proposer signature over the proposer attestation.
    fn verify_block_signature(
        &self,
        proposer_index: ValidatorIndex,
        message: &BlockWithAttestation,
        signature: &Bytes3112,
    ) -> bool;
    /// Verify a single validator's signed attestation.
    fn verify_signed_attestation_signature(&self, attestation: &SignedAttestation) -> bool;
    /// Verify aggregated attestation signatures for participating validators.
    fn verify_attestation_signature(
        &self,
        attestation: &Attestation,
        proof: &AggregatedSignatureProof,
    ) -> bool;
}

/// A [`GossipSignatureVerifier`] that accepts every message unconditionally.
///
/// Useful in tests or when running without a validator key registry.
#[derive(Clone)]
pub struct NoopGossipVerifier;

/// [`GossipSignatureVerifier`] impl — all methods return `true`.
impl GossipSignatureVerifier for NoopGossipVerifier {
    fn verify_block_signature(
        &self,
        _proposer_index: ValidatorIndex,
        _message: &BlockWithAttestation,
        _signature: &Bytes3112,
    ) -> bool {
        true
    }

    fn verify_signed_attestation_signature(&self, _attestation: &SignedAttestation) -> bool {
        true
    }

    fn verify_attestation_signature(
        &self,
        _attestation: &Attestation,
        _proof: &AggregatedSignatureProof,
    ) -> bool {
        true
    }
}

/// A [`GossipSignatureVerifier`] backed by a flat public-key registry.
///
/// Performs real PQ signature verification via `crypto::pq`. Initialises the
/// aggregate verifier on construction via [`crypto::pq::setup_aggregate_verifier`].
pub struct SimpleGossipVerifier {
    pubkeys: Vec<Bytes52>,
}

impl SimpleGossipVerifier {
    /// Creates a new verifier from a slice of validator public keys.
    ///
    /// Keys must be ordered by validator index. Calls
    /// `setup_aggregate_verifier` to initialise any global verifier state.
    pub fn new(pubkeys: Vec<Bytes52>) -> Self {
        crypto::pq::setup_aggregate_verifier();
        Self { pubkeys }
    }
}

/// [`GossipSignatureVerifier`] impl using PQ crypto.
impl GossipSignatureVerifier for SimpleGossipVerifier {
    fn verify_block_signature(
        &self,
        proposer_index: ValidatorIndex,
        message: &BlockWithAttestation,
        signature: &Bytes3112,
    ) -> bool {
        let proposer_attestation = &message.proposer_attestation;
        let idx = proposer_index.0.0 as usize;
        let Some(pubkey) = self.pubkeys.get(idx) else {
            return false;
        };
        let root = proposer_attestation.data.hash_tree_root();
        let epoch = proposer_attestation.data.slot.0.0 as u32;
        crypto::pq::verify_signature(pubkey, epoch, &root, signature).is_ok()
    }

    fn verify_signed_attestation_signature(&self, attestation: &SignedAttestation) -> bool {
        let idx = attestation.validator_id.0 as usize;
        let Some(pubkey) = self.pubkeys.get(idx) else {
            return false;
        };
        let root = attestation.message.hash_tree_root();
        let epoch = attestation.message.slot.0.0 as u32;
        crypto::pq::verify_signature(pubkey, epoch, &root, &attestation.signature).is_ok()
    }

    fn verify_attestation_signature(
        &self,
        attestation: &Attestation,
        proof: &AggregatedSignatureProof,
    ) -> bool {
        let Some(participants) = gather_pubkeys(&self.pubkeys, &proof.participants) else {
            return false;
        };
        if participants.is_empty() {
            return false;
        }
        let root = attestation.hash_tree_root();
        let epoch = attestation.data.slot.0.0 as u32;
        crypto::pq::verify_aggregate_signature(
            &participants,
            &root,
            proof.proof_data.as_slice(),
            epoch,
        )
        .is_ok()
    }
}

/// Collects the public keys of all participants indicated by `participants`.
///
/// Returns `None` if any participant index is out of bounds in `registry`.
fn gather_pubkeys(
    registry: &[Bytes52],
    participants: &BitList<VALIDATOR_REGISTRY_LIMIT>,
) -> Option<Vec<Bytes52>> {
    let mut out = Vec::new();
    let total = participants.len();
    for idx in 0..total {
        if bit_is_set(participants, idx) {
            let pubkey = *registry.get(idx)?;
            out.push(pubkey);
        }
    }
    Some(out)
}

/// Returns `true` if bit `idx` is set in `participants`.
fn bit_is_set(participants: &BitList<VALIDATOR_REGISTRY_LIMIT>, idx: usize) -> bool {
    if idx >= participants.len() {
        return false;
    }
    let byte = idx / 8;
    let bit = idx % 8;
    if byte >= participants.data.len() {
        return false;
    }
    (participants.data[byte] & (1u8 << bit)) != 0
}

/// Returns the indices of all set bits in `participants`, in ascending order.
fn set_bits(participants: &BitList<VALIDATOR_REGISTRY_LIMIT>) -> Vec<usize> {
    let mut out = Vec::new();
    let len = participants.len();
    for i in 0..len {
        if bit_is_set(participants, i) {
            out.push(i);
        }
    }
    out
}

/// Validates a raw gossip `payload` of the given `kind` using `verifier`.
///
/// Returns `true` if the message is structurally valid and all required
/// signature checks pass; `false` otherwise.
///
/// Dispatch by kind:
/// - `None` — always `true`.
/// - `Block` — SSZ decode + proposer-attestation slot/index + all signatures.
/// - `BlockHeader` — SSZ decode only.
/// - `Attestation` — SSZ decode + single-validator signature.
/// - `VoluntaryExit` — SSZ decode only.
pub fn validate_gossip(
    kind: GossipValidatorKind,
    payload: &[u8],
    verifier: &Arc<dyn GossipSignatureVerifier>,
) -> bool {
    match kind {
        GossipValidatorKind::None => true,
        GossipValidatorKind::Block => {
            // Full block validation: SSZ decode + proposer + attestation signatures.
            let Ok(block) = GossipBlock::decode_ssz_checked(payload) else {
                return false;
            };
            let message = &block.block.message;
            let block_body = &message.block.body;
            let proposer_attestation = &message.proposer_attestation;
            if proposer_attestation.data.slot != message.block.slot {
                return false;
            }
            let proposer_bits = set_bits(&proposer_attestation.aggregation_bits);
            if proposer_bits.len() != 1 {
                return false;
            }
            if proposer_bits[0] != message.block.proposer_index.0.0 as usize {
                return false;
            }
            if !verifier.verify_block_signature(
                message.block.proposer_index,
                message,
                &block.block.signature.proposer_signature,
            ) {
                return false;
            }
            let proofs = &block.block.signature.attestation_signatures;
            if block_body.attestations.data.len() != proofs.data.len() {
                return false;
            }
            for (attestation, proof) in block_body.attestations.data.iter().zip(proofs.data.iter())
            {
                if proof.participants != attestation.aggregation_bits {
                    return false;
                }
                if !verifier.verify_attestation_signature(attestation, proof) {
                    return false;
                }
            }
            true
        }
        GossipValidatorKind::BlockHeader => GossipBlockHeader::decode_ssz_checked(payload).is_ok(),
        GossipValidatorKind::Attestation => {
            // Attestation gossip is a signed attestation (single validator).
            let Ok(attestation) = GossipAttestation::decode_ssz_checked(payload) else {
                return false;
            };
            verifier.verify_signed_attestation_signature(&attestation.attestation)
        }
        GossipValidatorKind::VoluntaryExit => VoluntaryExit::decode_ssz_checked(payload).is_ok(),
    }
}

/// Constructs the appropriate [`GossipSignatureVerifier`] for `validators`.
///
/// Returns a [`NoopGossipVerifier`] if the registry is empty, otherwise a
/// [`SimpleGossipVerifier`] built from the validators' public keys.
pub fn verifier_from_validators(validators: &[Validator]) -> Arc<dyn GossipSignatureVerifier> {
    if validators.is_empty() {
        return Arc::new(NoopGossipVerifier);
    }
    let pubkeys = validators
        .iter()
        .map(|validator| validator.pubkey)
        .collect();
    Arc::new(SimpleGossipVerifier::new(pubkeys))
}
