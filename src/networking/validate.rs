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

use peam_consensus_types::containers::attestation::{
    AggregatedSignatureProof, Attestation, SignedAggregatedAttestation, SignedAttestation,
    VALIDATOR_REGISTRY_LIMIT,
};
use peam_consensus_types::containers::block::{Block, proposer_attestation_present};
use peam_consensus_types::containers::validator::{Validator, ValidatorIndex};
use peam_consensus_types::types::bitlist::BitList;
use peam_consensus_types::types::bytes::{Bytes52, Bytes3112};
use crate::containers::gossip::{
    GossipAggregatedAttestation, GossipAttestation, GossipBlock, GossipBlockHeader, VoluntaryExit,
};
use crate::crypto;
use crate::ssz::{HashTreeRoot, SszFixedLen};
use crate::unsafe_vec::write_at;
use tracing::warn;

fn payload_prefix_hex(bytes: &[u8], max_bytes: usize) -> String {
    let shown = bytes.len().min(max_bytes);
    let mut out = String::with_capacity(shown * 2 + if bytes.len() > shown { 3 } else { 0 });
    for byte in &bytes[..shown] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    if bytes.len() > shown {
        out.push_str("...");
    }
    out
}

fn describe_attestation_topic_payload(payload: &[u8]) -> String {
    let signed_expected = SignedAttestation::fixed_len();
    let signed_err = SignedAttestation::decode_ssz_checked(payload)
        .err()
        .unwrap_or_else(|| "decoded".to_string());
    let plain_shape = match Attestation::decode_ssz_checked(payload) {
        Ok(attestation) => format!(
            "ok(slot={}, bits={})",
            attestation.data.slot.0.0, attestation.aggregation_bits.len
        ),
        Err(err) => format!("err({err})"),
    };
    let aggregated_shape = match SignedAggregatedAttestation::decode_ssz_checked(payload) {
        Ok(attestation) => format!(
            "ok(slot={}, proof_bytes={}, bits={})",
            attestation.data.slot.0.0,
            attestation.proof.proof_data.as_slice().len(),
            attestation.proof.participants.len
        ),
        Err(err) => format!("err({err})"),
    };

    format!(
        "len={} expected_signed_len={} signed={} plain_attestation={} signed_aggregate={} prefix=0x{}",
        payload.len(),
        signed_expected,
        signed_err,
        plain_shape,
        aggregated_shape,
        payload_prefix_hex(payload, 16)
    )
}

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
    /// Validate a signed aggregated attestation (`/aggregation` topic).
    AggregatedAttestation,
    /// Validate a voluntary-exit message (SSZ decode only).
    VoluntaryExit,
}

/// Cryptographic signature verifier for gossip messages.
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// networking tasks.
pub trait GossipSignatureVerifier: Send + Sync {
    /// Verify proposer signature over the block.
    fn verify_block_signature(
        &self,
        proposer_index: ValidatorIndex,
        message: &Block,
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
        _message: &Block,
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
    attestation_pubkeys: Vec<Bytes52>,
    proposal_pubkeys: Vec<Bytes52>,
}

impl SimpleGossipVerifier {
    /// Creates a new verifier from a slice of validator public keys.
    ///
    /// Keys must be ordered by validator index. Calls
    /// `setup_aggregate_verifier` to initialise any global verifier state.
    pub fn new(attestation_pubkeys: Vec<Bytes52>, proposal_pubkeys: Vec<Bytes52>) -> Self {
        assert_eq!(
            attestation_pubkeys.len(),
            proposal_pubkeys.len(),
            "attestation/proposal pubkey registries must have the same length"
        );
        crypto::pq::setup_aggregate_verifier();
        Self {
            attestation_pubkeys,
            proposal_pubkeys,
        }
    }
}

/// [`GossipSignatureVerifier`] impl using PQ crypto.
impl GossipSignatureVerifier for SimpleGossipVerifier {
    fn verify_block_signature(
        &self,
        proposer_index: ValidatorIndex,
        message: &Block,
        signature: &Bytes3112,
    ) -> bool {
        let idx = proposer_index.0.0 as usize;
        let Some(pubkey) = self.proposal_pubkeys.get(idx) else {
            return false;
        };
        let root = message.hash_tree_root();
        let epoch = message.slot.0.0 as u32;
        crypto::pq::verify_signature(pubkey, epoch, &root, signature).is_ok()
    }

    fn verify_signed_attestation_signature(&self, attestation: &SignedAttestation) -> bool {
        let idx = attestation.validator_id.0 as usize;
        let Some(pubkey) = self.attestation_pubkeys.get(idx) else {
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
        let Some(participants) =
            gather_pubkeys(&self.attestation_pubkeys, &attestation.aggregation_bits)
        else {
            return false;
        };
        if participants.is_empty() {
            return false;
        }
        let root = attestation.data.hash_tree_root();
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
    let total = participants.len;
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
    if idx >= participants.len {
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
    let len = participants.len;
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
/// - `AggregatedAttestation` — SSZ decode + aggregated signature verification.
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
                warn!("gossip block decode failed");
                return false;
            };
            let message = &block.block.message;
            let block_body = &message.block.body;
            let proposer_attestation = &message.proposer_attestation;
            if proposer_attestation_present(proposer_attestation) {
                if proposer_attestation.data.slot != message.block.slot {
                    warn!(
                        "gossip block rejected: proposer attestation slot mismatch att_slot={} block_slot={}",
                        proposer_attestation.data.slot.0.0, message.block.slot.0.0
                    );
                    return false;
                }
                let proposer_bits = set_bits(&proposer_attestation.aggregation_bits);
                if proposer_bits.len() != 1 {
                    warn!(
                        "gossip block rejected: proposer aggregation bits count={} expected=1",
                        proposer_bits.len()
                    );
                    return false;
                }
                if proposer_bits[0] != message.block.proposer_index.0.0 as usize {
                    warn!(
                        "gossip block rejected: proposer bit index={} proposer_index={}",
                        proposer_bits[0], message.block.proposer_index.0.0
                    );
                    return false;
                }
            }
            if !verifier.verify_block_signature(
                message.block.proposer_index,
                &message.block,
                &block.block.signature.proposer_signature,
            ) {
                warn!(
                    "gossip block rejected: proposer signature invalid slot={} proposer={}",
                    message.block.slot.0.0, message.block.proposer_index.0.0
                );
                return false;
            }
            let proofs = &block.block.signature.attestation_signatures;
            if block_body.attestations.len() != proofs.len() {
                warn!(
                    "gossip block rejected: attestation/proof length mismatch attestations={} proofs={}",
                    block_body.attestations.len(),
                    proofs.len()
                );
                return false;
            }
            for (idx, (attestation, proof)) in block_body
                .attestations
                .iter()
                .zip(proofs.iter())
                .enumerate()
            {
                if proof.participants != attestation.aggregation_bits {
                    warn!(
                        "gossip block attestation participants mismatch at index={idx}: proof bits differ from attestation bits"
                    );
                    return false;
                }
                if !verifier.verify_attestation_signature(attestation, proof) {
                    warn!(
                        "gossip block rejected: attestation aggregate signature invalid at index={idx}"
                    );
                    return false;
                }
            }
            true
        }
        GossipValidatorKind::BlockHeader => GossipBlockHeader::decode_ssz_checked(payload).is_ok(),
        GossipValidatorKind::Attestation => {
            // Attestation gossip is a signed attestation (single validator).
            let Ok(attestation) = GossipAttestation::decode_ssz_checked(payload) else {
                warn!(
                    "gossip attestation decode failed {}",
                    describe_attestation_topic_payload(payload)
                );
                return false;
            };
            let ok = verifier.verify_signed_attestation_signature(&attestation.attestation);
            if !ok {
                warn!(
                    "gossip attestation rejected: signature invalid validator={} slot={}",
                    attestation.attestation.validator_id.0,
                    attestation.attestation.message.slot.0.0
                );
            }
            ok
        }
        GossipValidatorKind::AggregatedAttestation => {
            let Ok(attestation) = GossipAggregatedAttestation::decode_ssz_checked(payload) else {
                warn!("gossip aggregated attestation decode failed");
                return false;
            };
            let signed = &attestation.attestation;
            if set_bits(&signed.proof.participants).is_empty() {
                warn!("gossip aggregated attestation rejected: no participants set");
                return false;
            }
            let aggregated = Attestation {
                aggregation_bits: signed.proof.participants.clone(),
                data: signed.data.clone(),
            };
            let ok = verifier.verify_attestation_signature(&aggregated, &signed.proof);
            if !ok {
                warn!(
                    "gossip aggregated attestation rejected: aggregate signature invalid slot={}",
                    signed.data.slot.0.0
                );
            }
            ok
        }
        GossipValidatorKind::VoluntaryExit => VoluntaryExit::decode_ssz_checked(payload).is_ok(),
    }
}

pub fn verifier_from_validators(validators: &[Validator]) -> Arc<dyn GossipSignatureVerifier> {
    if validators.is_empty() {
        return Arc::new(NoopGossipVerifier);
    }
    let len = validators.len();
    let mut attestation_pubkeys = Vec::with_capacity(len);
    let mut proposal_pubkeys = Vec::with_capacity(len);
    // SAFETY:
    // - both vectors are allocated with capacity `len`.
    // - the loop writes each slot in `0..len` exactly once.
    // - lengths are increased only after the corresponding slots are initialized.
    unsafe {
        for (idx, validator) in validators.iter().enumerate() {
            write_at(&mut attestation_pubkeys, idx, validator.attestation_pubkey);
            write_at(&mut proposal_pubkeys, idx, validator.proposal_pubkey);
            let initialized_len = idx.unchecked_add(1);
            attestation_pubkeys.set_len(initialized_len);
            proposal_pubkeys.set_len(initialized_len);
        }
    }
    Arc::new(SimpleGossipVerifier::new(
        attestation_pubkeys,
        proposal_pubkeys,
    ))
}

#[cfg(test)]
mod tests {
    use super::{GossipSignatureVerifier, SimpleGossipVerifier};
    use peam_consensus_types::containers::attestation::{
        AggregatedSignatureProof, Attestation, AttestationData, PROOF_MAX_BYTES,
    };
    use peam_consensus_types::containers::block::{Block, BlockBody};
    use peam_consensus_types::containers::checkpoint::Checkpoint;
    use peam_consensus_types::containers::validator::ValidatorIndex;
    use peam_consensus_types::slot::Slot;
    use peam_consensus_types::types::bitlist::BitList;
    use peam_consensus_types::types::bytes::{ByteList, Bytes32, Bytes52};
    use peam_consensus_types::types::collections::SszList;
    use peam_consensus_types::types::uint::Uint64;
    use crate::crypto::pq::{self, DevnetValidatorKeyRole};
    use crate::ssz::HashTreeRoot;

    fn sample_attestation_data(slot: u64) -> AttestationData {
        let checkpoint = Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        };
        AttestationData {
            slot: Slot(Uint64(slot)),
            head: checkpoint,
            target: checkpoint,
            source: checkpoint,
        }
    }

    #[test]
    fn simple_verifier_rejects_placeholder_aggregate_proof() {
        let verifier = SimpleGossipVerifier {
            attestation_pubkeys: vec![Bytes52::from([0u8; 52])],
            proposal_pubkeys: vec![Bytes52::from([0u8; 52])],
        };
        let bits = BitList::new(vec![true]).expect("bits");
        let attestation = Attestation {
            aggregation_bits: bits.clone(),
            data: sample_attestation_data(1),
        };
        let proof = AggregatedSignatureProof {
            participants: bits,
            proof_data: ByteList::<PROOF_MAX_BYTES>::new(Vec::new()).expect("proof bytes"),
        };

        assert!(!verifier.verify_attestation_signature(&attestation, &proof));
    }

    #[test]
    fn simple_verifier_rejects_invalid_non_placeholder_aggregate_proof() {
        let verifier = SimpleGossipVerifier {
            attestation_pubkeys: vec![Bytes52::from([0u8; 52])],
            proposal_pubkeys: vec![Bytes52::from([0u8; 52])],
        };
        let bits = BitList::new(vec![true]).expect("bits");
        let attestation = Attestation {
            aggregation_bits: bits.clone(),
            data: sample_attestation_data(2),
        };
        let proof = AggregatedSignatureProof {
            participants: bits,
            proof_data: ByteList::<PROOF_MAX_BYTES>::new(vec![0u8; 10]).expect("proof bytes"),
        };

        assert!(!verifier.verify_attestation_signature(&attestation, &proof));
    }

    #[test]
    fn simple_verifier_uses_proposal_pubkeys_for_block_signatures() {
        std::thread::Builder::new()
            .name("proposal-pubkey-verifier-test".to_string())
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let block = Block {
                    slot: Slot(Uint64(4)),
                    proposer_index: ValidatorIndex(Uint64(0)),
                    parent_root: Bytes32::zero(),
                    state_root: Bytes32::zero(),
                    body: BlockBody {
                        attestations: SszList::new(vec![]).expect("attestations"),
                    },
                };
                let (attestation_pubkey, attestation_signature) = {
                    pq::key_gen_for_devnet_validator_with_role(
                        0,
                        DevnetValidatorKeyRole::Attestation,
                    )
                    .map(|(pubkey, secret_key)| {
                        let message_root = block.hash_tree_root();
                        let signature = pq::sign_message(&secret_key, 4, &message_root)
                            .expect("attestation signature");
                        (pubkey, signature)
                    })
                    .expect("attestation key")
                };
                let (proposal_pubkey, proposal_signature) = {
                    pq::key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Proposal)
                        .map(|(pubkey, secret_key)| {
                            let message_root = block.hash_tree_root();
                            let signature = pq::sign_message(&secret_key, 4, &message_root)
                                .expect("proposal signature");
                            (pubkey, signature)
                        })
                        .expect("proposal key")
                };

                let verifier =
                    SimpleGossipVerifier::new(vec![attestation_pubkey], vec![proposal_pubkey]);
                assert!(verifier.verify_block_signature(
                    ValidatorIndex(Uint64(0)),
                    &block,
                    &proposal_signature
                ));
                assert!(!verifier.verify_block_signature(
                    ValidatorIndex(Uint64(0)),
                    &block,
                    &attestation_signature
                ));
            })
            .expect("spawn verifier test thread")
            .join()
            .expect("join verifier test thread");
    }
}
