//! Gossipsub message validation logic.
//!
//! Two validation passes are defined:
//!
//! 1. **Basic validation** ([`validate_basic_message`]) — structural checks
//!    that require no external context (slot ordering, proposer-slot match,
//!    etc.).
//! 2. **Context validation** ([`validate_with_context`]) — slot-range checks
//!    that require a live [`GossipContext`] (future-slot, finalized-slot).
//!
//! Each function returns a [`ValidationResult`] whose variant determines how
//! the p2p layer scores and propagates the message.

use crate::containers::attestation::{
    ATTESTATION_COMMITTEE_COUNT, AttestationData, SignedAttestation,
};
use crate::containers::block::SignedBlockWithAttestation;
use crate::networking::gossipsub::context::GossipContext;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;

/// The outcome of a gossip validation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Message is valid and should be forwarded.
    Accept,
    /// Message should be silently dropped; carries a human-readable reason.
    Ignore(String),
    /// Message is invalid; the sender should be penalised; carries a reason.
    Reject(String),
}

/// Runs basic (context-free) validation on a decoded gossipsub message.
///
/// Dispatches to [`validate_block_basic`] or [`validate_attestation_basic`]
/// as appropriate.
pub fn validate_basic_message(message: &LeanGossipsubMessage) -> ValidationResult {
    match message {
        LeanGossipsubMessage::Block(block) => validate_block_basic(&block.block),
        LeanGossipsubMessage::Attestation(attestation) => {
            validate_attestation_basic(&attestation.attestation)
        }
        LeanGossipsubMessage::AttestationSubnet {
            subnet_id,
            attestation,
        } => validate_subnet_attestation_basic(*subnet_id, &attestation.attestation),
    }
}

/// Runs context-dependent (slot-range) validation on a decoded message.
///
/// Requires a [`GossipContext`] to compare against the node's current and
/// finalized slots.
pub fn validate_with_context(
    message: &LeanGossipsubMessage,
    context: &dyn GossipContext,
) -> ValidationResult {
    match message {
        LeanGossipsubMessage::Block(block) => validate_block_with_context(&block.block, context),
        LeanGossipsubMessage::Attestation(attestation) => {
            validate_attestation_with_context(&attestation.attestation, context)
        }
        LeanGossipsubMessage::AttestationSubnet {
            subnet_id,
            attestation,
        } => {
            validate_subnet_attestation_with_context(*subnet_id, &attestation.attestation, context)
        }
    }
}

/// Basic block validation: proposer-attestation slot match and per-attestation
/// field checks.
fn validate_block_basic(block: &SignedBlockWithAttestation) -> ValidationResult {
    let message = &block.message;
    let proposer_attestation = &message.proposer_attestation;
    if proposer_attestation.data.slot != message.block.slot {
        return ValidationResult::Reject("proposer attestation slot mismatch".to_string());
    }
    for att in message.block.body.attestations.data.iter() {
        let res = validate_attestation_fields(&att.data, Some(message.block.slot.0.0));
        if !matches!(res, ValidationResult::Accept) {
            return res;
        }
    }
    ValidationResult::Accept
}

/// Basic attestation validation: delegates to [`validate_attestation_fields`]
/// with no slot upper bound.
fn validate_attestation_basic(attestation: &SignedAttestation) -> ValidationResult {
    validate_attestation_fields(&attestation.message, None)
}

/// Basic attestation-subnet validation: validator must publish on its assigned subnet.
fn validate_subnet_attestation_basic(
    subnet_id: u64,
    attestation: &SignedAttestation,
) -> ValidationResult {
    let committee_count = ATTESTATION_COMMITTEE_COUNT;
    let expected_subnet = if committee_count <= 1 {
        0
    } else {
        attestation.validator_id.0 % committee_count
    };
    if expected_subnet != subnet_id {
        return ValidationResult::Reject("attestation published on wrong subnet".to_string());
    }
    validate_attestation_fields(&attestation.message, None)
}

/// Validates attestation data fields.
///
/// Checks:
/// - `target.slot > source.slot`
/// - if `max_slot` is provided: `data.slot <= max_slot`
fn validate_attestation_fields(
    attestation: &AttestationData,
    max_slot: Option<u64>,
) -> ValidationResult {
    let data = attestation;
    if data.target.slot <= data.source.slot {
        return ValidationResult::Reject("attestation target not above source".to_string());
    }
    if data.head.slot < data.target.slot {
        return ValidationResult::Reject("attestation head below target".to_string());
    }
    if data.slot < data.head.slot {
        return ValidationResult::Reject("attestation slot below head slot".to_string());
    }
    if let Some(max_slot) = max_slot {
        if data.slot.0.0 > max_slot {
            return ValidationResult::Ignore("attestation from future slot".to_string());
        }
    }
    ValidationResult::Accept
}

/// Context validation for blocks: rejects blocks at or before finalized,
/// ignores blocks from future slots.
fn validate_block_with_context(
    block: &SignedBlockWithAttestation,
    context: &dyn GossipContext,
) -> ValidationResult {
    if !context.knows_block_root(&block.message.block.parent_root) {
        return ValidationResult::Ignore("block parent root unknown locally".to_string());
    }
    if let Some(finalized_slot) = context.finalized_slot() {
        if block.message.block.slot <= finalized_slot {
            return ValidationResult::Ignore("block at or before finalized slot".to_string());
        }
    }
    if let Some(current_slot) = context.current_slot() {
        if block.message.block.slot.0.0 > current_slot.0.0 + 1 {
            return ValidationResult::Ignore("block from future slot".to_string());
        }
    }
    let proposer_check = validate_attestation_with_context(
        &SignedAttestation {
            validator_id: crate::types::uint::Uint64(0),
            message: block.message.proposer_attestation.data.clone(),
            signature: crate::types::bytes::Bytes3112::zero(),
        },
        context,
    );
    if !matches!(proposer_check, ValidationResult::Accept) {
        return proposer_check;
    }
    for att in block.message.block.body.attestations.data.iter() {
        let check = validate_attestation_fields(&att.data, Some(block.message.block.slot.0.0));
        if !matches!(check, ValidationResult::Accept) {
            return check;
        }
        if !context.knows_block_root(&att.data.head.root)
            || !context.knows_block_root(&att.data.source.root)
            || !context.knows_block_root(&att.data.target.root)
        {
            return ValidationResult::Ignore(
                "attestation references unknown chain roots".to_string(),
            );
        }
    }
    ValidationResult::Accept
}

/// Context validation for attestations: ignores attestations from future slots.
fn validate_attestation_with_context(
    attestation: &SignedAttestation,
    context: &dyn GossipContext,
) -> ValidationResult {
    let msg = &attestation.message;
    if msg.target.slot <= msg.source.slot {
        return ValidationResult::Reject("attestation target not above source".to_string());
    }
    if msg.head.slot < msg.target.slot {
        return ValidationResult::Reject("attestation head below target".to_string());
    }
    if !context.knows_block_root(&msg.head.root)
        || !context.knows_block_root(&msg.source.root)
        || !context.knows_block_root(&msg.target.root)
    {
        return ValidationResult::Ignore("attestation references unknown chain roots".to_string());
    }
    if let Some(current_slot) = context.current_slot() {
        if msg.slot.0.0 > current_slot.0.0 + 1 {
            return ValidationResult::Ignore("attestation from future slot".to_string());
        }
    }
    if let Some(finalized_slot) = context.finalized_slot() {
        if msg.source.slot < finalized_slot {
            return ValidationResult::Ignore(
                "attestation source before finalized slot".to_string(),
            );
        }
    }
    ValidationResult::Accept
}

fn validate_subnet_attestation_with_context(
    subnet_id: u64,
    attestation: &SignedAttestation,
    context: &dyn GossipContext,
) -> ValidationResult {
    let basic = validate_subnet_attestation_basic(subnet_id, attestation);
    if !matches!(basic, ValidationResult::Accept) {
        return basic;
    }
    validate_attestation_with_context(attestation, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::checkpoint::Checkpoint;
    use crate::networking::gossipsub::context::GossipContext;
    use crate::slot::Slot;
    use crate::types::bytes::{Bytes32, Bytes3112};
    use crate::types::uint::Uint64;

    struct MockContext {
        current: Option<Slot>,
        finalized: Option<Slot>,
        known: std::collections::HashSet<Bytes32>,
    }

    impl GossipContext for MockContext {
        fn current_slot(&self) -> Option<Slot> {
            self.current
        }
        fn finalized_slot(&self) -> Option<Slot> {
            self.finalized
        }
        fn knows_block_root(&self, root: &Bytes32) -> bool {
            self.known.contains(root)
        }
    }

    fn signed_attestation(slot: u64, source: u64, target: u64, head: u64) -> SignedAttestation {
        SignedAttestation {
            validator_id: Uint64(0),
            message: AttestationData {
                slot: Slot(Uint64(slot)),
                source: Checkpoint {
                    root: Bytes32::from([1; 32]),
                    slot: Slot(Uint64(source)),
                },
                target: Checkpoint {
                    root: Bytes32::from([2; 32]),
                    slot: Slot(Uint64(target)),
                },
                head: Checkpoint {
                    root: Bytes32::from([3; 32]),
                    slot: Slot(Uint64(head)),
                },
            },
            signature: Bytes3112::zero(),
        }
    }

    #[test]
    fn attestation_context_rejects_inconsistent_time_geometry() {
        let ctx = MockContext {
            current: Some(Slot(Uint64(10))),
            finalized: Some(Slot(Uint64(5))),
            known: [
                Bytes32::from([1; 32]),
                Bytes32::from([2; 32]),
                Bytes32::from([3; 32]),
            ]
            .into_iter()
            .collect(),
        };
        let att = signed_attestation(9, 8, 9, 8);
        let res = validate_attestation_with_context(&att, &ctx);
        assert!(matches!(res, ValidationResult::Reject(_)));
    }

    #[test]
    fn attestation_context_ignores_far_future_slot() {
        let ctx = MockContext {
            current: Some(Slot(Uint64(10))),
            finalized: Some(Slot(Uint64(5))),
            known: [
                Bytes32::from([1; 32]),
                Bytes32::from([2; 32]),
                Bytes32::from([3; 32]),
            ]
            .into_iter()
            .collect(),
        };
        let att = signed_attestation(12, 8, 9, 10);
        let res = validate_attestation_with_context(&att, &ctx);
        assert!(matches!(res, ValidationResult::Ignore(_)));
    }

    #[test]
    fn subnet_attestation_rejects_wrong_subnet() {
        let att = signed_attestation(10, 8, 9, 10);
        // With committee count set to 1, validator 0 must publish on subnet 0.
        let res = validate_subnet_attestation_basic(1, &att);
        assert!(matches!(res, ValidationResult::Reject(_)));
    }
}
