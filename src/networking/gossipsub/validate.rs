use crate::containers::attestation::{AttestationData, SignedAttestation};
use crate::containers::block::SignedBlockWithAttestation;
use crate::networking::gossipsub::context::GossipContext;
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Accept,
    Ignore(String),
    Reject(String),
}

pub fn validate_basic_message(message: &LeanGossipsubMessage) -> ValidationResult {
    match message {
        LeanGossipsubMessage::Block(block) => validate_block_basic(&block.block),
        LeanGossipsubMessage::Attestation(attestation) => {
            validate_attestation_basic(&attestation.attestation)
        }
        LeanGossipsubMessage::AttestationSubnet { attestation, .. } => {
            validate_attestation_basic(&attestation.attestation)
        }
    }
}

pub fn validate_with_context(
    message: &LeanGossipsubMessage,
    context: &dyn GossipContext,
) -> ValidationResult {
    match message {
        LeanGossipsubMessage::Block(block) => validate_block_with_context(&block.block, context),
        LeanGossipsubMessage::Attestation(attestation) => {
            validate_attestation_with_context(&attestation.attestation, context)
        }
        LeanGossipsubMessage::AttestationSubnet { attestation, .. } => {
            validate_attestation_with_context(&attestation.attestation, context)
        }
    }
}

fn validate_block_basic(block: &SignedBlockWithAttestation) -> ValidationResult {
    let message = &block.message;
    let proposer_attestation = &message.proposer_attestation;
    if proposer_attestation.data.slot != message.block.slot {
        return ValidationResult::Reject("proposer attestation slot mismatch".to_string());
    }
    for att in message.block.body.attestations.data.iter() {
        let res = validate_attestation_fields(&att.data, Some(message.block.slot.0 .0));
        if !matches!(res, ValidationResult::Accept) {
            return res;
        }
    }
    ValidationResult::Accept
}

fn validate_attestation_basic(attestation: &SignedAttestation) -> ValidationResult {
    validate_attestation_fields(&attestation.message, None)
}

fn validate_attestation_fields(
    attestation: &AttestationData,
    max_slot: Option<u64>,
) -> ValidationResult {
    let data = attestation;
    if data.target.slot < data.source.slot {
        return ValidationResult::Reject("attestation target below source".to_string());
    }
    if let Some(max_slot) = max_slot {
        if data.slot.0 .0 > max_slot {
            return ValidationResult::Ignore("attestation from future slot".to_string());
        }
    }
    ValidationResult::Accept
}

fn validate_block_with_context(
    block: &SignedBlockWithAttestation,
    context: &dyn GossipContext,
) -> ValidationResult {
    if let Some(finalized_slot) = context.finalized_slot() {
        if block.message.block.slot <= finalized_slot {
            return ValidationResult::Ignore("block at or before finalized slot".to_string());
        }
    }
    if let Some(current_slot) = context.current_slot() {
        if block.message.block.slot > current_slot {
            return ValidationResult::Ignore("block from future slot".to_string());
        }
    }
    ValidationResult::Accept
}

fn validate_attestation_with_context(
    attestation: &SignedAttestation,
    context: &dyn GossipContext,
) -> ValidationResult {
    if let Some(current_slot) = context.current_slot() {
        if attestation.message.slot > current_slot {
            return ValidationResult::Ignore("attestation from future slot".to_string());
        }
    }
    ValidationResult::Accept
}
