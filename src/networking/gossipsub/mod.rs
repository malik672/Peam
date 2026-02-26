//! Gossipsub layer: topic parsing, message decoding, and validation.
//!
//! Sub-modules:
//! - [`context`] — slot/finality context for validation.
//! - [`error`] — error types.
//! - [`lean`] — lean-Ethereum topic/message definitions.
//! - [`validate`] — per-message validation logic.

pub mod context;
pub mod error;
pub mod lean;
pub mod validate;

use libp2p::gossipsub::TopicHash;

use crate::networking::GossipValidatorKind;
use crate::networking::gossipsub::error::GossipsubError;
use crate::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};

/// Maps a libp2p [`TopicHash`] to the corresponding [`GossipValidatorKind`].
///
/// # Errors
///
/// Returns [`GossipsubError::InvalidTopic`] if the topic hash does not match
/// the expected lean-Ethereum format.
pub fn kind_from_topic_hash(topic: &TopicHash) -> Result<GossipValidatorKind, GossipsubError> {
    match LeanGossipTopic::from_topic_hash(topic)?.kind {
        LeanGossipTopicKind::Block => Ok(GossipValidatorKind::Block),
        LeanGossipTopicKind::Attestation => Ok(GossipValidatorKind::Attestation),
        LeanGossipTopicKind::AttestationSubnet(_) => Ok(GossipValidatorKind::Attestation),
    }
}
