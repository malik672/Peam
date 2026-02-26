//! Lean-Ethereum gossipsub topic and message definitions.
//!
//! Sub-modules:
//! - [`message`] — typed gossipsub message envelope.
//! - [`topics`] — topic string constants and [`LeanGossipTopic`] parsing.

pub mod message;
pub mod topics;

use libp2p::gossipsub::TopicHash;

use crate::networking::GossipValidatorKind;
use crate::networking::gossipsub::error::GossipsubError;
use crate::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};

/// Resolves the [`GossipValidatorKind`] for a given libp2p [`TopicHash`].
///
/// Both `Attestation` and `AttestationSubnet` topics map to
/// [`GossipValidatorKind::Attestation`].
///
/// # Errors
///
/// Returns [`GossipsubError::InvalidTopic`] if the hash does not match the
/// lean-Ethereum topic format.
pub fn kind_from_topic_hash(topic: &TopicHash) -> Result<GossipValidatorKind, GossipsubError> {
    match LeanGossipTopic::from_topic_hash(topic)?.kind {
        LeanGossipTopicKind::Block => Ok(GossipValidatorKind::Block),
        LeanGossipTopicKind::Attestation => Ok(GossipValidatorKind::Attestation),
        LeanGossipTopicKind::AttestationSubnet(_) => Ok(GossipValidatorKind::Attestation),
    }
}
