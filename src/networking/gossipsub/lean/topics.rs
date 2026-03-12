//! Lean-Ethereum gossipsub topic definitions.
//!
//! Topics follow the format:
//! ```text
//! /{TOPIC_PREFIX}/{fork}/{kind}/{ENCODING_POSTFIX}
//! ```
//! e.g. `/leanconsensus/devnet3/blocks/ssz_snappy`.
//!
//! [`LeanGossipTopic`] represents a parsed topic and converts to/from libp2p
//! [`TopicHash`] and [`IdentTopic`].

use libp2p::gossipsub::{IdentTopic as Topic, TopicHash};

use crate::networking::gossipsub::error::GossipsubError;

/// Common prefix for all lean-Ethereum gossipsub topics.
pub const TOPIC_PREFIX: &str = "leanconsensus";
/// Encoding suffix appended to every topic string.
pub const ENCODING_POSTFIX: &str = "ssz_snappy";

/// Canonical topic name segment for full signed blocks.
pub const LEAN_BLOCK_TOPIC: &str = "blocks";
/// Topic name segment for aggregated-attestation gossip.
pub const LEAN_AGGREGATION_TOPIC: &str = "aggregation";
/// Prefix for per-subnet attestation topics.
pub const LEAN_ATTESTATION_SUBNET_PREFIX: &str = "attestation_";

/// A parsed lean-Ethereum gossipsub topic.
///
/// Carries the fork string (e.g. `"devnet3"`) and the message [`LeanGossipTopicKind`].
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LeanGossipTopic {
    /// Fork identifier, e.g. `"devnet3"`.
    pub fork: String,
    /// Message kind encoded in the topic.
    pub kind: LeanGossipTopicKind,
}

impl LeanGossipTopic {
    /// Parses a libp2p [`TopicHash`] into a [`LeanGossipTopic`].
    ///
    /// Expected format: `/{TOPIC_PREFIX}/{fork}/{kind}/{ENCODING_POSTFIX}`
    ///
    /// # Errors
    ///
    /// Returns [`GossipsubError::InvalidTopic`] if the format is wrong or the
    /// kind segment is unrecognised.
    pub fn from_topic_hash(topic: &TopicHash) -> Result<Self, GossipsubError> {
        let topic_parts: Vec<&str> = topic.as_str().trim_start_matches('/').split('/').collect();

        if topic_parts.len() != 4
            || topic_parts[0] != TOPIC_PREFIX
            || topic_parts[3] != ENCODING_POSTFIX
        {
            return Err(GossipsubError::InvalidTopic(format!(
                "Invalid topic format: {topic:?}"
            )));
        }

        let fork = topic_parts[1].to_string();
        let topic_name = topic_parts[2];

        let kind = match topic_name {
            LEAN_BLOCK_TOPIC => LeanGossipTopicKind::Block,
            LEAN_AGGREGATION_TOPIC => LeanGossipTopicKind::AggregatedAttestation,
            other if other.starts_with(LEAN_ATTESTATION_SUBNET_PREFIX) => {
                let subnet_str = other.trim_start_matches(LEAN_ATTESTATION_SUBNET_PREFIX);
                let subnet_id = subnet_str.parse::<u64>().map_err(|err| {
                    GossipsubError::InvalidTopic(format!(
                        "Invalid attestation subnet id: {subnet_str:?}, error: {err}"
                    ))
                })?;
                LeanGossipTopicKind::AttestationSubnet(subnet_id)
            }
            other => {
                return Err(GossipsubError::InvalidTopic(format!(
                    "Invalid topic: {other:?}"
                )));
            }
        };

        Ok(LeanGossipTopic { fork, kind })
    }
}

/// Renders the full topic string, e.g. `/leanconsensus/devnet3/blocks/ssz_snappy`.
impl std::fmt::Display for LeanGossipTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let topic_name = match &self.kind {
            LeanGossipTopicKind::Block => LEAN_BLOCK_TOPIC.to_string(),
            LeanGossipTopicKind::AggregatedAttestation => LEAN_AGGREGATION_TOPIC.to_string(),
            LeanGossipTopicKind::AttestationSubnet(subnet_id) => {
                format!("{LEAN_ATTESTATION_SUBNET_PREFIX}{subnet_id}")
            }
        };

        write!(
            f,
            "/{TOPIC_PREFIX}/{}/{topic_name}/{ENCODING_POSTFIX}",
            self.fork,
        )
    }
}

/// Converts a [`LeanGossipTopic`] into a libp2p [`IdentTopic`].
impl From<LeanGossipTopic> for Topic {
    fn from(topic: LeanGossipTopic) -> Topic {
        Topic::new(topic)
    }
}

/// Converts a [`LeanGossipTopic`] to its string representation.
impl From<LeanGossipTopic> for String {
    fn from(topic: LeanGossipTopic) -> Self {
        topic.to_string()
    }
}

/// Converts a [`LeanGossipTopic`] into a raw [`TopicHash`].
impl From<LeanGossipTopic> for TopicHash {
    fn from(val: LeanGossipTopic) -> Self {
        let kind_str = match &val.kind {
            LeanGossipTopicKind::Block => LEAN_BLOCK_TOPIC.to_string(),
            LeanGossipTopicKind::AggregatedAttestation => LEAN_AGGREGATION_TOPIC.to_string(),
            LeanGossipTopicKind::AttestationSubnet(subnet_id) => {
                format!("{LEAN_ATTESTATION_SUBNET_PREFIX}{subnet_id}")
            }
        };

        TopicHash::from_raw(format!(
            "/{TOPIC_PREFIX}/{}/{kind_str}/{ENCODING_POSTFIX}",
            val.fork,
        ))
    }
}

/// The category of message carried by a lean-Ethereum gossipsub topic.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub enum LeanGossipTopicKind {
    /// A full signed block.
    Block,
    /// Aggregated attestation gossip payload (data + aggregated signature proof).
    AggregatedAttestation,
    /// A subnet-specific attestation; carries the subnet ID.
    AttestationSubnet(u64),
}

/// Renders the kind as its topic name segment.
impl std::fmt::Display for LeanGossipTopicKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeanGossipTopicKind::Block => write!(f, "{LEAN_BLOCK_TOPIC}"),
            LeanGossipTopicKind::AggregatedAttestation => write!(f, "{LEAN_AGGREGATION_TOPIC}"),
            LeanGossipTopicKind::AttestationSubnet(subnet_id) => {
                write!(f, "{LEAN_ATTESTATION_SUBNET_PREFIX}{subnet_id}")
            }
        }
    }
}
