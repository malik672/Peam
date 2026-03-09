//! Typed lean-Ethereum gossipsub message envelope.
//!
//! [`LeanGossipsubMessage`] is the decoded form of a raw gossipsub payload.
//! Decoding is topic-driven: the [`TopicHash`] determines which SSZ type to
//! deserialise the bytes as.

use libp2p::gossipsub::TopicHash;

use crate::containers::gossip::{GossipAggregatedAttestation, GossipAttestation, GossipBlock};
use crate::networking::gossipsub::error::GossipsubError;
use crate::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};

/// A decoded lean-Ethereum gossipsub message.
///
/// Boxed where the inner type is large to keep the enum itself pointer-sized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanGossipsubMessage {
    /// A full signed block received on the block topic.
    Block(Box<GossipBlock>),
    /// An attestation received on the global attestation topic.
    Attestation(Box<GossipAttestation>),
    /// An attestation received on a per-subnet attestation topic.
    AttestationSubnet {
        subnet_id: u64,
        attestation: Box<GossipAttestation>,
    },
    /// An aggregated attestation received on the aggregation topic.
    AggregatedAttestation(Box<GossipAggregatedAttestation>),
}

impl LeanGossipsubMessage {
    /// Decodes `data` into the appropriate message variant for `topic`.
    ///
    /// # Errors
    ///
    /// Returns [`GossipsubError`] if the topic is not a recognised lean topic
    /// or if SSZ decoding fails.
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self, GossipsubError> {
        match LeanGossipTopic::from_topic_hash(topic)?.kind {
            LeanGossipTopicKind::Block => Ok(Self::Block(Box::new(
                GossipBlock::decode_ssz_checked(data).map_err(GossipsubError::from)?,
            ))),
            LeanGossipTopicKind::Attestation => Ok(Self::Attestation(Box::new(
                GossipAttestation::decode_ssz_checked(data).map_err(GossipsubError::from)?,
            ))),
            LeanGossipTopicKind::AggregatedAttestation => {
                Ok(Self::AggregatedAttestation(Box::new(
                    GossipAggregatedAttestation::decode_ssz_checked(data)
                        .map_err(GossipsubError::from)?,
                )))
            }
            LeanGossipTopicKind::AttestationSubnet(subnet_id) => Ok(Self::AttestationSubnet {
                subnet_id,
                attestation: Box::new(
                    GossipAttestation::decode_ssz_checked(data).map_err(GossipsubError::from)?,
                ),
            }),
        }
    }
}
