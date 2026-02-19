use libp2p::gossipsub::TopicHash;

use crate::containers::gossip::{GossipAttestation, GossipBlock};
use crate::networking::gossipsub::error::GossipsubError;
use crate::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanGossipsubMessage {
    Block(Box<GossipBlock>),
    Attestation(Box<GossipAttestation>),
    AttestationSubnet { subnet_id: u64, attestation: Box<GossipAttestation> },
}

impl LeanGossipsubMessage {
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self, GossipsubError> {
        match LeanGossipTopic::from_topic_hash(topic)?.kind {
            LeanGossipTopicKind::Block => Ok(Self::Block(Box::new(
                GossipBlock::decode_ssz_checked(data).map_err(GossipsubError::from)?,
            ))),
            LeanGossipTopicKind::Attestation => Ok(Self::Attestation(Box::new(
                GossipAttestation::decode_ssz_checked(data).map_err(GossipsubError::from)?,
            ))),
            LeanGossipTopicKind::AttestationSubnet(subnet_id) => Ok(Self::AttestationSubnet {
                subnet_id,
                attestation: Box::new(
                    GossipAttestation::decode_ssz_checked(data).map_err(GossipsubError::from)?,
                ),
            }),
        }
    }
}
