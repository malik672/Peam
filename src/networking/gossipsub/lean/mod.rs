pub mod message;
pub mod topics;

use libp2p::gossipsub::TopicHash;

use crate::networking::gossipsub::error::GossipsubError;
use crate::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};
use crate::networking::GossipValidatorKind;

pub fn kind_from_topic_hash(topic: &TopicHash) -> Result<GossipValidatorKind, GossipsubError> {
    match LeanGossipTopic::from_topic_hash(topic)?.kind {
        LeanGossipTopicKind::Block => Ok(GossipValidatorKind::Block),
        LeanGossipTopicKind::Attestation => Ok(GossipValidatorKind::Attestation),
        LeanGossipTopicKind::AttestationSubnet(_) => Ok(GossipValidatorKind::Attestation),
    }
}
