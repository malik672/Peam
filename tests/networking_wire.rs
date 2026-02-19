use std::sync::Arc;

use lean_eth::containers::attestation::{AggregatedSignatureProof, Attestation, AttestationData, SignedAttestation};
use lean_eth::containers::block::{Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::containers::gossip::GossipBlock;
use lean_eth::containers::validator::ValidatorIndex;
use lean_eth::networking::gossipsub::lean::message::LeanGossipsubMessage;
use lean_eth::networking::gossipsub::lean::topics::{
    LeanGossipTopic, LeanGossipTopicKind, TOPIC_PREFIX, ENCODING_POSTFIX, LEAN_ATTESTATION_TOPIC,
    LEAN_BLOCK_TOPIC, LEAN_ATTESTATION_SUBNET_PREFIX,
};
use lean_eth::networking::{validate_gossip, GossipSignatureVerifier, GossipValidatorKind, LeanSupportedProtocol, NoopGossipVerifier};
use lean_eth::ssz::SszEncode;
use lean_eth::slot::Slot;
use lean_eth::types::bytes::{ByteList, Bytes3112};
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::collections::SszList;
use lean_eth::types::uint::Uint64;
use libp2p::gossipsub::TopicHash;

#[test]
fn gossip_topic_roundtrip_block() {
    let topic = LeanGossipTopic {
        fork: "devnet2".to_string(),
        kind: LeanGossipTopicKind::Block,
    };
    let hash: TopicHash = topic.clone().into();
    let parsed = LeanGossipTopic::from_topic_hash(&hash).expect("parse");
    assert_eq!(parsed, topic);
    assert_eq!(
        hash.as_str(),
        format!(
            "/{TOPIC_PREFIX}/devnet2/{LEAN_BLOCK_TOPIC}/{ENCODING_POSTFIX}"
        )
    );
}

#[test]
fn gossip_topic_roundtrip_attestation() {
    let topic = LeanGossipTopic {
        fork: "devnet2".to_string(),
        kind: LeanGossipTopicKind::Attestation,
    };
    let hash: TopicHash = topic.clone().into();
    let parsed = LeanGossipTopic::from_topic_hash(&hash).expect("parse");
    assert_eq!(parsed, topic);
    assert_eq!(
        hash.as_str(),
        format!(
            "/{TOPIC_PREFIX}/devnet2/{LEAN_ATTESTATION_TOPIC}/{ENCODING_POSTFIX}"
        )
    );
}

#[test]
fn gossip_topic_roundtrip_attestation_subnet() {
    let topic = LeanGossipTopic {
        fork: "devnet2".to_string(),
        kind: LeanGossipTopicKind::AttestationSubnet(12),
    };
    let hash: TopicHash = topic.clone().into();
    let parsed = LeanGossipTopic::from_topic_hash(&hash).expect("parse");
    assert_eq!(parsed, topic);
    assert_eq!(
        hash.as_str(),
        format!(
            "/{TOPIC_PREFIX}/devnet2/{LEAN_ATTESTATION_SUBNET_PREFIX}12/{ENCODING_POSTFIX}"
        )
    );
}

#[test]
fn gossip_attestation_message_decode_signed() {
    let data = AttestationData {
        slot: Slot(Uint64(1)),
        head: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        target: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        source: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
    };
    let signed = SignedAttestation {
        validator_id: Uint64(1),
        message: data,
        signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    let payload = signed.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet2".to_string(),
        kind: LeanGossipTopicKind::Attestation,
    };
    let topic_hash: TopicHash = topic.into();
    let decoded = LeanGossipsubMessage::decode(&topic_hash, &payload).expect("decode");
    match decoded {
        LeanGossipsubMessage::Attestation(att) => {
            assert_eq!(att.attestation, signed);
        }
        _ => panic!("expected attestation"),
    }
}

#[test]
fn gossip_attestation_subnet_message_decode_signed() {
    let data = AttestationData {
        slot: Slot(Uint64(1)),
        head: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        target: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
        source: Checkpoint {
            root: Bytes32::zero(),
            slot: Slot(Uint64(0)),
        },
    };
    let signed = SignedAttestation {
        validator_id: Uint64(1),
        message: data,
        signature: lean_eth::types::bytes::Bytes3112::zero(),
    };
    let payload = signed.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet2".to_string(),
        kind: LeanGossipTopicKind::AttestationSubnet(3),
    };
    let topic_hash: TopicHash = topic.into();
    let decoded = LeanGossipsubMessage::decode(&topic_hash, &payload).expect("decode");
    match decoded {
        LeanGossipsubMessage::AttestationSubnet { subnet_id, attestation } => {
            assert_eq!(subnet_id, 3);
            assert_eq!(attestation.attestation, signed);
        }
        _ => panic!("expected attestation subnet"),
    }
}

#[test]
fn reqresp_protocol_roundtrip() {
    for proto in [
        LeanSupportedProtocol::StatusV1,
        LeanSupportedProtocol::BlocksByRootV1,
    ] {
        let id = proto.protocol_id();
        let parsed = LeanSupportedProtocol::parse_protocol_id(&id).expect("parse");
        assert_eq!(parsed, proto);
    }
    assert!(LeanSupportedProtocol::parse_protocol_id("/lean_eth/reqresp/status/2").is_none());
    assert!(LeanSupportedProtocol::parse_protocol_id("/other/reqresp/status/1").is_none());
}

#[test]
fn gossip_block_rejects_mismatched_aggregate_participants() {
    let att = Attestation {
        aggregation_bits: lean_eth::types::bitlist::BitList::new(vec![true, false]).expect("bits"),
        data: AttestationData {
            slot: Slot(Uint64(0)),
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let block = Block {
        slot: Slot(Uint64(0)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root: Bytes32::zero(),
        state_root: Bytes32::zero(),
        body: BlockBody {
            attestations: SszList::new(vec![att]).expect("atts"),
        },
    };
    let proposer_attestation = Attestation {
        aggregation_bits: lean_eth::types::bitlist::BitList::new(vec![true]).expect("bits"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let proof = AggregatedSignatureProof {
        participants: lean_eth::types::bitlist::BitList::new(vec![false, true]).expect("parts"),
        proof_data: ByteList::new(vec![0x42]).expect("proof"),
    };
    let signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![proof]).expect("sigs"),
            proposer_signature: Bytes3112::zero(),
        },
    };
    let payload = GossipBlock { block: signed }.encode_ssz();
    let verifier: Arc<dyn GossipSignatureVerifier> = Arc::new(NoopGossipVerifier);
    assert!(!validate_gossip(
        GossipValidatorKind::Block,
        &payload,
        &verifier,
    ));
}
