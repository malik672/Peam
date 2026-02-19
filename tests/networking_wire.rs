use lean_eth::containers::attestation::{AttestationData, SignedAttestation};
use lean_eth::containers::checkpoint::Checkpoint;
use lean_eth::networking::gossipsub::lean::message::LeanGossipsubMessage;
use lean_eth::networking::gossipsub::lean::topics::{
    LeanGossipTopic, LeanGossipTopicKind, TOPIC_PREFIX, ENCODING_POSTFIX, LEAN_ATTESTATION_TOPIC,
    LEAN_BLOCK_TOPIC, LEAN_ATTESTATION_SUBNET_PREFIX,
};
use lean_eth::networking::LeanSupportedProtocol;
use lean_eth::ssz::SszEncode;
use lean_eth::slot::Slot;
use lean_eth::types::bytes::Bytes32;
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
