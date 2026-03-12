use std::sync::Arc;

use libp2p::gossipsub::TopicHash;
use peam::containers::attestation::{
    AggregatedSignatureProof, Attestation, AttestationData, SignedAttestation,
};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::gossip::GossipBlock;
use peam::containers::validator::ValidatorIndex;
use peam::networking::gossipsub::lean::message::LeanGossipsubMessage;
use peam::networking::gossipsub::lean::topics::{
    ENCODING_POSTFIX, LEAN_ATTESTATION_SUBNET_PREFIX, LEAN_BLOCK_TOPIC, LeanGossipTopic,
    LeanGossipTopicKind, TOPIC_PREFIX,
};
use peam::networking::{
    GossipSignatureVerifier, GossipValidatorKind, LeanSupportedProtocol, NoopGossipVerifier,
    validate_gossip,
};
use peam::slot::Slot;
use peam::ssz::SszEncode;
use peam::types::bytes::Bytes32;
use peam::types::bytes::{ByteList, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

#[test]
fn gossip_topic_roundtrip_block() {
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::Block,
    };
    let hash: TopicHash = topic.clone().into();
    let parsed = LeanGossipTopic::from_topic_hash(&hash).expect("parse");
    assert_eq!(parsed, topic);
    assert_eq!(
        hash.as_str(),
        format!("/{TOPIC_PREFIX}/devnet3/{LEAN_BLOCK_TOPIC}/{ENCODING_POSTFIX}")
    );
}

#[test]
fn gossip_topic_rejects_legacy_block_alias() {
    let hash = TopicHash::from_raw(format!("/{TOPIC_PREFIX}/devnet3/block/{ENCODING_POSTFIX}"));
    assert!(LeanGossipTopic::from_topic_hash(&hash).is_err());
}

#[test]
fn gossip_topic_roundtrip_attestation_subnet() {
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::AttestationSubnet(12),
    };
    let hash: TopicHash = topic.clone().into();
    let parsed = LeanGossipTopic::from_topic_hash(&hash).expect("parse");
    assert_eq!(parsed, topic);
    assert_eq!(
        hash.as_str(),
        format!("/{TOPIC_PREFIX}/devnet3/{LEAN_ATTESTATION_SUBNET_PREFIX}12/{ENCODING_POSTFIX}")
    );
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
        signature: peam::types::bytes::Bytes3112::zero(),
    };
    let payload = signed.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::AttestationSubnet(3),
    };
    let topic_hash: TopicHash = topic.into();
    let decoded = LeanGossipsubMessage::decode(&topic_hash, &payload).expect("decode");
    match decoded {
        LeanGossipsubMessage::AttestationSubnet {
            subnet_id,
            attestation,
        } => {
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
    assert!(
        LeanSupportedProtocol::parse_protocol_id("/leanconsensus/req/status/2/ssz_snappy")
            .is_none()
    );
    assert!(LeanSupportedProtocol::parse_protocol_id("/other/req/status/1/ssz_snappy").is_none());
    assert!(LeanSupportedProtocol::parse_protocol_id("/peam/reqresp/status/1").is_none());
}

#[test]
fn gossip_block_rejects_mismatched_aggregate_participants() {
    let att = Attestation {
        aggregation_bits: peam::types::bitlist::BitList::new(vec![true, false]).expect("bits"),
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
        aggregation_bits: peam::types::bitlist::BitList::new(vec![true]).expect("bits"),
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
        participants: peam::types::bitlist::BitList::new(vec![false, true]).expect("parts"),
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
