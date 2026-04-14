use std::sync::{Arc, RwLock};

use peam::containers::attestation::{Attestation, AttestationData, SignedAttestation};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::gossip::{GossipAttestation, GossipBlock};
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::crypto::pq::{DevnetValidatorKeyRole, key_gen_for_devnet_validator_with_role, sign_message};
use peam::metrics::MetricsRegistry;
use peam::networking::gossipsub::lean::topics::{LeanGossipTopic, LeanGossipTopicKind};
use peam::node::handle_gossip_event;
use peam::slot::Slot;
use peam::ssz::{HashTreeRoot, SszEncode};
use peam::storage::MemoryStore;
use peam::types::bitlist::BitList;
use peam::types::bytes::{Bytes32, Bytes3112};
use peam::types::collections::SszList;
use peam::types::uint::Uint64;

fn build_signed_block(state: &State, slot: u64) -> (SignedBlockWithAttestation, State, Bytes32) {
    let mut temp = state.clone();
    temp.process_slots(Slot(Uint64(slot)))
        .expect("process slots");
    let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
    let body = BlockBody {
        attestations: SszList::new(vec![]).expect("attestations"),
    };
    let mut block = Block {
        slot: Slot(Uint64(slot)),
        proposer_index: ValidatorIndex(Uint64(0)),
        parent_root,
        state_root: Bytes32::zero(),
        body,
    };
    let mut post = state.clone();
    post.process_slots(block.slot).expect("process slots");
    let header = block.header();
    post.process_block_header(header).expect("process header");
    post.process_block_body(&block.body, header.body_root)
        .expect("process body");
    block.state_root = Bytes32::from(post.hash_tree_root());

    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
        data: AttestationData {
            slot: block.slot,
            head: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(slot)),
            },
            target: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(slot)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
    };
    let (_, secret_key) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Proposal)
            .expect("validator key");
    let proposer_message = proposer_attestation.data.hash_tree_root();
    let proposer_signature = sign_message(
        &secret_key,
        proposer_attestation.data.slot.0.0 as u32,
        &proposer_message,
    )
    .expect("proposer signature");

    let message = BlockWithAttestation {
        block,
        proposer_attestation,
    };
    let signature = BlockSignatures {
        attestation_signatures: SszList::new(vec![]).expect("attestation sigs"),
        proposer_signature,
    };
    let root = Bytes32::from(message.block.hash_tree_root());
    (
        SignedBlockWithAttestation { message, signature },
        post,
        root,
    )
}

#[test]
#[ignore = "integration test uses placeholder signatures; pq path is covered separately"]
fn gossip_block_updates_fork_choice_head() {
    let (pubkey, _) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Attestation)
            .expect("validator key");
    let v = Validator {
        attestation_pubkey: pubkey,
        proposal_pubkey: pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = Arc::new(RwLock::new(State::generate_genesis(Uint64(0), validators)));
    let store = Arc::new(RwLock::new(MemoryStore::new()));
    let fork_choice = Arc::new(RwLock::new(None));
    let pending_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_individual_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_block_attestations = Arc::new(RwLock::new(Vec::new()));
    let metrics = Arc::new(MetricsRegistry::new());

    let (signed, _post, root) = {
        let s = state.read().expect("state lock");
        build_signed_block(&s, 1)
    };
    let gossip = GossipBlock { block: signed };
    let payload = gossip.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::Block,
    }
    .to_string();

    handle_gossip_event(
        &topic,
        &payload,
        &state,
        &store,
        &fork_choice,
        &pending_attestations,
        &pending_individual_attestations,
        &pending_block_attestations,
        false,
        &metrics,
    );
    let fc = fork_choice.read().expect("fork choice lock");
    let fc = fc.as_ref().expect("fork choice");
    assert_eq!(fc.head(), root);
}

#[test]
#[ignore = "integration test uses placeholder signatures; pq path is covered separately"]
fn gossip_attestation_enqueues_for_aggregation_when_aggregator() {
    let (pubkey, _) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Attestation)
            .expect("validator key");
    let v = Validator {
        attestation_pubkey: pubkey,
        proposal_pubkey: pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = Arc::new(RwLock::new(State::generate_genesis(Uint64(0), validators)));
    let store = Arc::new(RwLock::new(MemoryStore::new()));
    let fork_choice = Arc::new(RwLock::new(None));
    let pending_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_individual_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_block_attestations = Arc::new(RwLock::new(Vec::new()));
    let metrics = Arc::new(MetricsRegistry::new());

    let (signed, _post, root) = {
        let s = state.read().expect("state lock");
        build_signed_block(&s, 1)
    };
    let gossip = GossipBlock { block: signed };
    let payload = gossip.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::Block,
    }
    .to_string();

    handle_gossip_event(
        &topic,
        &payload,
        &state,
        &store,
        &fork_choice,
        &pending_attestations,
        &pending_individual_attestations,
        &pending_block_attestations,
        false,
        &metrics,
    );

    let signed_att = SignedAttestation {
        validator_id: Uint64(0),
        message: AttestationData {
            slot: Slot(Uint64(1)),
            head: Checkpoint {
                root,
                slot: Slot(Uint64(1)),
            },
            target: Checkpoint {
                root,
                slot: Slot(Uint64(1)),
            },
            source: Checkpoint {
                root: Bytes32::zero(),
                slot: Slot(Uint64(0)),
            },
        },
        signature: Bytes3112::zero(),
    };
    let gossip_att = GossipAttestation {
        attestation: signed_att,
    };
    let att_payload = gossip_att.encode_ssz();
    let att_topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::AttestationSubnet(0),
    }
    .to_string();

    handle_gossip_event(
        &att_topic,
        &att_payload,
        &state,
        &store,
        &fork_choice,
        &pending_attestations,
        &pending_individual_attestations,
        &pending_block_attestations,
        true,
        &metrics,
    );
    let pending = pending_individual_attestations
        .read()
        .expect("pending individual attestations lock");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message.head.root, root);
}

#[test]
fn gossip_block_enqueues_proposer_attestation_for_future_aggregation() {
    let (pubkey, _) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Attestation)
            .expect("validator key");
    let v = Validator {
        attestation_pubkey: pubkey,
        proposal_pubkey: pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    };
    let validators = Validators::new(vec![v]).expect("validators");
    let state = Arc::new(RwLock::new(State::generate_genesis(Uint64(0), validators)));
    let store = Arc::new(RwLock::new(MemoryStore::new()));
    let fork_choice = Arc::new(RwLock::new(None));
    let pending_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_individual_attestations = Arc::new(RwLock::new(Vec::new()));
    let pending_block_attestations = Arc::new(RwLock::new(Vec::new()));
    let metrics = Arc::new(MetricsRegistry::new());

    let (signed, _post, _root) = {
        let s = state.read().expect("state lock");
        build_signed_block(&s, 1)
    };
    let expected = signed.message.proposer_attestation.clone();
    let gossip = GossipBlock { block: signed };
    let payload = gossip.encode_ssz();
    let topic = LeanGossipTopic {
        fork: "devnet3".to_string(),
        kind: LeanGossipTopicKind::Block,
    }
    .to_string();

    handle_gossip_event(
        &topic,
        &payload,
        &state,
        &store,
        &fork_choice,
        &pending_attestations,
        &pending_individual_attestations,
        &pending_block_attestations,
        false,
        &metrics,
    );

    let pending = pending_attestations
        .read()
        .expect("pending attestations lock");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0], expected);
}
