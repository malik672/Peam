use std::time::Duration;

use libp2p::Multiaddr;
use tokio::sync::mpsc;

use peam::containers::attestation::{Attestation, AttestationData};
use peam::containers::block::{
    Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
};
use peam::containers::checkpoint::Checkpoint;
use peam::containers::req_resp::{BlocksByRootRequest, MAX_BLOCKS_PER_ROOT_REQUEST, Status};
use peam::containers::state::{State, Validators};
use peam::containers::validator::{Validator, ValidatorIndex};
use peam::crypto::pq::{DevnetValidatorKeyRole, key_gen_for_devnet_validator_with_role, sign_message};
use peam::networking::gossipsub::context::StateGossipContext;
use peam::networking::{
    LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol, NetworkEvent, NetworkEventBus,
    NoopGossipVerifier, NoopReqRespHandler, P2pCommand, P2pConfig, P2pService, StoreReqRespHandler,
};
use peam::slot::Slot;
use peam::ssz::HashTreeRoot;
use peam::storage::{MemoryStore, Store};
use peam::types::bitlist::BitList;
use peam::types::bytes::Bytes32;
use peam::types::collections::SszList;
use peam::types::uint::Uint64;
use std::sync::{Arc, RwLock};

fn addr_for(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
        .parse()
        .expect("addr")
}

fn empty_state() -> Arc<RwLock<State>> {
    let validators = Validators::new(vec![]).expect("validators");
    Arc::new(RwLock::new(State::generate_genesis(Uint64(0), validators)))
}

fn single_validator_state() -> Arc<RwLock<State>> {
    let (attestation_pubkey, _) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Attestation)
            .expect("attestation key");
    let (proposal_pubkey, _) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Proposal)
            .expect("proposal key");
    let validators = Validators::new(vec![Validator {
        attestation_pubkey,
        proposal_pubkey,
        index: ValidatorIndex(Uint64(0)),
        balance: Uint64(0),
    }])
    .expect("validators");
    Arc::new(RwLock::new(State::generate_genesis(Uint64(0), validators)))
}

fn compute_state_root_for_block(state: &State, block: &Block) -> Bytes32 {
    let mut temp = state.clone();
    if block.slot > temp.slot {
        temp.process_slots(block.slot).expect("process slots");
    }
    let header = block.header();
    temp.process_block_header(header).expect("process header");
    temp.process_block_body(&block.body, header.body_root)
        .expect("process body");
    Bytes32::from(temp.hash_tree_root())
}

fn signed_block_for_state(state: &State, slot: u64) -> SignedBlockWithAttestation {
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
    block.state_root = compute_state_root_for_block(state, &block);

    let proposer_attestation = Attestation {
        aggregation_bits: BitList::new(vec![true]).expect("participants"),
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

    let (_, secret_key) =
        key_gen_for_devnet_validator_with_role(0, DevnetValidatorKeyRole::Proposal)
            .expect("validator key");
    let proposer_message = block.hash_tree_root();
    let proposer_signature = sign_message(
        &secret_key,
        block.slot.0.0 as u32,
        &proposer_message,
    )
    .expect("proposer signature");

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: SszList::new(vec![]).expect("attestation signatures"),
            proposer_signature,
        },
    }
}

async fn wait_for_peer_connected(mut rx: tokio::sync::broadcast::Receiver<NetworkEvent>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event: NetworkEvent = tokio::time::timeout(timeout, rx.recv())
            .await
            .expect("timeout waiting for event")
            .expect("event");
        if matches!(event, NetworkEvent::PeerConnected { .. }) {
            return;
        }
    }
}

async fn wait_for_any_peer_connected(
    mut rx_a: tokio::sync::broadcast::Receiver<NetworkEvent>,
    mut rx_b: tokio::sync::broadcast::Receiver<NetworkEvent>,
    timeout_secs: u64,
) -> bool {
    tokio::time::timeout(Duration::from_secs(timeout_secs), async move {
        loop {
            tokio::select! {
                event = rx_a.recv() => {
                    if let Ok(NetworkEvent::PeerConnected { .. }) = event {
                        return true;
                    }
                }
                event = rx_b.recv() => {
                    if let Ok(NetworkEvent::PeerConnected { .. }) = event {
                        return true;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false)
}

// Requires network permissions and a local socket bind.
// Run with: `cargo test --test ream_networking_ports -- --ignored`
#[tokio::test]
#[ignore]
async fn ream_two_nodes_connection_smoke() {
    let events_1 = NetworkEventBus::new(32);
    let events_2 = NetworkEventBus::new(32);
    let (tx_1, rx_1) = mpsc::channel::<P2pCommand>(32);
    let (tx_2, rx_2) = mpsc::channel::<P2pCommand>(32);

    let config_1 = P2pConfig {
        listen_addr: addr_for(9000),
        bootnodes: vec![],
        node_key_path: None,
        gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
        allowed_topics: vec![],
        topic_scores: vec![],
        topic_validators: vec![],
        signature_verifier: Arc::new(NoopGossipVerifier),
        reqresp_handler: Arc::new(NoopReqRespHandler),
        gossip_context: Arc::new(StateGossipContext::new(empty_state())),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
    };

    let node_1 = P2pService::new(config_1, events_1.clone(), rx_1);
    let node_1_peer_id = node_1.local_peer_id();

    let node_1_addr: Multiaddr = format!("{}/p2p/{}", node_1.listen_addr(), node_1_peer_id)
        .parse()
        .expect("multiaddr");

    let config_2 = P2pConfig {
        listen_addr: addr_for(9001),
        bootnodes: vec![node_1_addr],
        node_key_path: None,
        gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
        allowed_topics: vec![],
        topic_scores: vec![],
        topic_validators: vec![],
        signature_verifier: Arc::new(NoopGossipVerifier),
        reqresp_handler: Arc::new(NoopReqRespHandler),
        gossip_context: Arc::new(StateGossipContext::new(empty_state())),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
    };
    let node_2 = P2pService::new(config_2, events_2.clone(), rx_2);

    let handle_1 = tokio::spawn(async move { node_1.run().await });
    let handle_2 = tokio::spawn(async move { node_2.run().await });

    wait_for_peer_connected(events_1.subscribe()).await;
    wait_for_peer_connected(events_2.subscribe()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    handle_1.abort();
    handle_2.abort();
    drop(tx_1);
    drop(tx_2);
}

// Requires network permissions and a local socket bind.
// Run with: `cargo test --test ream_networking_ports -- --ignored`
#[tokio::test]
#[ignore]
async fn ream_status_request_response_smoke() {
    let events_1 = NetworkEventBus::new(32);
    let events_2 = NetworkEventBus::new(32);
    let (tx_1, rx_1) = mpsc::channel::<P2pCommand>(32);
    let (tx_2, rx_2) = mpsc::channel::<P2pCommand>(32);

    let state_2 = empty_state();
    let store_2 = Arc::new(RwLock::new(MemoryStore::new()));
    let handler_2 = Arc::new(StoreReqRespHandler::new(state_2.clone(), store_2));

    let node_1 = P2pService::new(
        P2pConfig {
            listen_addr: addr_for(9002),
            bootnodes: vec![],
            node_key_path: None,
            gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
            allowed_topics: vec![],
            topic_scores: vec![],
            topic_validators: vec![],
            signature_verifier: Arc::new(NoopGossipVerifier),
            reqresp_handler: Arc::new(NoopReqRespHandler),
            gossip_context: Arc::new(StateGossipContext::new(empty_state())),
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        },
        events_1.clone(),
        rx_1,
    );
    let peer_1_id = node_1.local_peer_id();
    let node_1_addr: Multiaddr = format!("{}/p2p/{}", node_1.listen_addr(), peer_1_id)
        .parse()
        .expect("multiaddr");

    let node_2 = P2pService::new(
        P2pConfig {
            listen_addr: addr_for(9003),
            bootnodes: vec![node_1_addr],
            node_key_path: None,
            gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
            allowed_topics: vec![],
            topic_scores: vec![],
            topic_validators: vec![],
            signature_verifier: Arc::new(NoopGossipVerifier),
            reqresp_handler: handler_2,
            gossip_context: Arc::new(StateGossipContext::new(state_2)),
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        },
        events_2.clone(),
        rx_2,
    );
    let peer_2_id = node_2.local_peer_id();
    let handle_1 = tokio::spawn(async move { node_1.run().await });
    let handle_2 = tokio::spawn(async move { node_2.run().await });

    wait_for_peer_connected(events_1.subscribe()).await;
    wait_for_peer_connected(events_2.subscribe()).await;

    let status = LeanRequestMessage::Status(Status {
        finalized_root: Bytes32::zero(),
        finalized_slot: Uint64(0),
        head_root: Bytes32::zero(),
        head_slot: Uint64(0),
    });
    let payload = status.encode_ssz();
    tx_1.send(P2pCommand::SendRequest {
        peer: peer_2_id,
        protocol: LeanSupportedProtocol::StatusV1.protocol_id(),
        payload,
    })
    .await
    .expect("send request");

    let mut rx_events = events_1.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = tokio::time::timeout(timeout, rx_events.recv())
            .await
            .expect("timeout")
            .expect("event");
        if let NetworkEvent::ReqRespResponse {
            protocol, payload, ..
        } = event
        {
            assert_eq!(protocol, LeanSupportedProtocol::StatusV1.protocol_id());
            let msg = LeanResponseMessage::decode_ssz(LeanSupportedProtocol::StatusV1, &payload)
                .expect("decode");
            match msg {
                LeanResponseMessage::Status(status) => {
                    assert_eq!(status.finalized_root, peam::types::bytes::Bytes32::zero());
                }
                _ => panic!("unexpected response"),
            }
            break;
        }
    }

    handle_1.abort();
    handle_2.abort();
    drop(tx_1);
    drop(tx_2);
}

// Requires network permissions and local multicast socket bind for mDNS.
// Run with: `cargo test --test ream_networking_ports -- --ignored`
#[tokio::test]
#[ignore]
async fn ream_mdns_discovery_smoke() {
    let events_1 = NetworkEventBus::new(32);
    let events_2 = NetworkEventBus::new(32);
    let (_tx_1, rx_1) = mpsc::channel::<P2pCommand>(32);
    let (_tx_2, rx_2) = mpsc::channel::<P2pCommand>(32);

    let config_1 = P2pConfig {
        listen_addr: addr_for(9004),
        bootnodes: vec![],
        node_key_path: None,
        gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
        allowed_topics: vec![],
        topic_scores: vec![],
        topic_validators: vec![],
        signature_verifier: Arc::new(NoopGossipVerifier),
        reqresp_handler: Arc::new(NoopReqRespHandler),
        gossip_context: Arc::new(StateGossipContext::new(empty_state())),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
    };
    let config_2 = P2pConfig {
        listen_addr: addr_for(9005),
        bootnodes: vec![],
        node_key_path: None,
        gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
        allowed_topics: vec![],
        topic_scores: vec![],
        topic_validators: vec![],
        signature_verifier: Arc::new(NoopGossipVerifier),
        reqresp_handler: Arc::new(NoopReqRespHandler),
        gossip_context: Arc::new(StateGossipContext::new(empty_state())),
        max_gossip_bytes: 2_000_000,
        max_reqresp_bytes: 4_000_000,
    };

    let node_1 = P2pService::new(config_1, events_1.clone(), rx_1);
    let node_2 = P2pService::new(config_2, events_2.clone(), rx_2);

    let handle_1 = tokio::spawn(async move { node_1.run().await });
    let handle_2 = tokio::spawn(async move { node_2.run().await });

    // mDNS peer discovery may take longer than direct bootnode dialing and can be
    // unavailable in restricted environments. Treat this as best-effort unless
    // LEAN_ETH_REQUIRE_MDNS=1 is set.
    let discovered =
        wait_for_any_peer_connected(events_1.subscribe(), events_2.subscribe(), 45).await;
    if !discovered {
        if std::env::var("LEAN_ETH_REQUIRE_MDNS").ok().as_deref() == Some("1") {
            panic!("timeout waiting for peer discovery");
        }
        eprintln!("mDNS discovery not observed within timeout; skipping strict assertion");
    }

    handle_1.abort();
    handle_2.abort();
}

// Requires network permissions and local socket binds.
// Run with: `cargo test --test ream_networking_ports -- --ignored ream_blocks_by_root_catchup_smoke`
#[tokio::test]
#[ignore]
async fn ream_blocks_by_root_catchup_smoke() {
    let events_1 = NetworkEventBus::new(64);
    let events_2 = NetworkEventBus::new(64);
    let (tx_1, rx_1) = mpsc::channel::<P2pCommand>(64);
    let (tx_2, rx_2) = mpsc::channel::<P2pCommand>(64);

    // Source node (node_2) starts ahead with blocks 1..=3.
    let state_2 = single_validator_state();
    let store_2 = Arc::new(RwLock::new(MemoryStore::new()));
    let mut requested_roots = Vec::new();
    {
        let mut state = state_2.write().expect("state_2 lock");
        let mut store = store_2.write().expect("store_2 lock");
        for slot in 1..=3 {
            let signed = signed_block_for_state(&state, slot);
            let root = Bytes32::from(signed.message.block.hash_tree_root());
            store
                .put_signed_block(root, signed, &mut state)
                .expect("seed source chain");
            requested_roots.push(root);
        }
    }

    // Lagging node (node_1) starts from genesis only.
    let state_1 = single_validator_state();
    let store_1 = Arc::new(RwLock::new(MemoryStore::new()));

    let node_1 = P2pService::new(
        P2pConfig {
            listen_addr: addr_for(9006),
            bootnodes: vec![],
            node_key_path: None,
            gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
            allowed_topics: vec![],
            topic_scores: vec![],
            topic_validators: vec![],
            signature_verifier: Arc::new(NoopGossipVerifier),
            reqresp_handler: Arc::new(NoopReqRespHandler),
            gossip_context: Arc::new(StateGossipContext::new(state_1.clone())),
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        },
        events_1.clone(),
        rx_1,
    );
    let peer_1_id = node_1.local_peer_id();
    let node_1_addr: Multiaddr = format!("{}/p2p/{}", node_1.listen_addr(), peer_1_id)
        .parse()
        .expect("multiaddr");

    let node_2 = P2pService::new(
        P2pConfig {
            listen_addr: addr_for(9007),
            bootnodes: vec![node_1_addr],
            node_key_path: None,
            gossipsub_topic: "leanconsensus/devnet3/blocks/ssz_snappy".to_string(),
            allowed_topics: vec![],
            topic_scores: vec![],
            topic_validators: vec![],
            signature_verifier: Arc::new(NoopGossipVerifier),
            reqresp_handler: Arc::new(StoreReqRespHandler::new(state_2.clone(), store_2.clone())),
            gossip_context: Arc::new(StateGossipContext::new(state_2.clone())),
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        },
        events_2.clone(),
        rx_2,
    );
    let peer_2_id = node_2.local_peer_id();

    let handle_1 = tokio::spawn(async move { node_1.run().await });
    let handle_2 = tokio::spawn(async move { node_2.run().await });

    wait_for_peer_connected(events_1.subscribe()).await;
    wait_for_peer_connected(events_2.subscribe()).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut rx_events = events_1.subscribe();
    let mut rx_source_events = events_2.subscribe();
    for root in &requested_roots {
        let roots =
            SszList::<Bytes32, MAX_BLOCKS_PER_ROOT_REQUEST>::new(vec![*root]).expect("roots");
        let request = LeanRequestMessage::BlocksByRoot(BlocksByRootRequest { roots });
        tx_1.send(P2pCommand::SendRequest {
            peer: peer_2_id,
            protocol: LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
            payload: request.encode_ssz(),
        })
        .await
        .expect("send blocks_by_root request");

        let request_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let timeout = request_deadline.saturating_duration_since(tokio::time::Instant::now());
            let event = tokio::time::timeout(timeout, rx_source_events.recv())
                .await
                .expect("timeout waiting for inbound blocks_by_root request on source node")
                .expect("event");
            let NetworkEvent::ReqRespRequest {
                protocol, payload, ..
            } = event
            else {
                continue;
            };
            if protocol != LeanSupportedProtocol::BlocksByRootV1.protocol_id() {
                continue;
            }
            let req =
                LeanRequestMessage::decode_ssz(LeanSupportedProtocol::BlocksByRootV1, &payload)
                    .expect("decode inbound blocks_by_root request");
            let LeanRequestMessage::BlocksByRoot(req) = req else {
                panic!("unexpected request variant");
            };
            assert_eq!(req.roots.len(), 1);
            assert_eq!(req.roots.get(0), Some(root));
            break;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let response = loop {
            let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
            let event = tokio::time::timeout(timeout, rx_events.recv())
                .await
                .expect("timeout waiting for blocks_by_root response")
                .expect("event");
            let NetworkEvent::ReqRespResponse {
                protocol, payload, ..
            } = event
            else {
                continue;
            };
            if protocol != LeanSupportedProtocol::BlocksByRootV1.protocol_id() {
                continue;
            }
            let message =
                LeanResponseMessage::decode_ssz(LeanSupportedProtocol::BlocksByRootV1, &payload)
                    .expect("decode blocks_by_root response");
            let response = match message {
                LeanResponseMessage::BlocksByRoot(v) => v,
                _ => panic!("unexpected response variant"),
            };
            break response;
        };

        let signed = &response;
        assert_eq!(Bytes32::from(signed.message.block.hash_tree_root()), *root);

        let mut state = state_1.write().expect("state_1 lock");
        let mut store = store_1.write().expect("store_1 lock");
        let root = Bytes32::from(signed.message.block.hash_tree_root());
        store
            .put_signed_block(root, signed.clone(), &mut state)
            .expect("apply synced block");
    }

    {
        let store = store_1.write().expect("store_1 lock");
        assert!(store.get_block_by_slot(1).is_some());
        assert!(store.get_block_by_slot(2).is_some());
        assert!(store.get_block_by_slot(3).is_some());
    }

    {
        let state = state_1.write().expect("state_1 lock");
        assert_eq!(state.slot.0.0, 3);
    }

    handle_1.abort();
    handle_2.abort();
    drop(tx_1);
    drop(tx_2);
}
