use std::time::Duration;

use libp2p::Multiaddr;
use tokio::sync::mpsc;

use lean_eth::containers::req_resp::Status;
use lean_eth::containers::state::{State, Validators};
use lean_eth::networking::gossipsub::context::StateGossipContext;
use lean_eth::networking::{
    LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol, NetworkEvent,
    NetworkEventBus, NoopGossipVerifier, NoopReqRespHandler, P2pCommand, P2pConfig, P2pService,
    StoreReqRespHandler,
};
use lean_eth::storage::MemoryStore;
use lean_eth::types::bytes::Bytes32;
use lean_eth::types::uint::Uint64;
use std::sync::{Arc, RwLock};

fn addr_for(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().expect("addr")
}

fn empty_state() -> Arc<RwLock<State>> {
    let validators = Validators::new(vec![]).expect("validators");
    Arc::new(RwLock::new(
        State::generate_genesis(Uint64(0), validators),
    ))
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

async fn wait_for_peer_connected_with_timeout(
    mut rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    timeout_secs: u64,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
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
        gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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
        gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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
            gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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
            gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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
        fork_digest: Bytes32::zero(),
        finalized_root: Bytes32::zero(),
        finalized_epoch: Uint64(0),
        head_root: Bytes32::zero(),
        head_slot: Uint64(0),
    });
    let payload = status.encode_ssz();
    tx_1
        .send(P2pCommand::SendRequest {
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
        if let NetworkEvent::ReqRespResponse { protocol, payload, .. } = event {
            assert_eq!(protocol, LeanSupportedProtocol::StatusV1.protocol_id());
            let msg = LeanResponseMessage::decode_ssz(
                LeanSupportedProtocol::StatusV1,
                &payload,
            )
            .expect("decode");
            match msg {
                LeanResponseMessage::Status(status) => {
                    assert_eq!(status.fork_digest, lean_eth::types::bytes::Bytes32::zero());
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
        gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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
        gossipsub_topic: "leanconsensus/devnet2/block/ssz_snappy".to_string(),
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

    wait_for_peer_connected_with_timeout(events_1.subscribe(), 15).await;
    wait_for_peer_connected_with_timeout(events_2.subscribe(), 15).await;

    handle_1.abort();
    handle_2.abort();
}
