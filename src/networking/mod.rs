//! Networking stack: gossipsub, req/resp, peer scoring, and discovery.
//!
//! The top-level entry point is [`Networking::start_with_config`], which
//! constructs and spawns all background tasks:
//!
//! | Task              | Description |
//! |-------------------|-------------|
//! | `gossip_task`     | Inbound gossip pipeline with per-peer and per-topic rate limiting |
//! | `reqresp_task`    | Inbound req/resp pipeline with per-peer rate limiting and scoring |
//! | `p2p_task`        | libp2p swarm event loop |
//! | `score_decay_task`| Periodic peer score decay and ban pruning |
//! | `discovery_task`  | Periodic seed dialing |
//!
//! Re-exports the public surface of all sub-modules for convenience.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::networking::events::EventBus;

mod discovery;
mod events;
mod gossip;
pub mod gossipsub;
mod p2p;
pub mod peer_manager;
mod rate_limiter;
mod reqresp;
mod reqresp_handler;
mod reqresp_messages;
mod validate;

pub use discovery::Discovery;
pub use events::{EventBus as NetworkEventBus, NetworkEvent};
pub use gossip::{Gossip, GossipMessage};
pub use gossipsub::context::{GossipContext, NoopGossipContext, StateGossipContext};
pub use p2p::{P2pCommand, P2pConfig, P2pService};
pub use peer_manager::PeerManager;
pub use rate_limiter::RateLimiter;
pub use reqresp::{ReqResp, ReqRespMessage};
pub use reqresp_handler::{NoopReqRespHandler, ReqRespHandler, StoreReqRespHandler};
pub use reqresp_messages::{LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol};
pub use validate::{
    GossipSignatureVerifier, GossipValidatorKind, NoopGossipVerifier, SimpleGossipVerifier,
    validate_gossip, verifier_from_validators,
};

/// The fully-assembled networking runtime.
///
/// Owns all networking sub-systems and the [`JoinHandle`]s of the background
/// tasks that drive them. Call [`shutdown`] to abort all tasks.
pub struct Networking {
    /// Broadcast event bus — subscribe to observe all network events.
    pub events: EventBus,
    /// Peer registry and scorer.
    pub peers: PeerManager,
    /// Outbound gossip publisher.
    pub gossip: Gossip,
    /// Outbound req/resp handle.
    pub reqresp: ReqResp,
    /// Peer discovery (seed dialing).
    pub discovery: Discovery,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    gossip_task: JoinHandle<()>,
    reqresp_task: JoinHandle<()>,
    discovery_task: JoinHandle<()>,
    p2p_task: JoinHandle<()>,
    peer_event_task: JoinHandle<()>,
    score_decay_task: JoinHandle<()>,
}

impl Networking {
    /// Constructs and starts the full networking runtime from `config`.
    ///
    /// Spawns five background tasks (see module-level table) and returns
    /// a [`Networking`] handle with access to all sub-systems.
    pub fn start_with_config(config: NetworkingConfig) -> Self {
        let events = EventBus::new(256);
        let peers = PeerManager::new(events.clone());
        let (gossip, mut gossip_rx) = Gossip::new(events.clone(), 128);
        let (reqresp, mut reqresp_rx) = ReqResp::new(events.clone(), 128);
        let discovery = Discovery::new(std::time::Duration::from_secs(
            config.discovery_interval_secs,
        ));
        let discovery_runner = discovery.clone();
        let inbound_gossip_limiter = RateLimiter::new(std::time::Duration::from_secs(1), 256);
        let inbound_reqresp_limiter = RateLimiter::new(std::time::Duration::from_secs(1), 128);
        let inbound_topic_limiter = RateLimiter::new(std::time::Duration::from_secs(5), 10);
        let inbound_gossip_limiter_task = inbound_gossip_limiter.clone();
        let inbound_reqresp_limiter_task = inbound_reqresp_limiter.clone();
        let inbound_topic_limiter_task = inbound_topic_limiter.clone();
        let events_gossip = events.clone();
        let peers_gossip = peers.clone();
        let events_reqresp = events.clone();
        let peers_reqresp = peers.clone();

        // Gossip inbound pipeline with per-peer and per-topic rate limiting.
        let gossip_task = tokio::spawn(async move {
            while let Some(msg) = gossip_rx.recv().await {
                let peer_key = msg
                    .peer_id
                    .as_ref()
                    .map(|peer_id| format!("gossip_in:{peer_id}"))
                    .unwrap_or_else(|| "gossip_in".to_string());
                let peer_id = msg.peer_id.clone().unwrap_or_else(|| "unknown".to_string());
                if !inbound_gossip_limiter_task.allow(&peer_key).await {
                    events_gossip.emit(NetworkEvent::RateLimited {
                        peer_id: peer_id.clone(),
                        category: "gossip_in".to_string(),
                    });
                    if peer_id != "unknown" {
                        let _ = peers_gossip.score_delta(&peer_id, -5).await;
                    }
                    continue;
                }
                let topic_key = format!("gossip_topic:{peer_id}:{}", msg.topic);
                if !inbound_topic_limiter_task.allow(&topic_key).await {
                    events_gossip.emit(NetworkEvent::RateLimited {
                        peer_id: peer_id.clone(),
                        category: "gossip_topic".to_string(),
                    });
                    if peer_id != "unknown" {
                        let _ = peers_gossip.score_delta(&peer_id, -10).await;
                    }
                    continue;
                }
                if peer_id != "unknown" {
                    let _ = peers_gossip.score_delta(&peer_id, 1).await;
                }
                info!("gossip_in topic={} bytes={}", msg.topic, msg.payload.len());
            }
        });

        // Req/resp inbound pipeline with per-peer rate limiting + scoring.
        let reqresp_task = tokio::spawn(async move {
            while let Some(msg) = reqresp_rx.recv().await {
                match msg {
                    ReqRespMessage::Request {
                        peer_id,
                        protocol,
                        payload,
                    } => {
                        let key = format!("reqresp_in:{peer_id}:{protocol}");
                        if !inbound_reqresp_limiter_task.allow(&key).await {
                            events_reqresp.emit(NetworkEvent::RateLimited {
                                peer_id: peer_id.clone(),
                                category: "reqresp_in".to_string(),
                            });
                            let _ = peers_reqresp.failed_response_from_peer(&peer_id).await;
                            continue;
                        }
                        info!(
                            "reqresp_in request peer={peer_id} protocol={protocol} bytes={}",
                            payload.len()
                        );
                        let _ = peers_reqresp.successful_response_from_peer(&peer_id).await;
                    }
                    ReqRespMessage::Response {
                        peer_id,
                        protocol,
                        payload,
                    } => {
                        let key = format!("reqresp_in:{peer_id}:{protocol}");
                        if !inbound_reqresp_limiter_task.allow(&key).await {
                            events_reqresp.emit(NetworkEvent::RateLimited {
                                peer_id: peer_id.clone(),
                                category: "reqresp_in".to_string(),
                            });
                            let _ = peers_reqresp.failed_response_from_peer(&peer_id).await;
                            continue;
                        }
                        info!(
                            "reqresp_in response peer={peer_id} protocol={protocol} bytes={}",
                            payload.len()
                        );
                        let _ = peers_reqresp.successful_response_from_peer(&peer_id).await;
                    }
                }
            }
        });

        let (p2p_tx, p2p_rx) = tokio::sync::mpsc::channel(256);
        let listen_addr = config
            .listen_addr
            .parse()
            .unwrap_or_else(|_| "/ip4/0.0.0.0/udp/9000/quic-v1".parse().unwrap());
        let mut bootnodes = Vec::new();
        for addr in &config.bootnodes {
            match addr.parse() {
                Ok(parsed) => bootnodes.push(parsed),
                Err(err) => warn!("invalid_bootnode_multiaddr addr={addr} err={err}"),
            }
        }
        for addr in &config.trusted_peers {
            match addr.parse() {
                Ok(parsed) => bootnodes.push(parsed),
                Err(err) => warn!("invalid_trusted_peer_multiaddr addr={addr} err={err}"),
            }
        }
        let gossipsub_topic = config
            .allowed_topics
            .first()
            .cloned()
            .unwrap_or_else(|| "/leanconsensus/devnet0/block/ssz_snappy".to_string());
        let p2p_config = P2pConfig {
            listen_addr,
            bootnodes,
            node_key_path: config.node_key_path.clone(),
            gossipsub_topic,
            allowed_topics: config.allowed_topics.clone(),
            topic_scores: config.topic_scores.clone(),
            topic_validators: config.topic_validators.clone(),
            signature_verifier: config.signature_verifier.clone(),
            reqresp_handler: config.reqresp_handler.clone(),
            gossip_context: config.gossip_context.clone(),
            max_gossip_bytes: config.max_gossip_bytes,
            max_reqresp_bytes: config.max_reqresp_bytes,
        };
        let p2p_service = P2pService::new(p2p_config, events.clone(), p2p_rx);
        // libp2p service loop.
        let p2p_task = tokio::spawn(async move {
            p2p_service.run().await;
        });

        // Keep PeerManager in sync with actual swarm connection lifecycle.
        let peers_for_events = peers.clone();
        let mut peer_events_rx = events.subscribe();
        let peer_event_task = tokio::spawn(async move {
            loop {
                match peer_events_rx.recv().await {
                    Ok(NetworkEvent::PeerConnected { peer_id, inbound }) => {
                        peers_for_events.connect(peer_id, inbound).await;
                    }
                    Ok(NetworkEvent::PeerDisconnected { peer_id, inbound }) => {
                        peers_for_events.disconnect(&peer_id, inbound).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let score_decay_interval = std::time::Duration::from_secs(config.score_decay_interval_secs);
        let score_decay_amount = config.score_decay_amount;
        let ban_threshold = config.ban_threshold;
        let peers_decay = peers.clone();
        // Background peer score decay and ban pruning.
        let score_decay_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(score_decay_interval);
            loop {
                ticker.tick().await;
                let _ = peers_decay
                    .decay_and_prune(score_decay_amount, ban_threshold)
                    .await;
            }
        });

        // Periodic discovery loop (bootnodes + mDNS).
        let discovery_p2p_tx = p2p_tx.clone();
        let discovery_peers = peers.clone();
        let discovery_task = tokio::spawn(async move {
            discovery_runner
                .run(discovery_p2p_tx, discovery_peers)
                .await;
        });

        Self {
            events,
            peers,
            gossip,
            reqresp,
            discovery,
            p2p_tx,
            gossip_task,
            reqresp_task,
            discovery_task,
            p2p_task,
            peer_event_task,
            score_decay_task,
        }
    }

    /// Aborts all background tasks and releases networking resources.
    pub async fn shutdown(self) {
        self.gossip_task.abort();
        self.reqresp_task.abort();
        self.discovery_task.abort();
        self.p2p_task.abort();
        self.peer_event_task.abort();
        self.score_decay_task.abort();
    }

    /// Adds `peer_id` to the discovery seed queue for future dialing.
    pub async fn add_seed_peer(&self, peer_id: String) {
        self.discovery.add_seed(peer_id).await;
    }

    /// Returns a clone of the internal libp2p command sender.
    pub fn p2p_sender(&self) -> tokio::sync::mpsc::Sender<P2pCommand> {
        self.p2p_tx.clone()
    }
}

/// Configuration for [`Networking::start_with_config`].
#[derive(Clone)]
pub struct NetworkingConfig {
    /// Seconds between discovery dial attempts.
    pub discovery_interval_secs: u64,
    /// Seconds between peer score decay passes.
    pub score_decay_interval_secs: u64,
    /// Amount by which peer scores move toward zero on each decay pass.
    pub score_decay_amount: i64,
    /// Score threshold below which a peer is banned.
    pub ban_threshold: i64,
    /// Multiaddr strings to dial on startup.
    pub bootnodes: Vec<String>,
    /// Multiaddr strings treated as trusted; added to the bootnode dial list.
    pub trusted_peers: Vec<String>,
    /// Multiaddr string the node listens on.
    pub listen_addr: String,
    /// Optional filesystem path to a secp256k1 private key used for peer identity.
    pub node_key_path: Option<String>,
    /// Gossipsub topic strings the node subscribes to and validates.
    pub allowed_topics: Vec<String>,
    /// Score increment per topic awarded on valid message receipt.
    pub topic_scores: Vec<(String, i64)>,
    /// Validator kind to use for each topic.
    pub topic_validators: Vec<(String, GossipValidatorKind)>,
    /// Gossip signature verifier (shared across tasks).
    pub signature_verifier: Arc<dyn GossipSignatureVerifier>,
    /// Req/resp request handler (shared across tasks).
    pub reqresp_handler: Arc<dyn ReqRespHandler>,
    /// Gossip context for slot-range validation (shared across tasks).
    pub gossip_context: Arc<dyn GossipContext>,
    /// Maximum gossip message payload size in bytes.
    pub max_gossip_bytes: usize,
    /// Maximum req/resp message payload size in bytes.
    pub max_reqresp_bytes: usize,
}

/// Sensible defaults for a devnet configuration.
impl Default for NetworkingConfig {
    fn default() -> Self {
        Self {
            discovery_interval_secs: 5,
            score_decay_interval_secs: 30,
            score_decay_amount: 1,
            ban_threshold: -100,
            bootnodes: Vec::new(),
            trusted_peers: Vec::new(),
            listen_addr: "/ip4/0.0.0.0/udp/9000/quic-v1".to_string(),
            node_key_path: None,
            allowed_topics: vec![
                "/leanconsensus/devnet0/block/ssz_snappy".to_string(),
                "/leanconsensus/devnet0/attestation_0/ssz_snappy".to_string(),
                "/leanconsensus/devnet0/aggregation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("/leanconsensus/devnet0/block/ssz_snappy".to_string(), 2),
                (
                    "/leanconsensus/devnet0/attestation_0/ssz_snappy".to_string(),
                    1,
                ),
                (
                    "/leanconsensus/devnet0/aggregation/ssz_snappy".to_string(),
                    1,
                ),
            ],
            topic_validators: vec![
                (
                    "/leanconsensus/devnet0/block/ssz_snappy".to_string(),
                    GossipValidatorKind::Block,
                ),
                (
                    "/leanconsensus/devnet0/attestation_0/ssz_snappy".to_string(),
                    GossipValidatorKind::Attestation,
                ),
                (
                    "/leanconsensus/devnet0/aggregation/ssz_snappy".to_string(),
                    GossipValidatorKind::AggregatedAttestation,
                ),
            ],
            signature_verifier: Arc::new(NoopGossipVerifier),
            reqresp_handler: Arc::new(NoopReqRespHandler),
            gossip_context: Arc::new(NoopGossipContext),
            max_gossip_bytes: 2_000_000,
            max_reqresp_bytes: 4_000_000,
        }
    }
}
