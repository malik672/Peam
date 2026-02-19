use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;

use crate::networking::events::EventBus;

mod events;
mod gossip;
pub mod gossipsub;
mod peer_manager;
mod reqresp;
mod reqresp_messages;
mod reqresp_handler;
mod discovery;
mod rate_limiter;
mod p2p;
mod validate;

pub use events::{EventBus as NetworkEventBus, NetworkEvent};
pub use gossip::{Gossip, GossipMessage};
pub use peer_manager::PeerManager;
pub use reqresp::{ReqResp, ReqRespMessage};
pub use reqresp_messages::{
    LeanRequestMessage, LeanResponseMessage, LeanSupportedProtocol,
};
pub use reqresp_handler::{NoopReqRespHandler, ReqRespHandler, StoreReqRespHandler};
pub use gossipsub::context::{GossipContext, NoopGossipContext, StateGossipContext};
pub use discovery::Discovery;
pub use rate_limiter::RateLimiter;
pub use p2p::{P2pService, P2pConfig, P2pCommand};
pub use validate::{
    GossipSignatureVerifier, GossipValidatorKind, NoopGossipVerifier, SimpleGossipVerifier,
    validate_gossip, verifier_from_validators,
};

/// Networking runtime: gossipsub + req/resp + discovery + peer scoring.
pub struct Networking {
    pub events: EventBus,
    pub peers: PeerManager,
    pub gossip: Gossip,
    pub reqresp: ReqResp,
    pub discovery: Discovery,
    p2p_tx: tokio::sync::mpsc::Sender<P2pCommand>,
    gossip_task: JoinHandle<()>,
    reqresp_task: JoinHandle<()>,
    discovery_task: JoinHandle<()>,
    p2p_task: JoinHandle<()>,
    score_decay_task: JoinHandle<()>,
}

impl Networking {
    /// Build and start the networking runtime (gossip + req/resp + discovery + scoring).
    pub fn start_with_config(config: NetworkingConfig) -> Self {
        let events = EventBus::new(256);
        let peers = PeerManager::new(events.clone());
        let (gossip, mut gossip_rx) = Gossip::new(events.clone(), 128);
        let (reqresp, mut reqresp_rx) = ReqResp::new(events.clone(), 128);
        let discovery =
            Discovery::new(std::time::Duration::from_secs(config.discovery_interval_secs));
        let discovery_peers = peers.clone();
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
                    ReqRespMessage::Request { peer_id, protocol, payload } => {
                        let key = format!("reqresp_in:{peer_id}:{protocol}");
                        if !inbound_reqresp_limiter_task.allow(&key).await {
                            events_reqresp.emit(NetworkEvent::RateLimited {
                                peer_id: peer_id.clone(),
                                category: "reqresp_in".to_string(),
                            });
                            let _ = peers_reqresp.failed_response_from_peer(&peer_id).await;
                            continue;
                        }
                        info!("reqresp_in request peer={peer_id} protocol={protocol} bytes={}", payload.len());
                        let _ = peers_reqresp.successful_response_from_peer(&peer_id).await;
                    }
                    ReqRespMessage::Response { peer_id, protocol, payload } => {
                        let key = format!("reqresp_in:{peer_id}:{protocol}");
                        if !inbound_reqresp_limiter_task.allow(&key).await {
                            events_reqresp.emit(NetworkEvent::RateLimited {
                                peer_id: peer_id.clone(),
                                category: "reqresp_in".to_string(),
                            });
                            let _ = peers_reqresp.failed_response_from_peer(&peer_id).await;
                            continue;
                        }
                        info!("reqresp_in response peer={peer_id} protocol={protocol} bytes={}", payload.len());
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
        let mut bootnodes = config
            .bootnodes
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect::<Vec<_>>();
        bootnodes.extend(
            config
                .trusted_peers
                .iter()
                .filter_map(|addr| addr.parse().ok()),
        );
        let gossipsub_topic = config
            .allowed_topics
            .first()
            .cloned()
            .unwrap_or_else(|| "leanconsensus/devnet2/block/ssz_snappy".to_string());
        let p2p_config = P2pConfig {
            listen_addr,
            bootnodes,
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
        let discovery_task = tokio::spawn(async move {
            discovery_runner.run(discovery_peers).await;
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
            score_decay_task,
        }
    }

    pub fn start() -> Self {
        Self::start_with_config(NetworkingConfig::default())
    }

    pub async fn shutdown(self) {
        self.gossip_task.abort();
        self.reqresp_task.abort();
        self.discovery_task.abort();
        self.p2p_task.abort();
        self.score_decay_task.abort();
    }

    pub async fn add_seed_peer(&self, peer_id: String) {
        self.discovery.add_seed(peer_id).await;
    }

    pub async fn p2p_publish(&self, topic: String, payload: Vec<u8>) {
        let _ = self
            .p2p_tx
            .send(P2pCommand::Publish { topic, payload })
            .await;
    }

    pub async fn p2p_send_request(&self, peer_id: libp2p::PeerId, protocol: String, payload: Vec<u8>) {
        let _ = self
            .p2p_tx
            .send(P2pCommand::SendRequest { peer: peer_id, protocol, payload })
            .await;
    }
}

#[derive(Clone)]
pub struct NetworkingConfig {
    pub discovery_interval_secs: u64,
    pub score_decay_interval_secs: u64,
    pub score_decay_amount: i64,
    pub ban_threshold: i64,
    pub bootnodes: Vec<String>,
    pub trusted_peers: Vec<String>,
    pub listen_addr: String,
    pub allowed_topics: Vec<String>,
    pub topic_scores: Vec<(String, i64)>,
    pub topic_validators: Vec<(String, GossipValidatorKind)>,
    pub signature_verifier: Arc<dyn GossipSignatureVerifier>,
    pub reqresp_handler: Arc<dyn ReqRespHandler>,
    pub gossip_context: Arc<dyn GossipContext>,
    pub max_gossip_bytes: usize,
    pub max_reqresp_bytes: usize,
}

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
            allowed_topics: vec![
                "leanconsensus/devnet2/block/ssz_snappy".to_string(),
                "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
            ],
            topic_scores: vec![
                ("leanconsensus/devnet2/block/ssz_snappy".to_string(), 2),
                ("leanconsensus/devnet2/attestation/ssz_snappy".to_string(), 1),
            ],
            topic_validators: vec![
                ("leanconsensus/devnet2/block/ssz_snappy".to_string(), GossipValidatorKind::Block),
                (
                    "leanconsensus/devnet2/attestation/ssz_snappy".to_string(),
                    GossipValidatorKind::Attestation,
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
