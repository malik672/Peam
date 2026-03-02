//! libp2p swarm integration: transport, behaviours, and event dispatch.
//!
//! [`P2pService`] owns the libp2p [`Swarm`] and drives it in a `select!` loop
//! that interleaves swarm events with outbound [`P2pCommand`]s.
//!
//! # Transport stack
//!
//! QUIC (`quic-v1`)
//!
//! # Behaviours
//!
//! | Behaviour    | Purpose |
//! |--------------|---------|
//! | `gossipsub`  | Pub/sub block and attestation propagation |
//! | `identify`   | Peer protocol/address advertisement |
//! | `ping`       | Liveness probing |
//! | `reqresp`    | Typed request/response (status, blocks-by-root) |
//! | `mdns`       | Local-network peer discovery |

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::gossipsub::{
    self, Behaviour as Gossipsub, Event as GossipsubEvent, IdentTopic, MessageAuthenticity,
};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::identity::Keypair;
use libp2p::mdns::{Config as MdnsConfig, Event as MdnsEvent, tokio::Behaviour as Mdns};
use libp2p::ping::{Behaviour as Ping, Config as PingConfig, Event as PingEvent};
use libp2p::quic;
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec as RequestResponseCodec, Config as RequestResponseConfig,
    Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Transport};
use libp2p_swarm_derive::NetworkBehaviour;
use tokio::sync::mpsc;
use tracing::info;

use super::events::{EventBus, NetworkEvent};
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::networking::gossipsub::validate::ValidationResult;
use crate::networking::reqresp_messages::{LeanRequestMessage, LeanSupportedProtocol};

/// Explicit gossipsub protocol id pinned to v1.0.
const GOSSIPSUB_PROTOCOL_ID_V1_0: &str = "/meshsub/1.0.0";

/// Configuration for constructing a [`P2pService`].
#[derive(Clone)]
pub struct P2pConfig {
    /// Multiaddr the swarm will listen on.
    pub listen_addr: Multiaddr,
    /// Boot-node addresses to dial immediately on startup.
    pub bootnodes: Vec<Multiaddr>,
    /// Primary gossipsub topic to subscribe to.
    pub gossipsub_topic: String,
    /// Full list of topic strings the node will accept messages from.
    pub allowed_topics: Vec<String>,
    /// Per-topic score increments awarded on valid message receipt.
    pub topic_scores: Vec<(String, i64)>,
    /// Per-topic validator kind used to verify inbound gossip payloads.
    pub topic_validators: Vec<(String, super::GossipValidatorKind)>,
    /// Cryptographic signature verifier for gossip messages.
    pub signature_verifier: Arc<dyn super::GossipSignatureVerifier>,
    /// Application-level req/resp request handler.
    pub reqresp_handler: Arc<dyn crate::networking::ReqRespHandler>,
    /// Gossip context for slot-range validation.
    pub gossip_context: Arc<dyn crate::networking::GossipContext>,
    /// Maximum acceptable payload size for gossip messages (bytes).
    pub max_gossip_bytes: usize,
    /// Maximum acceptable payload size for req/resp messages (bytes).
    pub max_reqresp_bytes: usize,
}

/// The running libp2p service: owns the swarm and dispatches all events.
pub struct P2pService {
    swarm: Swarm<LeanBehaviour>,
    events: EventBus,
    outbound: mpsc::Receiver<P2pCommand>,
    topic_scores: std::collections::HashMap<String, i64>,
    allowed_topics: std::collections::HashSet<String>,
    topic_validators: std::collections::HashMap<String, super::GossipValidatorKind>,
    signature_verifier: Arc<dyn super::GossipSignatureVerifier>,
    reqresp_handler: Arc<dyn crate::networking::ReqRespHandler>,
    gossip_context: Arc<dyn crate::networking::GossipContext>,
    gossipsub_topic: String,
    local_peer_id: PeerId,
    listen_addr: Multiaddr,
    max_gossip_bytes: usize,
    max_reqresp_bytes: usize,
}

/// Commands sent from higher-level networking code down to the swarm loop.
pub enum P2pCommand {
    /// Publish `payload` to the given gossipsub `topic`.
    Publish { topic: String, payload: Vec<u8> },
    /// Send a req/resp `payload` to `peer` using `protocol`.
    SendRequest {
        peer: PeerId,
        protocol: String,
        payload: Vec<u8>,
    },
}

/// The composed libp2p [`NetworkBehaviour`] for lean-Ethereum.
#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    gossipsub: Gossipsub,
    identify: Identify,
    ping: Ping,
    reqresp: RequestResponse<LeanReqRespCodec>,
    mdns: Mdns,
}

/// Codec for the lean-Ethereum req/resp protocol.
///
/// Reads raw bytes into [`LeanRequest`] / [`LeanResponse`] and writes them
/// back verbatim — framing and protocol selection are handled by libp2p.
#[derive(Clone, Default)]
pub struct LeanReqRespCodec;

/// A req/resp protocol identifier wrapping the protocol ID string.
#[derive(Clone)]
pub struct LeanReqRespProtocol(pub String);

/// Allows the protocol to be used as a string reference in libp2p internals.
impl AsRef<str> for LeanReqRespProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[inline]
fn encode_reqresp_envelope(protocol: &str, payload: &[u8]) -> Vec<u8> {
    let proto = protocol.as_bytes();
    let proto_len = proto.len().min(u16::MAX as usize) as u16;
    let mut out = Vec::with_capacity(2 + proto_len as usize + payload.len());
    out.extend_from_slice(&proto_len.to_le_bytes());
    out.extend_from_slice(&proto[..proto_len as usize]);
    out.extend_from_slice(payload);
    out
}

#[inline]
fn decode_reqresp_envelope(buf: Vec<u8>, negotiated_protocol: &str) -> (String, Vec<u8>) {
    if buf.len() < 2 {
        return (negotiated_protocol.to_string(), buf);
    }
    let proto_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + proto_len {
        return (negotiated_protocol.to_string(), buf);
    }
    let proto = std::str::from_utf8(&buf[2..(2 + proto_len)]).ok();
    let payload = buf[(2 + proto_len)..].to_vec();
    match proto {
        Some(protocol) => (protocol.to_string(), payload),
        None => (negotiated_protocol.to_string(), payload),
    }
}

/// A raw inbound or outbound req/resp request.
#[derive(Debug, Clone)]
pub struct LeanRequest {
    /// Protocol ID string.
    pub protocol: String,
    /// Raw SSZ-encoded request payload.
    pub payload: Vec<u8>,
}

/// A raw inbound or outbound req/resp response.
#[derive(Debug, Clone)]
pub struct LeanResponse {
    /// Protocol ID string.
    pub protocol: String,
    /// Raw SSZ-encoded response payload.
    pub payload: Vec<u8>,
}

#[inline]
fn build_gossipsub_config_v1_0_strict() -> gossipsub::Config {
    let mut builder = gossipsub::ConfigBuilder::default();
    builder.protocol_id(GOSSIPSUB_PROTOCOL_ID_V1_0, gossipsub::Version::V1_0);
    builder.validation_mode(gossipsub::ValidationMode::Strict);
    builder.build().expect("valid gossipsub v1.0 config")
}

/// [`RequestResponseCodec`] impl for [`LeanReqRespCodec`].
///
/// All four methods read/write the full payload as a flat byte buffer.
#[async_trait]
impl RequestResponseCodec for LeanReqRespCodec {
    type Protocol = LeanReqRespProtocol;
    type Request = LeanRequest;
    type Response = LeanResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &LeanReqRespProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        let (protocol, payload) = decode_reqresp_envelope(buf, &protocol.0);
        Ok(LeanRequest { protocol, payload })
    }

    async fn read_response<T>(
        &mut self,
        protocol: &LeanReqRespProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        let (protocol, payload) = decode_reqresp_envelope(buf, &protocol.0);
        Ok(LeanResponse { protocol, payload })
    }

    async fn write_request<T>(
        &mut self,
        _: &LeanReqRespProtocol,
        io: &mut T,
        LeanRequest { protocol, payload }: LeanRequest,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let framed = encode_reqresp_envelope(&protocol, &payload);
        futures::AsyncWriteExt::write_all(io, &framed).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &LeanReqRespProtocol,
        io: &mut T,
        LeanResponse { protocol, payload }: LeanResponse,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let framed = encode_reqresp_envelope(&protocol, &payload);
        futures::AsyncWriteExt::write_all(io, &framed).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }
}

impl P2pService {
    /// Constructs and starts the libp2p swarm.
    ///
    /// Generates a fresh ephemeral Ed25519 keypair, subscribes to the
    /// configured gossipsub topic, dials all bootnodes, and listens on
    /// `config.listen_addr`.
    pub fn new(config: P2pConfig, events: EventBus, outbound: mpsc::Receiver<P2pCommand>) -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(keypair.clone()),
            build_gossipsub_config_v1_0_strict(),
        )
        .expect("gossipsub");
        let identify = Identify::new(IdentifyConfig::new(
            "/peam/1.0.0".to_string(),
            keypair.public(),
        ));
        let ping = Ping::new(PingConfig::new().with_interval(Duration::from_secs(10)));
        let reqresp_protocols = [
            LeanSupportedProtocol::StatusV1.protocol_id(),
            LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
        ]
        .into_iter()
        .map(|protocol| (LeanReqRespProtocol(protocol), ProtocolSupport::Full));
        let reqresp = RequestResponse::new(reqresp_protocols, RequestResponseConfig::default());

        // Local discovery for dev/test networks (LAN scope).
        let mdns = Mdns::new(MdnsConfig::default(), peer_id).expect("mdns");
        let mut behaviour = LeanBehaviour {
            gossipsub,
            identify,
            ping,
            reqresp,
            mdns,
        };
        let mut topics = std::collections::HashSet::new();
        topics.insert(config.gossipsub_topic.clone());
        for topic in &config.allowed_topics {
            topics.insert(topic.clone());
        }
        for topic in topics {
            let ident = IdentTopic::new(topic);
            let _ = behaviour.gossipsub.subscribe(&ident);
        }

        let transport = quic::tokio::Transport::new(quic::Config::new(&keypair))
            .map(|(peer_id, conn), _| (peer_id, StreamMuxerBox::new(conn)))
            .boxed();

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(config.listen_addr.clone()).expect("listen");

        for addr in config.bootnodes {
            let _ = swarm.dial(addr);
        }

        let allowed_topics = config.allowed_topics.iter().cloned().collect();
        let topic_scores = config.topic_scores.into_iter().collect();
        let topic_validators = config.topic_validators.into_iter().collect();
        let signature_verifier = config.signature_verifier;
        let reqresp_handler = config.reqresp_handler;
        let gossip_context = config.gossip_context;
        let gossipsub_topic = config.gossipsub_topic;
        let max_gossip_bytes = config.max_gossip_bytes;
        let max_reqresp_bytes = config.max_reqresp_bytes;
        info!("p2p_started peer_id={peer_id}");
        Self {
            swarm,
            events,
            outbound,
            topic_scores,
            allowed_topics,
            topic_validators,
            signature_verifier,
            reqresp_handler,
            gossip_context,
            gossipsub_topic,
            local_peer_id: peer_id,
            listen_addr: config.listen_addr,
            max_gossip_bytes,
            max_reqresp_bytes,
        }
    }

    /// Returns the local node's libp2p [`PeerId`].
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Returns the address the swarm is listening on.
    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    /// Runs the swarm event loop until the outbound command channel is closed.
    ///
    /// Interleaves swarm events (gossip, identify, ping, req/resp, mDNS) with
    /// outbound [`P2pCommand`]s from the higher-level networking layer.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                swarm_event = self.swarm.select_next_some() => {
                    // Drive libp2p state machine + dispatch events.
                    self.on_swarm_event(swarm_event);
                }
                cmd = self.outbound.recv() => {
                    if let Some(cmd) = cmd {
                        // Outbound commands from higher-level networking.
                        self.on_command(cmd);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Executes an outbound [`P2pCommand`].
    fn on_command(&mut self, cmd: P2pCommand) {
        match cmd {
            P2pCommand::Publish { topic, payload } => {
                // Publish raw payload to the selected topic.
                let topic = IdentTopic::new(topic.clone());
                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, payload);
            }
            P2pCommand::SendRequest {
                peer,
                protocol,
                payload,
            } => {
                // Send a req/resp request to a specific peer.
                self.swarm
                    .behaviour_mut()
                    .reqresp
                    .send_request(&peer, LeanRequest { protocol, payload });
            }
        }
    }

    /// Dispatches a single swarm event to the appropriate handler.
    ///
    /// Scoring rules applied per event:
    /// - Oversized gossip payload: −25
    /// - Unknown / invalid topic: −5
    /// - Invalid payload signature: −10
    /// - Ignore result from basic/context validation: −1
    /// - Reject result from basic/context validation: −25
    /// - Valid gossip: topic-score increment (default +1)
    /// - Successful req/resp response: +1
    /// - Oversized req/resp payload: −25
    /// - Ping failure: emit `PeerDisconnected`
    fn on_swarm_event(&mut self, event: SwarmEvent<LeanBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                // Track peer connection and send a hello for basic liveness.
                self.events.emit(NetworkEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                });
                let topic = IdentTopic::new(self.gossipsub_topic.clone());
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, b"hello".to_vec());
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                message,
                propagation_source,
                ..
            })) => {
                // Validate and score inbound gossipsub messages.
                if message.data.len() > self.max_gossip_bytes {
                    self.events.emit(NetworkEvent::PeerScored {
                        peer_id: propagation_source.to_string(),
                        score: -25,
                    });
                    return;
                }
                let topic_hash = message.topic.clone();
                let topic = topic_hash.to_string();
                let lean_kind =
                    crate::networking::gossipsub::lean::kind_from_topic_hash(&topic_hash).ok();
                let valid = lean_kind.is_some() || self.allowed_topics.contains(&topic);
                self.events.emit(NetworkEvent::GossipValidated {
                    topic: topic.clone(),
                    valid,
                });
                if !valid {
                    self.events.emit(NetworkEvent::PeerScored {
                        peer_id: propagation_source.to_string(),
                        score: -5,
                    });
                    return;
                }
                let validator = lean_kind.unwrap_or_else(|| {
                    self.topic_validators
                        .get(&topic)
                        .copied()
                        .unwrap_or(super::GossipValidatorKind::None)
                });
                let payload_valid =
                    super::validate_gossip(validator, &message.data, &self.signature_verifier);
                if !payload_valid {
                    self.events.emit(NetworkEvent::PeerScored {
                        peer_id: propagation_source.to_string(),
                        score: -10,
                    });
                    return;
                }
                if let Ok(decoded) = LeanGossipsubMessage::decode(&topic_hash, &message.data) {
                    match crate::networking::gossipsub::validate::validate_basic_message(&decoded) {
                        ValidationResult::Accept => {}
                        ValidationResult::Ignore(reason) => {
                            self.events.emit(NetworkEvent::GossipValidated {
                                topic: topic.clone(),
                                valid: false,
                            });
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -1,
                            });
                            info!("gossip_ignore topic={topic} reason={reason}");
                            return;
                        }
                        ValidationResult::Reject(reason) => {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -25,
                            });
                            info!("gossip_reject topic={topic} reason={reason}");
                            return;
                        }
                    }
                    match crate::networking::gossipsub::validate::validate_with_context(
                        &decoded,
                        self.gossip_context.as_ref(),
                    ) {
                        ValidationResult::Accept => {}
                        ValidationResult::Ignore(reason) => {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -1,
                            });
                            info!("gossip_ignore topic={topic} reason={reason}");
                            return;
                        }
                        ValidationResult::Reject(reason) => {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -25,
                            });
                            info!("gossip_reject topic={topic} reason={reason}");
                            return;
                        }
                    }
                }
                let score = self.topic_scores.get(&topic).copied().unwrap_or(1);
                self.events.emit(NetworkEvent::GossipMessage {
                    topic,
                    payload: message.data,
                });
                self.events.emit(NetworkEvent::PeerScored {
                    peer_id: propagation_source.to_string(),
                    score,
                });
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Mdns(MdnsEvent::Discovered(peers))) => {
                for (_peer_id, addr) in peers {
                    // Attempt to connect to newly discovered peers.
                    let _ = self.swarm.dial(addr.clone());
                }
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Mdns(MdnsEvent::Expired(_))) => {}
            SwarmEvent::Behaviour(LeanBehaviourEvent::Identify(IdentifyEvent::Received {
                peer_id,
                ..
            })) => {
                self.events.emit(NetworkEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                });
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Ping(PingEvent { peer, result, .. })) => {
                if result.is_err() {
                    self.events.emit(NetworkEvent::PeerDisconnected {
                        peer_id: peer.to_string(),
                    });
                }
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Reqresp(RequestResponseEvent::Message {
                peer,
                message,
            })) => {
                match message {
                    RequestResponseMessage::Request {
                        request, channel, ..
                    } => {
                        // Inbound req/resp request.
                        let LeanRequest { protocol, payload } = request;
                        if payload.len() > self.max_reqresp_bytes {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: peer.to_string(),
                                score: -25,
                            });
                            return;
                        }
                        let message = LeanSupportedProtocol::parse_protocol_id(&protocol)
                            .and_then(|kind| LeanRequestMessage::decode_ssz(kind, &payload).ok());
                        self.events.emit(NetworkEvent::ReqRespRequest {
                            peer_id: peer.to_string(),
                            protocol: protocol.clone(),
                            payload: payload.clone(),
                        });
                        let response_payload = message
                            .and_then(|req| self.reqresp_handler.on_request(req))
                            .map(|resp| resp.encode_ssz())
                            .unwrap_or_else(|| payload.clone());
                        let _ = self.swarm.behaviour_mut().reqresp.send_response(
                            channel,
                            LeanResponse {
                                protocol,
                                payload: response_payload,
                            },
                        );
                    }
                    RequestResponseMessage::Response { response, .. } => {
                        // Inbound req/resp response.
                        let LeanResponse { protocol, payload } = response;
                        if payload.len() > self.max_reqresp_bytes {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: peer.to_string(),
                                score: -25,
                            });
                            return;
                        }
                        self.events.emit(NetworkEvent::ReqRespResponse {
                            peer_id: peer.to_string(),
                            protocol,
                            payload,
                        });
                        self.events.emit(NetworkEvent::PeerScored {
                            peer_id: peer.to_string(),
                            score: 1,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossipsub_config_is_pinned_to_v1_0_and_strict_validation() {
        let config = build_gossipsub_config_v1_0_strict();
        let dbg = format!("{config:?}");
        assert_eq!(GOSSIPSUB_PROTOCOL_ID_V1_0, "/meshsub/1.0.0");
        assert!(dbg.contains(GOSSIPSUB_PROTOCOL_ID_V1_0));
        assert!(!dbg.contains("/meshsub/1.1.0"));
        assert!(!dbg.contains("/meshsub/1.2.0"));
        assert!(matches!(
            config.validation_mode(),
            gossipsub::ValidationMode::Strict
        ));
    }
}
