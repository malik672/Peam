use std::sync::Arc;
use std::time::Duration;

use libp2p::core::upgrade;
use libp2p::gossipsub::{self, Behaviour as Gossipsub, Event as GossipsubEvent, MessageAuthenticity, IdentTopic};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::identity::Keypair;
use libp2p::mdns::{tokio::Behaviour as Mdns, Config as MdnsConfig, Event as MdnsEvent};
use libp2p::noise;
use libp2p::ping::{Behaviour as Ping, Config as PingConfig, Event as PingEvent};
use libp2p::request_response::{
    ProtocolSupport, Behaviour as RequestResponse, Codec as RequestResponseCodec, Config as RequestResponseConfig,
    Event as RequestResponseEvent, Message as RequestResponseMessage,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p_swarm_derive::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, Transport};
use libp2p::{tcp, yamux};
use tokio::sync::mpsc;
use tracing::info;
use async_trait::async_trait;
use futures::StreamExt;

use super::events::{EventBus, NetworkEvent};
use crate::networking::reqresp_messages::{LeanRequestMessage, LeanSupportedProtocol};
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::networking::gossipsub::validate::ValidationResult;

#[derive(Clone)]
pub struct P2pConfig {
    pub listen_addr: Multiaddr,
    pub bootnodes: Vec<Multiaddr>,
    pub gossipsub_topic: String,
    pub allowed_topics: Vec<String>,
    pub topic_scores: Vec<(String, i64)>,
    pub topic_validators: Vec<(String, super::GossipValidatorKind)>,
    pub signature_verifier: Arc<dyn super::GossipSignatureVerifier>,
    pub reqresp_handler: Arc<dyn crate::networking::ReqRespHandler>,
    pub gossip_context: Arc<dyn crate::networking::GossipContext>,
    pub max_gossip_bytes: usize,
    pub max_reqresp_bytes: usize,
}

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

pub enum P2pCommand {
    Publish { topic: String, payload: Vec<u8> },
    SendRequest { peer: PeerId, protocol: String, payload: Vec<u8> },
}

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    gossipsub: Gossipsub,
    identify: Identify,
    ping: Ping,
    reqresp: RequestResponse<LeanReqRespCodec>,
    mdns: Mdns,
}

#[derive(Clone, Default)]
pub struct LeanReqRespCodec;

#[derive(Clone)]
pub struct LeanReqRespProtocol(pub String);

impl AsRef<str> for LeanReqRespProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct LeanRequest {
    pub protocol: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LeanResponse {
    pub protocol: String,
    pub payload: Vec<u8>,
}

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
        Ok(LeanRequest {
            protocol: protocol.0.clone(),
            payload: buf,
        })
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
        Ok(LeanResponse {
            protocol: protocol.0.clone(),
            payload: buf,
        })
    }

    async fn write_request<T>(
        &mut self,
        _: &LeanReqRespProtocol,
        io: &mut T,
        LeanRequest { payload, .. }: LeanRequest,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        futures::AsyncWriteExt::write_all(io, &payload).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &LeanReqRespProtocol,
        io: &mut T,
        LeanResponse { payload, .. }: LeanResponse,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        futures::AsyncWriteExt::write_all(io, &payload).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }
}

impl P2pService {
    pub fn new(config: P2pConfig, events: EventBus, outbound: mpsc::Receiver<P2pCommand>) -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let gossipsub = Gossipsub::new(MessageAuthenticity::Signed(keypair.clone()), gossipsub::Config::default())
            .expect("gossipsub");
        let identify = Identify::new(IdentifyConfig::new("/lean_eth/1.0.0".to_string(), keypair.public()));
        let ping = Ping::new(PingConfig::new().with_interval(Duration::from_secs(10)));
        let reqresp_protocols = [
            LeanSupportedProtocol::StatusV1.protocol_id(),
            LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
        ]
        .into_iter()
        .map(|protocol| (LeanReqRespProtocol(protocol), ProtocolSupport::Full));
        let reqresp = RequestResponse::new(
            reqresp_protocols,
            RequestResponseConfig::default(),
        );

        // Local discovery for dev/test networks (LAN scope).
        let mdns = Mdns::new(MdnsConfig::default(), peer_id).expect("mdns");
        let mut behaviour = LeanBehaviour { gossipsub, identify, ping, reqresp, mdns };
        let topic = IdentTopic::new(config.gossipsub_topic.clone());
        let _ = behaviour.gossipsub.subscribe(&topic);

        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).expect("noise config"))
            .multiplex(yamux::Config::default())
            .boxed();

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm
            .listen_on(config.listen_addr.clone())
            .expect("listen");

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

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

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

    fn on_command(&mut self, cmd: P2pCommand) {
        match cmd {
            P2pCommand::Publish { topic, payload } => {
                // Publish raw payload to the selected topic.
                let topic = IdentTopic::new(topic.clone());
                let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, payload);
            }
            P2pCommand::SendRequest { peer, protocol, payload } => {
                // Send a req/resp request to a specific peer.
                self.swarm
                    .behaviour_mut()
                    .reqresp
                    .send_request(
                        &peer,
                        LeanRequest {
                            protocol,
                            payload,
                        },
                    );
            }
        }
    }

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
            SwarmEvent::Behaviour(LeanBehaviourEvent::Gossipsub(GossipsubEvent::Message { message, propagation_source, .. })) => {
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
            SwarmEvent::Behaviour(LeanBehaviourEvent::Identify(IdentifyEvent::Received { peer_id, .. })) => {
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
            SwarmEvent::Behaviour(LeanBehaviourEvent::Reqresp(RequestResponseEvent::Message { peer, message })) => {
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
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
