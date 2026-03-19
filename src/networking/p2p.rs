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
//! | `reqresp`    | Typed request/response (status, blocks-by-root, blocks-by-range) |
//! | `mdns`       | Local-network peer discovery |

use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use async_trait::async_trait;
use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::gossipsub::{
    self, AllowAllSubscriptionFilter, DataTransform, Event as GossipsubEvent, IdentTopic, Message,
    MessageAuthenticity, RawMessage, TopicHash,
};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::identity::Keypair;
use libp2p::mdns::{Config as MdnsConfig, Event as MdnsEvent, tokio::Behaviour as Mdns};
use libp2p::quic;
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec as RequestResponseCodec, Config as RequestResponseConfig,
    Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Transport};
use libp2p_swarm_derive::NetworkBehaviour;
use rapidhash::{RapidHashMap, RapidHashSet};
use snap::raw::{Decoder as RawDecoder, Encoder as RawEncoder, decompress_len};
use snap::{read::FrameDecoder, write::FrameEncoder};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::events::{EventBus, NetworkEvent};
use crate::containers::req_resp::{BlocksByRangeResponse, MAX_BLOCKS_PER_REQUEST};
use crate::networking::gossipsub::lean::message::LeanGossipsubMessage;
use crate::networking::gossipsub::validate::ValidationResult;
use crate::networking::reqresp_messages::{LeanRequestMessage, LeanSupportedProtocol};
use crate::ssz::SszEncode;
use crate::types::collections::SszList;

/// Ream-compatible snappy transform for gossip payloads.
#[derive(Clone)]
pub struct SnappyTransform {
    max_size_per_message: usize,
}

impl SnappyTransform {
    #[inline]
    fn new(max_size_per_message: usize) -> Self {
        Self {
            max_size_per_message,
        }
    }
}

impl DataTransform for SnappyTransform {
    fn inbound_transform(&self, raw_message: RawMessage) -> Result<Message, std::io::Error> {
        let len = decompress_len(&raw_message.data)?;
        if len > self.max_size_per_message {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "gossip message size ({len}) exceeds max ({})",
                    self.max_size_per_message
                ),
            ));
        }
        let mut decoder = RawDecoder::new();
        let data = decoder.decompress_vec(&raw_message.data)?;
        Ok(Message {
            source: raw_message.source,
            data,
            sequence_number: raw_message.sequence_number,
            topic: raw_message.topic,
        })
    }

    fn outbound_transform(
        &self,
        _topic: &TopicHash,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        if data.len() > self.max_size_per_message {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "gossip message size ({}) exceeds max ({})",
                    data.len(),
                    self.max_size_per_message
                ),
            ));
        }
        let mut encoder = RawEncoder::new();
        encoder.compress_vec(&data).map_err(std::io::Error::other)
    }
}

type Gossipsub = gossipsub::Behaviour<SnappyTransform, AllowAllSubscriptionFilter>;

/// Configuration for constructing a [`P2pService`].
#[derive(Clone)]
pub struct P2pConfig {
    /// Multiaddr the swarm will listen on.
    pub listen_addr: Multiaddr,
    /// Boot-node addresses to dial immediately on startup.
    pub bootnodes: Vec<Multiaddr>,
    /// Optional filesystem path to secp256k1 private key used for peer identity.
    pub node_key_path: Option<String>,
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
    topic_scores: RapidHashMap<String, i64>,
    allowed_topics: RapidHashSet<String>,
    topic_validators: RapidHashMap<String, super::GossipValidatorKind>,
    signature_verifier: Arc<dyn super::GossipSignatureVerifier>,
    reqresp_handler: Arc<dyn crate::networking::ReqRespHandler>,
    gossip_context: Arc<dyn crate::networking::GossipContext>,
    local_peer_id: PeerId,
    listen_addr: Multiaddr,
    max_gossip_bytes: usize,
    max_reqresp_bytes: usize,
}

/// Commands sent from higher-level networking code down to the swarm loop.
pub enum P2pCommand {
    /// Publish `payload` to the given gossipsub `topic`.
    Publish { topic: String, payload: Vec<u8> },
    /// Dial a peer using the provided multiaddr.
    Dial { addr: Multiaddr },
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
    reqresp_status: RequestResponse<LeanReqRespCodec>,
    reqresp_blocks: RequestResponse<LeanReqRespCodec>,
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
fn encode_uvi_len(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[inline]
fn decode_uvi_len(buf: &[u8]) -> std::io::Result<(usize, usize)> {
    let mut value: usize = 0;
    let mut shift = 0u32;
    for (idx, byte) in buf.iter().copied().enumerate() {
        let low = (byte & 0x7f) as usize;
        let shifted = low.checked_shl(shift).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid varint length")
        })?;
        value = value.checked_add(shifted).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "varint length overflow")
        })?;
        if (byte & 0x80) == 0 {
            return Ok((value, idx + 1));
        }
        shift = shift.saturating_add(7);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "incomplete varint length",
    ))
}

async fn read_uvi_len_async<T>(io: &mut T) -> std::io::Result<usize>
where
    T: futures::AsyncRead + Unpin + Send,
{
    let mut value: usize = 0;
    let mut shift = 0u32;
    let mut buf = [0u8; 1];
    for _ in 0..10 {
        futures::AsyncReadExt::read_exact(io, &mut buf).await?;
        let byte = buf[0];
        let low = (byte & 0x7f) as usize;
        let shifted = low.checked_shl(shift).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid varint length")
        })?;
        value = value.checked_add(shifted).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "varint length overflow")
        })?;
        if (byte & 0x80) == 0 {
            return Ok(value);
        }
        shift = shift.saturating_add(7);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "varint length too long",
    ))
}

async fn read_snappy_frame_exact<T>(io: &mut T, expected_len: usize) -> std::io::Result<Vec<u8>>
where
    T: futures::AsyncRead + Unpin + Send,
{
    const CHUNK_COMPRESSED: u8 = 0x00;
    const CHUNK_UNCOMPRESSED: u8 = 0x01;
    const CHUNK_STREAM: u8 = 0xff;
    const CHUNK_PADDING: u8 = 0xfe;

    let mut out = Vec::with_capacity(expected_len);
    let mut decoder = RawDecoder::new();
    let mut saw_any_chunk = false;

    while out.len() < expected_len || !saw_any_chunk {
        let mut header = [0u8; 4];
        futures::AsyncReadExt::read_exact(io, &mut header).await?;
        saw_any_chunk = true;
        let chunk_type = header[0];
        let len = (header[1] as usize) | ((header[2] as usize) << 8) | ((header[3] as usize) << 16);
        if len == 0 {
            continue;
        }
        let mut chunk = vec![0u8; len];
        futures::AsyncReadExt::read_exact(io, &mut chunk).await?;

        match chunk_type {
            CHUNK_STREAM => {
                // Stream identifier chunk. Skip payload.
            }
            CHUNK_PADDING => {
                // Padding chunk. Skip payload.
            }
            CHUNK_UNCOMPRESSED => {
                if len < 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snappy uncompressed chunk too short",
                    ));
                }
                let data = &chunk[4..];
                if out.len() + data.len() > expected_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snappy output exceeds expected length",
                    ));
                }
                out.extend_from_slice(data);
            }
            CHUNK_COMPRESSED => {
                if len < 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snappy compressed chunk too short",
                    ));
                }
                let compressed = &chunk[4..];
                let decoded_len = decompress_len(compressed).map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("snappy length decode failed: {err}"),
                    )
                })?;
                if out.len() + decoded_len > expected_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snappy output exceeds expected length",
                    ));
                }
                let mut decoded = vec![0u8; decoded_len];
                decoder
                    .decompress(compressed, &mut decoded)
                    .map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("snappy decompress failed: {err}"),
                        )
                    })?;
                out.extend_from_slice(&decoded);
            }
            other if (0x02..=0x7f).contains(&other) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "snappy reserved unskippable chunk",
                ));
            }
            other if (0x80..=0xfd).contains(&other) => {
                // Reserved skippable chunk. Ignore payload.
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "snappy unknown chunk type",
                ));
            }
        }

        if out.len() > expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snappy output exceeds expected length",
            ));
        }
    }

    if out.len() != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snappy output length mismatch",
        ));
    }

    Ok(out)
}

async fn read_response_chunk<T>(io: &mut T) -> std::io::Result<Option<(u8, Vec<u8>)>>
where
    T: futures::AsyncRead + Unpin + Send,
{
    let mut code_buf = [0u8; 1];
    match futures::AsyncReadExt::read_exact(io, &mut code_buf).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    let response_code = code_buf[0];
    let expected_len = read_uvi_len_async(io).await?;
    let payload = read_snappy_frame_exact(io, expected_len).await?;
    Ok(Some((response_code, payload)))
}

#[inline]
fn snappy_frame_compress(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(payload)?;
    encoder.flush()?;
    Ok(encoder.get_ref().clone())
}

#[inline]
fn snappy_frame_decompress(payload: &[u8], expected_len: usize) -> std::io::Result<Vec<u8>> {
    let mut decoder = FrameDecoder::new(Cursor::new(payload));
    let mut out = vec![0u8; expected_len];
    decoder.read_exact(&mut out)?;
    Ok(out)
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
    /// Req/resp response code (0 = success).
    pub response_code: u8,
    /// Raw SSZ-encoded response payloads (one per chunk).
    pub payloads: Vec<Vec<u8>>,
}

#[inline]
fn build_gossipsub_config_lean(max_transmit_size: usize) -> gossipsub::Config {
    let mut builder = gossipsub::ConfigBuilder::default();
    // In Anonymous mode, default message-id behavior can collapse many
    // messages into the same id on some peers. Use content-addressed ids.
    builder.message_id_fn(lean_gossip_message_id);
    builder.max_transmit_size(max_transmit_size);
    builder.heartbeat_interval(Duration::from_millis(700));
    builder.fanout_ttl(Duration::from_secs(60));
    builder.mesh_n(8);
    builder.mesh_n_low(6);
    builder.mesh_n_high(12);
    builder.gossip_lazy(6);
    builder.history_length(6);
    builder.history_gossip(3);
    builder.max_messages_per_rpc(Some(500));
    builder.validate_messages();
    builder.validation_mode(gossipsub::ValidationMode::Anonymous);
    builder.allow_self_origin(true);
    builder.flood_publish(false);
    builder.build().expect("valid lean gossipsub config")
}

#[inline]
fn lean_gossip_message_id(message: &Message) -> gossipsub::MessageId {
    let mut hasher = DefaultHasher::new();
    message.topic.hash(&mut hasher);
    message.data.hash(&mut hasher);
    gossipsub::MessageId::from(format!("{:016x}", hasher.finish()))
}

/// [`RequestResponseCodec`] impl for [`LeanReqRespCodec`].
///
/// Ream-compatible lean req/resp framing:
/// - Request: `varint(len) || snappy_frame(ssz_payload)`
/// - Response: `response_code(1 byte) || varint(len) || snappy_frame(ssz_payload)`
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
        let (len, prefix_len) = decode_uvi_len(&buf)?;
        let compressed = &buf[prefix_len..];
        let payload = snappy_frame_decompress(compressed, len)?;
        Ok(LeanRequest {
            protocol: protocol.0.clone(),
            payload,
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
        match LeanSupportedProtocol::parse_protocol_id(&protocol.0) {
            Some(
                LeanSupportedProtocol::BlocksByRootV1 | LeanSupportedProtocol::BlocksByRangeV1,
            ) => {
                let mut payloads = Vec::new();
                while let Some((response_code, payload)) = read_response_chunk(io).await? {
                    if response_code != 0 {
                        // Skip non-success chunks for streaming block responses.
                        continue;
                    }
                    payloads.push(payload);
                }
                Ok(LeanResponse {
                    protocol: protocol.0.clone(),
                    response_code: 0,
                    payloads,
                })
            }
            _ => {
                let Some((response_code, payload)) = read_response_chunk(io).await? else {
                    return Ok(LeanResponse {
                        protocol: protocol.0.clone(),
                        response_code: 0,
                        payloads: Vec::new(),
                    });
                };
                if response_code != 0 {
                    let detail = String::from_utf8_lossy(&payload);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "non-success reqresp response code={} protocol={} detail={}",
                            response_code, protocol.0, detail
                        ),
                    ));
                }
                Ok(LeanResponse {
                    protocol: protocol.0.clone(),
                    response_code,
                    payloads: vec![payload],
                })
            }
        }
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
        let mut framed = Vec::with_capacity(payload.len() + 16);
        let _ = protocol;
        encode_uvi_len(payload.len(), &mut framed);
        framed.extend_from_slice(&snappy_frame_compress(&payload)?);
        futures::AsyncWriteExt::write_all(io, &framed).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &LeanReqRespProtocol,
        io: &mut T,
        LeanResponse {
            protocol,
            response_code,
            payloads,
        }: LeanResponse,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        if response_code != 0 {
            let payload = payloads
                .into_iter()
                .next()
                .unwrap_or_else(|| b"invalid request".to_vec());
            let mut framed = Vec::with_capacity(payload.len() + 17);
            let _ = protocol;
            framed.push(response_code);
            encode_uvi_len(payload.len(), &mut framed);
            framed.extend_from_slice(&snappy_frame_compress(&payload)?);
            futures::AsyncWriteExt::write_all(io, &framed).await?;
            futures::AsyncWriteExt::close(io).await?;
            return Ok(());
        }

        if payloads.is_empty() {
            // Align with spec-style BlocksByRoot responses: no chunks when empty.
            futures::AsyncWriteExt::close(io).await?;
            return Ok(());
        }

        let is_streaming_blocks = matches!(
            LeanSupportedProtocol::parse_protocol_id(&protocol),
            Some(LeanSupportedProtocol::BlocksByRootV1 | LeanSupportedProtocol::BlocksByRangeV1)
        );

        if is_streaming_blocks {
            for payload in payloads {
                let mut framed = Vec::with_capacity(payload.len() + 17);
                framed.push(0);
                encode_uvi_len(payload.len(), &mut framed);
                framed.extend_from_slice(&snappy_frame_compress(&payload)?);
                futures::AsyncWriteExt::write_all(io, &framed).await?;
            }
            futures::AsyncWriteExt::close(io).await?;
            return Ok(());
        }

        let payload = payloads.into_iter().next().unwrap_or_else(|| Vec::new());
        let mut framed = Vec::with_capacity(payload.len() + 17);
        let _ = protocol;
        framed.push(0);
        encode_uvi_len(payload.len(), &mut framed);
        framed.extend_from_slice(&snappy_frame_compress(&payload)?);
        futures::AsyncWriteExt::write_all(io, &framed).await?;
        futures::AsyncWriteExt::close(io).await?;
        Ok(())
    }
}

impl P2pService {
    fn decode_hex_key(mut raw: &str) -> Result<Vec<u8>, String> {
        raw = raw.trim();
        if let Some(stripped) = raw.strip_prefix("0x") {
            raw = stripped;
        }
        if raw.len() != 64 {
            return Err(format!(
                "expected 32-byte hex (64 chars), got {} chars",
                raw.len()
            ));
        }
        let mut out = Vec::with_capacity(32);
        for i in (0..raw.len()).step_by(2) {
            let byte = u8::from_str_radix(&raw[i..i + 2], 16)
                .map_err(|err| format!("invalid hex at [{i}..{}]: {err}", i + 2))?;
            out.push(byte);
        }
        Ok(out)
    }

    fn load_keypair_from_path(path: &Path) -> Result<Keypair, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let mut secret_bytes = Self::decode_hex_key(&raw)?;
        let secret = libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut secret_bytes)
            .map_err(|err| format!("failed to parse secp256k1 secret key: {err}"))?;
        let secp_keypair = libp2p::identity::secp256k1::Keypair::from(secret);
        Ok(Keypair::from(secp_keypair))
    }

    /// Constructs and starts the libp2p swarm.
    ///
    /// Loads a secp256k1 keypair from `config.node_key_path` when provided
    /// (falls back to an ephemeral key on parse/load failure), subscribes to
    /// the configured gossipsub topic, dials all bootnodes, and listens on
    /// `config.listen_addr`.
    pub fn new(config: P2pConfig, events: EventBus, outbound: mpsc::Receiver<P2pCommand>) -> Self {
        let keypair = if let Some(path) = config.node_key_path.as_deref() {
            let path = Path::new(path);
            match Self::load_keypair_from_path(path) {
                Ok(keypair) => keypair,
                Err(err) => {
                    warn!(
                        "p2p_node_key_load_failed path={} err={err}; using ephemeral key",
                        path.display()
                    );
                    Keypair::generate_secp256k1()
                }
            }
        } else {
            Keypair::generate_secp256k1()
        };
        let peer_id = PeerId::from(keypair.public());

        let gossipsub = Gossipsub::new_with_transform(
            MessageAuthenticity::Anonymous,
            build_gossipsub_config_lean(config.max_gossip_bytes),
            None,
            SnappyTransform::new(config.max_gossip_bytes),
        )
        .expect("gossipsub");
        let identify = Identify::new(IdentifyConfig::new(
            "eth2/1.0.0".to_string(),
            keypair.public(),
        ));
        let reqresp_status_protocols = [LeanSupportedProtocol::StatusV1.protocol_id()]
            .into_iter()
            .map(|protocol| (LeanReqRespProtocol(protocol), ProtocolSupport::Full));
        let reqresp_blocks_protocols = [
            LeanSupportedProtocol::BlocksByRootV1.protocol_id(),
            LeanSupportedProtocol::BlocksByRangeV1.protocol_id(),
        ]
        .into_iter()
        .map(|protocol| (LeanReqRespProtocol(protocol), ProtocolSupport::Full));
        let reqresp_status =
            RequestResponse::new(reqresp_status_protocols, RequestResponseConfig::default());
        let reqresp_blocks =
            RequestResponse::new(reqresp_blocks_protocols, RequestResponseConfig::default());

        // Local discovery for dev/test networks (LAN scope).
        let mdns = Mdns::new(MdnsConfig::default(), peer_id).expect("mdns");
        let mut behaviour = LeanBehaviour {
            gossipsub,
            identify,
            reqresp_status,
            reqresp_blocks,
            mdns,
        };
        let mut topics = std::collections::HashSet::new();
        topics.insert(config.gossipsub_topic.clone());
        for topic in &config.allowed_topics {
            topics.insert(topic.clone());
        }
        for topic in topics {
            let ident = IdentTopic::new(topic);
            let topic_name = ident.to_string();
            let subscribed = behaviour.gossipsub.subscribe(&ident);
            tracing::info!(
                topic = %topic_name,
                subscribed = ?subscribed,
                "peam gossipsub subscription"
            );
        }

        let transport = quic::tokio::Transport::new(quic::Config::new(&keypair))
            .map(|(peer_id, conn), _| (peer_id, StreamMuxerBox::new(conn)))
            .boxed();

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(120)),
        );
        swarm.listen_on(config.listen_addr.clone()).expect("listen");

        for addr in config.bootnodes {
            if let Err(err) = swarm.dial(addr.clone()) {
                tracing::warn!("initial_dial_failed addr={addr} err={err}");
            }
        }

        let allowed_topics: RapidHashSet<String> = config.allowed_topics.iter().cloned().collect();
        let topic_scores: RapidHashMap<String, i64> = config.topic_scores.into_iter().collect();
        let topic_validators: RapidHashMap<String, super::GossipValidatorKind> =
            config.topic_validators.into_iter().collect();
        let signature_verifier = config.signature_verifier;
        let reqresp_handler = config.reqresp_handler;
        let gossip_context = config.gossip_context;
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
    /// Interleaves swarm events (gossip, identify, req/resp, mDNS) with
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
            P2pCommand::Dial { addr } => {
                if let Err(err) = self.swarm.dial(addr.clone()) {
                    tracing::warn!("dial_command_failed addr={addr} err={err}");
                }
            }
            P2pCommand::SendRequest {
                peer,
                protocol,
                payload,
            } => {
                // Send a req/resp request to a specific peer using the matching protocol behaviour.
                let kind = LeanSupportedProtocol::parse_protocol_id(&protocol);
                let request = LeanRequest {
                    protocol: protocol.clone(),
                    payload,
                };
                match kind {
                    Some(LeanSupportedProtocol::StatusV1) => {
                        self.swarm
                            .behaviour_mut()
                            .reqresp_status
                            .send_request(&peer, request);
                    }
                    Some(
                        LeanSupportedProtocol::BlocksByRootV1
                        | LeanSupportedProtocol::BlocksByRangeV1,
                    ) => {
                        self.swarm
                            .behaviour_mut()
                            .reqresp_blocks
                            .send_request(&peer, request);
                    }
                    None => {
                        warn!(
                            "reqresp_send_request_unknown_protocol peer={} protocol={}",
                            peer, protocol
                        );
                    }
                }
            }
        }
    }

    fn handle_reqresp_event(
        &mut self,
        event: RequestResponseEvent<LeanRequest, LeanResponse>,
        use_blocks_behaviour: bool,
    ) {
        match event {
            RequestResponseEvent::Message { peer, message, .. } => match message {
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
                    let response_to_send: Option<LeanResponse>;
                    match LeanSupportedProtocol::parse_protocol_id(&protocol) {
                        Some(kind) => match LeanRequestMessage::decode_ssz(kind, &payload) {
                            Ok(request) => {
                                let responses = self.reqresp_handler.on_request(request);
                                if responses.is_empty() {
                                    debug!(
                                        "reqresp_no_response_chunk peer={} protocol={} bytes={}",
                                        peer,
                                        protocol,
                                        payload.len()
                                    );
                                    response_to_send = Some(match kind {
                                        // Missing block chunks are normal. Reply with no chunks.
                                        LeanSupportedProtocol::BlocksByRootV1
                                        | LeanSupportedProtocol::BlocksByRangeV1 => LeanResponse {
                                            protocol: protocol.clone(),
                                            response_code: 0,
                                            payloads: Vec::new(),
                                        },
                                        LeanSupportedProtocol::StatusV1 => LeanResponse {
                                            protocol: protocol.clone(),
                                            response_code: 1, // ResponseCode::InvalidRequest
                                            payloads: vec![b"invalid request".to_vec()],
                                        },
                                    });
                                } else {
                                    let payloads = responses
                                        .into_iter()
                                        .map(|response| response.encode_ssz())
                                        .collect();
                                    response_to_send = Some(LeanResponse {
                                        protocol: protocol.clone(),
                                        response_code: 0,
                                        payloads,
                                    });
                                }
                            }
                            Err(err) => {
                                let prefix = payload
                                    .iter()
                                    .take(8)
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<Vec<_>>()
                                    .join("");
                                warn!(
                                    "reqresp_request_decode_failed peer={} protocol={} bytes={} prefix={} err={}",
                                    peer,
                                    protocol,
                                    payload.len(),
                                    prefix,
                                    err
                                );
                                response_to_send = Some(LeanResponse {
                                    protocol: protocol.clone(),
                                    response_code: 1, // ResponseCode::InvalidRequest
                                    //runtime waste
                                    payloads: vec![b"invalid request".to_vec()],
                                });
                            }
                        },
                        None => {
                            let prefix = payload
                                .iter()
                                .take(8)
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<Vec<_>>()
                                .join("");
                            warn!(
                                "reqresp_request_decode_failed peer={} protocol={} bytes={} prefix={} err=unsupported protocol",
                                peer,
                                protocol,
                                payload.len(),
                                prefix,
                            );
                            response_to_send = Some(LeanResponse {
                                protocol: protocol.clone(),
                                response_code: 1, // ResponseCode::InvalidRequest
                                //runtime waste
                                payloads: vec![b"invalid request".to_vec()],
                            });
                        }
                    }
                    self.events.emit(NetworkEvent::ReqRespRequest {
                        peer_id: peer.to_string(),
                        protocol: protocol.clone(),
                        payload: payload.clone(),
                    });

                    if let Some(response) = response_to_send {
                        let send_result = if use_blocks_behaviour {
                            self.swarm
                                .behaviour_mut()
                                .reqresp_blocks
                                .send_response(channel, response)
                        } else {
                            self.swarm
                                .behaviour_mut()
                                .reqresp_status
                                .send_response(channel, response)
                        };

                        if let Err(err) = send_result {
                            warn!("reqresp_send_response_failed peer={} err={:?}", peer, err);
                        }
                    }
                }
                RequestResponseMessage::Response { response, .. } => {
                    // Inbound req/resp response.
                    let LeanResponse {
                        protocol,
                        response_code,
                        payloads,
                    } = response;
                    let kind = LeanSupportedProtocol::parse_protocol_id(&protocol);
                    if payloads.is_empty() {
                        if matches!(kind, Some(LeanSupportedProtocol::BlocksByRangeV1)) {
                            let empty = BlocksByRangeResponse {
                                blocks: SszList::default(),
                            }
                            .encode_ssz();
                            self.events.emit(NetworkEvent::ReqRespResponse {
                                peer_id: peer.to_string(),
                                protocol: protocol.clone(),
                                payload: empty,
                            });
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: peer.to_string(),
                                score: 1,
                            });
                        }
                        debug!(
                            "reqresp_response_eos peer={} protocol={} code={}",
                            peer, protocol, response_code
                        );
                        return;
                    }
                    if matches!(kind, Some(LeanSupportedProtocol::BlocksByRangeV1)) {
                        let mut blocks = Vec::with_capacity(payloads.len());
                        for payload in payloads {
                            if payload.len() > self.max_reqresp_bytes {
                                self.events.emit(NetworkEvent::PeerScored {
                                    peer_id: peer.to_string(),
                                    score: -25,
                                });
                                continue;
                            }
                            match crate::networking::LeanResponseMessage::decode_ssz(
                                LeanSupportedProtocol::BlocksByRangeV1,
                                &payload,
                            ) {
                                Ok(crate::networking::LeanResponseMessage::BlocksByRange(
                                    block,
                                )) => {
                                    blocks.push(block);
                                }
                                Ok(other) => {
                                    warn!(
                                        "reqresp_response_decode_unexpected peer={} protocol={} variant={other:?}",
                                        peer, protocol
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        "reqresp_response_decode_failed peer={} protocol={} bytes={} err={}",
                                        peer,
                                        protocol,
                                        payload.len(),
                                        err
                                    );
                                }
                            }
                        }
                        let payload = BlocksByRangeResponse {
                            blocks: SszList::new(
                                blocks.into_iter().take(MAX_BLOCKS_PER_REQUEST).collect(),
                            )
                            .expect("range response block count bounded"),
                        }
                        .encode_ssz();
                        self.events.emit(NetworkEvent::ReqRespResponse {
                            peer_id: peer.to_string(),
                            protocol: protocol.clone(),
                            payload,
                        });
                        self.events.emit(NetworkEvent::PeerScored {
                            peer_id: peer.to_string(),
                            score: 1,
                        });
                        return;
                    }
                    for payload in payloads {
                        if payload.len() > self.max_reqresp_bytes {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: peer.to_string(),
                                score: -25,
                            });
                            continue;
                        }
                        debug!(
                            "reqresp_response_in peer={} protocol={} bytes={}",
                            peer,
                            protocol,
                            payload.len()
                        );
                        self.events.emit(NetworkEvent::ReqRespResponse {
                            peer_id: peer.to_string(),
                            protocol: protocol.clone(),
                            payload,
                        });
                        self.events.emit(NetworkEvent::PeerScored {
                            peer_id: peer.to_string(),
                            score: 1,
                        });
                    }
                }
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!(
                    "reqresp_outbound_failure peer={} request_id={request_id:?} err={error}",
                    peer
                );
                self.events.emit(NetworkEvent::PeerScored {
                    peer_id: peer.to_string(),
                    score: -10,
                });
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!(
                    "reqresp_inbound_failure peer={} request_id={request_id:?} err={error}",
                    peer
                );
                self.events.emit(NetworkEvent::PeerScored {
                    peer_id: peer.to_string(),
                    score: -10,
                });
            }
            RequestResponseEvent::ResponseSent {
                peer, request_id, ..
            } => {
                debug!(
                    "reqresp_response_sent peer={} request_id={request_id:?}",
                    peer
                );
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
    fn on_swarm_event(&mut self, event: SwarmEvent<LeanBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                // Mark connected on first established connection for this peer.
                if num_established.get() == 1 {
                    let inbound = endpoint.is_listener();
                    self.events.emit(NetworkEvent::PeerConnected {
                        peer_id: peer_id.to_string(),
                        inbound,
                    });
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                cause,
                num_established,
                ..
            } => {
                info!(
                    "connection_closed peer_id={peer_id} endpoint={endpoint:?} cause={cause:?} remaining_connections={num_established}"
                );
                // Emit disconnected only when the last active connection closes.
                if num_established == 0 {
                    let inbound = endpoint.is_listener();
                    self.events.emit(NetworkEvent::PeerDisconnected {
                        peer_id: peer_id.to_string(),
                        inbound,
                    });
                }
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
                    crate::networking::gossipsub::kind_from_topic_hash(&topic_hash).ok();
                let valid = lean_kind.is_some() || self.allowed_topics.contains(&topic);
                self.events.emit(NetworkEvent::GossipValidated {
                    topic: topic.clone(),
                    valid,
                });
                if !valid {
                    tracing::warn!(
                        "gossip dropped: unknown topic={topic} peer={propagation_source}"
                    );
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
                    tracing::warn!(
                        "gossip dropped: payload validation failed topic={topic} peer={propagation_source}"
                    );
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
                            tracing::warn!(
                                "gossip_ignore topic={topic} reason={reason} peer={propagation_source}"
                            );
                            return;
                        }
                        ValidationResult::Reject(reason) => {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -25,
                            });
                            tracing::warn!("gossip_reject topic={topic} reason={reason}");
                            return;
                        }
                    }
                    match crate::networking::gossipsub::validate::validate_with_context(
                        &decoded,
                        self.gossip_context.as_ref(),
                    ) {
                        ValidationResult::Accept => {}
                        ValidationResult::Ignore(reason) => {
                            if crate::networking::gossipsub::validate::is_retryable_unknown_roots_ignore(&reason) {
                                match &decoded {
                                    LeanGossipsubMessage::AggregatedAttestation(attestation) => {
                                        let data = &attestation.attestation.data;
                                        tracing::info!(
                                            peer = %propagation_source,
                                            slot = ?data.slot,
                                            head_slot = ?data.head.slot,
                                            head_root = ?data.head.root,
                                            target_slot = ?data.target.slot,
                                            target_root = ?data.target.root,
                                            source_slot = ?data.source.slot,
                                            source_root = ?data.source.root,
                                            "gossip_ignore aggregated attestation unknown roots"
                                        );
                                    }
                                    LeanGossipsubMessage::AttestationSubnet {
                                        subnet_id,
                                        attestation,
                                    } => {
                                        let data = &attestation.attestation.message;
                                        tracing::info!(
                                            peer = %propagation_source,
                                            subnet_id,
                                            slot = ?data.slot,
                                            head_slot = ?data.head.slot,
                                            head_root = ?data.head.root,
                                            target_slot = ?data.target.slot,
                                            target_root = ?data.target.root,
                                            source_slot = ?data.source.slot,
                                            source_root = ?data.source.root,
                                            "gossip_ignore attestation unknown roots"
                                        );
                                    }
                                    LeanGossipsubMessage::Block(_) => {}
                                }
                                self.events.emit(NetworkEvent::GossipDeferredUnknownRoots {
                                    topic: topic.clone(),
                                    payload: message.data.clone(),
                                });
                            }
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -1,
                            });
                            tracing::warn!(
                                "gossip_ignore topic={topic} reason={reason} peer={propagation_source}"
                            );
                            return;
                        }
                        ValidationResult::Reject(reason) => {
                            self.events.emit(NetworkEvent::PeerScored {
                                peer_id: propagation_source.to_string(),
                                score: -25,
                            });
                            tracing::warn!("gossip_reject topic={topic} reason={reason}");
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
                    if let Err(err) = self.swarm.dial(addr.clone()) {
                        tracing::warn!("mdns_dial_failed addr={addr} err={err}");
                    }
                }
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::Mdns(MdnsEvent::Expired(_))) => {}
            SwarmEvent::Behaviour(LeanBehaviourEvent::Identify(IdentifyEvent::Received {
                peer_id,
                ..
            })) => {
                self.events.emit(NetworkEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                    inbound: true,
                });
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    tracing::warn!("outgoing_connection_error peer_id={peer_id} err={error}");
                } else {
                    tracing::warn!("outgoing_connection_error err={error}");
                }
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::ReqrespStatus(event)) => {
                self.handle_reqresp_event(event, false);
            }
            SwarmEvent::Behaviour(LeanBehaviourEvent::ReqrespBlocks(event)) => {
                self.handle_reqresp_event(event, true);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossipsub_config_uses_anonymous_validation() {
        let config = build_gossipsub_config_lean(2_000_000);
        assert!(matches!(
            config.validation_mode(),
            gossipsub::ValidationMode::Anonymous
        ));
        assert_eq!(config.max_transmit_size(), 2_000_000);
    }

    #[test]
    fn reqresp_request_framing_roundtrip() {
        let payload = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut frame = Vec::new();
        encode_uvi_len(payload.len(), &mut frame);
        frame.extend_from_slice(&snappy_frame_compress(&payload).expect("compress"));

        let (len, prefix_len) = decode_uvi_len(&frame).expect("decode varint");
        assert_eq!(len, payload.len());
        let decoded =
            snappy_frame_decompress(&frame[prefix_len..], len).expect("decompress request");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn reqresp_response_framing_roundtrip() {
        let payload = vec![42u8; 32];
        let mut frame = Vec::new();
        frame.push(0);
        encode_uvi_len(payload.len(), &mut frame);
        frame.extend_from_slice(&snappy_frame_compress(&payload).expect("compress"));

        assert_eq!(frame[0], 0);
        let (len, prefix_len) = decode_uvi_len(&frame[1..]).expect("decode varint");
        assert_eq!(len, payload.len());
        let decoded =
            snappy_frame_decompress(&frame[(1 + prefix_len)..], len).expect("decompress response");
        assert_eq!(decoded, payload);
    }
}
