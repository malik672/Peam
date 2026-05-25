//! Network event bus — typed events and a broadcast channel.
//!
//! [`EventBus`] is a thin, cheaply-cloneable wrapper around a
//! `tokio::sync::broadcast` channel. Any number of components can subscribe
//! to receive [`NetworkEvent`]s without knowing about each other.

use peam_consensus_types::types::bytes::Bytes32;
use tokio::sync::broadcast;

/// All observable events emitted by the networking stack.
///
/// Subscribers receive a clone of each event via [`EventBus::subscribe`].
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer connection was established.
    PeerConnected { peer_id: String, inbound: bool },
    /// An existing peer connection was closed.
    PeerDisconnected { peer_id: String, inbound: bool },
    /// A peer was banned and removed.
    PeerBanned { peer_id: String, reason: String },
    /// A gossipsub message was received from the network.
    GossipMessage { topic: String, payload: Vec<u8> },
    /// A gossipsub message was ignored because it referenced roots that may
    /// become known shortly after import/sync catches up.
    GossipDeferredUnknownRoots { topic: String, payload: Vec<u8> },
    /// A gossip attestation referenced a head block that is the only missing
    /// dependency; callers may fetch the block and replay the message when it arrives.
    GossipDeferredMissingHead {
        topic: String,
        payload: Vec<u8>,
        head_root: Bytes32,
        peer_id: String,
    },
    /// A gossipsub message passed (`valid: true`) or failed (`valid: false`) validation.
    GossipValidated { topic: String, valid: bool },
    /// An inbound req/resp request arrived from a peer.
    ReqRespRequest {
        peer_id: String,
        protocol: String,
        payload: Vec<u8>,
    },
    /// An inbound req/resp response arrived from a peer.
    ReqRespResponse {
        peer_id: String,
        protocol: String,
        payload: Vec<u8>,
    },
    /// A peer's score was updated; `score` is the new value.
    PeerScored { peer_id: String, score: i64 },
    /// A message or request was dropped because a rate limit was exceeded.
    RateLimited { peer_id: String, category: String },
}

/// A multi-producer, multi-consumer event bus backed by a broadcast channel.
///
/// Clone this freely — all clones share the same underlying sender.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<NetworkEvent>,
}

impl EventBus {
    /// Creates a new [`EventBus`] with a channel capacity of `buffer` events.
    ///
    /// Slow receivers will lose events once the buffer is full (broadcast
    /// channel semantics).
    pub fn new(buffer: usize) -> Self {
        let (sender, _) = broadcast::channel(buffer);
        Self { sender }
    }

    /// Returns a new receiver that will observe all future events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.sender.subscribe()
    }

    /// Broadcasts `event` to all active subscribers.
    ///
    /// If no subscribers are currently active the send is silently dropped.
    pub fn emit(&self, event: NetworkEvent) {
        let _ = self.sender.send(event);
    }
}
