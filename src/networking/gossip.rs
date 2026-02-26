//! Outbound gossip publishing with egress rate limiting.
//!
//! [`Gossip`] is a cloneable handle for publishing messages to the gossipsub
//! network. Published messages are rate-limited to prevent flooding, then
//! forwarded to an internal channel consumed by the networking runtime, and
//! also broadcast on the [`EventBus`].

use tokio::sync::mpsc;
use tracing::info;

use super::events::{EventBus, NetworkEvent};
use super::rate_limiter::RateLimiter;

/// Cloneable outbound gossip publisher.
///
/// Rate-limited with a per-second token bucket on the `"gossip_out"` key.
/// If the limit is exceeded the message is dropped and a
/// [`NetworkEvent::RateLimited`] event is emitted.
#[derive(Clone)]
pub struct Gossip {
    tx: mpsc::Sender<GossipMessage>,
    events: EventBus,
    limiter: RateLimiter,
}

/// A gossipsub message routed through the internal pipeline.
#[derive(Debug)]
pub struct GossipMessage {
    /// Source peer ID, or `None` for locally-originated messages.
    pub peer_id: Option<String>,
    /// Gossipsub topic string.
    pub topic: String,
    /// Raw SSZ-encoded payload.
    pub payload: Vec<u8>,
}

impl Gossip {
    /// Creates a new [`Gossip`] publisher and returns the paired receiver.
    ///
    /// `buffer` sets the internal channel capacity. The receiver is consumed
    /// by the inbound gossip pipeline in the networking runtime.
    pub fn new(events: EventBus, buffer: usize) -> (Self, mpsc::Receiver<GossipMessage>) {
        let (tx, rx) = mpsc::channel(buffer);
        let limiter = RateLimiter::new(std::time::Duration::from_secs(1), 64);
        (
            Self {
                tx,
                events,
                limiter,
            },
            rx,
        )
    }

    /// Publishes `payload` to `topic`.
    ///
    /// Silently drops the message and emits [`NetworkEvent::RateLimited`] if
    /// the egress rate limit is exceeded.
    pub async fn publish(&self, topic: String, payload: Vec<u8>) {
        if !self.limiter.allow("gossip_out").await {
            self.events.emit(NetworkEvent::RateLimited {
                peer_id: "self".to_string(),
                category: "gossip_out".to_string(),
            });
            return;
        }
        let msg = GossipMessage {
            peer_id: None,
            topic: topic.clone(),
            payload: payload.clone(),
        };
        let _ = self.tx.send(msg).await;
        info!("gossip_publish topic={topic}");
        self.events
            .emit(NetworkEvent::GossipMessage { topic, payload });
    }
}
