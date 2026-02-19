use tokio::sync::mpsc;
use tracing::info;

use super::events::{EventBus, NetworkEvent};
use super::rate_limiter::RateLimiter;

#[derive(Clone)]
pub struct Gossip {
    tx: mpsc::Sender<GossipMessage>,
    events: EventBus,
    limiter: RateLimiter,
}

#[derive(Debug)]
pub struct GossipMessage {
    pub peer_id: Option<String>,
    pub topic: String,
    pub payload: Vec<u8>,
}

impl Gossip {
    pub fn new(events: EventBus, buffer: usize) -> (Self, mpsc::Receiver<GossipMessage>) {
        let (tx, rx) = mpsc::channel(buffer);
        let limiter = RateLimiter::new(std::time::Duration::from_secs(1), 64);
        (Self { tx, events, limiter }, rx)
    }

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
