use std::collections::HashSet;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;

use super::events::{EventBus, NetworkEvent};

#[derive(Clone)]
pub struct PeerManager {
    inner: Arc<InnerPeerManager>,
}

struct InnerPeerManager {
    peers: Mutex<HashSet<String>>,
    scores: Mutex<HashMap<String, i64>>,
    events: EventBus,
}

impl PeerManager {
    pub fn new(events: EventBus) -> Self {
        Self {
            inner: Arc::new(InnerPeerManager {
                peers: Mutex::new(HashSet::new()),
                scores: Mutex::new(HashMap::new()),
                events,
            }),
        }
    }

    pub async fn connect(&self, peer_id: String) {
        let mut peers = self.inner.peers.lock().await;
        if peers.insert(peer_id.clone()) {
            info!("peer_connected={peer_id}");
            self.inner.scores.lock().await.entry(peer_id.clone()).or_insert(0);
            self.inner.events
                .emit(NetworkEvent::PeerConnected { peer_id });
        }
    }

    pub async fn disconnect(&self, peer_id: &str) {
        let mut peers = self.inner.peers.lock().await;
        if peers.remove(peer_id) {
            self.inner.scores.lock().await.remove(peer_id);
            info!("peer_disconnected={peer_id}");
            self.inner.events.emit(NetworkEvent::PeerDisconnected {
                peer_id: peer_id.to_string(),
            });
        }
    }

    pub async fn score_delta(&self, peer_id: &str, delta: i64) -> i64 {
        let mut scores = self.inner.scores.lock().await;
        let entry = scores.entry(peer_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(delta);
        self.inner.events.emit(NetworkEvent::PeerScored {
            peer_id: peer_id.to_string(),
            score: *entry,
        });
        *entry
    }

    pub async fn successful_response_from_peer(&self, peer_id: &str) -> i64 {
        self.score_delta(peer_id, 10).await
    }

    pub async fn failed_response_from_peer(&self, peer_id: &str) -> i64 {
        self.score_delta(peer_id, -20).await
    }

    pub async fn decay_and_prune(&self, decay_by: i64, ban_threshold: i64) -> Vec<String> {
        let mut scores = self.inner.scores.lock().await;
        let mut peers = self.inner.peers.lock().await;
        let mut banned = Vec::new();

        for (peer_id, score) in scores.iter_mut() {
            if *score > 0 {
                *score = (*score - decay_by).max(0);
            } else if *score < 0 {
                *score = (*score + decay_by).min(0);
            }
            self.inner.events.emit(NetworkEvent::PeerScored {
                peer_id: peer_id.to_string(),
                score: *score,
            });
        }

        let to_remove: Vec<String> = scores
            .iter()
            .filter_map(|(peer_id, score)| {
                if *score <= ban_threshold {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
            .collect();

        for peer_id in to_remove {
            scores.remove(&peer_id);
            peers.remove(&peer_id);
            self.inner.events.emit(NetworkEvent::PeerBanned {
                peer_id: peer_id.clone(),
                reason: "score below ban threshold".to_string(),
            });
            self.inner.events.emit(NetworkEvent::PeerDisconnected {
                peer_id: peer_id.clone(),
            });
            banned.push(peer_id);
        }

        banned
    }

    pub async fn score(&self, peer_id: &str) -> Option<i64> {
        let scores = self.inner.scores.lock().await;
        scores.get(peer_id).copied()
    }

    pub async fn list(&self) -> Vec<String> {
        let peers = self.inner.peers.lock().await;
        peers.iter().cloned().collect()
    }
}
