//! Peer registry with score-based banning.
//!
//! [`PeerManager`] tracks the set of connected peers and maintains a score for
//! each one. Scores change via [`score_delta`], with helpers for common
//! feedback signals. A background task should call [`decay_and_prune`]
//! periodically to decay scores toward zero and ban peers whose score falls
//! below the configured threshold.

use std::collections::HashSet;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;
use tracing::info;

use super::events::{EventBus, NetworkEvent};
use crate::metrics::MetricsRegistry;

/// Cheaply-cloneable peer registry and scorer.
///
/// All clones share the same underlying state via `Arc`.
#[derive(Clone)]
pub struct PeerManager {
    inner: Arc<InnerPeerManager>,
}

/// Shared peer manager state.
struct InnerPeerManager {
    /// Set of currently connected peer IDs.
    peers: Mutex<HashSet<String>>,
    /// Score map: peer ID → current score (may be negative).
    scores: Mutex<HashMap<String, i64>>,
    events: EventBus,
    /// Connected peer count, updated atomically for sync access from metrics.
    peer_count: AtomicUsize,
    /// Optional shared metrics registry for connection counters.
    metrics: Option<Arc<MetricsRegistry>>,
}

impl PeerManager {
    #[inline]
    fn build(events: EventBus, metrics: Option<Arc<MetricsRegistry>>) -> Self {
        Self {
            inner: Arc::new(InnerPeerManager {
                peers: Mutex::new(HashSet::new()),
                scores: Mutex::new(HashMap::new()),
                events,
                peer_count: AtomicUsize::new(0),
                metrics,
            }),
        }
    }

    /// Creates a new [`PeerManager`] that emits events on `events`.
    pub fn new(events: EventBus) -> Self {
        Self::build(events, None)
    }

    /// Creates a new [`PeerManager`] with a shared metrics registry.
    pub fn with_metrics(events: EventBus, metrics: Arc<MetricsRegistry>) -> Self {
        Self::build(events, Some(metrics))
    }

    /// Registers `peer_id` as connected, initialising its score to 0.
    ///
    /// If the peer is already connected this is a no-op.
    /// `inbound` indicates whether the connection was initiated by the remote peer.
    pub async fn connect(&self, peer_id: String, inbound: bool) {
        let mut peers = self.inner.peers.lock().await;
        if peers.insert(peer_id.clone()) {
            self.inner.peer_count.store(peers.len(), Ordering::Relaxed);
            info!("peer_connected={peer_id} inbound={inbound}");
            self.inner
                .scores
                .lock()
                .await
                .entry(peer_id.clone())
                .or_insert(0);
            if let Some(metrics) = &self.inner.metrics {
                if inbound {
                    metrics.peer_connection_inbound.inc();
                } else {
                    metrics.peer_connection_outbound.inc();
                }
            }
        }
    }

    /// Removes `peer_id` from the registry and its score entry.
    ///
    /// If the peer is not currently connected this is a no-op.
    /// `inbound` indicates whether the original connection was inbound.
    pub async fn disconnect(&self, peer_id: &str, inbound: bool) {
        let mut peers = self.inner.peers.lock().await;
        if peers.remove(peer_id) {
            self.inner.peer_count.store(peers.len(), Ordering::Relaxed);
            self.inner.scores.lock().await.remove(peer_id);
            info!("peer_disconnected={peer_id} inbound={inbound}");
            if let Some(metrics) = &self.inner.metrics {
                if inbound {
                    metrics.peer_disconnection_inbound.inc();
                } else {
                    metrics.peer_disconnection_outbound.inc();
                }
            }
        }
    }

    /// Adjusts `peer_id`'s score by `delta` (may be negative) and returns the
    /// new score.
    ///
    /// Creates a score entry at 0 if one does not exist. Uses saturating
    /// arithmetic to avoid overflow.
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

    /// Awards +10 score for a well-behaved req/resp response.
    pub async fn successful_response_from_peer(&self, peer_id: &str) -> i64 {
        // Positive feedback for peers that respond correctly.
        self.score_delta(peer_id, 10).await
    }

    /// Deducts 20 score for a failed or misbehaving req/resp response.
    pub async fn failed_response_from_peer(&self, peer_id: &str) -> i64 {
        // Negative feedback for peers that fail or misbehave.
        self.score_delta(peer_id, -20).await
    }

    /// Decays all scores toward zero by `decay_by`, then bans and disconnects
    /// any peer whose score is at or below `ban_threshold`.
    ///
    /// Returns the list of peer IDs that were banned in this pass.
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
                inbound: false,
            });
            banned.push(peer_id);
        }

        if !banned.is_empty() {
            self.inner.peer_count.store(peers.len(), Ordering::Relaxed);
        }

        banned
    }

    /// Returns `peer_id`'s current score, or `None` if the peer is unknown.
    pub async fn score(&self, peer_id: &str) -> Option<i64> {
        let scores = self.inner.scores.lock().await;
        scores.get(peer_id).copied()
    }

    /// Returns a snapshot of all currently connected peer IDs.
    pub async fn list(&self) -> Vec<String> {
        let peers = self.inner.peers.lock().await;
        peers.iter().cloned().collect()
    }

    /// Returns whether `peer_id` is currently tracked as connected.
    pub async fn is_connected(&self, peer_id: &str) -> bool {
        let peers = self.inner.peers.lock().await;
        peers.contains(peer_id)
    }

    /// Returns the current connected peer count without async locking.
    ///
    /// Safe to call from synchronous contexts (e.g. metrics rendering).
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.inner.peer_count.load(Ordering::Relaxed)
    }
}
