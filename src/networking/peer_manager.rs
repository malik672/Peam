//! Peer registry with score-based banning.
//!
//! [`PeerManager`] tracks the set of connected peers and maintains a score for
//! each one. Scores change via [`score_delta`], with helpers for common
//! feedback signals. A background task should call [`decay_and_prune`]
//! periodically to decay scores toward zero and ban peers whose score falls
//! below the configured threshold.

use rapidhash::{RapidHashMap, RapidHashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
    /// remove prod
    peers: Mutex<RapidHashSet<String>>,
    /// Score map: peer ID → current score (may be negative).
    scores: Mutex<RapidHashMap<String, i64>>,
    events: EventBus,
    /// Connected peer count, updated atomically for sync access from metrics.
    peer_count: AtomicUsize,
    /// Optional shared metrics registry for connection counters.
    metrics: Option<Arc<MetricsRegistry>>,
    /// Exponential backoff state for recently banned peers.
    backoff: Mutex<RapidHashMap<String, BackoffState>>,
}

#[derive(Clone, Copy, Debug)]
struct BackoffState {
    attempts: u32,
    next_allowed: Instant,
}

impl PeerManager {
    /// Creates a new [`PeerManager`] that emits events on `events`.
    pub fn new(events: EventBus) -> Self {
        Self {
            inner: Arc::new(InnerPeerManager {
                peers: Mutex::new(RapidHashSet::default()),
                scores: Mutex::new(RapidHashMap::default()),
                events,
                peer_count: AtomicUsize::new(0),
                metrics: None,
                backoff: Mutex::new(RapidHashMap::default()),
            }),
        }
    }

    /// Creates a new [`PeerManager`] with a shared metrics registry.
    pub fn with_metrics(events: EventBus, metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            inner: Arc::new(InnerPeerManager {
                peers: Mutex::new(RapidHashSet::default()),
                scores: Mutex::new(RapidHashMap::default()),
                events,
                peer_count: AtomicUsize::new(0),
                metrics: Some(metrics),
                backoff: Mutex::new(RapidHashMap::default()),
            }),
        }
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
            self.inner.backoff.lock().await.remove(&peer_id);
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
        let mut backoff = self.inner.backoff.lock().await;
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
            let backoff_for = record_backoff(&mut backoff, &peer_id);
            self.inner.events.emit(NetworkEvent::PeerBanned {
                peer_id: peer_id.clone(),
                reason: format!(
                    "score below ban threshold (backoff {}s)",
                    backoff_for.as_secs()
                ),
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

    /// Returns remaining backoff duration for `peer_id` if dialing should be delayed.
    pub async fn backoff_remaining(&self, peer_id: &str) -> Option<Duration> {
        let backoff = self.inner.backoff.lock().await;
        let entry = backoff.get(peer_id)?;
        let now = Instant::now();
        if entry.next_allowed > now {
            Some(entry.next_allowed.duration_since(now))
        } else {
            None
        }
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

fn record_backoff(backoff: &mut RapidHashMap<String, BackoffState>, peer_id: &str) -> Duration {
    const BASE_BACKOFF_SECS: u64 = 2;
    const MAX_BACKOFF_SECS: u64 = 120;
    let entry = backoff.entry(peer_id.to_string()).or_insert(BackoffState {
        attempts: 0,
        next_allowed: Instant::now(),
    });
    entry.attempts = entry.attempts.saturating_add(1);
    let exp = 2u64.saturating_pow(entry.attempts.saturating_sub(1));
    let backoff_secs = (BASE_BACKOFF_SECS.saturating_mul(exp)).min(MAX_BACKOFF_SECS);
    let backoff_for = Duration::from_secs(backoff_secs);
    entry.next_allowed = Instant::now()
        .checked_add(backoff_for)
        .unwrap_or_else(Instant::now);
    backoff_for
}
