//! Peer discovery — periodic dialing of seed peers.
//!
//! [`Discovery`] maintains a FIFO queue of seed peer IDs. At each tick of its
//! configured interval it pops one seed and asks the [`PeerManager`] to connect
//! to it. Seeds are added dynamically via [`Discovery::add_seed`].

use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::info;

use super::peer_manager::PeerManager;

/// Cheap-to-clone peer discovery handle.
///
/// Internally uses an `Arc` so all clones share the same seed queue and
/// interval configuration.
#[derive(Clone)]
pub struct Discovery {
    inner: Arc<InnerDiscovery>,
}

/// Shared discovery state.
struct InnerDiscovery {
    /// FIFO queue of peer IDs waiting to be dialed.
    seeds: Mutex<VecDeque<String>>,
    /// Set used to deduplicate configured seeds.
    seed_set: Mutex<HashSet<String>>,
    /// How often to attempt the next dial.
    interval: Duration,
}

impl Discovery {
    /// Creates a new [`Discovery`] instance that will attempt a dial every
    /// `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: Arc::new(InnerDiscovery {
                seeds: Mutex::new(VecDeque::new()),
                seed_set: Mutex::new(HashSet::new()),
                interval,
            }),
        }
    }

    /// Enqueues `peer_id` for dialing on the next available tick.
    pub async fn add_seed(&self, peer_id: String) {
        let mut seed_set = self.inner.seed_set.lock().await;
        if !seed_set.insert(peer_id.clone()) {
            return;
        }
        drop(seed_set);
        let mut seeds = self.inner.seeds.lock().await;
        seeds.push_back(peer_id);
    }

    /// Runs the discovery loop indefinitely, dialing one seed per tick.
    ///
    /// Call this inside a `tokio::spawn` task.
    pub async fn run(self, peers: PeerManager) {
        let mut ticker = tokio::time::interval(self.inner.interval);
        loop {
            ticker.tick().await;
            if let Some(peer_id) = self.next_seed().await {
                info!("discovery_dial peer={peer_id}");
                peers.connect(peer_id).await;
            }
        }
    }

    /// Pops the next seed from the front of the queue, returning `None` if
    /// the queue is empty.
    ///
    /// The popped seed is pushed back to preserve a round-robin dial cycle.
    async fn next_seed(&self) -> Option<String> {
        let mut seeds = self.inner.seeds.lock().await;
        let next = seeds.pop_front()?;
        seeds.push_back(next.clone());
        Some(next)
    }
}
