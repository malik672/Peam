//! Peer discovery — periodic dialing of seed multiaddrs.
//!
//! [`Discovery`] maintains a FIFO queue of seed addresses. At each tick of its
//! configured interval it pops one seed and asks the p2p service to dial it.
//! Seeds are added dynamically via [`Discovery::add_seed`].

use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::P2pCommand;
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
    /// FIFO queue of seed multiaddrs waiting to be dialed.
    seeds: Mutex<VecDeque<Multiaddr>>,
    /// Set used to deduplicate configured seeds.
    seed_set: Mutex<HashSet<Multiaddr>>,
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

    /// Enqueues `seed_addr` for dialing on the next available tick.
    pub async fn add_seed(&self, seed_addr: String) {
        let addr: Multiaddr = match seed_addr.parse() {
            Ok(addr) => addr,
            Err(err) => {
                warn!("discovery_invalid_seed addr={} err={err}", seed_addr);
                return;
            }
        };
        let mut seed_set = self.inner.seed_set.lock().await;
        if !seed_set.insert(addr.clone()) {
            return;
        }
        drop(seed_set);
        let mut seeds = self.inner.seeds.lock().await;
        seeds.push_back(addr);
    }

    /// Runs the discovery loop indefinitely, dialing one seed address per tick.
    ///
    /// Call this inside a `tokio::spawn` task.
    pub async fn run(self, p2p_tx: mpsc::Sender<P2pCommand>, peers: PeerManager) {
        let mut ticker = tokio::time::interval(self.inner.interval);
        loop {
            ticker.tick().await;
            if let Some(addr) = self.next_seed().await {
                // Avoid aggressive redial churn for peers that are already connected.
                let mut should_skip = false;
                for protocol in addr.iter() {
                    if let Protocol::P2p(peer_id) = protocol {
                        should_skip = peers.is_connected(&peer_id.to_string()).await;
                        break;
                    }
                }
                if should_skip {
                    continue;
                }
                info!("discovery_dial addr={addr}");
                if p2p_tx.send(P2pCommand::Dial { addr }).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Pops the next seed from the front of the queue, returning `None` if
    /// the queue is empty.
    ///
    /// The popped seed is pushed back to preserve a round-robin dial cycle.
    async fn next_seed(&self) -> Option<Multiaddr> {
        let mut seeds = self.inner.seeds.lock().await;
        let next = seeds.pop_front()?;
        seeds.push_back(next.clone());
        Some(next)
    }
}
