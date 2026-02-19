use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::info;

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct Discovery {
    inner: Arc<InnerDiscovery>,
}

struct InnerDiscovery {
    seeds: Mutex<VecDeque<String>>,
    interval: Duration,
}

impl Discovery {
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: Arc::new(InnerDiscovery {
                seeds: Mutex::new(VecDeque::new()),
                interval,
            }),
        }
    }

    pub async fn add_seed(&self, peer_id: String) {
        let mut seeds = self.inner.seeds.lock().await;
        seeds.push_back(peer_id);
    }

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

    async fn next_seed(&self) -> Option<String> {
        let mut seeds = self.inner.seeds.lock().await;
        seeds.pop_front()
    }
}
