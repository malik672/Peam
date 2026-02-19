use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<InnerRateLimiter>,
}

struct InnerRateLimiter {
    window: Duration,
    max_events: u64,
    counts: Mutex<HashMap<String, (u64, Instant)>>,
}

impl RateLimiter {
    pub fn new(window: Duration, max_events: u64) -> Self {
        Self {
            inner: Arc::new(InnerRateLimiter {
                window,
                max_events,
                counts: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let mut counts = self.inner.counts.lock().await;
        let now = Instant::now();
        let entry = counts.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > self.inner.window {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= self.inner.max_events
    }
}
