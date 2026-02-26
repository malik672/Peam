//! Token-bucket style rate limiter for per-key event counting.
//!
//! [`RateLimiter`] tracks event counts per string key within a sliding time
//! window. When a key's count exceeds `max_events` within the current window,
//! [`RateLimiter::allow`] returns `false`.
//!
//! All state is stored behind an `Arc<Mutex<…>>` so the limiter is
//! cheaply cloneable and safe to share across async tasks.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Cheaply-cloneable sliding-window rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<InnerRateLimiter>,
}

/// Shared limiter state.
struct InnerRateLimiter {
    /// Length of each measurement window.
    window: Duration,
    /// Maximum number of events allowed within one window.
    max_events: u64,
    /// Per-key counters: `(count, window_start)`.
    counts: Mutex<HashMap<String, (u64, Instant)>>,
}

impl RateLimiter {
    /// Creates a new [`RateLimiter`] that allows at most `max_events` per
    /// `window` duration for each key.
    pub fn new(window: Duration, max_events: u64) -> Self {
        Self {
            inner: Arc::new(InnerRateLimiter {
                window,
                max_events,
                counts: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Returns `true` and increments the counter if the event is within the
    /// current window's budget; returns `false` if the budget is exhausted.
    ///
    /// Automatically resets the counter when the current window has expired.
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
