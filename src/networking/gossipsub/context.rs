//! Runtime context injected into gossip validation.
//!
//! [`GossipContext`] provides validators with a read-only view of the node's
//! current slot and finalization state, enabling slot-range checks without
//! taking a full lock on the state.
//!
//! Two implementations are provided:
//! - [`NoopGossipContext`] — always returns `None` (no context available).
//! - [`StateGossipContext`] — reads live values from a shared [`State`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::containers::state::State;
use crate::slot::{Slot, slot_index_from_unix_millis, unix_now_millis};
use crate::ssz::HashTreeRoot;
use crate::storage::{FileStore, Store};
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

const RECENT_ROOT_CACHE_LEN: usize = 200;

/// Provides slot-related context to gossip validators.
///
/// Both methods return `Option` so that validators can safely skip slot checks
/// when the context is unavailable (e.g. before genesis).
pub trait GossipContext: Send + Sync {
    /// Returns the node's current slot, or `None` if not yet known.
    fn current_slot(&self) -> Option<Slot>;
    /// Returns the most recently finalized slot, or `None` if not yet known.
    fn finalized_slot(&self) -> Option<Slot>;
    /// Returns whether `root` is known in the local chain view.
    ///
    /// Default implementation is permissive for contexts that do not expose
    /// chain-root visibility.
    fn knows_block_root(&self, _root: &Bytes32) -> bool {
        true
    }
}

/// A [`GossipContext`] that provides no information.
///
/// All validators that depend on slot context will skip their checks when
/// using this implementation.
#[derive(Clone, Default)]
pub struct NoopGossipContext;

/// [`GossipContext`] impl — always returns `None`.
impl GossipContext for NoopGossipContext {
    fn current_slot(&self) -> Option<Slot> {
        None
    }

    fn finalized_slot(&self) -> Option<Slot> {
        None
    }
}

/// A [`GossipContext`] backed by a live [`State`] behind an `Arc<RwLock<…>>`.
///
/// Reads `state.slot` and `state.latest_finalized.slot` on each call.
pub struct StateGossipContext {
    state: Arc<RwLock<State>>,
    slot_clock: Option<Arc<AtomicU64>>,
    store: Option<Arc<RwLock<FileStore>>>,
    recent_roots: RwLock<RecentRootCache>,
}

impl StateGossipContext {
    /// Creates a new context that reads from `state`.
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self {
            state,
            slot_clock: None,
            store: None,
            recent_roots: RwLock::new(RecentRootCache::default()),
        }
    }

    /// Creates a new context backed by a strict slot ticker.
    pub fn with_slot_clock(state: Arc<RwLock<State>>, slot_clock: Arc<AtomicU64>) -> Self {
        Self {
            state,
            slot_clock: Some(slot_clock),
            store: None,
            recent_roots: RwLock::new(RecentRootCache::default()),
        }
    }

    /// Creates a new context backed by a strict slot ticker and store fallback.
    pub fn with_slot_clock_and_store(
        state: Arc<RwLock<State>>,
        slot_clock: Arc<AtomicU64>,
        store: Arc<RwLock<FileStore>>,
    ) -> Self {
        Self {
            state,
            slot_clock: Some(slot_clock),
            store: Some(store),
            recent_roots: RwLock::new(RecentRootCache::default()),
        }
    }
}

/// [`GossipContext`] impl — reads current and finalized slots from state.
impl GossipContext for StateGossipContext {
    fn current_slot(&self) -> Option<Slot> {
        if let Some(clock) = &self.slot_clock {
            return Some(Slot(Uint64(clock.load(Ordering::Relaxed))));
        }
        let guard = self.state.read().ok()?;
        let now = unix_now_millis()?;
        let slot = slot_index_from_unix_millis(guard.config.genesis_time.0, now);
        Some(Slot(Uint64(slot)))
    }

    fn finalized_slot(&self) -> Option<Slot> {
        let guard = self.state.read().ok()?;
        Some(guard.latest_finalized.slot)
    }

    fn knows_block_root(&self, root: &Bytes32) -> bool {
        if *root == Bytes32::zero() {
            return true;
        }
        let Ok(guard) = self.state.read() else {
            return false;
        };
        let snapshot = ContextSnapshot::from_state(&guard);
        if snapshot.knows_direct_root(root) {
            return true;
        }
        if let Ok(mut recent_roots) = self.recent_roots.write() {
            recent_roots.refresh_from_state(&guard);
            if recent_roots.contains(root) {
                return true;
            }
        }
        drop(guard);
        self.knows_block_root_cold(root, snapshot)
    }
}

#[derive(Clone, Copy)]
struct ContextSnapshot {
    latest_header_root: Bytes32,
    latest_header_slot: u64,
    latest_justified_root: Bytes32,
    latest_justified_slot: u64,
    latest_finalized_root: Bytes32,
    latest_finalized_slot: u64,
    state_slot: u64,
}

impl ContextSnapshot {
    #[inline]
    fn from_state(state: &State) -> Self {
        Self {
            latest_header_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
            latest_header_slot: state.latest_block_header.slot.0.0,
            latest_justified_root: state.latest_justified.root,
            latest_justified_slot: state.latest_justified.slot.0.0,
            latest_finalized_root: state.latest_finalized.root,
            latest_finalized_slot: state.latest_finalized.slot.0.0,
            state_slot: state.slot.0.0,
        }
    }

    #[inline]
    fn knows_direct_root(&self, root: &Bytes32) -> bool {
        *root == self.latest_header_root
            || *root == self.latest_justified_root
            || *root == self.latest_finalized_root
    }
}

#[derive(Clone, Copy)]
struct RecentRootEntry {
    slot: u64,
    root: Bytes32,
}

#[derive(Clone)]
struct RecentRootCache {
    entries: [Option<RecentRootEntry>; RECENT_ROOT_CACHE_LEN],
    latest_header_slot: u64,
    state_slot: u64,
}

impl Default for RecentRootCache {
    fn default() -> Self {
        Self {
            entries: [None; RECENT_ROOT_CACHE_LEN],
            latest_header_slot: u64::MAX,
            state_slot: u64::MAX,
        }
    }
}

impl RecentRootCache {
    #[inline]
    fn refresh_from_state(&mut self, state: &State) {
        let latest_header_slot = state.latest_block_header.slot.0.0;
        let state_slot = state.slot.0.0;
        if self.latest_header_slot == latest_header_slot && self.state_slot == state_slot {
            return;
        }

        self.entries = [None; RECENT_ROOT_CACHE_LEN];
        let latest_header_root = Bytes32::from(state.latest_block_header.hash_tree_root());
        self.insert(latest_header_slot, latest_header_root);

        let historical = &state.historical_block_hashes.data;
        let start = historical.len().saturating_sub(RECENT_ROOT_CACHE_LEN);
        for (slot, root) in historical.iter().copied().enumerate().skip(start) {
            if root == Bytes32::zero() {
                continue;
            }
            self.insert(slot as u64, root);
        }

        self.latest_header_slot = latest_header_slot;
        self.state_slot = state_slot;
    }

    #[inline]
    fn insert(&mut self, slot: u64, root: Bytes32) {
        let idx = (slot as usize) % RECENT_ROOT_CACHE_LEN;
        self.entries[idx] = Some(RecentRootEntry { slot, root });
    }

    #[inline]
    fn contains(&self, root: &Bytes32) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry.root == *root
                && self.entries[(entry.slot as usize) % RECENT_ROOT_CACHE_LEN].is_some()
        })
    }
}

impl StateGossipContext {
    #[cold]
    fn knows_block_root_cold(&self, root: &Bytes32, snapshot: ContextSnapshot) -> bool {
        let db_hit = self
            .store
            .as_ref()
            .and_then(|store| {
                store
                    .read()
                    .ok()
                    .map(|guard| guard.get_block(root).is_some())
            })
            .unwrap_or(false);
        tracing::trace!(
            queried_root = ?root,
            db_hit,
            latest_header_root = ?snapshot.latest_header_root,
            latest_header_slot = snapshot.latest_header_slot,
            latest_justified_root = ?snapshot.latest_justified_root,
            latest_justified_slot = snapshot.latest_justified_slot,
            latest_finalized_root = ?snapshot.latest_finalized_root,
            latest_finalized_slot = snapshot.latest_finalized_slot,
            state_slot = snapshot.state_slot,
            "peam gossip root cold lookup"
        );
        db_hit
    }
}

/// Converts a raw `u64` slot number into a typed [`Slot`].
pub fn slot_from_u64(slot: u64) -> Slot {
    Slot(Uint64(slot))
}
