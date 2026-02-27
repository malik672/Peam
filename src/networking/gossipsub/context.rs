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
use crate::types::bytes::Bytes32;
use crate::types::uint::Uint64;

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
}

impl StateGossipContext {
    /// Creates a new context that reads from `state`.
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self {
            state,
            slot_clock: None,
        }
    }

    /// Creates a new context backed by a strict slot ticker.
    pub fn with_slot_clock(state: Arc<RwLock<State>>, slot_clock: Arc<AtomicU64>) -> Self {
        Self {
            state,
            slot_clock: Some(slot_clock),
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
        if *root == Bytes32::from(guard.latest_block_header.hash_tree_root())
            || *root == guard.latest_justified.root
            || *root == guard.latest_finalized.root
        {
            return true;
        }
        guard.historical_block_hashes.data.iter().any(|v| v == root)
    }
}

/// Converts a raw `u64` slot number into a typed [`Slot`].
pub fn slot_from_u64(slot: u64) -> Slot {
    Slot(Uint64(slot))
}
