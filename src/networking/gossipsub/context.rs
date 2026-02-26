//! Runtime context injected into gossip validation.
//!
//! [`GossipContext`] provides validators with a read-only view of the node's
//! current slot and finalization state, enabling slot-range checks without
//! taking a full lock on the state.
//!
//! Two implementations are provided:
//! - [`NoopGossipContext`] — always returns `None` (no context available).
//! - [`StateGossipContext`] — reads live values from a shared [`State`].

use std::sync::{Arc, RwLock};

use crate::containers::state::State;
use crate::slot::Slot;
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
}

impl StateGossipContext {
    /// Creates a new context that reads from `state`.
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self { state }
    }
}

/// [`GossipContext`] impl — reads current and finalized slots from state.
impl GossipContext for StateGossipContext {
    fn current_slot(&self) -> Option<Slot> {
        let guard = self.state.read().ok()?;
        Some(guard.slot)
    }

    fn finalized_slot(&self) -> Option<Slot> {
        let guard = self.state.read().ok()?;
        Some(guard.latest_finalized.slot)
    }
}

/// Converts a raw `u64` slot number into a typed [`Slot`].
pub fn slot_from_u64(slot: u64) -> Slot {
    Slot(Uint64(slot))
}
