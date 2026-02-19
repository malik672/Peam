use std::sync::{Arc, RwLock};

use crate::containers::state::State;
use crate::slot::Slot;
use crate::types::uint::Uint64;

pub trait GossipContext: Send + Sync {
    fn current_slot(&self) -> Option<Slot>;
    fn finalized_slot(&self) -> Option<Slot>;
}

#[derive(Clone, Default)]
pub struct NoopGossipContext;

impl GossipContext for NoopGossipContext {
    fn current_slot(&self) -> Option<Slot> {
        None
    }

    fn finalized_slot(&self) -> Option<Slot> {
        None
    }
}

pub struct StateGossipContext {
    state: Arc<RwLock<State>>,
}

impl StateGossipContext {
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self { state }
    }
}

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

pub fn slot_from_u64(slot: u64) -> Slot {
    Slot(Uint64(slot))
}
