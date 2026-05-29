//! Persistent and in-memory block/state storage.
//!
//! Two implementations of [`Store`] are provided:
//!
//! | Type | Description |
//! |------|-------------|
//! | [`MemoryStore`] | Fully in-memory; intended for tests and simulation |
//! | [`FileStore`] | Disk-backed with index-driven lookup and on-demand decode |
//!
//! # FileStore on-disk layout
//!
//! ```text
//! <root>/
//!   canonical.redb   — canonical slot indexes + fork-choice metadata + blobs
//!   schema_version   — plain text schema version number
//! ```
//!
//! # Pending Window Model
//!
//! Writes land in a short-lived pending slot index (non-finalized horizon).
//! Finalized slots are promoted in batches into the canonical slot indexes.
//! This keeps canonical index writes stable while absorbing reorg churn in the
//! pending window. Pending indexes are in-memory only.

use peam_consensus_types::containers::block::{Block, SignedBlockWithAttestation};
use peam_consensus_types::containers::checkpoint::Checkpoint;
use peam_consensus_types::types::bytes::Bytes32;
use peam_ssz::ssz::HashTreeRoot;
use peam_state::state_metrics::TransitionMetricsSink;
use rapidhash::RapidHashMap;
use std::time::Instant;
use tracing::warn;

use peam_state::state::State;

mod canonical_db;
mod file_store;
mod index;
pub mod index_store;
mod logfmt;
mod pending;
mod prune;
mod storage_utils;
pub use self::file_store::FileStore;
pub use self::prune::PruneReport;
use self::storage_utils::*;

/// Canonical index/meta database file name.
const CANONICAL_DB_FILE: &str = "canonical.redb";
/// Number of slots stored in the in-memory pending window.
const PENDING_WINDOW_CAP: usize = 2_048;
/// Schema version file name.
const SCHEMA_FILE: &str = "schema_version";
/// Current on-disk schema version string.
const SCHEMA_VERSION: &str = "3";
/// Magic bytes at the start of every blob file.
const BLOB_MAGIC: &[u8; 8] = b"LEANSTRG";
/// Blob format version byte.
const BLOB_VERSION: u8 = 1;
/// Blob kind discriminant for state blobs.
const BLOB_KIND_STATE: u8 = 1;
/// Blob kind discriminant for block blobs.
const BLOB_KIND_BLOCK: u8 = 2;
/// Blob kind discriminant for signed-block blobs.
const BLOB_KIND_SIGNED_BLOCK: u8 = 3;

/// Statistics collected during [`FileStore::open`].
///
/// Returned by [`FileStore::recovery_report`]. All counters accumulate
/// across the initial `load_from_disk` pass and any subsequent index rebuilds.
// this might be better represented as a u64 per field or a u8
#[derive(Clone, Debug, Default)]
pub struct RecoveryReport {
    /// Number of state slot rows loaded into memory.
    pub loaded_states: usize,
    /// Number of block slot rows loaded into memory.
    pub loaded_blocks: usize,
    /// Number of signed block rows loaded at startup (currently always zero).
    pub loaded_signed_blocks: usize,
    /// Number of corrupt DB/index entries skipped during recovery.
    pub skipped_corrupt: usize,
}

/// Observes end-to-end storage-side block import latency.
pub trait StorageMetricsSink {
    fn observe_block_import_end_to_end_time(&self, start: Instant);
}

#[derive(Default)]
pub(crate) struct NoopStorageMetrics;

impl StorageMetricsSink for NoopStorageMetrics {
    #[inline]
    fn observe_block_import_end_to_end_time(&self, _start: Instant) {}
}

impl TransitionMetricsSink for NoopStorageMetrics {
    #[inline]
    fn observe_slots_processing_time(&self, _start: Instant) {}
    #[inline]
    fn add_slots_processed(&self, _n: u64) {}
    #[inline]
    fn observe_attestations_processing_time(&self, _start: Instant) {}
    #[inline]
    fn add_attestations_processed(&self, _n: u64) {}
    #[inline]
    fn observe_block_processing_time(&self, _start: Instant) {}
    #[inline]
    fn inc_finalizations_success(&self) {}
    #[inline]
    fn observe_state_transition_time(&self, _start: Instant) {}
}

/// Applies a signed block to a [`State`] using some concrete verification flow.
pub trait SignedBlockProcessor {
    fn process_signed_block(
        state: &mut State,
        signed: &SignedBlockWithAttestation,
    ) -> Result<(), String>;

    fn process_signed_block_with_metrics<M: TransitionMetricsSink>(
        state: &mut State,
        signed: &SignedBlockWithAttestation,
        metrics: &M,
    ) -> Result<(), String> {
        let _ = metrics;
        Self::process_signed_block(state, signed)
    }
}

/// The core storage interface shared by [`MemoryStore`] and [`FileStore`].
///
/// Canonical lookup is slot-driven (`get_*_by_slot`). Root-driven lookups
/// (`get_*`) also reach non-canonical fork data in [`FileStore`].
pub trait Store {
    /// Returns a decoded state for the owning block root `root`, or `None` if
    /// not found/decoding fails.
    ///
    /// Implementations may preserve compatibility with state-root lookup, but
    /// the intended storage contract is block-root-first.
    fn get_state(&self, root: &Bytes32) -> Option<State>;
    ///
    /// `root` should be the owning block root for this post-state. Implementations
    /// may preserve limited compatibility with older callers that pass a state
    /// root here, but the intended storage contract is block-root-first.
    fn put_state(&mut self, root: Bytes32, state: State);
    /// Returns a decoded block for `root`, or `None` if not found/decoding fails.
    fn get_block(&self, root: &Bytes32) -> Option<Block>;
    /// Returns a clone of the signed block with the given `root`, or `None`.
    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation>;
    /// Inserts or replaces the block keyed by `root`.
    fn put_block(&mut self, root: Bytes32, block: Block);
    /// Applies the full signed-block state transition, then persists the block,
    /// signed block, and resulting state.
    ///
    /// # Errors
    ///
    /// Returns `Err` if state transition or persistence fails.
    fn put_signed_block<P: SignedBlockProcessor>(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String>;
    /// Returns the canonical/pending state at `slot`, or `None`.
    fn get_state_by_slot(&self, slot: u64) -> Option<State>;
    /// Returns the canonical/pending block at `slot`, or `None`.
    fn get_block_by_slot(&self, slot: u64) -> Option<Block>;
    /// Returns the current finalized checkpoint root, if any.
    fn finalized(&self) -> Option<Bytes32>;
    /// Sets the finalized checkpoint root.
    fn set_finalized(&mut self, root: Bytes32);
    /// Sets the finalized checkpoint root and slot.
    fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_finalized(checkpoint.root);
    }
    /// Returns the current justified checkpoint root, if any.
    fn justified(&self) -> Option<Bytes32>;
    /// Sets the justified checkpoint root.
    fn set_justified(&mut self, root: Bytes32);
    /// Returns the current head root, if any.
    fn head(&self) -> Option<Bytes32>;
    /// Sets the head root.
    fn set_head(&mut self, root: Bytes32);
    /// Like [`put_signed_block`] but uses the metrics-instrumented state
    /// transition. Default implementation falls back to the non-metrics path.
    fn put_signed_block_with_metrics<
        P: SignedBlockProcessor,
        M: StorageMetricsSink + TransitionMetricsSink,
    >(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
        _metrics: &M,
    ) -> Result<(), String> {
        self.put_signed_block::<P>(root, signed, state)
    }
}

/// A fully in-memory [`Store`].
///
/// All data lives in `HashMap`s and is discarded when the store is dropped.
/// Intended for unit tests and simulation harnesses.
#[derive(Default)]
pub struct MemoryStore {
    states: RapidHashMap<Bytes32, State>,
    state_root_to_block_root: RapidHashMap<Bytes32, Bytes32>,
    blocks: RapidHashMap<Bytes32, Block>,
    signed_blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    finalized_slot: Option<u64>,
    justified: Option<Bytes32>,
}

impl MemoryStore {
    /// Creates a new empty [`MemoryStore`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// [`Store`] implementation for [`MemoryStore`].
impl Store for MemoryStore {
    fn get_state(&self, root: &Bytes32) -> Option<State> {
        let block_root = self
            .state_root_to_block_root
            .get(root)
            .copied()
            .unwrap_or(*root);
        self.states.get(&block_root).cloned()
    }

    fn put_state(&mut self, root: Bytes32, state: State) {
        let slot = state.slot.0.0;
        let block_root = root;
        let state_root = Bytes32::from(state.hash_tree_root());
        self.state_by_slot.insert(slot, block_root);
        self.state_root_to_block_root.insert(state_root, block_root);
        self.states.insert(block_root, state);
    }

    fn get_block(&self, root: &Bytes32) -> Option<Block> {
        self.blocks.get(root).cloned()
    }

    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.signed_blocks.get(root).cloned()
    }

    fn put_block(&mut self, root: Bytes32, block: Block) {
        self.block_by_slot.insert(block.slot.0.0, root);
        self.blocks.insert(root, block);
    }

    fn put_signed_block<P: SignedBlockProcessor>(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        // we clone here, inevitable right ?
        P::process_signed_block(state, &signed)?;
        let block = signed.message.block.clone();
        let slot = block.slot.0.0;
        let post_state = state.clone();
        let state_root = Bytes32::from(post_state.hash_tree_root());
        self.state_by_slot.insert(slot, root);
        self.state_root_to_block_root.insert(state_root, root);
        self.states.insert(root, post_state);
        self.block_by_slot.insert(block.slot.0.0, root);
        self.blocks.insert(root, block);
        self.signed_blocks.insert(root, signed);
        self.head = Some(root);
        self.justified = Some(state.latest_justified.root);
        self.finalized = Some(state.latest_finalized.root);
        self.finalized_slot = Some(state.latest_finalized.slot.0.0);
        Ok(())
    }

    fn get_state_by_slot(&self, slot: u64) -> Option<State> {
        let root = self.state_by_slot.get(&slot)?;
        self.states.get(root).cloned()
    }

    fn get_block_by_slot(&self, slot: u64) -> Option<Block> {
        let root = self.block_by_slot.get(&slot)?;
        self.blocks.get(root).cloned()
    }

    fn head(&self) -> Option<Bytes32> {
        self.head
    }

    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    fn set_finalized(&mut self, root: Bytes32) {
        let Some(block) = self.blocks.get(&root) else {
            warn!("set_finalized called with unknown root; ignoring");
            return;
        };
        let slot = block.slot.0.0;
        if let Some(current) = self.finalized_slot {
            if slot < current {
                warn!(
                    "set_finalized regression ignored new_slot={} current_slot={}",
                    slot, current
                );
                return;
            }
        }
        self.finalized = Some(root);
        self.finalized_slot = Some(slot);
    }

    fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        let slot = checkpoint.slot.0.0;
        if let Some(current) = self.finalized_slot {
            if slot < current {
                warn!(
                    "set_finalized_checkpoint regression ignored new_slot={} current_slot={}",
                    slot, current
                );
                return;
            }
        }
        self.finalized = Some(checkpoint.root);
        self.finalized_slot = Some(slot);
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryStore, Store};
    use peam_consensus_types::slot::Slot;
    use peam_consensus_types::types::bytes::Bytes32;
    use peam_consensus_types::types::uint::Uint64;
    use peam_ssz::ssz::HashTreeRoot;
    use peam_state::state::{State, Validators};

    fn root_from_u64(v: u64) -> Bytes32 {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&v.to_le_bytes());
        Bytes32::from(out)
    }

    fn dummy_state(slot: u64) -> State {
        let mut state =
            State::generate_genesis(Uint64(0), Validators::new(vec![]).expect("validators"));
        state.slot = Slot(Uint64(slot));
        state
    }

    #[test]
    fn memory_store_put_state_is_block_root_keyed_with_state_root_compatibility() {
        let mut store = MemoryStore::new();
        let block_root = root_from_u64(42);
        let state = dummy_state(7);
        let state_root = Bytes32::from(state.hash_tree_root());

        store.put_state(block_root, state.clone());

        assert_eq!(store.get_state(&block_root), Some(state.clone()));
        assert_eq!(store.get_state(&state_root), Some(state.clone()));
        assert_eq!(store.get_state_by_slot(7), Some(state));
    }
}
