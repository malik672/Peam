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

use rapidhash::RapidHashMap;

use crate::containers::block::{Block, SignedBlockWithAttestation};
use crate::containers::state::State;
use crate::metrics::MetricsRegistry;
use crate::types::bytes::Bytes32;

mod canonical_db;
mod file_store;
mod index;
pub mod index_store;
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
const SCHEMA_VERSION: &str = "1";
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
    /// Number of unknown on-disk legacy artifacts skipped.
    pub skipped_unknown_version: usize,
}

/// The core storage interface shared by [`MemoryStore`] and [`FileStore`].
///
/// Canonical lookup is slot-driven (`get_*_by_slot`). Root-driven lookups
/// (`get_*`) also reach non-canonical fork data in [`FileStore`].
pub trait Store {
    /// Returns a decoded state for `root`, or `None` if not found/decoding fails.
    fn get_state(&self, root: &Bytes32) -> Option<State>;
    /// Inserts or replaces the state keyed by `root`.
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
    fn put_signed_block(
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
    fn put_signed_block_with_metrics(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
        _metrics: &MetricsRegistry,
    ) -> Result<(), String> {
        self.put_signed_block(root, signed, state)
    }
}

/// A fully in-memory [`Store`].
///
/// All data lives in `HashMap`s and is discarded when the store is dropped.
/// Intended for unit tests and simulation harnesses.
#[derive(Default)]
pub struct MemoryStore {
    states: RapidHashMap<Bytes32, State>,
    blocks: RapidHashMap<Bytes32, Block>,
    signed_blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
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
        self.states.get(root).cloned()
    }

    fn put_state(&mut self, root: Bytes32, state: State) {
        self.state_by_slot.insert(state.slot.0.0, root);
        self.states.insert(root, state);
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

    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        // we clone here, inevitable right ?
        state.process_signed_block(&signed)?;
        let block = signed.message.block.clone();
        self.block_by_slot.insert(block.slot.0.0, root);
        self.blocks.insert(root, block);
        self.signed_blocks.insert(root, signed);
        self.head = Some(root);
        self.justified = Some(state.latest_justified.root);
        self.finalized = Some(state.latest_finalized.root);
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
        self.finalized = Some(root);
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
    }
}
