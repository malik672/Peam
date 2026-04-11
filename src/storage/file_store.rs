//! Disk-backed [`FileStore`] implementation.
//!
//! This module owns on-disk persistence, startup recovery/loading,
//! canonical/pending index bookkeeping, and [`Store`] implementation details
//! for database-backed operation.
//!
//! # Data flow
//!
//! ```text
//! put_signed_block(root, signed, state)
//!   ├─ state.process_signed_block()          state transition
//!   ├─ encode_blob(BLOCK|SIGNED|STATE)       wrap SSZ in LEANSTRG envelope
//!   ├─ index_block_slot / index_state_slot   route to canonical or pending
//!   ├─ promote_finalized_slot_in_memory()    drain pending ≤ finalized
//!   └─ canonical_db.persist_signed_block_bundle()  single atomic redb write txn
//! ```
//!
//! # Read paths
//!
//! | Method | Warm (in-memory) | Cold (redb) |
//! |--------|------------------|-------------|
//! | `get_state(root)` | — | state-root lookup → block-root blob decode |
//! | `get_block(root)` | — | redb read txn → decode blob → SSZ decode |
//! | `get_state_by_slot(slot)` | pending cache hit | slot index → state-root lookup → cold path |
//! | `get_block_by_slot(slot)` | pending cache hit | slot index → root → cold path |
//!
//! By-root reads always go to disk (no in-memory blob cache). By-slot reads
//! check the pending window first (`O(1)` mod-indexed lookup), then fall
//! through to the canonical `RapidHashMap` index for the root, then to redb.
//!
//! # Persistence model
//!
//! Dirty tracking (`index_dirty`, `meta_dirty`) defers redb writes until
//! `flush_canonical()`. The `Drop` impl flushes any remaining dirty state.
//! `put_signed_block` bypasses this and writes everything in one atomic
//! `persist_signed_block_bundle` transaction.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tracing::warn;

use super::canonical_db::CanonicalDb;
use super::pending::PendingSlotCache;
use super::*;
use crate::containers::checkpoint::Checkpoint;
use crate::ssz::{HashTreeRoot, SszEncode};

/// A disk-backed [`Store`] with canonical+pending slot indexes as truth.
///
/// Index model:
/// - `state_by_slot` / `block_by_slot`: canonical slot indexes.
/// - `pending_blocks`: hot non-finalized block slot index (in-memory only).
///
/// Object reads by root are decoded on demand from `canonical.redb`.
pub struct FileStore {
    /// Root directory of the store.
    pub(super) root: PathBuf,
    /// Canonical index + fork-choice metadata database.
    pub(super) canonical_db: CanonicalDb,
    /// Canonical finalized slot->state-root index.
    pub(super) state_by_slot: RapidHashMap<u64, Bytes32>,
    /// Secondary lookup from state root to the owning block root.
    pub(super) state_root_to_block_root: RapidHashMap<Bytes32, Bytes32>,
    /// Canonical finalized slot->block-root index.
    pub(super) block_by_slot: RapidHashMap<u64, Bytes32>,
    /// Pending (non-finalized) slot->block-root cache.
    pub(super) pending_blocks: PendingSlotCache,
    /// Current head block root.
    pub(super) head: Option<Bytes32>,
    /// Current finalized checkpoint root.
    pub(super) finalized: Option<Bytes32>,
    /// Cached slot of the current finalized checkpoint root.
    pub(super) finalized_slot: Option<u64>,
    /// Current justified checkpoint root.
    pub(super) justified: Option<Bytes32>,
    /// Counters accumulated during startup and index rebuilds.
    pub(super) recovery: RecoveryReport,
    /// True when canonical indexes changed in-memory but are not yet persisted.
    pub(super) index_dirty: bool,
    /// True when fork-choice metadata changed in-memory but is not yet persisted.
    pub(super) meta_dirty: bool,
}

#[derive(Debug)]
struct StateSnapshot {
    slot: u64,
    state_root: Bytes32,
    header_slot: u64,
    header_root: Bytes32,
    header_parent_root: Bytes32,
    header_state_root: Bytes32,
    justified_slot: u64,
    justified_root: Bytes32,
    finalized_slot: u64,
    finalized_root: Bytes32,
    historical_len: usize,
    historical_tail: Option<Bytes32>,
    historical_root: Bytes32,
    justified_slots_len: usize,
    justified_slots_root: Bytes32,
    validators_len: usize,
    validators_root: Bytes32,
    justifications_roots_len: usize,
    justifications_roots_root: Bytes32,
    justifications_validators_len: usize,
    justifications_validators_root: Bytes32,
}

impl StateSnapshot {
    fn capture(state: &State) -> Self {
        Self {
            slot: state.slot.0.0,
            state_root: Bytes32::from(state.hash_tree_root()),
            header_slot: state.latest_block_header.slot.0.0,
            header_root: Bytes32::from(state.latest_block_header.hash_tree_root()),
            header_parent_root: state.latest_block_header.parent_root,
            header_state_root: state.latest_block_header.state_root,
            justified_slot: state.latest_justified.slot.0.0,
            justified_root: state.latest_justified.root,
            finalized_slot: state.latest_finalized.slot.0.0,
            finalized_root: state.latest_finalized.root,
            historical_len: state.historical_block_hashes.len(),
            historical_tail: state.historical_block_hashes.last().copied(),
            historical_root: Bytes32::from(state.historical_block_hashes.hash_tree_root()),
            justified_slots_len: state.justified_slots.len,
            justified_slots_root: Bytes32::from(state.justified_slots.hash_tree_root()),
            validators_len: state.validators.len(),
            validators_root: Bytes32::from(state.validators.hash_tree_root()),
            justifications_roots_len: state.justifications_roots.len(),
            justifications_roots_root: Bytes32::from(state.justifications_roots.hash_tree_root()),
            justifications_validators_len: state.justifications_validators.len,
            justifications_validators_root: Bytes32::from(
                state.justifications_validators.hash_tree_root(),
            ),
        }
    }

    fn differing_fields(&self, other: &Self) -> Vec<&'static str> {
        let mut diffs = Vec::new();
        if self.slot != other.slot {
            diffs.push("slot");
        }
        if self.state_root != other.state_root {
            diffs.push("state_root");
        }
        if self.header_slot != other.header_slot {
            diffs.push("header_slot");
        }
        if self.header_root != other.header_root {
            diffs.push("header_root");
        }
        if self.header_parent_root != other.header_parent_root {
            diffs.push("header_parent_root");
        }
        if self.header_state_root != other.header_state_root {
            diffs.push("header_state_root");
        }
        if self.justified_slot != other.justified_slot {
            diffs.push("justified_slot");
        }
        if self.justified_root != other.justified_root {
            diffs.push("justified_root");
        }
        if self.finalized_slot != other.finalized_slot {
            diffs.push("finalized_slot");
        }
        if self.finalized_root != other.finalized_root {
            diffs.push("finalized_root");
        }
        if self.historical_len != other.historical_len {
            diffs.push("historical_len");
        }
        if self.historical_tail != other.historical_tail {
            diffs.push("historical_tail");
        }
        if self.historical_root != other.historical_root {
            diffs.push("historical_root");
        }
        if self.justified_slots_len != other.justified_slots_len {
            diffs.push("justified_slots_len");
        }
        if self.justified_slots_root != other.justified_slots_root {
            diffs.push("justified_slots_root");
        }
        if self.validators_len != other.validators_len {
            diffs.push("validators_len");
        }
        if self.validators_root != other.validators_root {
            diffs.push("validators_root");
        }
        if self.justifications_roots_len != other.justifications_roots_len {
            diffs.push("justifications_roots_len");
        }
        if self.justifications_roots_root != other.justifications_roots_root {
            diffs.push("justifications_roots_root");
        }
        if self.justifications_validators_len != other.justifications_validators_len {
            diffs.push("justifications_validators_len");
        }
        if self.justifications_validators_root != other.justifications_validators_root {
            diffs.push("justifications_validators_root");
        }
        diffs
    }
}

impl FileStore {
    /// Opens (or creates) a [`FileStore`] at `root`.
    ///
    /// Startup sequence:
    /// 1. Verify/create `schema_version` file.
    /// 2. Open `canonical.redb` (creates + ensures all 6 tables on first run).
    /// 3. Load state/block slot indexes into `RapidHashMap`s.
    /// 4. Load fork-choice metadata (head, finalized, justified).
    /// 5. Derive `finalized_slot` by decoding the finalized block (cold read).
    ///
    /// Recovery: corrupt index rows or metadata are silently skipped and
    /// counted in [`RecoveryReport`].
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        ensure_schema_version(&root)?;
        let canonical_db = CanonicalDb::open(&root.join(CANONICAL_DB_FILE))?;

        let mut store = Self {
            root,
            canonical_db,
            state_by_slot: RapidHashMap::default(),
            state_root_to_block_root: RapidHashMap::default(),
            block_by_slot: RapidHashMap::default(),
            pending_blocks: PendingSlotCache::new(PENDING_WINDOW_CAP),
            head: None,
            finalized: None,
            finalized_slot: None,
            justified: None,
            recovery: RecoveryReport::default(),
            index_dirty: false,
            meta_dirty: false,
        };
        store.load_from_disk()?;
        Ok(store)
    }

    /// Returns the filesystem root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[inline]
    pub fn recovery_report(&self) -> RecoveryReport {
        self.recovery.clone()
    }

    #[inline]
    pub fn canonical_state_rows(&self) -> usize {
        self.state_by_slot.len()
    }

    #[inline]
    pub fn canonical_block_rows(&self) -> usize {
        self.block_by_slot.len()
    }

    #[inline]
    pub fn pending_block_rows(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Cold-path state read by block root: zero-copy from redb mmap → validate
    /// header → SSZ decode. No intermediate heap allocation.
    #[inline]
    fn load_state_by_block_root(&self, root: &Bytes32) -> Option<State> {
        self.canonical_db
            .with_state_blob(*root, |bytes| {
                let off = decode_blob_offset(BLOB_KIND_STATE, bytes)?;
                decode_state_safe(&bytes[off..])
            })
            .ok()?
    }

    /// State lookup that accepts either a state root or a block root.
    #[inline]
    fn load_state_by_identifier(&self, root: &Bytes32) -> Option<State> {
        let block_root = self.state_root_to_block_root.get(root).copied().unwrap_or(*root);
        self.load_state_by_block_root(&block_root)
    }

    /// Cold-path block read. Same zero-copy pipeline.
    #[inline]
    fn load_block_by_root(&self, root: &Bytes32) -> Option<Block> {
        self.canonical_db
            .with_block_blob(*root, |bytes| {
                let off = decode_blob_offset(BLOB_KIND_BLOCK, bytes)?;
                decode_block_safe(&bytes[off..])
            })
            .ok()?
    }

    /// Cold-path signed-block read. Same zero-copy pipeline.
    #[inline]
    fn load_signed_block_by_root(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.canonical_db
            .with_signed_block_blob(*root, |bytes| {
                let off = decode_blob_offset(BLOB_KIND_SIGNED_BLOCK, bytes)?;
                decode_signed_block_safe(&bytes[off..])
            })
            .ok()?
    }

    /// Promote all pending rows at `slot <= finalized_slot` into canonical indexes.
    #[inline]
    fn promote_finalized_slot_in_memory(&mut self, finalized_slot: u64) {
        let block_by_slot = &mut self.block_by_slot;
        let state_by_slot = &mut self.state_by_slot;
        let pending = &mut self.pending_blocks;
        pending.drain_leq_with(finalized_slot, |value| {
            block_by_slot.insert(value.slot, value.block_root);
            state_by_slot.insert(value.slot, value.state_root);
        });
    }

    /// Promote finalized pending entries and persist all indexes.
    #[inline]
    pub fn promote_finalized(&mut self, finalized_slot: u64) -> Result<(), String> {
        self.promote_finalized_slot_in_memory(finalized_slot);
        self.flush_canonical()
    }

    /// Flushes canonical indexes + metadata to canonical DB if dirty.
    #[inline]
    pub(super) fn flush_canonical(&mut self) -> Result<(), String> {
        self.flush_canonical_with_state_root_index(true)
    }

    #[inline]
    pub(super) fn flush_canonical_with_state_root_index(
        &mut self,
        rewrite_state_root_index: bool,
    ) -> Result<(), String> {
        if !self.index_dirty && !self.meta_dirty {
            return Ok(());
        }
        self.canonical_db.persist_snapshot(
            &self.state_by_slot,
            &self.block_by_slot,
            &self.state_root_to_block_root,
            rewrite_state_root_index,
            self.head,
            self.finalized,
            self.finalized_slot,
            self.justified,
        )?;
        self.index_dirty = false;
        self.meta_dirty = false;
        Ok(())
    }

    /// Records a state root in the canonical slot index and marks dirty.
    #[inline]
    fn index_state_slot(&mut self, slot: u64, root: Bytes32) {
        self.state_by_slot.insert(slot, root);
        self.index_dirty = true;
    }

    /// Routes a block to the canonical or pending index based on finalized_slot.
    ///
    /// Returns `true` if routed to canonical (slot ≤ finalized), `false` if
    /// buffered in the pending window (slot > finalized).
    #[inline]
    fn index_block_slot(&mut self, slot: u64, root: Bytes32, state_root: Bytes32) -> bool {
        match self.finalized_slot {
            Some(finalized_slot) if slot > finalized_slot => {
                self.pending_blocks.insert(slot, root, state_root);
                false
            }
            _ => {
                self.block_by_slot.insert(slot, root);
                self.index_dirty = true;
                true
            }
        }
    }

    /// Loads startup metadata and all indexes from `canonical.redb`.
    ///
    /// Called once during [`open`]. Loads state/block slot indexes, fork-choice
    /// metadata, and derives `finalized_slot` from the finalized block (requires
    /// one cold read + SSZ decode).
    #[inline]
    fn load_from_disk(&mut self) -> Result<(), String> {
        self.load_state_index()?;
        self.load_block_index()?;
        match self.canonical_db.load_state_root_index() {
            Ok(index) => {
                self.state_root_to_block_root = index;
            }
            Err(err) => {
                warn!(
                    %err,
                    "failed to load state-root index; continuing with an empty mapping may require state reindexing and can reduce blob-retention accuracy until rebuilt"
                );
                self.state_root_to_block_root.clear();
                self.recovery.skipped_corrupt += 1;
            }
        }
        self.load_meta()?;
        if self.finalized_slot.is_none() {
            self.finalized_slot = self
                .finalized
                .and_then(|root| self.load_block_by_root(&root).map(|block| block.slot.0.0));
        }
        self.recovery.loaded_states = self.state_by_slot.len();
        self.recovery.loaded_blocks = self.block_by_slot.len();
        self.recovery.loaded_signed_blocks = 0;
        Ok(())
    }

    /// Returns roots that must never be pruned.
    #[inline]
    pub(super) fn pinned_roots(&self) -> [Option<Bytes32>; 3] {
        [self.head, self.justified, self.finalized]
    }

    /// Loads fork-choice metadata (`head`, `finalized`, `justified`) from canonical DB.
    fn load_meta(&mut self) -> Result<(), String> {
        match self.canonical_db.load_meta() {
            Ok((head, finalized, justified, finalized_slot)) => {
                self.head = head;
                self.finalized = finalized;
                self.finalized_slot = finalized_slot;
                self.justified = justified;
            }
            Err(_) => {
                // Recover by continuing with empty metadata.
                self.head = None;
                self.finalized = None;
                self.finalized_slot = None;
                self.justified = None;
                self.recovery.skipped_corrupt += 1;
            }
        }
        Ok(())
    }

    /// Marks fork-choice metadata as needing a flush to redb.
    #[inline]
    fn set_meta_dirty(&mut self) {
        self.meta_dirty = true;
    }

    /// Writes a state blob to `canonical.redb`, keyed by block root.
    #[inline]
    fn persist_state(&self, block_root: Bytes32, state: &State) -> Result<(), String> {
        let encoded = encode_blob(BLOB_KIND_STATE, &state.encode_ssz());
        self.canonical_db.persist_state_blob(block_root, &encoded)
    }

    /// Writes a block blob to `canonical.redb`.
    #[inline]
    fn persist_block(&self, root: Bytes32, block: &Block) -> Result<(), String> {
        let encoded = encode_blob(BLOB_KIND_BLOCK, &block.encode_ssz());
        self.canonical_db.persist_block_blob(root, &encoded)
    }

    #[inline]
    fn persist_signed_block_bundle_from_state(
        &mut self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
        persisted_state: &State,
        meta_justified: Checkpoint,
        meta_finalized: Checkpoint,
    ) -> Result<(), String> {
        self.persist_signed_block_bundle_inner(
            root,
            signed,
            persisted_state,
            meta_justified,
            meta_finalized,
            true,
        )
    }

    fn persist_signed_block_bundle_inner(
        &mut self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
        persisted_state: &State,
        meta_justified: Checkpoint,
        meta_finalized: Checkpoint,
        update_head: bool,
    ) -> Result<(), String> {
        static PERSIST_LOGS: OnceLock<AtomicUsize> = OnceLock::new();
        let block = signed.message.block.clone();
        let slot = block.slot.0.0;
        let state_root = block.state_root;
        let block_blob = encode_blob(BLOB_KIND_BLOCK, &block.encode_ssz());
        let signed_blob = encode_blob(BLOB_KIND_SIGNED_BLOCK, &signed.encode_ssz());
        let state_blob = encode_blob(BLOB_KIND_STATE, &persisted_state.encode_ssz());
        let next_head = if update_head { Some(root) } else { self.head };
        let next_justified = if update_head {
            Some(meta_justified.root)
        } else {
            self.justified
        };
        let next_finalized = if update_head {
            Some(meta_finalized.root)
        } else {
            self.finalized
        };
        let next_finalized_slot = if update_head {
            Some(meta_finalized.slot.0.0)
        } else {
            self.finalized_slot
        };

        let counter = PERSIST_LOGS.get_or_init(|| AtomicUsize::new(0));
        if counter.fetch_add(1, Ordering::Relaxed) < 64 {
            tracing::info!(
                block_root = ?root,
                block_slot = slot,
                parent_root = ?block.parent_root,
                state_root = ?state_root,
                head_root = ?next_head,
                justified_root = ?next_justified,
                finalized_root = ?next_finalized,
                finalized_slot = next_finalized_slot.unwrap_or(0),
                state_slot = persisted_state.slot.0.0,
                latest_header_slot = persisted_state.latest_block_header.slot.0.0,
                "persisted signed block bundle"
            );
        }

        let fin_slot = next_finalized_slot.unwrap_or(0);
        let block_canonical = !matches!(next_finalized_slot, Some(finalized_slot) if slot > finalized_slot);
        let pending_promotions = self.pending_blocks.entries_leq(fin_slot);

        let mut state_upserts = Vec::new();
        let mut block_upserts = Vec::new();
        state_upserts.push((slot, state_root));
        if block_canonical {
            block_upserts.push((slot, root));
        }
        for value in &pending_promotions {
            state_upserts.push((value.slot, value.state_root));
            block_upserts.push((value.slot, value.block_root));
        }

        self.canonical_db.persist_signed_block_bundle(
            root,
            &block_blob,
            &signed_blob,
            state_root,
            &state_blob,
            &state_upserts,
            &block_upserts,
            next_head,
            next_finalized,
            next_finalized_slot,
            next_justified,
        )?;

        self.state_root_to_block_root.insert(state_root, root);
        if update_head {
            self.head = next_head;
            self.justified = next_justified;
            self.finalized = next_finalized;
            self.finalized_slot = next_finalized_slot;
        }
        if block_canonical {
            self.block_by_slot.insert(slot, root);
        } else {
            self.pending_blocks.insert(slot, root, state_root);
        }
        self.state_by_slot.insert(slot, state_root);
        self.pending_blocks.drain_leq_with(fin_slot, |value| {
            self.block_by_slot.insert(value.slot, value.block_root);
            self.state_by_slot.insert(value.slot, value.state_root);
        });
        self.index_dirty = false;
        self.meta_dirty = false;
        Ok(())
    }

    #[inline]
    fn replay_signed_block_from_parent(
        &self,
        signed: &SignedBlockWithAttestation,
        metrics: Option<&crate::metrics::MetricsRegistry>,
    ) -> Result<State, String> {
        let parent_root = signed.message.block.parent_root;
        let _parent_block = self
            .load_block_by_root(&parent_root)
            .ok_or_else(|| "block parent root unknown in store".to_string())?;
        let mut parent_state = self
            .load_state_by_block_root(&parent_root)
            .ok_or_else(|| "parent state root missing in store".to_string())?;
        if let Some(metrics) = metrics {
            parent_state.process_signed_block_with_metrics(signed, metrics)?;
        } else {
            parent_state.process_signed_block(signed)?;
        }
        Ok(parent_state)
    }

    fn log_state_root_mismatch_context(
        &self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
        live_pre_state: &State,
        live_post_state: &State,
    ) {
        let block = &signed.message.block;
        let live_pre = StateSnapshot::capture(live_pre_state);
        let live_post = StateSnapshot::capture(live_post_state);
        let parent_root = block.parent_root;
        let Some(parent_block) = self.load_block_by_root(&parent_root) else {
            warn!(
                block_root = ?root,
                block_slot = block.slot.0.0,
                block_parent = ?parent_root,
                live_pre = ?live_pre,
                live_post = ?live_post,
                "state-root mismatch investigation missing parent block in store"
            );
            return;
        };
        let Some(parent_state) = self.load_state_by_block_root(&parent_root) else {
            warn!(
                block_root = ?root,
                block_slot = block.slot.0.0,
                block_parent = ?parent_root,
                parent_state_root = ?parent_block.state_root,
                live_pre = ?live_pre,
                live_post = ?live_post,
                "state-root mismatch investigation missing parent state in store"
            );
            return;
        };
        let parent_pre = StateSnapshot::capture(&parent_state);
        let mut parent_replayed = parent_state.clone();
        match parent_replayed.process_signed_block(signed) {
            Ok(()) => {
                let parent_post = StateSnapshot::capture(&parent_replayed);
                warn!(
                    block_root = ?root,
                    block_slot = block.slot.0.0,
                    block_parent = ?parent_root,
                    parent_state_root = ?parent_block.state_root,
                    live_parent_matches_header = block.parent_root == live_pre.header_root,
                    live_pre_equals_parent_pre = live_pre.state_root == parent_pre.state_root,
                    live_post_equals_parent_post = live_post.state_root == parent_post.state_root,
                    live_pre_vs_parent_pre = ?live_pre.differing_fields(&parent_pre),
                    live_post_vs_parent_post = ?live_post.differing_fields(&parent_post),
                    live_pre = ?live_pre,
                    parent_pre = ?parent_pre,
                    live_post = ?live_post,
                    parent_post = ?parent_post,
                    "state-root mismatch investigation snapshot"
                );
            }
            Err(replay_err) => {
                warn!(
                    block_root = ?root,
                    block_slot = block.slot.0.0,
                    block_parent = ?parent_root,
                    parent_state_root = ?parent_block.state_root,
                    live_pre_equals_parent_pre = live_pre.state_root == parent_pre.state_root,
                    live_pre_vs_parent_pre = ?live_pre.differing_fields(&parent_pre),
                    live_pre = ?live_pre,
                    parent_pre = ?parent_pre,
                    live_post = ?live_post,
                    replay_err = %replay_err,
                    "state-root mismatch investigation parent replay failed"
                );
            }
        }
    }

    #[inline]
    fn put_signed_block_inner(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
        metrics: Option<&crate::metrics::MetricsRegistry>,
    ) -> Result<(), String> {
        let import_start = metrics.map(|_| Instant::now());
        let result = (|| {
            let pre_import_state = state.clone();
            let pre_import_head_slot = state.latest_block_header.slot;
            let pre_import_head_root = Bytes32::from(state.latest_block_header.hash_tree_root());
            let pre_import_justified = state.latest_justified;
            let pre_import_finalized = state.latest_finalized;
            let process_result = if let Some(metrics) = metrics {
                state.process_signed_block_with_metrics(&signed, metrics)
            } else {
                state.process_signed_block(&signed)
            };
            if let Err(err) = process_result {
                if err.contains("block state root does not match computed state root") {
                    self.log_state_root_mismatch_context(root, &signed, &pre_import_state, state);
                }
                if !err.contains("block parent root does not match latest header root") {
                    return Err(err);
                }
                // The block builds on an older ancestor, not the current head.
                // Replay from the parent state to import it without corrupting
                // the live state. Only advance the live state if the block
                // extends to a higher slot.
                let replayed = match self.replay_signed_block_from_parent(&signed, metrics) {
                    Ok(post) => post,
                    Err(_) => {
                        tracing::warn!(
                            block_root = ?root,
                            block_slot = signed.message.block.slot.0.0,
                            block_parent = ?signed.message.block.parent_root,
                            live_head_slot = pre_import_head_slot.0.0,
                            live_head_root = ?pre_import_head_root,
                            "rejecting non-linear block import (parent replay failed)"
                        );
                        return Err(err);
                    }
                };
                let meta_finalized = if replayed.latest_finalized.slot < pre_import_finalized.slot {
                    pre_import_finalized
                } else {
                    replayed.latest_finalized
                };
                let meta_justified = if replayed.latest_justified.slot < pre_import_justified.slot {
                    pre_import_justified
                } else {
                    replayed.latest_justified
                };
                let promotes_head = replayed.slot >= state.slot;
                self.persist_signed_block_bundle_inner(
                    root,
                    &signed,
                    &replayed,
                    meta_justified,
                    meta_finalized,
                    promotes_head,
                )?;
                if promotes_head {
                    *state = replayed;
                    state.latest_finalized = meta_finalized;
                    state.latest_justified = meta_justified;
                } else {
                    if meta_justified.slot > state.latest_justified.slot {
                        state.latest_justified = meta_justified;
                    }
                    if meta_finalized.slot > state.latest_finalized.slot {
                        state.latest_finalized = meta_finalized;
                    }
                }
                return Ok(());
            }
            let exact_post_state = state.clone();
            let meta_finalized =
                if exact_post_state.latest_finalized.slot < pre_import_finalized.slot {
                    pre_import_finalized
                } else {
                    exact_post_state.latest_finalized
                };
            let meta_justified =
                if exact_post_state.latest_justified.slot < pre_import_justified.slot {
                    pre_import_justified
                } else {
                    exact_post_state.latest_justified
                };
            state.latest_finalized = meta_finalized;
            state.latest_justified = meta_justified;
            self.persist_signed_block_bundle_from_state(
                root,
                &signed,
                &exact_post_state,
                meta_justified,
                meta_finalized,
            )
        })();

        if let (Some(metrics), Some(start)) = (metrics, import_start) {
            metrics.block_import_end_to_end_time.observe_duration(start);
        }

        result
    }

    #[inline]
    pub(crate) fn put_backfill_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        let pre_import_slot = state.slot;
        let pre_import_head_slot = state.latest_block_header.slot;
        let pre_import_head_root = Bytes32::from(state.latest_block_header.hash_tree_root());
        let mut imported_from_fallback = false;
        let process_result = state.process_signed_block(&signed);
        if let Err(err) = process_result {
            if !err.contains("block parent root does not match latest header root") {
                return Err(err);
            }
            tracing::warn!(
                block_root = ?root,
                block_slot = signed.message.block.slot.0.0,
                block_parent = ?signed.message.block.parent_root,
                live_head_slot = pre_import_head_slot.0.0,
                live_head_root = ?pre_import_head_root,
                parent_matches_live_head = signed.message.block.parent_root == pre_import_head_root,
                "backfill import hit parent mismatch, replaying from parent state"
            );
            let replayed = self.replay_signed_block_from_parent(&signed, None)?;
            *state = replayed;
            imported_from_fallback = true;
        }
        if imported_from_fallback {
            tracing::info!(
                block_root = ?root,
                block_slot = signed.message.block.slot.0.0,
                parent_root = ?signed.message.block.parent_root,
                live_head_slot = pre_import_head_slot.0.0,
                live_head_root = ?pre_import_head_root,
                replayed_head_slot = state.latest_block_header.slot.0.0,
                replayed_head_root = ?Bytes32::from(state.latest_block_header.hash_tree_root()),
                branch_mix = signed.message.block.parent_root != pre_import_head_root,
                "imported backfill block via parent-state replay fallback"
            );
        }
        if state.slot < pre_import_slot {
            return Err("imported block would regress local state slot".to_string());
        }
        self.persist_signed_block_bundle_from_state(
            root,
            &signed,
            state,
            state.latest_justified,
            state.latest_finalized,
        )
    }

    #[inline]
    pub(crate) fn put_anchor_signed_block(
        &mut self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
        state: &State,
    ) -> Result<(), String> {
        self.persist_signed_block_bundle_from_state(
            root,
            signed,
            state,
            state.latest_justified,
            state.latest_finalized,
        )
    }

    pub fn put_prevalidated_signed_block_with_metrics(
        &mut self,
        root: Bytes32,
        signed: &SignedBlockWithAttestation,
        state: &mut State,
        post_state: State,
        metrics: &crate::metrics::MetricsRegistry,
    ) -> Result<(), String> {
        let import_start = Instant::now();
        let result = (|| {
            let pre_import_justified = state.latest_justified;
            let pre_import_finalized = state.latest_finalized;
            let block = &signed.message.block;
            let mut expected = state.clone();
            if block.slot > expected.slot {
                expected.process_slots(block.slot)?;
            }
            let expected_parent = Bytes32::from(expected.latest_block_header.hash_tree_root());
            if block.parent_root != expected_parent {
                return Err("block parent root does not match latest header root".to_string());
            }
            let computed_post_root = Bytes32::from(post_state.hash_tree_root());
            let header_root = post_state.latest_block_header.state_root;
            if header_root != block.state_root && computed_post_root != block.state_root {
                tracing::warn!(
                    block_root = ?root,
                    block_slot = block.slot.0.0,
                    parent_root = ?block.parent_root,
                    header_state_root = ?header_root,
                    block_state_root = ?block.state_root,
                    computed_state_root = ?computed_post_root,
                    "rejecting prevalidated block: post_state root mismatch"
                );
                return Err("post_state root does not match block.state_root".to_string());
            }

            *state = post_state;
            let exact_post_state = state.clone();
            let meta_finalized =
                if exact_post_state.latest_finalized.slot < pre_import_finalized.slot {
                    pre_import_finalized
                } else {
                    exact_post_state.latest_finalized
                };
            let meta_justified =
                if exact_post_state.latest_justified.slot < pre_import_justified.slot {
                    pre_import_justified
                } else {
                    exact_post_state.latest_justified
                };
            state.latest_finalized = meta_finalized;
            state.latest_justified = meta_justified;
            self.persist_signed_block_bundle_from_state(
                root,
                signed,
                &exact_post_state,
                meta_justified,
                meta_finalized,
            )
        })();
        metrics
            .block_import_end_to_end_time
            .observe_duration(import_start);
        result
    }
}

/// Best-effort flush on shutdown. Persists any dirty indexes/metadata that
/// were not yet written to `canonical.redb`. Errors are silently ignored.
impl Drop for FileStore {
    fn drop(&mut self) {
        if self.index_dirty || self.meta_dirty {
            let _ = self.flush_canonical();
        }
    }
}

/// [`Store`] implementation for [`FileStore`].
///
/// - **Reads by root** always hit redb (cold path).
/// - **Reads by slot** check the pending window first, then the canonical
///   slot index, then fall through to the cold path.
/// - **`put_state` / `put_block`** persist the blob immediately, then update
///   the in-memory index (deferred flush).
/// - **`put_signed_block`** runs state transition, encodes all three blobs,
///   updates indexes and metadata, then writes everything in a single atomic
///   redb transaction via `persist_signed_block_bundle`.
/// - **`set_head` / `set_justified`** update metadata and mark it dirty.
///   Metadata is flushed when a finalized checkpoint is set or a bundle write occurs.
/// - **`set_finalized`** updates metadata, promotes pending entries, and flushes.
impl Store for FileStore {
    #[inline]
    fn get_state(&self, root: &Bytes32) -> Option<State> {
        self.load_state_by_identifier(root)
    }

    #[inline]
    fn put_state(&mut self, root: Bytes32, state: State) {
        let slot = state.slot.0.0;
        // Standalone `put_state` callers only provide a single root identity,
        // so preserve that behavior by using the supplied root as the blob key
        // and secondary lookup target.
        let block_root = root;
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_state(block_root, &state).is_err() {
            return;
        }
        if self
            .canonical_db
            .persist_state_root_mapping(root, block_root)
            .is_err()
        {
            return;
        }
        self.state_root_to_block_root.insert(root, block_root);
        self.index_state_slot(slot, root);
    }

    #[inline]
    fn get_block(&self, root: &Bytes32) -> Option<Block> {
        self.load_block_by_root(root)
    }

    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.load_signed_block_by_root(root)
    }

    #[inline]
    fn put_block(&mut self, root: Bytes32, block: Block) {
        let slot = block.slot.0.0;
        let state_root = block.state_root;
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_block(root, &block).is_err() {
            return;
        }
        self.index_block_slot(slot, root, state_root);
    }

    /// Hot write path: state transition → encode → index → atomic persist.
    ///
    /// All three blobs (block, signed block, post-state) plus index/meta
    /// deltas are written in a single redb write transaction. If the
    /// transaction commits, the corresponding in-memory indexes and resolver
    /// entries are published. If it fails, neither the durable nor the live
    /// view is advanced.
    #[inline]
    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        self.put_signed_block_inner(root, signed, state, None)
    }

    /// By-slot state read: pending window (`O(1)`) → canonical index → cold path.
    fn get_state_by_slot(&self, slot: u64) -> Option<State> {
        if let Some(entry) = self.pending_blocks.get(slot) {
            return self.load_state_by_identifier(&entry.state_root);
        }
        let root = self.state_by_slot.get(&slot).copied()?;
        self.load_state_by_identifier(&root)
    }

    /// By-slot block read: pending window (`O(1)`) → canonical index → cold path.
    fn get_block_by_slot(&self, slot: u64) -> Option<Block> {
        if let Some(entry) = self.pending_blocks.get(slot) {
            return self.load_block_by_root(&entry.block_root);
        }
        let root = self.block_by_slot.get(&slot).copied()?;
        self.load_block_by_root(&root)
    }

    fn head(&self) -> Option<Bytes32> {
        self.head
    }

    #[inline]
    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
        // Head updates are frequent; defer persistence to finalized/bundle flushes.
        self.set_meta_dirty();
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    /// Sets finalized root, derives `finalized_slot` via cold read, promotes
    /// pending entries ≤ that slot into canonical, then flushes to redb.
    #[inline]
    fn set_finalized(&mut self, root: Bytes32) {
        let Some(block) = self.load_block_by_root(&root) else {
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
        self.set_meta_dirty();
        // Promote any pending rows up to the new finalized slot.
        let _ = self.promote_finalized_slot_in_memory(slot);
        // Persist finalized metadata + any promoted canonical entries.
        let _ = self.flush_canonical();
    }

    /// Sets finalized checkpoint root + slot explicitly, then flushes metadata.
    #[inline]
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
        self.set_meta_dirty();
        let _ = self.promote_finalized_slot_in_memory(slot);
        let _ = self.flush_canonical();
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
        // Justified moves often; persist alongside finalized updates.
        self.set_meta_dirty();
    }

    fn put_signed_block_with_metrics(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
        metrics: &crate::metrics::MetricsRegistry,
    ) -> Result<(), String> {
        self.put_signed_block_inner(root, signed, state, Some(metrics))
    }
}
