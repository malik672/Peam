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
//! | `get_state(root)` | — | redb read txn → decode blob → SSZ decode |
//! | `get_block(root)` | — | redb read txn → decode blob → SSZ decode |
//! | `get_state_by_slot(slot)` | pending cache hit | slot index → root → cold path |
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

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

    /// Cold-path state read: zero-copy from redb mmap → validate header →
    /// SSZ decode. No intermediate heap allocation.
    #[inline]
    fn load_state_by_root(&self, root: &Bytes32) -> Option<State> {
        self.canonical_db
            .with_state_blob(*root, |bytes| {
                let off = decode_blob_offset(BLOB_KIND_STATE, bytes)?;
                decode_state_safe(&bytes[off..])
            })
            .ok()?
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
    ///
    /// Returns the promoted entries so callers can use them for delta index writes.
    fn promote_finalized_slot_in_memory(
        &mut self,
        finalized_slot: u64,
    ) -> Vec<super::pending::PendingEntry> {
        let promoted = self.pending_blocks.drain_leq(finalized_slot);
        for entry in &promoted {
            self.block_by_slot.insert(entry.slot, entry.block_root);
            self.state_by_slot.insert(entry.slot, entry.state_root);
        }
        if !promoted.is_empty() {
            self.index_dirty = true;
        }
        promoted
    }

    /// Promote finalized pending entries and persist all indexes.
    pub fn promote_finalized(&mut self, finalized_slot: u64) -> Result<(), String> {
        self.promote_finalized_slot_in_memory(finalized_slot);
        self.flush_canonical()
    }

    /// Flushes canonical indexes + metadata to canonical DB if dirty.
    #[inline]
    pub(super) fn flush_canonical(&mut self) -> Result<(), String> {
        if !self.index_dirty && !self.meta_dirty {
            return Ok(());
        }
        self.canonical_db.persist_snapshot(
            &self.state_by_slot,
            &self.block_by_slot,
            self.head,
            self.finalized,
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
        self.load_meta()?;
        self.finalized_slot = self
            .finalized
            .and_then(|root| self.load_block_by_root(&root).map(|block| block.slot.0.0));
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
            Ok((head, finalized, justified)) => {
                self.head = head;
                self.finalized = finalized;
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

    /// Writes a state blob to `canonical.redb`.
    #[inline]
    fn persist_state(&self, root: Bytes32, state: &State) -> Result<(), String> {
        let encoded = encode_blob(BLOB_KIND_STATE, &state.encode_ssz());
        self.canonical_db.persist_state_blob(root, &encoded)
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
        static PERSIST_LOGS: OnceLock<AtomicUsize> = OnceLock::new();
        let block = signed.message.block.clone();
        let slot = block.slot.0.0;
        let state_root = block.state_root;
        let block_blob = encode_blob(BLOB_KIND_BLOCK, &block.encode_ssz());
        let signed_blob = encode_blob(BLOB_KIND_SIGNED_BLOCK, &signed.encode_ssz());
        let state_blob = encode_blob(BLOB_KIND_STATE, &persisted_state.encode_ssz());

        self.head = Some(root);
        self.justified = Some(meta_justified.root);
        self.finalized = Some(meta_finalized.root);
        self.finalized_slot = Some(meta_finalized.slot.0.0);
        self.set_meta_dirty();

        let counter = PERSIST_LOGS.get_or_init(|| AtomicUsize::new(0));
        if counter.fetch_add(1, Ordering::Relaxed) < 64 {
            tracing::info!(
                block_root = ?root,
                block_slot = slot,
                parent_root = ?block.parent_root,
                state_root = ?state_root,
                head_root = ?self.head,
                justified_root = ?self.justified,
                finalized_root = ?self.finalized,
                finalized_slot = self.finalized_slot.unwrap_or(0),
                state_slot = persisted_state.slot.0.0,
                latest_header_slot = persisted_state.latest_block_header.slot.0.0,
                "persisted signed block bundle"
            );
        }

        let fin_slot = meta_finalized.slot.0.0;
        let block_canonical = self.index_block_slot(slot, root, state_root);
        self.index_state_slot(slot, state_root);
        let promoted = self.promote_finalized_slot_in_memory(fin_slot);

        let mut state_upserts = Vec::with_capacity(1 + promoted.len());
        let mut block_upserts = Vec::with_capacity(usize::from(block_canonical) + promoted.len());
        state_upserts.push((slot, state_root));
        if block_canonical {
            block_upserts.push((slot, root));
        }
        for entry in &promoted {
            state_upserts.push((entry.slot, entry.state_root));
            block_upserts.push((entry.slot, entry.block_root));
        }

        self.canonical_db.persist_signed_block_bundle(
            root,
            &block_blob,
            &signed_blob,
            state_root,
            &state_blob,
            &state_upserts,
            &block_upserts,
            self.head,
            self.finalized,
            self.justified,
        )?;
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
        let parent_block = self
            .load_block_by_root(&parent_root)
            .ok_or_else(|| "block parent root unknown in store".to_string())?;
        let mut parent_state = self
            .load_state_by_root(&parent_block.state_root)
            .ok_or_else(|| "parent state root missing in store".to_string())?;
        if let Some(metrics) = metrics {
            parent_state.process_signed_block_with_metrics(signed, metrics)?;
        } else {
            parent_state.process_signed_block(signed)?;
        }
        Ok(parent_state)
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
                    "rejecting non-linear block import"
                );
                return Err(err);
            }
            let exact_post_state = state.clone();
            let meta_finalized = if exact_post_state.latest_finalized.slot < pre_import_finalized.slot
            {
                pre_import_finalized
            } else {
                exact_post_state.latest_finalized
            };
            let meta_justified = if exact_post_state.latest_justified.slot < pre_import_justified.slot
            {
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

            *state = post_state;
            let exact_post_state = state.clone();
            let meta_finalized = if exact_post_state.latest_finalized.slot < pre_import_finalized.slot
            {
                pre_import_finalized
            } else {
                exact_post_state.latest_finalized
            };
            let meta_justified = if exact_post_state.latest_justified.slot < pre_import_justified.slot
            {
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
/// - **`set_head` / `set_finalized` / `set_justified`** update metadata and
///   flush immediately. `set_finalized` also promotes pending entries.
impl Store for FileStore {
    #[inline]
    fn get_state(&self, root: &Bytes32) -> Option<State> {
        self.load_state_by_root(root)
    }

    #[inline]
    fn put_state(&mut self, root: Bytes32, state: State) {
        let slot = state.slot.0.0;
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_state(root, &state).is_err() {
            return;
        }
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
    /// transaction commits, in-memory dirty flags are cleared. If it fails,
    /// in-memory state is ahead of disk (recovered on next `flush_canonical`
    /// or `Drop`).
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
            return self.load_state_by_root(&entry.state_root);
        }
        let root = self.state_by_slot.get(&slot).copied()?;
        self.load_state_by_root(&root)
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

    fn set_head(&mut self, root: Bytes32) {
        self.head = Some(root);
        self.set_meta_dirty();
        let _ = self.flush_canonical();
    }

    fn finalized(&self) -> Option<Bytes32> {
        self.finalized
    }

    /// Sets finalized root, derives `finalized_slot` via cold read, promotes
    /// pending entries ≤ that slot into canonical, then flushes to redb.
    fn set_finalized(&mut self, root: Bytes32) {
        self.finalized = Some(root);
        self.finalized_slot = self.load_block_by_root(&root).map(|block| block.slot.0.0);
        self.set_meta_dirty();
        if let Some(slot) = self.finalized_slot {
            let _ = self.promote_finalized_slot_in_memory(slot);
        }
        let _ = self.flush_canonical();
    }

    fn justified(&self) -> Option<Bytes32> {
        self.justified
    }

    fn set_justified(&mut self, root: Bytes32) {
        self.justified = Some(root);
        self.set_meta_dirty();
        let _ = self.flush_canonical();
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
