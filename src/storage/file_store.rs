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
//!   ├─ load_state_by_block_root(parent_root) parent-state lookup
//!   ├─ parent_state.process_signed_block()   state transition
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
//! | `get_state(root)` | — | identifier compatibility lookup → block-root blob decode |
//! | `get_block(root)` | — | redb read txn → decode blob → SSZ decode |
//! | `get_state_by_slot(slot)` | pending cache hit | slot index → block-root decode |
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
use tracing::warn;

use super::canonical_db::CanonicalDb;
use super::pending::PendingSlotCache;
use super::*;
use crate::containers::checkpoint::Checkpoint;
use crate::logfmt::{short_opt_root_or_dash, short_root, short_slot_root};
use crate::ssz::{HashTreeRoot, SszEncode};

/// A disk-backed [`Store`] with canonical+pending slot indexes as truth.
///
/// Index model:
/// - `state_by_slot` / `block_by_slot`: canonical slot indexes keyed by block root.
/// - `pending_blocks`: hot non-finalized block slot index (in-memory only).
///
/// Object reads by root are decoded on demand from `canonical.redb`.
pub struct FileStore {
    /// Root directory of the store.
    pub(super) root: PathBuf,
    /// Canonical index + fork-choice metadata database.
    pub(super) canonical_db: CanonicalDb,
    /// Canonical finalized slot->block-root index used for state lookup.
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

    /// Compatibility lookup that accepts either a state root or a block root.
    ///
    /// The primary storage identity is block-root keyed. State-root lookup is
    /// retained only to support older callers and external compatibility paths.
    #[inline]
    fn load_state_by_identifier(&self, root: &Bytes32) -> Option<State> {
        let block_root = self
            .state_root_to_block_root
            .get(root)
            .copied()
            .unwrap_or(*root);
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
            state_by_slot.insert(value.slot, value.block_root);
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

    /// Records a block root in the canonical state slot index and marks dirty.
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
    fn index_block_slot(&mut self, slot: u64, root: Bytes32) -> bool {
        match self.finalized_slot {
            Some(finalized_slot) if slot > finalized_slot => {
                self.pending_blocks.insert(slot, root);
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
                .and_then(|root| self.load_block_by_root(&root).map(|block| block.slot.0 .0));
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

    /// Rebuilds the compatibility lookup from the currently live block roots.
    ///
    /// Canonical slot indexes and the pending window are block-root-native, so
    /// this path is only needed to preserve `get_state(state_root)` callers.
    pub(super) fn rebuild_live_state_root_index(&self) -> RapidHashMap<Bytes32, Bytes32> {
        let mut live_block_roots = rapidhash::RapidHashSet::<Bytes32>::default();
        live_block_roots.extend(self.state_by_slot.values().copied());
        live_block_roots.extend(self.pending_blocks.roots());
        live_block_roots.extend(self.pinned_roots().iter().flatten().copied());

        let mut live_index = RapidHashMap::default();
        for block_root in live_block_roots {
            if let Some(block) = self.load_block_by_root(&block_root) {
                live_index.insert(block.state_root, block_root);
            } else if self.load_state_by_block_root(&block_root).is_some() {
                // Standalone `put_state` stores use the provided root as both
                // the blob key and the compatibility lookup key.
                live_index.insert(block_root, block_root);
            }
        }
        live_index
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
        let slot = block.slot.0 .0;
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
            Some(meta_finalized.slot.0 .0)
        } else {
            self.finalized_slot
        };

        let counter = PERSIST_LOGS.get_or_init(|| AtomicUsize::new(0));
        if counter.fetch_add(1, Ordering::Relaxed) < 64 {
            tracing::info!(
                block = %short_slot_root(slot, &root),
                parent = %short_root(&block.parent_root),
                state = %short_root(&state_root),
                head = %short_opt_root_or_dash(next_head),
                justified = %short_opt_root_or_dash(next_justified),
                finalized = %short_opt_root_or_dash(next_finalized),
                finalized_slot = next_finalized_slot.unwrap_or(0),
                state_slot = persisted_state.slot.0.0,
                latest_header_slot = persisted_state.latest_block_header.slot.0.0,
                "signed block bundle persisted"
            );
        }

        let fin_slot = next_finalized_slot.unwrap_or(0);
        let block_canonical =
            !matches!(next_finalized_slot, Some(finalized_slot) if slot > finalized_slot);
        let pending_promotions = self.pending_blocks.entries_leq(fin_slot);

        let mut state_upserts = Vec::new();
        let mut block_upserts = Vec::new();
        state_upserts.push((slot, root));
        if block_canonical {
            block_upserts.push((slot, root));
        }
        for value in &pending_promotions {
            state_upserts.push((value.slot, value.block_root));
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
            self.pending_blocks.insert(slot, root);
        }
        self.state_by_slot.insert(slot, root);
        self.pending_blocks.drain_leq_with(fin_slot, |value| {
            self.block_by_slot.insert(value.slot, value.block_root);
            self.state_by_slot.insert(value.slot, value.block_root);
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

    #[cfg(test)]
    #[inline]
    fn replay_signed_block_from_parent_with_verifier<
        V: crate::containers::state::SignatureVerifier,
    >(
        &self,
        signed: &SignedBlockWithAttestation,
        verifier: &V,
    ) -> Result<State, String> {
        let parent_root = signed.message.block.parent_root;
        let mut parent_state = self
            .load_state_by_block_root(&parent_root)
            .ok_or_else(|| "parent state root missing in store".to_string())?;
        parent_state.process_signed_block_with_verifier(signed, verifier)?;
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
            let pre_import_justified = state.latest_justified;
            let pre_import_finalized = state.latest_finalized;
            let replayed = self.replay_signed_block_from_parent(&signed, metrics)?;
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
            Ok(())
        })();

        if let (Some(metrics), Some(start)) = (metrics, import_start) {
            metrics.block_import_end_to_end_time.observe_duration(start);
        }

        result
    }

    #[cfg(test)]
    #[inline]
    fn put_signed_block_inner_with_verifier<V: crate::containers::state::SignatureVerifier>(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
        verifier: &V,
    ) -> Result<(), String> {
        let pre_import_justified = state.latest_justified;
        let pre_import_finalized = state.latest_finalized;
        let replayed = self.replay_signed_block_from_parent_with_verifier(&signed, verifier)?;
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
        Ok(())
    }

    #[inline]
    pub(crate) fn put_backfill_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        let pre_import_slot = state.slot;
        let replayed = self.replay_signed_block_from_parent(&signed, None)?;
        if replayed.slot < pre_import_slot {
            return Err("imported block would regress local state slot".to_string());
        }
        self.persist_signed_block_bundle_from_state(
            root,
            &signed,
            &replayed,
            replayed.latest_justified,
            replayed.latest_finalized,
        )?;
        *state = replayed;
        Ok(())
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

            let exact_post_state = post_state;
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
            self.persist_signed_block_bundle_from_state(
                root,
                signed,
                &exact_post_state,
                meta_justified,
                meta_finalized,
            )?;
            *state = exact_post_state;
            state.latest_finalized = meta_finalized;
            state.latest_justified = meta_justified;
            Ok(())
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
        let slot = state.slot.0 .0;
        // `put_state` is keyed by the owning block root.
        let block_root = root;
        let state_root = Bytes32::from(state.hash_tree_root());
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_state(block_root, &state).is_err() {
            return;
        }
        if self
            .canonical_db
            .persist_state_root_mapping(state_root, block_root)
            .is_err()
        {
            return;
        }
        self.state_root_to_block_root.insert(state_root, block_root);
        self.index_state_slot(slot, block_root);
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
        let slot = block.slot.0 .0;
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_block(root, &block).is_err() {
            return;
        }
        self.index_block_slot(slot, root);
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
            return self.load_state_by_block_root(&entry.block_root);
        }
        let root = self.state_by_slot.get(&slot).copied()?;
        self.load_state_by_block_root(&root)
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
        let slot = block.slot.0 .0;
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
        let slot = checkpoint.slot.0 .0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::attestation::{Attestation, AttestationData};
    use crate::containers::block::{
        Block, BlockBody, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation,
    };
    use crate::containers::state::{NoopSignatureVerifier, Validators};
    use crate::containers::validator::{Validator, ValidatorIndex};
    use crate::slot::Slot;
    use crate::types::bitlist::BitList;
    use crate::types::bytes::{Bytes3112, Bytes52};
    use crate::types::collections::SszList;
    use crate::types::uint::Uint64;

    fn temp_store_dir(tag: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("peam_file_store_test_{tag}_{stamp}"))
    }

    fn single_validator_state() -> State {
        let validators = Validators::new(vec![Validator {
            attestation_pubkey: Bytes52::from([0u8; 52]),
            proposal_pubkey: Bytes52::from([1u8; 52]),
            index: ValidatorIndex(Uint64(0)),
            balance: Uint64(0),
        }])
        .expect("validators");
        State::generate_genesis(Uint64(0), validators)
    }

    fn build_signed_block(
        state: &State,
        slot: u64,
    ) -> (SignedBlockWithAttestation, State, Bytes32) {
        let mut temp = state.clone();
        temp.process_slots(Slot(Uint64(slot)))
            .expect("process slots");
        let parent_root = Bytes32::from(temp.latest_block_header.hash_tree_root());
        let body = BlockBody {
            attestations: SszList::new(vec![]).expect("attestations"),
        };
        let mut block = Block {
            slot: Slot(Uint64(slot)),
            proposer_index: ValidatorIndex(Uint64(0)),
            parent_root,
            state_root: Bytes32::zero(),
            body,
        };

        let mut post = state.clone();
        post.process_slots(block.slot).expect("process slots");
        let header = block.header();
        post.process_block_header(header).expect("process header");
        post.process_block_body(&block.body, header.body_root)
            .expect("process body");
        block.state_root = Bytes32::from(post.hash_tree_root());
        post.latest_block_header.state_root = block.state_root;

        let signed = SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation: Attestation {
                    aggregation_bits: BitList::new(vec![true]).expect("participants"),
                    data: AttestationData {
                        slot: Slot(Uint64(slot)),
                        head: Checkpoint {
                            root: parent_root,
                            slot: Slot(Uint64(slot)),
                        },
                        target: Checkpoint {
                            root: parent_root,
                            slot: Slot(Uint64(slot)),
                        },
                        source: Checkpoint {
                            root: Bytes32::zero(),
                            slot: Slot(Uint64(0)),
                        },
                    },
                },
            },
            signature: BlockSignatures {
                attestation_signatures: SszList::new(vec![]).expect("attestation signatures"),
                proposer_signature: Bytes3112::zero(),
            },
        };
        let root = Bytes32::from(signed.message.block.hash_tree_root());
        (signed, post, root)
    }

    #[test]
    fn replays_from_parent_when_live_state_checkpoints_drift() {
        let dir = temp_store_dir("checkpoint_drift");
        let mut store = FileStore::open(&dir).expect("open store");
        let verifier = NoopSignatureVerifier;
        let mut live_state = single_validator_state();
        let anchor_root = Bytes32::from(live_state.latest_block_header.hash_tree_root());
        store.put_state(anchor_root, live_state.clone());

        let (parent_signed, parent_post_state, parent_root) = build_signed_block(&live_state, 1);
        store
            .put_signed_block_inner_with_verifier(
                parent_root,
                parent_signed,
                &mut live_state,
                &verifier,
            )
            .expect("import parent block");

        let (child_signed, _expected_child_post_state, child_root) =
            build_signed_block(&parent_post_state, 2);
        let expected_child_state_root = child_signed.message.block.state_root;

        live_state.latest_justified = Checkpoint {
            root: parent_root,
            slot: Slot(Uint64(1)),
        };
        live_state.latest_finalized = Checkpoint {
            root: parent_root,
            slot: Slot(Uint64(1)),
        };

        let import_result = store.put_signed_block_inner_with_verifier(
            child_root,
            child_signed,
            &mut live_state,
            &verifier,
        );

        assert!(
            import_result.is_ok(),
            "import should replay from the stored parent state when live checkpoints drift, got {import_result:?}"
        );

        let persisted_child_state = store
            .get_state(&child_root)
            .expect("persisted child state by block root");
        assert_eq!(persisted_child_state.slot, Slot(Uint64(2)));
        assert_eq!(
            Bytes32::from(persisted_child_state.latest_block_header.hash_tree_root()),
            child_root
        );
        assert_eq!(
            persisted_child_state.latest_block_header.state_root,
            expected_child_state_root
        );
        assert_eq!(
            Bytes32::from(live_state.latest_block_header.hash_tree_root()),
            child_root
        );

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
