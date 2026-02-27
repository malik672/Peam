//! Disk-backed [`FileStore`] implementation.
//!
//! This module owns on-disk persistence, startup recovery/loading,
//! canonical/pending index bookkeeping, and [`Store`] implementation details
//! for database-backed operation.

use std::path::{Path, PathBuf};

use super::canonical_db::CanonicalDb;
use super::pending::PendingSlotCache;
use super::*;
use crate::ssz::SszEncode;

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

    #[inline]
    fn load_state_by_root(&self, root: &Bytes32) -> Option<State> {
        let bytes = self.canonical_db.load_state_blob(*root).ok()??;
        let bytes = decode_blob(BLOB_KIND_STATE, &bytes)?;
        decode_state_safe(&bytes)
    }

    #[inline]
    fn load_block_by_root(&self, root: &Bytes32) -> Option<Block> {
        let bytes = self.canonical_db.load_block_blob(*root).ok()??;
        let bytes = decode_blob(BLOB_KIND_BLOCK, &bytes)?;
        decode_block_safe(&bytes)
    }

    #[inline]
    fn load_signed_block_by_root(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        let bytes = self.canonical_db.load_signed_block_blob(*root).ok()??;
        let bytes = decode_blob(BLOB_KIND_SIGNED_BLOCK, &bytes)?;
        decode_signed_block_safe(&bytes)
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

    #[inline]
    fn index_state_slot(&mut self, slot: u64, root: Bytes32) {
        self.state_by_slot.insert(slot, root);
        self.index_dirty = true;
    }

    /// Returns `true` if the block was routed to the canonical index, `false` if pending.
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

    /// Loads startup metadata and all indexes.
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
}

impl Drop for FileStore {
    fn drop(&mut self) {
        if self.index_dirty || self.meta_dirty {
            let _ = self.flush_canonical();
        }
    }
}

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

    fn put_block(&mut self, root: Bytes32, block: Block) {
        let slot = block.slot.0.0;
        let state_root = block.state_root;
        // Blob write must succeed before canonical indexes can reference this root.
        if self.persist_block(root, &block).is_err() {
            return;
        }
        self.index_block_slot(slot, root, state_root);
    }

    #[inline]
    fn put_signed_block(
        &mut self,
        root: Bytes32,
        signed: SignedBlockWithAttestation,
        state: &mut State,
    ) -> Result<(), String> {
        state.process_signed_block(&signed)?;

        let block = signed.message.block.clone();
        let slot = block.slot.0.0;
        let state_root = block.state_root;
        let block_blob = encode_blob(BLOB_KIND_BLOCK, &block.encode_ssz());
        let signed_blob = encode_blob(BLOB_KIND_SIGNED_BLOCK, &signed.encode_ssz());
        let state_blob = encode_blob(BLOB_KIND_STATE, &state.encode_ssz());

        // Update in-memory view first, then persist blobs + snapshot atomically.
        self.head = Some(root);
        self.justified = Some(state.latest_justified.root);
        self.finalized = Some(state.latest_finalized.root);
        self.finalized_slot = Some(state.latest_finalized.slot.0.0);
        self.set_meta_dirty();

        let fin_slot = state.latest_finalized.slot.0.0;
        let block_canonical = self.index_block_slot(slot, root, state_root);
        self.index_state_slot(slot, state_root);
        let promoted = self.promote_finalized_slot_in_memory(fin_slot);

        // Build delta: only the entries that changed this call.
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

    fn get_state_by_slot(&self, slot: u64) -> Option<State> {
        if let Some(entry) = self.pending_blocks.get(slot) {
            return self.load_state_by_root(&entry.state_root);
        }
        let root = self.state_by_slot.get(&slot).copied()?;
        self.load_state_by_root(&root)
    }

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
}
