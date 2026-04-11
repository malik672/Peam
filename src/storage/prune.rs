use super::*;
use rapidhash::RapidHashSet;
use tracing::{info, warn};

/// Statistics returned by [`FileStore::prune`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Number of canonical state slot rows removed.
    pub removed_states: usize,
    /// Number of canonical block slot rows removed.
    pub removed_blocks: usize,
    /// Number of state blob rows removed from canonical blob storage.
    pub removed_state_blobs: usize,
    /// Number of block blob rows removed from canonical blob storage.
    pub removed_block_blobs: usize,
    /// Number of signed-block blob rows removed from canonical blob storage.
    pub removed_signed_blocks: usize,
    /// Number of entries skipped because their root is currently pinned
    /// (head, justified, or finalized).
    pub kept_pinned: usize,
}

impl FileStore {
    /// Prunes canonical slot indexes by retention window and garbage-collects
    /// unreferenced canonical blob rows.
    ///
    /// Flow:
    /// - Compute `prune_before = finalized_slot - keep_recent_slots` (saturating).
    /// - Prune canonical state/block slot indexes while preserving pinned roots.
    /// - Flush updated canonical state (`canonical.redb`) atomically.
    /// - Delete unreferenced state/block/signed-block blobs from `canonical.redb`
    ///   while preserving roots still referenced by canonical indexes, pending
    ///   entries, or pinned fork-choice roots.
    #[inline]
    pub fn prune(
        &mut self,
        finalized_slot: u64,
        keep_recent_slots: u64,
    ) -> Result<PruneReport, String> {
        let prune_before = finalized_slot.saturating_sub(keep_recent_slots);
        let pinned = self.pinned_roots();
        let mut report = PruneReport::default();
        info!(
            finalized_slot,
            keep_recent_slots, prune_before, "storage prune started"
        );

        // Canonical state index prune.
        self.state_by_slot.retain(|slot, root| {
            if *slot >= prune_before {
                return true;
            }
            if is_pinned(&pinned, root) {
                report.kept_pinned += 1;
                return true;
            }
            report.removed_states += 1;
            false
        });

        let mut live_state_roots = RapidHashSet::<Bytes32>::default();
        live_state_roots.extend(self.state_by_slot.values().copied());
        self.pending_blocks
            .extend_referenced_state_roots(&mut live_state_roots);
        self.state_root_to_block_root
            .retain(|state_root, _| live_state_roots.contains(state_root));

        // Canonical block index prune.
        self.block_by_slot.retain(|slot, root| {
            if *slot >= prune_before {
                return true;
            }
            if is_pinned(&pinned, root) {
                report.kept_pinned += 1;
                return true;
            }
            report.removed_blocks += 1;
            false
        });

        self.index_dirty = true;
        self.flush_canonical()?;

        let mut keep_state_block_roots = RapidHashSet::<Bytes32>::default();
        let mut missing_state_root_mappings = 0usize;
        for state_root in self.state_by_slot.values().copied() {
            if let Some(block_root) = self.state_root_to_block_root.get(&state_root).copied() {
                keep_state_block_roots.insert(block_root);
            } else {
                // Standalone `put_state` callers key state blobs directly by the
                // provided root, so keep that root too. If the missing mapping
                // belongs to migrated/imported state, we treat prune
                // conservatively below and retain all state blobs for this pass.
                keep_state_block_roots.insert(state_root);
                missing_state_root_mappings += 1;
            }
        }
        let mut keep_block_roots = RapidHashSet::<Bytes32>::default();
        keep_block_roots.extend(self.block_by_slot.values().copied());
        keep_block_roots.extend(pinned.iter().flatten().copied());
        keep_state_block_roots.extend(pinned.iter().flatten().copied());
        self.pending_blocks
            .extend_referenced_roots(&mut keep_block_roots, &mut keep_state_block_roots);

        if missing_state_root_mappings > 0 {
            warn!(
                missing_state_root_mappings,
                "state-root mapping is incomplete; skipping state-blob garbage collection for this prune pass to avoid deleting retained state"
            );
            keep_state_block_roots.extend(self.canonical_db.load_state_blob_roots()?);
        }

        let gc = self
            .canonical_db
            .gc_unreferenced_blobs(&keep_state_block_roots, &keep_block_roots)?;
        report.removed_state_blobs = gc.removed_state_blobs;
        report.removed_block_blobs = gc.removed_block_blobs;
        report.removed_signed_blocks = gc.removed_signed_block_blobs;

        info!(
            removed_states = report.removed_states,
            removed_blocks = report.removed_blocks,
            removed_state_blobs = report.removed_state_blobs,
            removed_block_blobs = report.removed_block_blobs,
            removed_signed_blocks = report.removed_signed_blocks,
            kept_pinned = report.kept_pinned,
            "storage prune finished"
        );
        Ok(report)
    }
}
