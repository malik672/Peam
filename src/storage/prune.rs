use super::*;

/// Statistics returned by [`FileStore::prune`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Number of canonical state slot rows removed.
    pub removed_states: usize,
    /// Number of canonical block slot rows removed.
    pub removed_blocks: usize,
    /// Always zero in index-only pruning mode.
    pub removed_signed_blocks: usize,
    /// Number of entries skipped because their root is currently pinned
    /// (head, justified, or finalized).
    pub kept_pinned: usize,
}

impl FileStore {
    /// Prunes canonical slot indexes by retention window and persists them.
    ///
    /// Flow:
    /// - Compute `prune_before = finalized_slot - keep_recent_slots` (saturating).
    /// - Prune canonical state/block slot indexes while preserving pinned roots.
    /// - Flush updated canonical state (`canonical.redb`) atomically.
    ///
    /// This operation intentionally does not prune pending caches or delete blob files.
    #[inline]
    pub fn prune(
        &mut self,
        finalized_slot: u64,
        keep_recent_slots: u64,
    ) -> Result<PruneReport, String> {
        let prune_before = finalized_slot.saturating_sub(keep_recent_slots);
        let pinned = self.pinned_roots();
        let mut report = PruneReport::default();

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
        Ok(report)
    }
}
