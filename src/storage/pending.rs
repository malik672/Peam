//! In-memory pending-slot cache used by [`super::FileStore`].
//!
//! Design goals:
//! - O(1) insert/lookup by slot.
//! - Fixed memory footprint.
//! - No heap growth during steady-state operation.
//!
//! The cache is addressed by `slot % capacity` and stores the original slot
//! alongside `(block_root, state_root)` so wraparound collisions are detected
//! safely.

use crate::types::bytes::Bytes32;

/// Single pending slot entry.
///
/// `slot` is stored explicitly (instead of only using bucket position) so a
/// lookup can distinguish a real hit from a modulo collision.
#[derive(Clone, Copy)]
pub(super) struct PendingEntry {
    /// Beacon slot number associated with `root`.
    pub(super) slot: u64,
    /// Block root stored for this slot.
    pub(super) block_root: Bytes32,
    /// State root stored for this slot.
    pub(super) state_root: Bytes32,
}

/// Fixed-capacity slot-indexed pending cache.
///
/// Backed by `Box<[Option<PendingEntry>]>` and addressed by `slot % capacity`.
/// The stored slot is checked to avoid false hits on wraparound.
/// Entry count is tracked incrementally to avoid O(n) scans.
#[derive(Clone)]
pub(super) struct PendingSlotCache {
    /// Fixed table of pending entries; `None` means empty bucket.
    entries: Box<[Option<PendingEntry>]>,
    /// Number of occupied buckets, maintained incrementally.
    count: usize,
}

impl PendingSlotCache {
    /// Creates a new pending cache with `capacity` buckets.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: vec![None; capacity].into_boxed_slice(),
            count: 0,
        }
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.count
    }

    #[inline]
    fn index(&self, slot: u64) -> usize {
        (slot as usize) % self.entries.len()
    }

    /// Inserts/overwrites the entry for `slot`.
    ///
    /// Returns the previously stored bucket value (if any), which may be:
    /// - the old value for the same slot, or
    /// - a collided value from a different slot that shared the same bucket.
    #[inline]
    pub(super) fn insert(
        &mut self,
        slot: u64,
        block_root: Bytes32,
        state_root: Bytes32,
    ) -> Option<PendingEntry> {
        let idx = self.index(slot);
        let prev = self.entries[idx];
        if prev.is_none() {
            self.count += 1;
        }
        self.entries[idx] = Some(PendingEntry {
            slot,
            block_root,
            state_root,
        });
        prev
    }

    /// Returns the entry for `slot` if present.
    ///
    /// A bucket hit is accepted only when the stored slot matches exactly.
    #[inline]
    pub(super) fn get(&self, slot: u64) -> Option<PendingEntry> {
        let idx = self.index(slot);
        match self.entries[idx] {
            Some(entry) if entry.slot == slot => Some(entry),
            _ => None,
        }
    }

    /// Drains entries with `slot <= upper_inclusive` and applies `on_entry`.
    ///
    /// Cleared buckets are set to `None` and `count` is updated in place.
    #[inline]
    pub(super) fn drain_leq_with<F>(&mut self, upper_inclusive: u64, mut on_entry: F)
    where
        F: FnMut(PendingEntry),
    {
        for entry in self.entries.iter_mut() {
            if let Some(value) = *entry {
                if value.slot <= upper_inclusive {
                    *entry = None;
                    self.count -= 1;
                    on_entry(value);
                }
            }
        }
    }

    /// Retains only entries for which `keep(slot, block_root, state_root)` returns `true`.
    #[allow(dead_code)]
    pub(super) fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(u64, Bytes32, Bytes32) -> bool,
    {
        for entry in self.entries.iter_mut() {
            if let Some(value) = *entry {
                if !keep(value.slot, value.block_root, value.state_root) {
                    *entry = None;
                    self.count -= 1;
                }
            }
        }
    }

    /// Returns a snapshot of all currently stored roots.
    ///
    /// Order is bucket order and therefore unspecified for semantic use.
    #[allow(dead_code)]
    pub(super) fn roots(&self) -> Vec<Bytes32> {
        self.entries
            .iter()
            .filter_map(|entry| entry.map(|value| value.block_root))
            .collect()
    }

    /// Extends root-retention sets with all currently buffered pending entries.
    ///
    /// Used by pruning to avoid deleting blobs that are still reachable from
    /// the in-memory non-finalized window.
    pub(super) fn extend_referenced_roots(
        &self,
        block_roots: &mut rapidhash::RapidHashSet<Bytes32>,
        state_block_roots: &mut rapidhash::RapidHashSet<Bytes32>,
    ) {
        for entry in self.entries.iter().flatten() {
            block_roots.insert(entry.block_root);
            state_block_roots.insert(entry.block_root);
        }
    }
}
