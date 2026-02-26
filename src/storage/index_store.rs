use std::collections::BTreeMap;

use crate::types::bytes::Bytes32;

/// Fork-choice metadata persisted alongside slot indexes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForkChoiceMeta {
    pub head: Option<Bytes32>,
    pub finalized: Option<Bytes32>,
    pub justified: Option<Bytes32>,
}

/// Batched index/meta updates to apply atomically in a backend.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexBatch {
    pub state_upserts: Vec<(u64, Bytes32)>,
    pub block_upserts: Vec<(u64, Bytes32)>,
    pub state_deletes: Vec<u64>,
    pub block_deletes: Vec<u64>,
    pub meta: Option<ForkChoiceMeta>,
}

/// Minimal backend interface for canonical slot indexes + fork-choice metadata.
///
/// This is the abstraction point for a custom ClickHouse-style LSM backend.
pub trait IndexStore {
    fn get_state_root_by_slot(&self, slot: u64) -> Option<Bytes32>;
    fn get_block_root_by_slot(&self, slot: u64) -> Option<Bytes32>;
    fn iter_state_slots_lt(&self, upper_exclusive: u64) -> Vec<(u64, Bytes32)>;
    fn iter_block_slots_lt(&self, upper_exclusive: u64) -> Vec<(u64, Bytes32)>;
    fn get_meta(&self) -> ForkChoiceMeta;
    fn apply_batch(&mut self, batch: IndexBatch) -> Result<(), String>;
}

/// In-memory reference implementation of [`IndexStore`].
#[derive(Default)]
pub struct MemoryIndexStore {
    state_by_slot: BTreeMap<u64, Bytes32>,
    block_by_slot: BTreeMap<u64, Bytes32>,
    meta: ForkChoiceMeta,
}

impl MemoryIndexStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl IndexStore for MemoryIndexStore {
    fn get_state_root_by_slot(&self, slot: u64) -> Option<Bytes32> {
        self.state_by_slot.get(&slot).copied()
    }

    fn get_block_root_by_slot(&self, slot: u64) -> Option<Bytes32> {
        self.block_by_slot.get(&slot).copied()
    }

    fn iter_state_slots_lt(&self, upper_exclusive: u64) -> Vec<(u64, Bytes32)> {
        self.state_by_slot
            .range(..upper_exclusive)
            .map(|(slot, root)| (*slot, *root))
            .collect()
    }

    fn iter_block_slots_lt(&self, upper_exclusive: u64) -> Vec<(u64, Bytes32)> {
        self.block_by_slot
            .range(..upper_exclusive)
            .map(|(slot, root)| (*slot, *root))
            .collect()
    }

    fn get_meta(&self) -> ForkChoiceMeta {
        self.meta
    }

    fn apply_batch(&mut self, batch: IndexBatch) -> Result<(), String> {
        for (slot, root) in batch.state_upserts {
            self.state_by_slot.insert(slot, root);
        }
        for (slot, root) in batch.block_upserts {
            self.block_by_slot.insert(slot, root);
        }
        for slot in batch.state_deletes {
            self.state_by_slot.remove(&slot);
        }
        for slot in batch.block_deletes {
            self.block_by_slot.remove(&slot);
        }
        if let Some(meta) = batch.meta {
            self.meta = meta;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(v: u8) -> Bytes32 {
        Bytes32::from([v; 32])
    }

    #[test]
    fn batch_upsert_delete_and_meta_roundtrip() {
        let mut store = MemoryIndexStore::new();
        let batch = IndexBatch {
            state_upserts: vec![(10, root(1)), (20, root(2))],
            block_upserts: vec![(10, root(3)), (30, root(4))],
            state_deletes: vec![],
            block_deletes: vec![],
            meta: Some(ForkChoiceMeta {
                head: Some(root(8)),
                finalized: Some(root(9)),
                justified: Some(root(7)),
            }),
        };
        store.apply_batch(batch).expect("apply batch");

        assert_eq!(store.get_state_root_by_slot(10), Some(root(1)));
        assert_eq!(store.get_block_root_by_slot(30), Some(root(4)));
        assert_eq!(
            store.get_meta(),
            ForkChoiceMeta {
                head: Some(root(8)),
                finalized: Some(root(9)),
                justified: Some(root(7)),
            }
        );

        let delete_batch = IndexBatch {
            state_upserts: vec![],
            block_upserts: vec![],
            state_deletes: vec![10],
            block_deletes: vec![30],
            meta: None,
        };
        store.apply_batch(delete_batch).expect("apply delete batch");
        assert_eq!(store.get_state_root_by_slot(10), None);
        assert_eq!(store.get_block_root_by_slot(30), None);
    }

    #[test]
    fn iter_lt_returns_sorted_rows() {
        let mut store = MemoryIndexStore::new();
        store
            .apply_batch(IndexBatch {
                state_upserts: vec![(4, root(4)), (1, root(1)), (3, root(3))],
                block_upserts: vec![(6, root(6)), (2, root(2))],
                state_deletes: vec![],
                block_deletes: vec![],
                meta: None,
            })
            .expect("apply batch");

        assert_eq!(
            store.iter_state_slots_lt(4),
            vec![(1, root(1)), (3, root(3))]
        );
        assert_eq!(
            store.iter_block_slots_lt(7),
            vec![(2, root(2)), (6, root(6))]
        );
    }
}
