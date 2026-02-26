# Pending Window

The pending window is a fixed-capacity ring buffer that holds non-finalized blocks in memory. It is implemented in `src/storage/pending.rs`.

## Design goals

- O(1) insert and lookup by slot.
- Fixed memory footprint — no heap growth during steady-state operation.
- No allocation per block write.

## PendingSlotCache

```rust
pub struct PendingSlotCache {
    entries: Box<[Option<PendingEntry>]>,
}

pub struct PendingEntry {
    pub slot: u64,
    pub block_root: Bytes32,
    pub state_root: Bytes32,
}
```

The backing array has `PENDING_WINDOW_CAP = 2048` buckets. A slot is mapped to a bucket by `slot % 2048`.

Each bucket stores the original `slot` alongside both roots so that:
- A wraparound collision (a new slot sharing the same bucket index as an old slot) is detected and the old value is silently evicted.
- A read can verify the stored slot matches the requested slot before returning.

## Operations

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `insert(slot, block_root, state_root)` | O(1) | Overwrites the bucket; returns the previous entry |
| `get(slot)` | O(1) | Returns `None` on slot mismatch (collision/eviction) |
| `drain_leq(upper)` | O(capacity) | Drains all entries with `slot <= upper`; used at finalization |

## Eviction policy

Silent eviction is intentional. When a new non-finalized block arrives for slot `s` and slot `s - 2048` (or any other slot sharing the same bucket) is still in the cache, the old entry is overwritten. Since the pending window is 2048 slots deep and finalization typically advances every few slots, this only evicts entries that are far enough behind to be unreachable anyway.

## Promotion at finalization

When the finalized slot advances to `F`, `drain_leq(F)` is called. All entries with `slot <= F` are collected, removed from the ring buffer, and written into the canonical `state_by_slot` and `block_by_slot` HashMaps. The resulting `(slot, root)` pairs become the delta for the next redb write.
