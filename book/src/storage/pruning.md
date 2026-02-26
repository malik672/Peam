# Pruning

`FileStore::prune` trims the canonical slot indexes to a rolling retention window and flushes the result to disk atomically.

## How it works

```rust
pub fn prune(
    &mut self,
    finalized_slot: u64,
    keep_recent_slots: u64,
) -> Result<PruneReport, String>
```

1. Compute `prune_before = finalized_slot - keep_recent_slots` (saturating sub — never wraps below zero).
2. Retain all canonical state slot entries where `slot >= prune_before` **or** `root` is pinned.
3. Retain all canonical block slot entries under the same rule.
4. Mark the index dirty and call `flush_canonical` — a full clear-and-reinsert snapshot written in a single redb transaction.

## Pinned roots

Roots currently referenced by `head`, `justified`, or `finalized` are never pruned, regardless of their slot. This prevents pruning an entry that the node actively needs to serve.

## What is not pruned

- **Blob data** — the state/block/signed-block blobs stored in redb are not deleted. Index-only pruning removes slot→root pointers but leaves the underlying blobs in place. A future blob GC pass can walk the index and delete unreferenced blobs.
- **Pending window** — non-finalized entries in `PendingSlotCache` are not touched.

## PruneReport

```rust
pub struct PruneReport {
    pub removed_states: usize,
    pub removed_blocks: usize,
    pub removed_signed_blocks: usize,  // always 0 in current implementation
    pub kept_pinned: usize,
}
```

## Performance

Pruning is O(canonical index size) for the retain pass, plus the cost of the full `persist_snapshot` write. It should be called infrequently — typically once per epoch or on a manual maintenance trigger.
