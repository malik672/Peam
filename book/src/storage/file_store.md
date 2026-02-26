# FileStore

`FileStore` is the disk-backed `Store` implementation used at runtime. It wraps a `CanonicalDb` (redb) and maintains in-memory canonical slot indexes alongside an in-memory pending window for non-finalized blocks.

## Structure

```rust
pub struct FileStore {
    root: PathBuf,
    canonical_db: CanonicalDb,          // redb wrapper
    state_by_slot: RapidHashMap<u64, Bytes32>,  // canonical, in-memory
    block_by_slot: RapidHashMap<u64, Bytes32>,  // canonical, in-memory
    pending_blocks: PendingSlotCache,    // non-finalized, ring buffer
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    finalized_slot: Option<u64>,        // cached to avoid redb reads on write
    justified: Option<Bytes32>,
    recovery: RecoveryReport,
    index_dirty: bool,
    meta_dirty: bool,
}
```

## Opening

```rust
let store = FileStore::open("/path/to/store")?;
```

`open` does four things:
1. Checks/writes `schema_version`.
2. Opens (or creates) `canonical.redb`.
3. Loads canonical slot indexes and fork-choice metadata into memory.
4. Resolves `finalized_slot` from the stored finalized block root.

## Write path — `put_signed_block`

This is the hot path. It is designed to touch redb exactly once per block:

1. Apply the state transition (`state.process_signed_block`).
2. Update all in-memory fields: `head`, `finalized`, `finalized_slot`, `justified`.
3. Route the new block to the pending window or canonical index via `index_block_slot`.
4. Promote any pending entries at `slot <= finalized_slot` to the canonical index.
5. Build a small delta of `(slot, root)` pairs for only the new/promoted entries.
6. Call `canonical_db.persist_signed_block_bundle` — a single redb write transaction that atomically persists all six tables: block blob, signed-block blob, state blob, state slot index upserts, block slot index upserts, and fork-choice metadata.

This avoids the O(n) full-index rewrite on every block and instead does O(1 + promoted) slot-table upserts.

## Read path

Slot-driven reads check the pending window first, then fall back to the canonical in-memory index:

```
get_state_by_slot(slot)
  ├── pending_blocks.get(slot)?
  │     → load_state_by_root(entry.state_root)
  └── state_by_slot.get(&slot)?
        → load_state_by_root(root)
```

Root-driven reads decode directly from the redb blob tables on each call (no blob cache).

## Dirty flags & flush

Two boolean flags track whether in-memory state has diverged from disk:

- `index_dirty` — canonical slot index has unsaved changes
- `meta_dirty` — head/finalized/justified have unsaved changes

`flush_canonical` writes a full snapshot (clear + reinsert all canonical rows) using `persist_snapshot`. This is used only on infrequent paths (explicit `set_head`, `set_finalized`, `set_justified`) and on `Drop`.

## Recovery report

`FileStore::recovery_report()` returns a `RecoveryReport` with counters for:

- `loaded_states` / `loaded_blocks` — rows loaded from disk at startup
- `skipped_corrupt` — entries skipped due to DB errors
- `skipped_unknown_version` — unknown blob version bytes encountered

## Pinned roots

`head`, `justified`, and `finalized` roots are always exempt from pruning. `FileStore::pinned_roots()` returns all three.
