# Storage Design

The storage layer exposes a single `Store` trait with two implementations.

## The `Store` trait

```rust
pub trait Store {
    fn get_state(&self, root: &Bytes32) -> Option<State>;
    fn put_state(&mut self, root: Bytes32, state: State);
    fn get_block(&self, root: &Bytes32) -> Option<Block>;
    fn get_signed_block(&self, root: &Bytes32) -> Option<SignedBlockWithAttestation>;
    fn put_block(&mut self, root: Bytes32, block: Block);
    fn put_signed_block(&mut self, root: Bytes32, signed: SignedBlockWithAttestation,
                        state: &mut State) -> Result<(), String>;
    fn get_state_by_slot(&self, slot: u64) -> Option<State>;
    fn get_block_by_slot(&self, slot: u64) -> Option<Block>;
    fn head(&self) -> Option<Bytes32>;
    fn set_head(&mut self, root: Bytes32);
    fn finalized(&self) -> Option<Bytes32>;
    fn set_finalized(&mut self, root: Bytes32);
    fn justified(&self) -> Option<Bytes32>;
    fn set_justified(&mut self, root: Bytes32);
}
```

Lookups are either **root-driven** (`get_state`, `get_block`) or **slot-driven** (`get_state_by_slot`, `get_block_by_slot`). The slot-driven path requires an index.

## Two-tier index model

```
Canonical index (finalized, HashMap<u64, Bytes32>)
  state_by_slot  ──┐
  block_by_slot  ──┤── persisted in canonical.redb
  head / finalized / justified ─┘

Pending window (non-finalized, ring buffer in memory)
  PendingSlotCache (2048 slots, slot % 2048 addressing)
```

Writes flow through the pending window first. When a new finalized checkpoint is established, all pending entries at `slot <= finalized_slot` are batch-promoted into the canonical index and written to disk in a single atomic transaction.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PENDING_WINDOW_CAP` | 2 048 | Ring-buffer capacity for pending slots |
| `CANONICAL_DB_FILE` | `canonical.redb` | Embedded database file name |
| `SCHEMA_FILE` | `schema_version` | Plain-text schema version file |
| `SCHEMA_VERSION` | `"1"` | Current on-disk schema version |

## On-disk layout

```
<storage_dir>/
  canonical.redb    — slot indexes + fork-choice metadata + blobs
  schema_version    — plain text schema version ("1")
```

There is no separate blob directory. All data lives in the single redb database.

## Implementations

| Type | Description |
|------|-------------|
| `MemoryStore` | Fully in-memory; backed by `RapidHashMap`. No persistence. |
| `FileStore` | Disk-backed via `canonical.redb`. Used by the node at runtime. |
