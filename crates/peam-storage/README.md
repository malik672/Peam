# peam-storage

Persistent and in-memory storage for `Peam`.

This crate owns the storage layer used by the node:

- `MemoryStore` for tests and simulation
- `FileStore` for disk-backed operation
- canonical index / metadata persistence through `CanonicalDb`
- pruning and index maintenance helpers

## Structure

- `canonical_db.rs`: low-level `redb` wrapper for canonical slot/root/meta data
- `file_store.rs`: node-facing persistent store
- `index*.rs`, `pending.rs`, `prune.rs`: supporting storage/index logic

## What belongs here

- persistence format and storage policy
- canonical indexes and metadata
- storage rebuild / recovery helpers
- pruning and blob lifecycle logic

## What does not belong here

- fork choice
- networking/runtime orchestration
- concrete PQ verification code

`peam-storage` is the bridge between the live node and durable chain/state
data, while the root `peam` crate provides the concrete PQ-backed block
processing glue used during imports.
