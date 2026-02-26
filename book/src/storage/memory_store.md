# MemoryStore

`MemoryStore` is the fully in-memory `Store` implementation. It is the default for unit tests and simulation harnesses.

## Structure

```rust
pub struct MemoryStore {
    states: RapidHashMap<Bytes32, State>,
    blocks: RapidHashMap<Bytes32, Block>,
    signed_blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    state_by_slot: RapidHashMap<u64, Bytes32>,
    block_by_slot: RapidHashMap<u64, Bytes32>,
    head: Option<Bytes32>,
    finalized: Option<Bytes32>,
    justified: Option<Bytes32>,
}
```

Everything is a plain `RapidHashMap`. There is no pending window, no disk I/O, and no slot-index vs blob distinction — the slot index and the object map are both updated in-place on every write.

## When to use it

- Unit tests — fast, deterministic, no file system dependency.
- In-memory simulations.
- Benchmarks that isolate consensus or networking from storage I/O.

## Behaviour differences from FileStore

| Behaviour | MemoryStore | FileStore |
|-----------|-------------|-----------|
| Persistence | None — lost on drop | Survives restart |
| Pending window | None | 2 048-slot ring buffer |
| Slot index promotion | Immediate | Batched at finalization |
| `get_state_by_slot` | Direct map lookup | Ring buffer then redb read |
| `put_signed_block` | In-memory update only | Atomic redb write |
