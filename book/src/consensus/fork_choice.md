# Fork Choice

`ForkChoiceStore` in `src/fork_choice.rs` implements a minimal GHOST-style fork-choice algorithm.

## Structure

```rust
pub struct ForkChoiceStore {
    head: Bytes32,
    head_slot: u64,
    latest_justified: Checkpoint,
    latest_finalized: Checkpoint,
    blocks: RapidHashMap<Bytes32, SignedBlockWithAttestation>,
    states: RapidHashMap<Bytes32, State>,
    parents: RapidHashMap<Bytes32, Bytes32>,
    children: RapidHashMap<Bytes32, Vec<Bytes32>>,
    latest_votes: RapidHashMap<usize, Bytes32>,  // validator_index → head vote
}
```

The store is keyed by block root throughout. Parent and child relations form an explicit DAG.

## Initialization

```rust
let fc = ForkChoiceStore::new(anchor_block, anchor_state)?;
```

The anchor must satisfy the post-state invariant: the state's `latest_block_header.state_root` must match `block.state_root`. This is the stable condition available after `state_transition` completes.

## Block import — `on_block`

```rust
fc.on_block(signed_block, post_state)?;
```

1. Verify the post-state invariant.
2. Insert the block root, block, state, and parent/child links.
3. Update `latest_justified` and `latest_finalized` from the post-state.
4. Advance `head` if the new block's slot is greater than the current head slot.

The current head-update rule is slot-monotone (highest-slot block wins). Full vote-weighted GHOST head selection from accumulated attestations is planned.

## Attestation import — `on_attestation`

```rust
fc.on_attestation(attestation)?;
```

Records the latest vote from the attesting validator (`validator_id → block_root`). These votes accumulate in `latest_votes` and will be used for weighted head selection in a future release.

## Current limitations

- **Head selection is slot-monotone**, not vote-weighted. Full GHOST from `latest_votes` is planned.
- **No reorg recovery** — the fork tree is grown forward but no explicit reorg path is taken when a competing branch outweighs the current head.
- **In-memory only** — the fork-choice store is not persisted to disk and is rebuilt from the `FileStore` on restart via the anchor block.
