# State Transition

The state transition logic lives in `src/containers/state.rs`. It is called by `Store::put_signed_block` and is the gatekeeper for all block acceptance.

## `State::process_signed_block`

```rust
pub fn process_signed_block(
    &mut self,
    signed: &SignedBlockWithAttestation,
) -> Result<(), String>
```

This is the top-level entry point. It runs the full pipeline:

1. **`process_slots`** — advance `state.slot` to `block.slot`, appending zero-hashes to `historical_block_hashes` for any skipped slots.
2. **`process_block_header`** — verify slot ordering, set `latest_block_header`.
3. **`process_attestations`** — validate and record each attestation.
4. **`verify_proposer_signature`** — verify the PQ proposer signature.
5. **Post-state root check** — compute `hash_tree_root(state)` and verify it equals `block.state_root`.
6. **Commit** — write `latest_block_header.state_root = block.state_root`.

If any step fails, the state is left partially mutated. Making the transition fully transactional (copy-on-write or rollback) is a planned improvement.

## Enforced invariants

| Check | Rule |
|-------|------|
| Slot ordering | `block.slot > state.slot` |
| Parent root | `block.parent_root == hash_tree_root(state.latest_block_header)` |
| Attestation proof count | equals `block.attestations.len()` |
| Proposer attestation slot | equals `block.slot` |
| Proposer attestation participant | exactly one participant matching `block.proposer_index` |
| Aggregation bits consistency | proof participants must match attestation aggregation bitfield |
| Participant index range | all indices < `VALIDATOR_REGISTRY_LIMIT` |
| Post-state root | `hash_tree_root(post_state) == block.state_root` |

## Justification and finalization

`process_attestations` accumulates vote bits into `justifications_validators`. When a supermajority threshold is reached for a slot, that slot's checkpoint is promoted to `latest_justified` and eventually to `latest_finalized`. The exact threshold rules and timing windows are an active development area (see TODO).

## Slot processing

For each slot between the current state slot and the block slot:
- Append the current `latest_block_header` root to `historical_block_hashes` (zero if the slot was skipped).
- Increment the state slot counter.

This ensures the history vector is always aligned with the slot timeline.
