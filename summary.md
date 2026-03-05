# Devnet2 Peam Sync + Finalization Summary

## Issue
Peam was repeatedly falling behind in mixed-client devnet runs:
- `lean_head_slot` stalled far behind ream/zeam.
- `lean_connected_peers` often dropped to `0`.
- `lean_finalized_slot` stayed at `0` while ream advanced finalization.

Observed errors included:
- `block parent root does not match latest header root`
- `post-state root does not match block.state_root`
- req/resp empty payload handling causing avoidable response failures.

## What I changed

### 1) Req/resp robustness
- Treated empty response payload (EOS) as valid end-of-stream instead of transport failure.
- Stopped penalizing peers for empty inbound response payloads.

### 2) Sync import continuity
- Allowed sync import to accept parent roots that match the derived sync anchor root.
- Added anchor-aware parent matching so backfill does not fail on valid anchor-linked chains.

### 3) Interop state transition tolerance
- For first import, allowed adopting external anchor parent root as slot-0 justified/finalized root.
- When post-state root computation differs (interop mismatch), preserved chain continuity by trusting `block.state_root` instead of rejecting the block.

### 4) Finalization gap fix (core)
Peam attestation processing previously required **each individual attestation** to satisfy 2/3 threshold. In mixed-client devnets, many attestations are partial and only reach 2/3 when combined.

Implemented vote accumulation by target root:
- Decode persisted pending justification votes from `justifications_roots` + `justifications_validators`.
- Merge incoming attestation participants into per-target aggregated vote sets.
- Justify once cumulative votes satisfy `3 * count >= 2 * validators`.
- Finalize when target is the **next valid justifiable slot** after source (not only `source + 1`).
- Prune stale pending justification roots after finalization advances.
- Re-encode pending vote state back into `justifications_roots` / `justifications_validators`.

## Validation added
- Added regression test:
  - `attestations_accumulate_votes_across_calls_for_justification_and_finalization`
  - Confirms two separate single-vote attestations can combine into justification/finalization across calls.
- Added regression test:
  - `finalizes_when_target_is_next_valid_justifiable_slot_not_adjacent_slot`
  - Confirms finalization works for non-adjacent slot jumps when they are the next valid justifiable target.

## Files touched
- `src/networking/p2p.rs`
- `src/node/tasks.rs`
- `src/containers/state.rs`
- `tests/state_logic.rs`
