# MMR In `lean_eth`

## Why We Added It

`lean_eth` now keeps an auxiliary Merkle Mountain Range (MMR) over finalized roots.

This was added for:

- efficient append-only historical commitments,
- compact inclusion/order proofs for finalized history,
- easier external verification of historical finalized roots.

The MMR is persisted in:

- `finalized_mmr.bin` (append-style leaf log, 32 bytes per finalized root).

## What It Is Not

This MMR does **not** replace SSZ Merkleization.

Consensus compatibility still depends on SSZ `hash_tree_root` commitments and SSZ proof formats.
If we replaced SSZ commitments with MMR commitments, our roots/proofs would diverge from other clients.

## Spec Context (SSZ Merkle Tree)

In spec-style consensus objects:

- SSZ defines serialization + tree hashing rules.
- `hash_tree_root` is the canonical commitment used by everyone.
- SSZ Merkle branches are the interoperable proof format for container/list field inclusion.

So SSZ is protocol truth, not optional.

## Architecture After This Change

- Canonical object integrity: SSZ root checks (content-addressed by root).
- Mutable pointers: `state_index.txt`, `block_index.txt`, `meta.txt`.
- Historical append-only commitment: `finalized_mmr.bin`.

## Current Runtime Mode

For maximum storage performance, MMR maintenance is currently disabled in
`FileStore` (`ENABLE_FINALIZED_MMR = false` in
`/Users/malik/Desktop/mc2/lean_eth/lean_eth/src/storage/mod.rs`).

In this mode, the node runs purely on local-trust indexes/meta and skips MMR
append/load work on finalize updates.

In short:

- SSZ root = canonical consensus commitment.
- MMR root = auxiliary commitment over finalized history.

## API Surface

`FileStore` now exposes:

- `finalized_mmr_root() -> Bytes32`
- `finalized_mmr_size() -> usize`
- `finalized_mmr_proof_by_index(index) -> Option<MmrInclusionProof>`
- `finalized_mmr_proof_by_root(root) -> Option<MmrInclusionProof>`

And verification helper:

- `verify_mmr_inclusion_proof(expected_root, proof) -> bool`

## Safety/Consistency Notes

- MMR appends only on finalized updates (duplicate consecutive roots are skipped).
- Per-file writes are atomic, but this is still a multi-file system overall.
- If stronger cross-file atomicity is needed, add a manifest/generation commit protocol.
