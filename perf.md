# Performance Notes

## Startup Cost (FileStore::open)

`FileStore::open()` currently pays a one-time startup cost:
- opens `canonical.redb`
- loads full `state_by_slot` and `block_by_slot` indexes into memory
- loads fork-choice metadata

This is expected to happen once per process start.  
The `storage_open/*cold*` Criterion benchmarks intentionally include this startup work in every iteration, so they are not steady-state read latency numbers.

## Practical Interpretation

If cold benchmark regresses but steady-state read/write is stable or better, that usually means startup work increased, not runtime path cost.

## Justification Votes Representation

Current vote-root count is small, so a linear `Vec` scan is acceptable in practice today.
However, this may not hold as scenarios scale.

Tradeoff:
- `Vec` only: deterministic order and no re-sort cost on encode, but O(n) lookup/update per attestation by `target.root`.
- Hash map only: fast lookup/update, but requires sorting for deterministic encode order.

Recommended structure for scale:
- Ordered storage for deterministic encoding (`Vec<Bytes32>` + parallel `Vec<JustificationVotes>`).
- Fast index map for updates (`RapidHashMap<Bytes32, usize>`).

This keeps deterministic serialization while avoiding per-attestation linear scans as root count grows.
