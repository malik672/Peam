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
