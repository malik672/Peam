# Benchmarks

This document defines how to run and interpret storage benchmarks in `lean_eth`.

## Scope

- `storage_open`: open-time and cold-read paths for `FileStore`
- `storage_lookup`: hot in-memory lookup paths for `MemoryStore` and `FileStore`

## Benchmark Files

- `benches/storage_open.rs`
- `benches/storage_lookup.rs`

## Prerequisites

Run from the repository root.

Optional (faster plots): install `gnuplot`.

## Commands

Build bench targets only:

```bash
cargo bench --bench storage_open --no-run
cargo bench --bench storage_lookup --no-run
```

Standard runs:

```bash
cargo bench --bench storage_open -- --sample-size 10 --measurement-time 2 --warm-up-time 1
cargo bench --bench storage_lookup -- --sample-size 10 --measurement-time 2 --warm-up-time 1
```

Higher-confidence runs (slower):

```bash
cargo bench --bench storage_open -- --sample-size 20
cargo bench --bench storage_lookup -- --sample-size 20
```

## Current Snapshot (2026-02-26)

`storage_open`:

- `file_store_open_1k_states_1k_blocks`: `16.886 ms .. 17.328 ms`
- `file_store_cold_read_state_by_root`: `17.029 ms .. 17.611 ms`
- `file_store_cold_read_block_by_root`: `17.791 ms .. 18.806 ms`
- `file_store_cold_read_state_by_slot`: `18.201 ms .. 18.848 ms`
- `file_store_cold_read_block_by_slot`: `18.546 ms .. 19.268 ms`

`storage_lookup`:

- `memory_get_state_by_root`: `35.430 ns .. 37.563 ns`
- `memory_get_state_by_slot`: `37.842 ns .. 39.520 ns`
- `file_get_state_by_root`: `1.0821 us .. 1.1446 us`
- `file_get_state_by_slot`: `1.0949 us .. 1.1824 us`
- `memory_random_slot_mix`: `3.9287 us .. 4.1318 us`
- `file_random_slot_mix`: `212.71 us .. 217.43 us`

Notes:

- `storage_lookup` now measures decode-on-demand DB blob reads for `FileStore`
  (no in-memory decoded-object map in the storage layer).
- `storage_open` cold-read benches include `FileStore::open(...)` on every iteration, so they include startup load cost.

## Result Output

Criterion writes reports to:

- `target/criterion/`

For trend tracking, compare the median range (`time: [low mid high]`) across runs on the same machine and power profile.

## Guardrails

- Do not compare runs across different machines for regression decisions.
- Re-run with the same sample-size/time settings before claiming a regression.
- Ignore Criterion "change" percentages when benchmark structure was modified.

