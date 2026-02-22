# Benchmarks

This document defines how to run and interpret storage benchmarks in `lean_eth`.

## Scope

- `storage_open`: open-time and cold-read paths for `FileStore`
- `storage_lookup`: hot in-memory lookup paths for `MemoryStore` and `FileStore`

## Benchmark Files

- `/Users/malik/Desktop/mc2/lean_eth/lean_eth/benches/storage_open.rs`
- `/Users/malik/Desktop/mc2/lean_eth/lean_eth/benches/storage_lookup.rs`

## Prerequisites

Run from:

```bash
cd /Users/malik/Desktop/mc2/lean_eth/lean_eth
```

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

## Current Snapshot (2026-02-20)

`storage_open`:

- `file_store_open_1k_states_1k_blocks`: `47.467 ms .. 58.541 ms`
- `file_store_cold_read_state_by_root`: `47.327 ms .. 57.640 ms`
- `file_store_cold_read_block_by_root`: `54.599 ms .. 79.654 ms`
- `file_store_cold_read_state_by_slot`: `53.117 ms .. 64.324 ms`
- `file_store_cold_read_block_by_slot`: `50.252 ms .. 53.353 ms`

`storage_lookup`:

- `memory_get_state_by_root`: `18.962 ns .. 39.445 ns`
- `memory_get_state_by_slot`: `106.43 ns .. 166.76 ns`
- `file_get_state_by_root`: `13.441 ns .. 18.250 ns`
- `file_get_state_by_slot`: `6.2137 ns .. 6.3521 ns`
- `memory_random_slot_mix`: `2.3901 us .. 2.6726 us`
- `file_random_slot_mix`: `2.3439 us .. 2.6060 us`

Notes:

- `storage_lookup` is a hot in-memory benchmark after store construction/open.
- `storage_open` cold-read benches include `FileStore::open(...)` on every iteration, so they include startup load cost.

## Result Output

Criterion writes reports to:

- `/Users/malik/Desktop/mc2/lean_eth/lean_eth/target/criterion/`

For trend tracking, compare the median range (`time: [low mid high]`) across runs on the same machine and power profile.

## Guardrails

- Do not compare runs across different machines for regression decisions.
- Re-run with the same sample-size/time settings before claiming a regression.
- Ignore Criterion "change" percentages when benchmark structure was modified.
