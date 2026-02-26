# Benchmarks

All benchmarks use [Criterion](https://github.com/bheisler/criterion.rs).

## Benchmark targets

| Name | What it measures |
|------|-----------------|
| `compare_ream` | SSZ encode/merkleize vs equivalent lean_eth types |
| `bitlist_compare` | BitList SSZ encode/decode throughput |
| `merkleize_loop` | Raw `merkleize` throughput at various tree depths |
| `chunkify_fixed` | `chunkify_fixed` throughput at various payload sizes |
| `storage_open` | `FileStore::open` and cold blob reads |
| `storage_lookup` | Hot in-memory lookup (MemoryStore vs FileStore) |
| `index_rebuild_strategy` | Canonical index rebuild strategies |
| `index_text_strategy` | Text-format index parsing strategies |

## Running

```bash
# Build all bench targets without running
cargo bench --no-run

# Run a specific bench
cargo bench --bench storage_open
cargo bench --bench storage_lookup
cargo bench --bench merkleize_loop

# Faster iteration (fewer samples)
cargo bench --bench storage_open -- --sample-size 10 --measurement-time 2 --warm-up-time 1
```

## Storage benchmark snapshot (2026-02-26)

### `storage_open` — cold paths

| Benchmark | Time |
|-----------|------|
| `file_store_open_1k_states_1k_blocks` | 16.9 – 17.3 ms |
| `file_store_cold_read_state_by_root` | 17.0 – 17.6 ms |
| `file_store_cold_read_block_by_root` | 17.8 – 18.8 ms |
| `file_store_cold_read_state_by_slot` | 18.2 – 18.8 ms |
| `file_store_cold_read_block_by_slot` | 18.5 – 19.3 ms |

Cold-read benches include `FileStore::open` on every iteration (includes startup index load cost).

### `storage_lookup` — hot paths

| Benchmark | Time |
|-----------|------|
| `memory_get_state_by_root` | 35 – 38 ns |
| `memory_get_state_by_slot` | 38 – 40 ns |
| `file_get_state_by_root` | 1.08 – 1.14 µs |
| `file_get_state_by_slot` | 1.09 – 1.18 µs |
| `memory_random_slot_mix` | 3.93 – 4.13 µs |
| `file_random_slot_mix` | 213 – 217 µs |

`FileStore` lookups include redb read + blob decode on each call (no decoded-object cache in the storage layer).

## Result output

Criterion writes HTML reports and JSON data to:

```
target/criterion/
```

## Guardrails

- Do not compare results across different machines or power profiles.
- Re-run with identical settings before claiming a regression.
- Ignore Criterion "change" percentages when benchmark structure was modified (new measurement, renamed group, etc.).
