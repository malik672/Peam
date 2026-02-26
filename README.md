# lean_eth

A minimal, high‑performance Lean Consensus client focused on clean SSZ, fast hashing, and practical networking.

## Project status
- **Alpha**: APIs, storage layout, and behavior may change between releases.
- The codebase is suitable for experimentation and benchmarking, not production mainnet use.

## Quick start
```bash
cargo build
cargo test
```

## Goals
- Minimal, auditable implementation.
- High‑performance SSZ + merkleization.
- PQ‑ready signature verification hooks.
- Practical libp2p networking with gossip + req/resp.

## Configuration
`lean_eth` accepts either SSZ config bytes or a simple text config.

Example config (`config.txt`):
```text
genesis_time=42
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
bootnodes=/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA
trusted_peers=/ip4/5.6.7.8/tcp/30303/p2p/12D3KooWTrustA
allowed_topics=leanconsensus/devnet2/block/ssz_snappy,leanconsensus/devnet2/attestation/ssz_snappy
topic_scores=leanconsensus/devnet2/block/ssz_snappy:2,leanconsensus/devnet2/attestation/ssz_snappy:1
topic_validators=leanconsensus/devnet2/block/ssz_snappy=block,leanconsensus/devnet2/attestation/ssz_snappy=attestation
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
storage_dir=store
```

## Storage
- `MemoryStore`: in-memory store for tests and local dev.
- `FileStore`: disk-backed store backed by a single `canonical.redb` database. Writes states, blocks, and signed blocks as versioned blob envelopes and restores head/finalized/justified metadata on restart.
- Node runtime uses `FileStore` by default at `<data-dir>/store` unless `storage_dir` is set in config.
- Schema version is written to a `schema_version` file on first open; mismatches are rejected at startup.
- Persisted blobs include a versioned envelope (`LEANSTRG` magic + version + kind + SHA-256 checksum); legacy raw SSZ blobs are still accepted on load.
- On startup, corrupt DB entries are skipped and counted in a recovery report.
- Non-finalized blocks are buffered in an in-memory pending window (ring buffer, 2048 slots) and promoted to the canonical index on finalization.

### Storage semantics
- Canonical indexes (`slot -> root`) are durable in `canonical.redb`.
- Pending index is **ephemeral** (memory-only); it is intentionally empty after restart.
- Root lookups still work for persisted blobs after restart; slot lookups for non-finalized/pending entries do not.

## Tests
```bash
cargo test
```

## Metrics
`lean_eth` exposes a lightweight Prometheus-style endpoint when enabled in config:

```text
metrics=true
metrics_address=127.0.0.1
metrics_port=8080
```

Available metrics include:
- `lean_state_slot`
- `lean_latest_justified_slot`
- `lean_latest_finalized_slot`
- `lean_storage_canonical_state_rows`
- `lean_storage_canonical_block_rows`
- `lean_storage_pending_block_rows`

### Local scrape
```bash
curl -s http://127.0.0.1:8080/metrics
```

### Networking tests (socket required)
```bash
cargo test --test ream_networking_ports -- --ignored
```
Set `LEAN_ETH_REQUIRE_MDNS=1` to make the mDNS discovery smoke test fail hard on discovery timeout.

### PQ negative tests
```bash
cargo test --test pq_negative
cargo test --features pq_crypto --test pq_negative
```

## Validation Rules (Current)
- Signed block checks enforce:
  - attestation proof count equals block attestation count
  - proposer attestation slot equals block slot
  - proposer attestation has exactly one participant matching proposer index
- Aggregated proof checks enforce:
  - proof participants must match attestation aggregation bits
  - out-of-range participant indices are rejected
- State transition checks enforce:
  - post-state root is recomputed and must equal `block.state_root`
  - `latest_block_header.state_root` is set immediately to the verified post-state root

## PQ Roadmap Decision
- Devnet-0 baseline keeps `pq_crypto` optional and non-default.
- Single-signature verification path exists behind `pq_crypto`.
- Aggregate PQ verification remains explicitly non-default roadmap work; consensus/devnet features should not assume it until implemented and benchmarked.
- Target: complete aggregate PQ verification before promoting from alpha interop phase.

## Interop Harness
See `/Users/malik/Desktop/mc2/lean_eth/lean_eth/testing/interop/README.md` for local devnet/interoperability workflow and config template.

## Contributing
PRs welcome. Please run `cargo test` before opening a PR.
Release notes are tracked in `CHANGELOG.md`.

## License
Dual-licensed under MIT or Apache-2.0. See `LICENSE` and `LICENSE-APACHE`.

## Acknowledgements
- Some networking test structure and PQ verification flow were adapted from the Ream client.
