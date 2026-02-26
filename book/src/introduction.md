# lean_eth

`lean_eth` is a minimal, high-performance Lean Consensus client for Ethereum.

**Project status:** Alpha — APIs, storage layout, and behavior may change between releases. Suitable for experimentation and benchmarking, not production mainnet use.

## Goals

| Goal | Description |
|------|-------------|
| Minimal & auditable | Small, readable codebase with no unnecessary abstractions |
| High-performance SSZ | Custom zero-copy SSZ encoder/decoder with fast merkleization |
| PQ-ready | Post-quantum signature verification hooks via `leansig` |
| Practical networking | libp2p gossipsub + req/resp with rate limiting and peer scoring |
| Disk-backed storage | Single-file redb database with atomic writes and crash recovery |

## Quick Start

```bash
cargo build
cargo test
```

Run the node:

```bash
cargo run -- --run --config config.txt --data-dir /tmp/lean_eth_data
```

## Repository Layout

```
src/
  app.rs              — config loading, genesis construction
  main.rs             — CLI entry point
  node.rs             — async node runtime (tokio)
  slot.rs             — slot timing logic
  containers/         — beacon chain data structures (Block, State, …)
  ssz/                — SSZ encoder/decoder and merkleization
  types/              — primitive types (Bytes32, BitList, collections, …)
  storage/            — MemoryStore and FileStore implementations
  networking/         — libp2p gossipsub, req/resp, discovery, peer manager
  fork_choice.rs      — GHOST fork-choice store
  crypto/             — PQ signature verification (leansig)
  unsafe_vec.rs       — performance-critical unsafe write helpers
book/                 — this documentation (mdBook)
benches/              — criterion benchmarks
tests/                — integration tests
```
