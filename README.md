# Peam

Peam is a Lean consensus client written in Rust.

It is built around a small core, fast SSZ and hashing paths, lean storage, and practical multi-client interoperability.

## Status

- Alpha software
- Suitable for experimentation, devnets, and benchmarking
- Not intended for production mainnet use yet

## Goals

- Small, auditable codebase
- Low-memory operation
- Fast serialization and merkleization paths using peam-ssz
- Straightforward networking and sync behavior
- Clean operational surface for mixed-client devnets

## Workspace Layout

Peam is a small Cargo workspace rather than one large crate:

- `crates/peam-consensus-types`:
  consensus-model types, SSZ-facing containers, slot/time model
- `crates/peam-state`:
  state transition logic plus generic verifier and metrics traits
- `crates/peam-fork-choice`:
  fork-choice store, vote tracking, head selection, pruning logic
- `crates/peam-storage`:
  persistent/in-memory storage, canonical indexes, blob persistence, pruning
- root `peam` crate:
  storage, networking, node/runtime orchestration, HTTP/API surfaces, PQ-specific glue

The root crate still re-exports some older module paths so the top-level API
stays stable while internals keep moving toward clearer workspace boundaries.

## Build

```bash
cargo build
cargo test
```

To run the fixture-backed leanSpec harness only:

```bash
bash scripts/test_lean_spec.sh
```

To run the broader pre-Hive confidence suite:

```bash
bash scripts/test_pre_hive_confidence.sh
```

That now includes:

- the fixture-backed leanSpec harness
- a minimal black-box leanSpec HTTP API smoke test
- deterministic fork-choice and state-transition regression tests

To build the binary only:

```bash
cargo build --release -p peam --bin peam
```

## Contributing

Before opening a PR, please run:

```bash
cargo test
```

If you are changing sync, state transition, or fork choice behavior, it is worth running at least one mixed-client devnet before pushing.

If you are changing SSZ, fork choice, or state-transition behavior, also run the leanSpec harness targets. See [testing/lean_spec.md](/Users/malik/Desktop/mc2/lean_eth/Peam/testing/lean_spec.md) and the pre-Hive confidence bar in [testing/impl.md](/Users/malik/Desktop/mc2/lean_eth/Peam/testing/impl.md).

## License

Dual-licensed under:

- MIT
- Apache-2.0

See:

- `LICENSE`
- `LICENSE-APACHE`

## Acknowledgements

- Some networking test structure and PQ verification flow were adapted from Ream.
