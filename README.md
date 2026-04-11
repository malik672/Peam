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

## Build

```bash
cargo build
cargo test
```

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

## License

Dual-licensed under:

- MIT
- Apache-2.0

See:

- `LICENSE`
- `LICENSE-APACHE`

## Acknowledgements

- Some networking test structure and PQ verification flow were adapted from Ream.
