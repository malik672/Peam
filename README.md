# lean_eth

Minimal Rust implementation of Lean Ethereum, guided by leanSpec.

## Quick start

Run tests from this folder:

```sh
cargo test
```

## CLI

Generate a genesis state root from a config file:

```sh
cargo run -- --config ./config.txt
```

Minimal config format (key=value):

```
genesis_time=0
```

Or pass genesis time directly:

```sh
cargo run -- --genesis-time 0
```

## Notes

- Decoders follow the "caller validates" rule. Use `decode_ssz_checked` at boundaries.
- `merkleize_tree_root` is specialized for 5 field roots (BlockHeader).
- `MemoryStore` uses `rapidhash` for in-memory map performance; do not use it for consensus hashing.
- PQ signature verification is available behind `pq_crypto` (leanSig). Use `pq_multisig` for aggregate verification (leanMultisig).

## leanSpec Fixtures

The `lean_spec_fixtures` tests read from `tests/fixtures/ssz/devnet`.
These fixtures are generated via leanSpec and snapshot into this repo.
Current coverage:
- `Config`
- `Checkpoint`
- `BlockHeader`
- `BlockBody` (empty)
- `BlocksByRootRequest` (empty)

Missing fixtures for the newer envelope types (e.g. `Block`, `BlockWithAttestation`,
`SignedBlockWithAttestation`) will be added when leanSpec exports them.
