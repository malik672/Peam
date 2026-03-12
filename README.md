# peam

A minimal, high‑performance Lean Consensus client focused on clean SSZ, fast hashing, and practical networking.

## Project status
- **Alpha**: APIs, storage layout, and behavior may change between releases.
- The codebase is suitable for experimentation and benchmarking, not production mainnet use.

## Quick start
```bash
cargo build
cargo test
```

## Docker
Build from the monorepo root (`../`) so patched path dependencies are available in build context.

```bash
# from repo root
make docker-build-peam
```

Default image tags:
- `ghcr.io/leanethereum/peam:latest`
- `ghcr.io/leanethereum/peam:latest-devnet3`

For multi-arch push with OCI labels (`org.opencontainers.*`):

```bash
# from repo root
make docker-buildx-push-peam
```

## Devnet status
- Currently devnet 3

## Contributing
PRs welcome. Please run `cargo test` before opening a PR.
Release notes are tracked in `CHANGELOG.md`.

## License
Dual-licensed under MIT or Apache-2.0. See `LICENSE` and `LICENSE-APACHE`.

## Acknowledgements
- Some networking test structure and PQ verification flow were adapted from the Ream client.
