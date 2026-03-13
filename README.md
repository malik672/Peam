# peam

A minimal, high‑performance Lean Consensus client focused on clean SSZ, fast hashing, and practical networking.

## Performance philosophy
Performance is a feature.

Fast software does not just feel better to use; it changes how developers use it. Short feedback loops make tools more interactive, more trustworthy, and more likely to be used as a first pass instead of a last resort.

That means performance cannot be treated as a final cleanup pass. The biggest gains usually come from architecture, data flow, data structures, and serialization choices made early. Hot-spot tuning matters, but it cannot recover a design that bakes in avoidable overhead.

Peam therefore treats performance as a first-class design constraint:
- optimize the architecture, not just the profiler output
- prefer fast foundations over compensating layers
- pay local complexity where it buys global simplicity
- keep the critical path direct, observable, and cheap

A fast core reduces the need for elaborate caching, excessive bookkeeping, and coordination layers. That keeps the system simpler, easier to reason about, and easier to evolve.

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
