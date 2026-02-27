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

## Devnet-0 defaults
- Slot duration: exact `4` second boundaries (`SLOT_DURATION_SECS`, strict slot ticker)
- Transport: QUIC (`/quic-v1`)
- Gossip protocol: gossipsub pinned to `/meshsub/1.0.0` with strict validation mode

## Devnet-0 status
- **Complete** as of commit `9601b03`.
- Scope covered:
  - Slot duration: `4` seconds
  - Networking transport: QUIC
  - Gossip: gossipsub v1.0
  - Consensus mechanism: modified 3SF-mini
  - Infrastructure: local machines only

## Contributing
PRs welcome. Please run `cargo test` before opening a PR.
Release notes are tracked in `CHANGELOG.md`.

## License
Dual-licensed under MIT or Apache-2.0. See `LICENSE` and `LICENSE-APACHE`.

## Acknowledgements
- Some networking test structure and PQ verification flow were adapted from the Ream client.
