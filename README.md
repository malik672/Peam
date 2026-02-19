# lean_eth

A minimal, high‑performance Lean Consensus client focused on clean SSZ, fast hashing, and practical networking.

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
```

## Tests
```bash
cargo test
```

## Contributing
PRs welcome. Please run `cargo test` before opening a PR.

## License
Dual-licensed under MIT or Apache-2.0. See `LICENSE` and `LICENSE-APACHE`.

## Acknowledgements
- Some networking test structure and PQ verification flow were adapted from the Ream client.

## Repo description (short)
Minimal, fast Lean Consensus client with SSZ, PQ‑ready crypto hooks, and libp2p networking.
