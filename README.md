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

## Ops quick start

### Prerequisites
- Rust toolchain (`cargo`, `rustc`)
- Git
- Docker (optional, for images)

### Build & test
```bash
cargo build
cargo test
```

### Run a single node
Peam expects a small text config file (key=value). At minimum you need `genesis_time`.

Create a config file (example `node.conf`):
```bash
cat > node.conf <<'EOF'
genesis_time=42
# Optional network settings
# listen_addr=/ip4/0.0.0.0/udp/9000/quic-v1
# bootnodes=/ip4/127.0.0.1/udp/9001/quic-v1/p2p/12D3KooW...
# validator_count=4
# local_validator_index=0
# http_api=true
# metrics=true
EOF
```

Run the node:
```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data
```

Run the node with checkpoint sync:
```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data \
  --checkpoint-sync-url http://localhost:5052
```

Run with direct runtime overrides:
```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data \
  --listen /ip4/0.0.0.0/udp/9001/quic-v1 \
  --bootnode /ip4/127.0.0.1/udp/9000/quic-v1/p2p/<peer-id> \
  --api-port 5052 \
  --is-aggregator
```

To print the genesis root only (no node):
```bash
cargo run --release -- --config node.conf
```

CLI flags are still small, but now include the main leanSpec-style runtime overrides:
`--config`, `--data-dir`, `--run`, `--genesis-time`, `--checkpoint-sync-url`,
`--listen`, `--bootnode`, `--api-port`, and `--is-aggregator`.
Most other operational settings still live in the config file.

### Run a multi-client devnet
```bash
./scripts/run_devnet2_3clients.sh
```

### Ops notes
- Data lives under `--data-dir` (defaults to `data_dir/store` when `storage_dir` is unset).
- Logs are written by the devnet scripts into `.tmp/<run>/logs/`.
- Metrics (if enabled) bind to `metrics_address:metrics_port` in the node config.
- HTTP API endpoints are served when `http_api=true` (defaults to true).
  - `/lean/v0/health`
  - `/lean/v0/states/finalized`
  - `/lean/v0/checkpoints/justified`
  - `/lean/v0/fork_choice`
  - `/metrics` (only when `metrics=true`)
- Clean old devnet runs to reclaim disk:
```bash
rm -rf .tmp/devnet*
```

### Config keys (common)
```text
genesis_time=<u64>                 # required
http_api=true|false                # default true
metrics=true|false                 # default false
metrics_address=127.0.0.1
metrics_port=8080
listen_addr=/ip4/0.0.0.0/udp/9000/quic-v1
bootnodes=/ip4/.../p2p/...
trusted_peers=/ip4/.../p2p/...
validator_count=4
local_validator_index=0
checkpoint_sync_url=http://host:port
```

### Config keys (full)
```text
genesis_time=<u64>
http_api=true|false
metrics=true|false
metrics_address=127.0.0.1
metrics_port=8080
metrics_node_name=peam_0
metrics_client_name=peam
listen_addr=/ip4/0.0.0.0/udp/9000/quic-v1
node_key_path=/path/to/node.key
bootnodes=/ip4/.../p2p/...
trusted_peers=/ip4/.../p2p/...
allowed_topics=/leanconsensus/devnet0/block/ssz_snappy,...
topic_scores=/leanconsensus/devnet0/block/ssz_snappy:2,...
topic_validators=/leanconsensus/devnet0/block/ssz_snappy=block,...
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
is_aggregator=true|false
attestation_committee_count=1
validator_count=4
local_validator_index=0
storage_dir=store
validator_config_path=validator-config.yaml
checkpoint_sync_url=http://host:port
```

### Publish a devnet tag
Push a tag (or dispatch the workflow with tags) to publish new images:
```bash
git tag devnet3
git push origin devnet3
```
Or use workflow dispatch with `tags=devnet3,devnet3-2026-03-19`.

## Docker
Build from the Peam repo root.

```bash
docker build -t peam:local .
```

Published images:
- `ghcr.io/malik672/peam:latest`
- `ghcr.io/malik672/peam:sha-<commit>`
- `ghcr.io/malik672/peam:devnet3`
- `ghcr.io/malik672/peam:devnet3-2026-03-19`
- `ghcr.io/malik672/peam:<tag>` for pushed release/devnet tags

The GitHub Actions workflow at [`.github/workflows/docker_publish.yml`](./.github/workflows/docker_publish.yml)
publishes multi-arch images to GHCR on `master`, on pushed tags, and on manual dispatch.

For a local multi-arch build:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t peam:local .
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
