# Peam

Peam is a minimal, performance-first Lean consensus client written in Rust.

The project is built around a small core, fast SSZ and hashing paths, lean storage, and practical multi-client interoperability. The goal is not to be feature-heavy; the goal is to keep the critical path cheap, observable, and easy to reason about.

## Status

- Alpha software
- Suitable for experimentation, devnets, and benchmarking
- Not intended for production mainnet use yet

## What Peam Optimizes For

- Small, auditable codebase
- Low-memory operation
- Fast serialization and merkleization paths using peam-ssz
- Straightforward networking and sync behavior
- Clean operational surface for mixed-client devnets

## Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Git
- Docker (optional)

## Build

```bash
cargo build
cargo test
```

To build the binary only:

```bash
cargo build --release -p peam --bin peam
```

## Quick Start

Peam runs from a small `key=value` config file.

Example `node.conf`:

```text
genesis_time=42
http_api=true
http_address=127.0.0.1
http_port=5052
metrics=true
metrics_address=127.0.0.1
metrics_port=8080
listen_addr=/ip4/0.0.0.0/udp/9000/quic-v1
```

Run the node:

```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data
```

Print the genesis root only:

```bash
cargo run --release -- --config node.conf
```

## Runtime Overrides

Peam supports direct CLI overrides for the main devnet and quickstart paths.

Example:

```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data \
  --listen /ip4/0.0.0.0/udp/9001/quic-v1 \
  --bootnode /ip4/127.0.0.1/udp/9000/quic-v1/p2p/<peer-id> \
  --metrics-port 8081 \
  --http-port 5053 \
  --node-id peam_0 \
  --validator-keys /path/to/hash-sig-keys \
  --is-aggregator
```

Checkpoint sync:

```bash
cargo run --release -- --run --config node.conf --data-dir /tmp/peam_data \
  --checkpoint-sync-url http://localhost:5052
```

leanSpec-style aliases supported by the CLI:

- `--genesis`
- `--custom_genesis`
- `--network`
- `--bootnodes`
- `--validators`
- `--validator-registry-path`
- `--node-key`
- `--metrics-port`
- `--api-port`
- `--http-port`
- `--aggregator`

For the full CLI surface:

```bash
cargo run --release -- -- --help
```

## Config

Most operational settings can be supplied in the config file.

Common keys:

```text
genesis_time=<u64>
http_api=true|false
http_address=127.0.0.1
http_port=5052
metrics=true|false
metrics_address=127.0.0.1
metrics_port=8080
listen_addr=/ip4/0.0.0.0/udp/9000/quic-v1
node_key_path=/path/to/node.key
bootnodes=/ip4/.../p2p/...
bootnodes_file=/path/to/nodes.yaml
trusted_peers=/ip4/.../p2p/...
validator_count=4
local_validator_index=0
attestation_committee_count=1
is_aggregator=true|false
validator_config_path=/path/to/validator-config.yaml
checkpoint_sync_url=http://host:port
storage_dir=store
```

A few notes:

- `bootnodes_file` accepts a `nodes.yaml` / ENR file and is the cleanest path for quickstart-style deployments.
- If `http_port` is omitted, it falls back to `metrics_port`.
- If `http_address` is omitted, it falls back to `metrics_address`.
- Setting `--metrics-port 0` disables metrics.
- Setting `--api-port 0` disables the HTTP API listener.

## HTTP API And Metrics

Peam exposes:

- `GET /v0/health`
- `GET /lean/v0/health`
- `GET /v0/states/finalized`
- `GET /lean/v0/states/finalized`
- `GET /v0/checkpoints/justified`
- `GET /lean/v0/checkpoints/justified`
- `GET /v0/fork_choice`
- `GET /lean/v0/fork_choice`
- `GET /metrics`

By default:

- HTTP API is enabled
- Metrics are disabled unless `metrics=true`

Example:

```bash
curl http://127.0.0.1:5052/v0/health
curl http://127.0.0.1:8080/metrics | head
```

## Docker

Build locally:

```bash
docker build -t peam:local .
```

Published images:

- `ghcr.io/malik672/peam:latest`
- `ghcr.io/malik672/peam:sha-<commit>`
- `ghcr.io/malik672/peam:<tag>`

Run with Docker:

```bash
docker run --rm \
  -v "$PWD/node.conf:/config/node.conf:ro" \
  -v /tmp/peam_data:/data \
  ghcr.io/malik672/peam:latest \
  --run --config /config/node.conf --data-dir /data
```

The Docker publish workflow is:

- `.github/workflows/docker_publish.yml`

## Devnet Usage

Run the mixed-client devnet script from the Peam repo:

```bash
./scripts/run_devnet2_3clients.sh
```

Logs are written under:

```text
.tmp/<run>/logs/
```

Clean old runs:

```bash
rm -rf .tmp/devnet*
```

## Development Notes

- Peam uses a disk-backed store for long-lived chain data.
- Fork choice is in memory and optimized for the live working set.
- Metrics and logging are intended to be useful in mixed-client debugging, not only local happy-path runs.

## Contributing

PRs are welcome.

Before opening one, please run:

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
