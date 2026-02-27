# Interop / Local Devnet Harness

This folder tracks the minimal workflow to run `lean_eth` against a local multi-client devnet.

## Scope
- `lean_eth` node process startup with configurable storage + metrics.
- Connection to external bootnodes/devnet orchestrators (for example `local-pq-devnet`).
- Basic health checks: gossip traffic, req/resp, slot/finality movement.

## 1) Create node config
Use the template at `/Users/malik/Desktop/mc2/lean_eth/lean_eth/testing/interop/lean_eth_node.conf` and set:
- `bootnodes`
- `trusted_peers`
- `genesis_time` (must match the devnet)
- `allowed_topics` (must match devnet topics)

## 2) Run node
```bash
cargo run --release -- --run \
  --config /absolute/path/to/lean_eth_node.conf \
  --data-dir /tmp/lean-eth-devnet-a
```

## 3) Verify
- Logs should show QUIC listen startup and peer activity.
- If metrics are enabled:
  - `curl -s http://127.0.0.1:8080/metrics | rg lean_state_slot`
- `lean_latest_finalized_slot` should move on an active devnet.

## 4) Multi-node local checks
Run a second instance with:
- different `--data-dir`
- different `metrics_port`
- different QUIC listen port (once listen address is configurable via config path in networking).

## Latest verification run
- Date: February 26, 2026
- Command:
```bash
cargo test --test ream_networking_ports -- --ignored
```
- Result: `ok` (3/3)
  - `ream_two_nodes_connection_smoke`
  - `ream_status_request_response_smoke`
  - `ream_mdns_discovery_smoke`

## Notes
- Pending slot index is memory-only; restart clears pending slots by design.
- Canonical slot indexes + blobs remain in `canonical.redb`.
