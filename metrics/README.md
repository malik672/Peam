# Peam Metrics Stack

Grafana + Prometheus setup for local lean devnet clients.

## Scrape Targets

- Peam: `http://127.0.0.1:18080/metrics`
- Ethlambda: `http://127.0.0.1:18081/metrics`
- Zeam: `http://127.0.0.1:18082/metrics`
- Ream: `http://127.0.0.1:18083/metrics`
## Run Visualizer

From the repo root:

```bash
./scripts/visualizer.sh up
```

Other commands:

```bash
./scripts/visualizer.sh ps
./scripts/visualizer.sh logs
./scripts/visualizer.sh down
```

## Access

- Grafana dashboard: `http://127.0.0.1:3000/d/peam-devnet-metrics/peam-devnet-metrics?orgId=1`
- Prometheus: `http://127.0.0.1:9090`

Default Grafana login is usually `admin/admin` unless changed locally.

## Run Local Devnet

From the repo root:

```bash
./scripts/run_devnet2_3clients.sh
```

Optional external peers:

```bash
PEER1_CMD='/absolute/path/to/peer1 ...' \
PEER2_CMD='/absolute/path/to/peer2 ...' \
PEER3_CMD='/absolute/path/to/zeam ...' \
./scripts/run_devnet2_3clients.sh
```
