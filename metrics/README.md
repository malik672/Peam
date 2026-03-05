# Peam Metrics Stack

Grafana + Prometheus setup for Peam metrics.

## Targets

- Peam metrics endpoint: `http://127.0.0.1:18080/metrics`
- Prometheus scrape target inside Docker: `host.docker.internal:18080`

## Run

```bash
cd /Users/malik/Desktop/mc2/lean_eth/lean_eth/metrics
docker compose up -d
```

## Access

- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9090`

Default Grafana login is usually `admin/admin` unless changed locally.
