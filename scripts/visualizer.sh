#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
METRICS_DIR="$ROOT_DIR/metrics"
DASHBOARD_URL="http://127.0.0.1:3000/d/peam-devnet-metrics/peam-devnet-metrics?orgId=1"
PROM_URL="http://127.0.0.1:9090"

cmd="${1:-up}"

case "$cmd" in
  up)
    (cd "$METRICS_DIR" && docker compose up -d)
    echo "Grafana:   $DASHBOARD_URL"
    echo "Prometheus:$PROM_URL"
    if command -v open >/dev/null 2>&1; then
      open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    fi
    ;;
  down)
    (cd "$METRICS_DIR" && docker compose down)
    ;;
  restart)
    (cd "$METRICS_DIR" && docker compose down && docker compose up -d)
    echo "Grafana:   $DASHBOARD_URL"
    echo "Prometheus:$PROM_URL"
    ;;
  logs)
    (cd "$METRICS_DIR" && docker compose logs -f --tail=200)
    ;;
  ps|status)
    (cd "$METRICS_DIR" && docker compose ps)
    ;;
  *)
    echo "Usage: $0 [up|down|restart|logs|ps]"
    exit 2
    ;;
esac
