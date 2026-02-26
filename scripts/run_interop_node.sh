#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <config-path> <data-dir>"
  exit 2
fi

CONFIG_PATH="$1"
DATA_DIR="$2"

exec cargo run --release -- --run --config "$CONFIG_PATH" --data-dir "$DATA_DIR"
