#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMP_ROOT:-$ROOT_DIR/.tmp}"
RUN_ID="${RUN_ID:-devnet2_3clients_$(date +%s)}"
RUN_DIR="$TMP_ROOT/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"

BUILD="${BUILD:-1}"
GENESIS_DELAY_SECS="${GENESIS_DELAY_SECS:-20}"
TOPIC_DOMAIN="${TOPIC_DOMAIN:-devnet2}"

PEAM_REPO="${PEAM_REPO:-$ROOT_DIR}"
PEAM_BIN="${PEAM_BIN:-$PEAM_REPO/target/release/peam}"
REGISTRY_GEN_BIN="${REGISTRY_GEN_BIN:-$PEAM_REPO/target/release/devnet2_registry_gen}"

PEAM_METRICS_PORT="${PEAM_METRICS_PORT:-18080}"
PEER1_METRICS_PORT="${PEER1_METRICS_PORT:-18081}"
PEER2_METRICS_PORT="${PEER2_METRICS_PORT:-18082}"

VALIDATOR_COUNT="${VALIDATOR_COUNT:-1}"
NODE_MAP="${NODE_MAP:-peam_0:0}"
PEAM_VALIDATOR_INDEX="${PEAM_VALIDATOR_INDEX:-0}"

BOOTNODES="${BOOTNODES:-}"
TRUSTED_PEERS="${TRUSTED_PEERS:-}"

# Optional external peers (generic, no client-specific names)
PEER1_CMD="${PEER1_CMD:-}"
PEER2_CMD="${PEER2_CMD:-}"

mkdir -p "$LOG_DIR" "$RUN_DIR/peam_data"
mkdir -p "$LOG_DIR" "$RUN_DIR/peam_data"

echo "run_dir=$RUN_DIR"

if [[ "$BUILD" == "1" ]]; then
  echo "Building peam + registry generator..."
  cargo build --manifest-path "$PEAM_REPO/Cargo.toml" --release --bin peam --bin devnet2_registry_gen
fi

for bin in "$PEAM_BIN" "$REGISTRY_GEN_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "Missing binary: $bin"
    echo "Either set BUILD=1 or provide a valid path."
    exit 1
  fi
done

GENESIS_TIME="$(( $(date +%s) + GENESIS_DELAY_SECS ))"
echo "genesis_time=$GENESIS_TIME"

"$REGISTRY_GEN_BIN" \
  --out "$RUN_DIR" \
  --genesis-time "$GENESIS_TIME" \
  --validators "$VALIDATOR_COUNT" \
  --node-map "$NODE_MAP" \
  >"$LOG_DIR/registry_gen.log" 2>&1

PEAM_CONFIG="$RUN_DIR/peam_node.conf"
cat >"$PEAM_CONFIG" <<EOF
genesis_time=$GENESIS_TIME
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
bootnodes=$BOOTNODES
trusted_peers=$TRUSTED_PEERS
allowed_topics=leanconsensus/$TOPIC_DOMAIN/block/ssz_snappy,leanconsensus/$TOPIC_DOMAIN/attestation/ssz_snappy
topic_scores=leanconsensus/$TOPIC_DOMAIN/block/ssz_snappy:2,leanconsensus/$TOPIC_DOMAIN/attestation/ssz_snappy:1
topic_validators=leanconsensus/$TOPIC_DOMAIN/block/ssz_snappy=block,leanconsensus/$TOPIC_DOMAIN/attestation/ssz_snappy=attestation
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
validator_count=$VALIDATOR_COUNT
local_validator_index=$PEAM_VALIDATOR_INDEX
storage_dir=store
metrics=true
metrics_address=127.0.0.1
metrics_port=$PEAM_METRICS_PORT
EOF

echo "Starting peam..."
"$PEAM_BIN" --run --config "$PEAM_CONFIG" --data-dir "$RUN_DIR/peam_data" >"$LOG_DIR/peam.log" 2>&1 &
PEAM_PID=$!
echo "$PEAM_PID" >"$RUN_DIR/peam.pid"

if [[ -n "$PEER1_CMD" ]]; then
  echo "Starting peer1..."
  (
    export DEVNET_RUN_DIR="$RUN_DIR"
    export DEVNET_GENESIS_TIME="$GENESIS_TIME"
    export DEVNET_VALIDATOR_COUNT="$VALIDATOR_COUNT"
    export DEVNET_METRICS_PORT="$PEER1_METRICS_PORT"
    export DEVNET_TOPIC_DOMAIN="$TOPIC_DOMAIN"
    eval "$PEER1_CMD"
  ) >"$LOG_DIR/peer1.log" 2>&1 &
  PEER1_PID=$!
  echo "$PEER1_PID" >"$RUN_DIR/peer1.pid"
fi

if [[ -n "$PEER2_CMD" ]]; then
  echo "Starting peer2..."
  (
    export DEVNET_RUN_DIR="$RUN_DIR"
    export DEVNET_GENESIS_TIME="$GENESIS_TIME"
    export DEVNET_VALIDATOR_COUNT="$VALIDATOR_COUNT"
    export DEVNET_METRICS_PORT="$PEER2_METRICS_PORT"
    export DEVNET_TOPIC_DOMAIN="$TOPIC_DOMAIN"
    eval "$PEER2_CMD"
  ) >"$LOG_DIR/peer2.log" 2>&1 &
  PEER2_PID=$!
  echo "$PEER2_PID" >"$RUN_DIR/peer2.pid"
fi

{
  echo "PEAM_PID=$PEAM_PID"
  if [[ -n "${PEER1_PID:-}" ]]; then
    echo "PEER1_PID=$PEER1_PID"
  fi
  if [[ -n "${PEER2_PID:-}" ]]; then
    echo "PEER2_PID=$PEER2_PID"
  fi
  echo "RUN_DIR=$RUN_DIR"
} >"$RUN_DIR/pids.env"

cat <<EOF

Devnet started.
run_dir: $RUN_DIR

Logs:
  tail -f $LOG_DIR/peam.log
  $( [[ -n "$PEER1_CMD" ]] && echo "tail -f $LOG_DIR/peer1.log" )
  $( [[ -n "$PEER2_CMD" ]] && echo "tail -f $LOG_DIR/peer2.log" )

Quick metrics check:
  curl -s http://127.0.0.1:$PEAM_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'
  $( [[ -n "$PEER1_CMD" ]] && echo "curl -s http://127.0.0.1:$PEER1_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'" )
  $( [[ -n "$PEER2_CMD" ]] && echo "curl -s http://127.0.0.1:$PEER2_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'" )

To stop:
  pkill -f '$PEAM_BIN --run'
  $( [[ -n "$PEER1_CMD" ]] && echo "pkill -f peer1 || true" )
  $( [[ -n "$PEER2_CMD" ]] && echo "pkill -f peer2 || true" )
EOF
