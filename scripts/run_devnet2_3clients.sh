#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMP_ROOT:-$ROOT_DIR/.tmp}"
RUN_ID="${RUN_ID:-devnet2_3clients_$(date +%s)}"
RUN_DIR="$TMP_ROOT/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"

BUILD="${BUILD:-1}"
GENESIS_DELAY_SECS="${GENESIS_DELAY_SECS:-20}"

PEAM_REPO="${PEAM_REPO:-$ROOT_DIR}"
PEAM_BIN="${PEAM_BIN:-$PEAM_REPO/target/release/peam}"
REGISTRY_GEN_BIN="${REGISTRY_GEN_BIN:-$PEAM_REPO/target/release/devnet2_registry_gen}"

PEAM_METRICS_PORT="${PEAM_METRICS_PORT:-18080}"
PEER1_METRICS_PORT="${PEER1_METRICS_PORT:-18081}"
PEER2_METRICS_PORT="${PEER2_METRICS_PORT:-18082}"
PEER3_METRICS_PORT="${PEER3_METRICS_PORT:-18083}"
ALLOW_UNVERIFIED_AGGREGATE_PROOFS="${ALLOW_UNVERIFIED_AGGREGATE_PROOFS:-1}"

VALIDATOR_COUNT="${VALIDATOR_COUNT:-3}"
NODE_MAP="${NODE_MAP:-peam_0:0,peer1_0:1,peer2_0:2}"
PEAM_VALIDATOR_INDEX="${PEAM_VALIDATOR_INDEX:-0}"

BOOTNODES="${BOOTNODES:-}"
TRUSTED_PEERS="${TRUSTED_PEERS:-}"

# Optional external peers (generic, no client-specific names)
PEER1_CMD="${PEER1_CMD:-}"
PEER2_CMD="${PEER2_CMD:-}"
PEER3_CMD="${PEER3_CMD:-}"

# Topic domain:
# - devnet2 by default
# - auto-fallback to devnet0 when EthLambda is part of the run, unless user overrides.
TOPIC_DOMAIN="${TOPIC_DOMAIN:-}"
if [[ -z "$TOPIC_DOMAIN" ]]; then
  if [[ "$PEER1_CMD $PEER2_CMD $PEER3_CMD" == *ethlambda* ]]; then
    TOPIC_DOMAIN="devnet0"
  else
    TOPIC_DOMAIN="devnet2"
  fi
fi

BLOCK_TOPIC="/leanconsensus/$TOPIC_DOMAIN/block/ssz_snappy"
ATTESTATION_SUBNET_TOPIC="/leanconsensus/$TOPIC_DOMAIN/attestation_0/ssz_snappy"
ATTESTATION_TOPIC="/leanconsensus/$TOPIC_DOMAIN/attestation/ssz_snappy"
AGGREGATION_TOPIC="/leanconsensus/$TOPIC_DOMAIN/aggregation/ssz_snappy"

mkdir -p "$LOG_DIR" "$RUN_DIR/peam_data"

echo "run_dir=$RUN_DIR"

validate_peer_cmd() {
  local name="$1"
  local cmd="$2"

  if [[ -z "${cmd//[[:space:]]/}" ]]; then
    echo "$name is empty; skipping launch."
    return 1
  fi

  # Common copy/paste placeholder mistake from docs/chat snippets: <placeholder>.
  # Keep shell redirection operators (>, >>, <) valid.
  local placeholder_re='<[^>]+>'
  if [[ "$cmd" =~ $placeholder_re ]]; then
    echo "Invalid $name: contains placeholder tokens like <...>."
    echo "Replace placeholders with a real command."
    echo "$name=$cmd"
    exit 2
  fi

  if ! bash -n -c "$cmd" >/dev/null 2>&1; then
    echo "Invalid $name shell syntax:"
    echo "$name=$cmd"
    exit 2
  fi

  return 0
}

START_PEER1=0
START_PEER2=0
START_PEER3=0
if validate_peer_cmd "PEER1_CMD" "$PEER1_CMD"; then
  START_PEER1=1
fi
if validate_peer_cmd "PEER2_CMD" "$PEER2_CMD"; then
  START_PEER2=1
fi
if validate_peer_cmd "PEER3_CMD" "$PEER3_CMD"; then
  START_PEER3=1
fi

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

write_node_key_from_validator_config() {
  local node_name="$1"
  local out_file="$2"
  local validator_cfg="$RUN_DIR/validator-config.yaml"

  [[ -f "$validator_cfg" ]] || return 0
  [[ -f "$out_file" ]] && return 0

  local key_hex
  key_hex="$(awk -v node="$node_name" '
    $1=="-" && $2=="name:" {
      name=$3
      gsub(/"/, "", name)
      next
    }
    $1=="privkey:" && name==node {
      key=$2
      gsub(/"/, "", key)
      print key
      exit
    }
  ' "$validator_cfg")"

  if [[ -n "$key_hex" ]]; then
    printf '%s\n' "$key_hex" > "$out_file"
  fi
}

# Interop helpers: Ream/EthLambda commonly read secp256k1 keys from files.
# Generator outputs validator-config.yaml; derive key files when missing.
write_node_key_from_validator_config "peer1_0" "$RUN_DIR/peer1_node.key"
write_node_key_from_validator_config "peer2_0" "$RUN_DIR/peer2_node.key"
write_node_key_from_validator_config "peer3_0" "$RUN_DIR/peer3_node.key"

# EthLambda expects nodes.yaml (list of ENR strings). For local interop runs,
# an empty list is valid and allows inbound-only peering via other clients.
if [[ ! -f "$RUN_DIR/nodes.yaml" ]]; then
  printf '[]\n' > "$RUN_DIR/nodes.yaml"
fi

PEAM_CONFIG="$RUN_DIR/peam_node.conf"
cat >"$PEAM_CONFIG" <<EOF
genesis_time=$GENESIS_TIME
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
bootnodes=$BOOTNODES
trusted_peers=$TRUSTED_PEERS
allowed_topics=$BLOCK_TOPIC,$ATTESTATION_SUBNET_TOPIC,$ATTESTATION_TOPIC,$AGGREGATION_TOPIC
topic_scores=$BLOCK_TOPIC:2,$ATTESTATION_SUBNET_TOPIC:1,$ATTESTATION_TOPIC:1,$AGGREGATION_TOPIC:1
topic_validators=$BLOCK_TOPIC=block,$ATTESTATION_SUBNET_TOPIC=attestation,$ATTESTATION_TOPIC=attestation,$AGGREGATION_TOPIC=aggregation
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
allow_unverified_aggregate_proofs=$ALLOW_UNVERIFIED_AGGREGATE_PROOFS
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

if [[ "$START_PEER1" == "1" ]]; then
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

if [[ "$START_PEER2" == "1" ]]; then
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

if [[ "$START_PEER3" == "1" ]]; then
  echo "Starting peer3..."
  (
    export DEVNET_RUN_DIR="$RUN_DIR"
    export DEVNET_GENESIS_TIME="$GENESIS_TIME"
    export DEVNET_VALIDATOR_COUNT="$VALIDATOR_COUNT"
    export DEVNET_METRICS_PORT="$PEER3_METRICS_PORT"
    export DEVNET_TOPIC_DOMAIN="$TOPIC_DOMAIN"
    eval "$PEER3_CMD"
  ) >"$LOG_DIR/peer3.log" 2>&1 &
  PEER3_PID=$!
  echo "$PEER3_PID" >"$RUN_DIR/peer3.pid"
fi

{
  echo "PEAM_PID=$PEAM_PID"
  if [[ -n "${PEER1_PID:-}" ]]; then
    echo "PEER1_PID=$PEER1_PID"
  fi
  if [[ -n "${PEER2_PID:-}" ]]; then
    echo "PEER2_PID=$PEER2_PID"
  fi
  if [[ -n "${PEER3_PID:-}" ]]; then
    echo "PEER3_PID=$PEER3_PID"
  fi
  echo "RUN_DIR=$RUN_DIR"
} >"$RUN_DIR/pids.env"

cat <<EOF

Devnet started.
run_dir: $RUN_DIR

Logs:
  tail -f $LOG_DIR/peam.log
  $( [[ "$START_PEER1" == "1" ]] && echo "tail -f $LOG_DIR/peer1.log" )
  $( [[ "$START_PEER2" == "1" ]] && echo "tail -f $LOG_DIR/peer2.log" )
  $( [[ "$START_PEER3" == "1" ]] && echo "tail -f $LOG_DIR/peer3.log" )

Quick metrics check:
  curl -s http://127.0.0.1:$PEAM_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'
  $( [[ "$START_PEER1" == "1" ]] && echo "curl -s http://127.0.0.1:$PEER1_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'" )
  $( [[ "$START_PEER2" == "1" ]] && echo "curl -s http://127.0.0.1:$PEER2_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'" )
  $( [[ "$START_PEER3" == "1" ]] && echo "curl -s http://127.0.0.1:$PEER3_METRICS_PORT/metrics | rg 'lean_current_slot|lean_head_slot|lean_justified_slot|lean_finalized_slot'" )

Devnet visualizer (single frontend for all clients):
  python3 "$ROOT_DIR/scripts/devnet_visualizer.py" --port 8090
  open http://127.0.0.1:8090

To stop:
  pkill -f '$PEAM_BIN --run'
  $( [[ "$START_PEER1" == "1" ]] && echo "pkill -f peer1 || true" )
  $( [[ "$START_PEER2" == "1" ]] && echo "pkill -f peer2 || true" )
  $( [[ "$START_PEER3" == "1" ]] && echo "pkill -f peer3 || true" )
EOF
