#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMP_ROOT:-$ROOT_DIR/.tmp}"
RUN_ID="${RUN_ID:-devnet3_3clients_$(date +%s)}"
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

VALIDATOR_COUNT="${VALIDATOR_COUNT:-3}"
NODE_MAP="${NODE_MAP:-peam_0:0,peer1_0:1,peer2_0:2}"
PEAM_VALIDATOR_INDEX="${PEAM_VALIDATOR_INDEX:-0}"
ATTESTATION_COMMITTEE_COUNT="${ATTESTATION_COMMITTEE_COUNT:-1}"
PEAM_IS_AGGREGATOR="${PEAM_IS_AGGREGATOR:-1}"
# Optional: comma-separated node names to force as aggregators (e.g. "peer3_0").
AGGREGATOR_NODE_NAMES="${AGGREGATOR_NODE_NAMES:-}"

# Optional ENR/node settings for bootnodes.yaml generation.
NODE_IP="${NODE_IP:-127.0.0.1}"
PEAM_QUIC_PORT="${PEAM_QUIC_PORT:-9000}"
PEER1_QUIC_PORT="${PEER1_QUIC_PORT:-9001}"
PEER2_QUIC_PORT="${PEER2_QUIC_PORT:-9002}"
PEER3_QUIC_PORT="${PEER3_QUIC_PORT:-9003}"
GENERATE_NODES_YAML="${GENERATE_NODES_YAML:-0}"
ZEAM_TOOLS_BIN="${ZEAM_TOOLS_BIN:-$ROOT_DIR/zeam/zig-out/bin/zeam-tools}"

BOOTNODES="${BOOTNODES:-}"
TRUSTED_PEERS="${TRUSTED_PEERS:-}"

# Optional external peers (generic, no client-specific names)
PEER1_CMD="${PEER1_CMD:-}"
PEER2_CMD="${PEER2_CMD:-}"
PEER3_CMD="${PEER3_CMD:-}"

# Topic domain defaults to the canonical devnet3 namespace.
TOPIC_DOMAIN="${TOPIC_DOMAIN:-devnet0}"

BLOCK_TOPIC="/leanconsensus/$TOPIC_DOMAIN/block/ssz_snappy"
AGGREGATION_TOPIC="/leanconsensus/$TOPIC_DOMAIN/aggregation/ssz_snappy"
if ! [[ "$ATTESTATION_COMMITTEE_COUNT" =~ ^[0-9]+$ ]] || [[ "$ATTESTATION_COMMITTEE_COUNT" -le 0 ]]; then
  echo "Invalid ATTESTATION_COMMITTEE_COUNT=$ATTESTATION_COMMITTEE_COUNT (must be integer > 0)"
  exit 2
fi
PEAM_ATTESTATION_SUBNET_ID="$(( PEAM_VALIDATOR_INDEX % ATTESTATION_COMMITTEE_COUNT ))"
ATTESTATION_SUBNET_TOPIC="/leanconsensus/$TOPIC_DOMAIN/attestation_${PEAM_ATTESTATION_SUBNET_ID}/ssz_snappy"

normalize_bool_literal() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) printf 'true\n' ;;
    0|false|FALSE|no|NO|off|OFF) printf 'false\n' ;;
    *)
      echo "Invalid boolean value: $1"
      exit 2
      ;;
  esac
}

resolve_local_node_name_from_map() {
  local validator_index="$1"
  local node_map="$2"
  local entry name idx

  IFS=',' read -r -a entries <<< "$node_map"
  for entry in "${entries[@]}"; do
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ -z "$entry" ]] && continue
    name="${entry%%:*}"
    idx="${entry#*:}"
    if [[ "$idx" == "$validator_index" ]]; then
      printf '%s\n' "$name"
      return 0
    fi
  done
  return 1
}

set_validator_config_is_aggregator() {
  local validator_cfg="$1"
  local node_name="$2"
  local bool_literal="$3"

  [[ -f "$validator_cfg" ]] || return 0

  local tmp
  tmp="$(mktemp)"
  awk -v node="$node_name" -v agg="$bool_literal" '
    /^  - name: / {
      current = $3
      gsub(/"/, "", current)
      print
      next
    }
    current == node && /^    is_aggregator:/ {
      print "    is_aggregator: " agg
      next
    }
    current == node && /^      is_aggregator:/ {
      print "      is_aggregator: " agg
      next
    }
    { print }
  ' "$validator_cfg" > "$tmp"
  mv "$tmp" "$validator_cfg"
}

set_validator_config_enr_fields() {
  local validator_cfg="$1"
  local node_name="$2"
  local ip_addr="$3"
  local quic_port="$4"

  [[ -f "$validator_cfg" ]] || return 0
  [[ -n "$node_name" ]] || return 0

  local tmp
  tmp="$(mktemp)"
  awk -v node="$node_name" -v ip="$ip_addr" -v quic="$quic_port" '
    function print_missing() {
      if (!seen_ip) {
        print "      ip: \"" ip "\""
      }
      if (!seen_quic) {
        print "      quic: " quic
      }
    }
    /^  - name: / {
      if (in_enr) {
        print_missing()
        in_enr = 0
      }
      current = $3
      gsub(/"/, "", current)
      seen_ip = 0
      seen_quic = 0
      print
      next
    }
    current == node && /^    enrFields:/ {
      in_enr = 1
      print
      next
    }
    current == node && in_enr && /^      ip:/ {
      print "      ip: \"" ip "\""
      seen_ip = 1
      next
    }
    current == node && in_enr && /^      quic:/ {
      print "      quic: " quic
      seen_quic = 1
      next
    }
    current == node && in_enr && /^    [^ ]/ {
      print_missing()
      in_enr = 0
      print
      next
    }
    { print }
    END {
      if (in_enr) {
        print_missing()
      }
    }
  ' "$validator_cfg" > "$tmp"
  mv "$tmp" "$validator_cfg"
}

generate_nodes_yaml() {
  local out_file="$1"
  shift
  local -a node_entries=("$@")

  if [[ ! -x "$ZEAM_TOOLS_BIN" ]]; then
    echo "zeam-tools not found at $ZEAM_TOOLS_BIN"
    echo "Build it with: (cd \"$ROOT_DIR/zeam\" && zig build tools)"
    exit 2
  fi

  local tmp
  tmp="$(mktemp)"
  : > "$tmp"
  for entry in "${node_entries[@]}"; do
    local node_name="${entry%%:*}"
    local quic_port="${entry#*:}"
    [[ -z "$node_name" ]] && continue
    [[ -z "$quic_port" ]] && continue
    local key_file
    key_file="$(node_key_path_for_name "$node_name")"
    write_node_key_from_validator_config "$node_name" "$key_file"
    if [[ ! -f "$key_file" ]]; then
      echo "Missing node key for $node_name; skipping ENR generation."
      continue
    fi
    local key_hex
    key_hex="$(tr -d ' \n\r' < "$key_file")"
    if [[ -z "$key_hex" ]]; then
      echo "Empty node key for $node_name; skipping ENR generation."
      continue
    fi
    local enr
    enr="$("$ZEAM_TOOLS_BIN" enrgen -s "$key_hex" -i "$NODE_IP" -q "$quic_port")"
    printf -- "- %s\n" "$enr" >> "$tmp"
  done
  mv "$tmp" "$out_file"
}

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
  --attestation-subnets "$ATTESTATION_COMMITTEE_COUNT" \
  --node-map "$NODE_MAP" \
  >"$LOG_DIR/registry_gen.log" 2>&1

PEAM_IS_AGGREGATOR_BOOL="$(normalize_bool_literal "$PEAM_IS_AGGREGATOR")"
PEAM_NODE_NAME="$(resolve_local_node_name_from_map "$PEAM_VALIDATOR_INDEX" "$NODE_MAP" || true)"
PEER1_NODE_NAME="$(resolve_local_node_name_from_map 1 "$NODE_MAP" || true)"
PEER2_NODE_NAME="$(resolve_local_node_name_from_map 2 "$NODE_MAP" || true)"
PEER3_NODE_NAME="$(resolve_local_node_name_from_map 3 "$NODE_MAP" || true)"
if [[ -n "$PEAM_NODE_NAME" ]]; then
  set_validator_config_is_aggregator \
    "$RUN_DIR/validator-config.yaml" \
    "$PEAM_NODE_NAME" \
    "$PEAM_IS_AGGREGATOR_BOOL"
fi

if [[ -n "${AGGREGATOR_NODE_NAMES//[[:space:]]/}" ]]; then
  IFS=',' read -r -a agg_nodes <<< "$AGGREGATOR_NODE_NAMES"
  for agg_node in "${agg_nodes[@]}"; do
    agg_node="${agg_node#"${agg_node%%[![:space:]]*}"}"
    agg_node="${agg_node%"${agg_node##*[![:space:]]}"}"
    [[ -z "$agg_node" ]] && continue
    set_validator_config_is_aggregator \
      "$RUN_DIR/validator-config.yaml" \
      "$agg_node" \
      "true"
  done
fi

if [[ -n "$PEAM_NODE_NAME" ]]; then
  set_validator_config_enr_fields \
    "$RUN_DIR/validator-config.yaml" \
    "$PEAM_NODE_NAME" \
    "$NODE_IP" \
    "$PEAM_QUIC_PORT"
fi
if [[ -n "$PEER1_NODE_NAME" ]]; then
  set_validator_config_enr_fields \
    "$RUN_DIR/validator-config.yaml" \
    "$PEER1_NODE_NAME" \
    "$NODE_IP" \
    "$PEER1_QUIC_PORT"
fi
if [[ -n "$PEER2_NODE_NAME" ]]; then
  set_validator_config_enr_fields \
    "$RUN_DIR/validator-config.yaml" \
    "$PEER2_NODE_NAME" \
    "$NODE_IP" \
    "$PEER2_QUIC_PORT"
fi
if [[ -n "$PEER3_NODE_NAME" ]]; then
  set_validator_config_enr_fields \
    "$RUN_DIR/validator-config.yaml" \
    "$PEER3_NODE_NAME" \
    "$NODE_IP" \
    "$PEER3_QUIC_PORT"
fi

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

node_key_path_for_name() {
  local node_name="$1"
  if [[ -z "$node_name" ]]; then
    printf '\n'
    return 0
  fi
  case "$node_name" in
    "$PEAM_NODE_NAME")
      printf '%s\n' "$RUN_DIR/peam_node.key"
      ;;
    "$PEER1_NODE_NAME")
      printf '%s\n' "$RUN_DIR/peer1_node.key"
      ;;
    "$PEER2_NODE_NAME")
      printf '%s\n' "$RUN_DIR/peer2_node.key"
      ;;
    "$PEER3_NODE_NAME")
      printf '%s\n' "$RUN_DIR/peer3_node.key"
      ;;
    *)
      printf '%s\n' "$RUN_DIR/${node_name}_node.key"
      ;;
  esac
}

# Generator outputs validator-config.yaml; derive key files when missing.
if [[ -n "$PEAM_NODE_NAME" ]]; then
  write_node_key_from_validator_config "$PEAM_NODE_NAME" "$(node_key_path_for_name "$PEAM_NODE_NAME")"
fi
# Generator outputs validator-config.yaml; derive key files when missing.
write_node_key_from_validator_config "peer1_0" "$RUN_DIR/peer1_node.key"
write_node_key_from_validator_config "peer2_0" "$RUN_DIR/peer2_node.key"
write_node_key_from_validator_config "peer3_0" "$RUN_DIR/peer3_node.key"

if [[ "$GENERATE_NODES_YAML" == "1" ]]; then
  generate_nodes_yaml \
    "$RUN_DIR/nodes.yaml" \
    "${PEAM_NODE_NAME:-}:$PEAM_QUIC_PORT" \
    "${PEER1_NODE_NAME:-}:$PEER1_QUIC_PORT" \
    "${PEER2_NODE_NAME:-}:$PEER2_QUIC_PORT" \
    "${PEER3_NODE_NAME:-}:$PEER3_QUIC_PORT"
elif [[ ! -f "$RUN_DIR/nodes.yaml" ]]; then
  printf '[]\n' > "$RUN_DIR/nodes.yaml"
fi

PEAM_CONFIG="$RUN_DIR/peam_node.conf"
PEAM_NODE_KEY_PATH=""
if [[ -n "$PEAM_NODE_NAME" ]]; then
  PEAM_NODE_KEY_PATH="$(node_key_path_for_name "$PEAM_NODE_NAME")"
fi
PEAM_NODE_KEY_LINE=""
if [[ -n "$PEAM_NODE_KEY_PATH" ]]; then
  PEAM_NODE_KEY_LINE="node_key_path=$PEAM_NODE_KEY_PATH"
fi
ALLOWED_TOPICS=("$BLOCK_TOPIC" "$AGGREGATION_TOPIC")
TOPIC_SCORES=("$BLOCK_TOPIC:2" "$AGGREGATION_TOPIC:1")
TOPIC_VALIDATORS=("$BLOCK_TOPIC=block" "$AGGREGATION_TOPIC=aggregation")
if [[ "$PEAM_IS_AGGREGATOR_BOOL" == "true" ]]; then
  for ((subnet=0; subnet<ATTESTATION_COMMITTEE_COUNT; subnet++)); do
    topic="/leanconsensus/$TOPIC_DOMAIN/attestation_${subnet}/ssz_snappy"
    ALLOWED_TOPICS+=("$topic")
    TOPIC_SCORES+=("$topic:1")
    TOPIC_VALIDATORS+=("$topic=attestation")
  done
else
  ALLOWED_TOPICS+=("$ATTESTATION_SUBNET_TOPIC")
  TOPIC_SCORES+=("$ATTESTATION_SUBNET_TOPIC:1")
  TOPIC_VALIDATORS+=("$ATTESTATION_SUBNET_TOPIC=attestation")
fi
ALLOWED_TOPICS_CSV="$(IFS=,; echo "${ALLOWED_TOPICS[*]}")"
TOPIC_SCORES_CSV="$(IFS=,; echo "${TOPIC_SCORES[*]}")"
TOPIC_VALIDATORS_CSV="$(IFS=,; echo "${TOPIC_VALIDATORS[*]}")"
cat >"$PEAM_CONFIG" <<EOF
genesis_time=$GENESIS_TIME
discovery_interval_secs=5
score_decay_interval_secs=30
score_decay_amount=1
ban_threshold=-100
bootnodes=$BOOTNODES
trusted_peers=$TRUSTED_PEERS
allowed_topics=$ALLOWED_TOPICS_CSV
topic_scores=$TOPIC_SCORES_CSV
topic_validators=$TOPIC_VALIDATORS_CSV
max_gossip_bytes=2000000
max_reqresp_bytes=4000000
is_aggregator=$PEAM_IS_AGGREGATOR_BOOL
attestation_committee_count=$ATTESTATION_COMMITTEE_COUNT
validator_count=$VALIDATOR_COUNT
local_validator_index=$PEAM_VALIDATOR_INDEX
storage_dir=store
metrics=true
metrics_address=127.0.0.1
metrics_port=$PEAM_METRICS_PORT
$PEAM_NODE_KEY_LINE
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
    export DEVNET_ATTESTATION_COMMITTEE_COUNT="$ATTESTATION_COMMITTEE_COUNT"
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
    export DEVNET_ATTESTATION_COMMITTEE_COUNT="$ATTESTATION_COMMITTEE_COUNT"
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
    export DEVNET_ATTESTATION_COMMITTEE_COUNT="$ATTESTATION_COMMITTEE_COUNT"
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
