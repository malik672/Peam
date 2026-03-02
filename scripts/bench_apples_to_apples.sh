#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEAN_DIR="$ROOT_DIR"
REAM_DIR="${REAM_DIR:-$ROOT_DIR/../ream}"

TMP_BASE="${TMP_BASE:-$ROOT_DIR/.tmp}"
SAMPLE_SIZE="${SAMPLE_SIZE:-10}"
WARMUP_TIME="${WARMUP_TIME:-0.1}"
MEASUREMENT_TIME="${MEASUREMENT_TIME:-0.2}"

LEAN_OPEN_OUT="$TMP_BASE/lean_storage_open.out"
LEAN_LOOKUP_OUT="$TMP_BASE/lean_storage_lookup.out"
REAM_OUT="$TMP_BASE/ream_storage_open.out"
LEAN_TARGET="$TMP_BASE/lean_target"
REAM_TARGET="$TMP_BASE/ream_target"

mkdir -p "$TMP_BASE"

if [[ ! -f "$LEAN_DIR/Cargo.toml" ]]; then
  echo "lean_eth Cargo.toml not found at: $LEAN_DIR/Cargo.toml" >&2
  exit 1
fi
if [[ ! -d "$REAM_DIR/crates/storage" ]]; then
  echo "ream storage crate not found at: $REAM_DIR/crates/storage" >&2
  echo "Set REAM_DIR to the ream checkout path and rerun." >&2
  exit 1
fi

echo "[1/4] lean_eth storage_open"
(
  cd "$LEAN_DIR"
  TMPDIR="$TMP_BASE" CARGO_TARGET_DIR="$LEAN_TARGET" \
    cargo bench -q --bench storage_open -- \
      --sample-size "$SAMPLE_SIZE" \
      --warm-up-time "$WARMUP_TIME" \
      --measurement-time "$MEASUREMENT_TIME" | tee "$LEAN_OPEN_OUT"
)

echo "[2/4] lean_eth storage_lookup"
(
  cd "$LEAN_DIR"
  TMPDIR="$TMP_BASE" CARGO_TARGET_DIR="$LEAN_TARGET" \
    cargo bench -q --bench storage_lookup -- \
      --sample-size "$SAMPLE_SIZE" \
      --warm-up-time "$WARMUP_TIME" \
      --measurement-time "$MEASUREMENT_TIME" | tee "$LEAN_LOOKUP_OUT"
)

echo "[3/4] ream storage_open (+lookup group in same bench)"
(
  cd "$REAM_DIR"
  TMPDIR="$TMP_BASE" CARGO_TARGET_DIR="$REAM_TARGET" \
    cargo bench -q --manifest-path crates/storage/Cargo.toml --bench storage_open -- \
      --sample-size "$SAMPLE_SIZE" \
      --warm-up-time "$WARMUP_TIME" \
      --measurement-time "$MEASUREMENT_TIME" | tee "$REAM_OUT"
)

echo "[4/4] summary"
python3 - "$LEAN_OPEN_OUT" "$LEAN_LOOKUP_OUT" "$REAM_OUT" <<'PY'
import re
import sys
from pathlib import Path

lean_open_path, lean_lookup_path, ream_path = [Path(p) for p in sys.argv[1:4]]

pattern = re.compile(
    r"(?m)^([A-Za-z0-9_/\-]+)\n\s*time:\s+\[[^\]]*?\s([0-9.]+)\s*(ns|µs|us|ms|s)\]"
)

def parse_metrics(path: Path):
    text = path.read_text()
    out = {}
    for name, value, unit in pattern.findall(text):
        out[name] = (float(value), unit)
    return out

def to_us(value: float, unit: str) -> float:
    if unit == "ns":
        return value / 1000.0
    if unit in ("µs", "us"):
        return value
    if unit == "ms":
        return value * 1000.0
    if unit == "s":
        return value * 1_000_000.0
    raise ValueError(f"unknown unit: {unit}")

def fmt_us(us: float) -> str:
    if us >= 1000.0:
        return f"{us / 1000.0:.3f} ms"
    if us >= 1.0:
        return f"{us:.3f} µs"
    return f"{us * 1000.0:.3f} ns"

lean = {}
lean.update(parse_metrics(lean_open_path))
lean.update(parse_metrics(lean_lookup_path))
ream = parse_metrics(ream_path)

pairs = [
    ("storage_open/file_store_open_1k_states_1k_blocks", "storage_open/ream_store_open_1k_states_1k_blocks", "open_1k_states_1k_blocks"),
    ("storage_open/file_store_cold_read_state_by_root", "storage_open/ream_store_cold_read_state_by_root", "cold_read_state_by_root"),
    ("storage_open/file_store_cold_read_block_by_root", "storage_open/ream_store_cold_read_block_by_root", "cold_read_block_by_root"),
    ("storage_open/file_store_cold_read_state_by_slot", "storage_open/ream_store_cold_read_state_by_slot", "cold_read_state_by_slot"),
    ("storage_open/file_store_cold_read_block_by_slot", "storage_open/ream_store_cold_read_block_by_slot", "cold_read_block_by_slot"),
    ("storage_lookup/file_get_state_by_root", "storage_lookup/ream_get_state_by_root", "warm_get_state_by_root"),
    ("storage_lookup/file_get_block_by_root", "storage_lookup/ream_get_block_by_root", "warm_get_block_by_root"),
    ("storage_lookup/file_get_state_by_slot", "storage_lookup/ream_get_state_by_slot", "warm_get_state_by_slot"),
    ("storage_lookup/file_get_block_by_slot", "storage_lookup/ream_get_block_by_slot", "warm_get_block_by_slot"),
]

rows = []
missing = []
for lean_key, ream_key, label in pairs:
    if lean_key not in lean:
        missing.append(f"missing lean metric: {lean_key}")
        continue
    if ream_key not in ream:
        missing.append(f"missing ream metric: {ream_key}")
        continue
    lean_us = to_us(*lean[lean_key])
    ream_us = to_us(*ream[ream_key])
    winner = "lean_eth" if lean_us < ream_us else "ream"
    delta = ((lean_us - ream_us) / ream_us) * 100.0
    rows.append((label, lean_us, ream_us, winner, delta))

print("Metric | lean_eth | ream | Faster | Delta vs ream")
print("--- | --- | --- | --- | ---")
for label, lean_us, ream_us, winner, delta in rows:
    print(f"{label} | {fmt_us(lean_us)} | {fmt_us(ream_us)} | {winner} | {delta:+.2f}%")

if missing:
    print("\nMissing metrics:")
    for item in missing:
        print(f"- {item}")
PY
