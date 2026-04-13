#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# FlexStack RX Benchmark Orchestrator
#
# Runs the B2 (Full-Stack RX Throughput) benchmarks for all implementations.
# Requires a remote sender running send_packets_for_rx_benchmarks.sh on another
# machine, transmitting CAMs on the same L2 interface.
#
# Usage:
#   sudo ./run_rx_benchmarks.sh [platform] [runs] [duration] [interface]
#
# Examples:
#   sudo ./run_rx_benchmarks.sh rpi5 30 60 eth0
#   sudo ./run_rx_benchmarks.sh laptop 30 60 enp3s0
#
# Prerequisites:
#   1. Run prepare_system.sh first
#   2. Generate certificates: cd ../python && python3 generate_certs.py
#   3. Build Rust benchmark: cd ../rust && cargo build --release
#   4. Start the sender on the remote machine BEFORE running this script:
#        sudo ./send_packets_for_rx_benchmarks.sh eth0 [duration]

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
PLATFORM="${1:-laptop}"
RUNS="${2:-30}"
DURATION="${3:-60}"
INTERFACE="${4:-eth0}"
COOLDOWN=10
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="../results/results_rx_${PLATFORM}_${TIMESTAMP}.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RUST_BIN="$PROJECT_DIR/rust/target/release/flexstack-bench"
PYTHON_BENCH="$PROJECT_DIR/python/benchmark.py"

CPYTHON="${CPYTHON:-$PROJECT_DIR/venv/bin/python3}"
PYPY="${PYPY:-pypy3}"

BENCH_CORES="${BENCH_CORES:-2,3}"

echo "============================================================"
echo "FlexStack RX Benchmark Orchestrator"
echo "============================================================"
echo "  Platform   : $PLATFORM"
echo "  Runs/cell  : $RUNS"
echo "  Duration   : ${DURATION}s"
echo "  Cooldown   : ${COOLDOWN}s"
echo "  Interface  : $INTERFACE"
echo "  Output     : $OUTPUT"
echo "  Rust binary: $RUST_BIN"
echo "  CPython    : $CPYTHON"
echo "  PyPy       : $PYPY"
echo "  Cores      : $BENCH_CORES"
echo "============================================================"
echo
echo "  IMPORTANT: Ensure the remote sender is already running:"
echo "    sudo ./send_packets_for_rx_benchmarks.sh $INTERFACE"
echo "============================================================"
echo

# ── Validate prerequisites ──────────────────────────────────────────────────
if [ ! -f "$RUST_BIN" ]; then
  echo "ERROR: Rust benchmark binary not found at $RUST_BIN"
  echo "       Build it first: cd $PROJECT_DIR/rust && cargo build --release"
  exit 1
fi

# ── Helper: run a single benchmark cell ─────────────────────────────────────
run_cell() {
  local IMPL="$1"
  local SECURITY="$2"

  local WARMUP=5
  if [ "$IMPL" = "pypy" ]; then
    WARMUP=15
  fi

  for RUN in $(seq 1 "$RUNS"); do
    echo ""
    echo "──────────────────────────────────────────────────────────"
    echo "[$(date '+%H:%M:%S')] $IMPL | $SECURITY | rx | run $RUN/$RUNS"
    echo "──────────────────────────────────────────────────────────"

    case "$IMPL" in
      rust)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$RUST_BIN" \
          --mode rx --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" --interface "$INTERFACE" \
          2>&1 || echo "  [WARN] Rust benchmark exited with error"
        ;;
      cpython)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$CPYTHON" "$PYTHON_BENCH" \
          --mode rx --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" --interface "$INTERFACE" \
          2>&1 || echo "  [WARN] CPython benchmark exited with error"
        ;;
      pypy)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$PYPY" "$PYTHON_BENCH" \
          --mode rx --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" --interface "$INTERFACE" \
          2>&1 || echo "  [WARN] PyPy benchmark exited with error"
        ;;
    esac

    if [ "$RUN" -lt "$RUNS" ]; then
      echo "  Cooling down (${COOLDOWN}s)..."
      sleep "$COOLDOWN"
    fi
  done
}

# ── Main: B2 RX throughput matrix ───────────────────────────────────────────
TOTAL_START=$(date +%s)

echo "Starting B2: Full-Stack RX Throughput benchmarks..."
echo

echo "================================================================"
echo "  B2: Full-Stack RX Throughput"
echo "================================================================"
for IMPL in rust cpython pypy; do
  for SEC in off on; do
    run_cell "$IMPL" "$SEC"
  done
done

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))
TOTAL_HOURS=$((TOTAL_ELAPSED / 3600))
TOTAL_MINS=$(( (TOTAL_ELAPSED % 3600) / 60 ))

echo
echo "============================================================"
echo "RX benchmarks complete!"
echo "  Total time : ${TOTAL_HOURS}h ${TOTAL_MINS}m"
echo "  Results    : $OUTPUT"
echo "============================================================"
