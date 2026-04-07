#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# FlexStack Benchmark Orchestrator
#
# Runs all benchmark combinations (implementation × security × benchmark mode)
# for a given platform, producing unified CSV output.
#
# Usage:
#   sudo ./run_benchmarks.sh [platform] [runs] [duration]
#
# Examples:
#   sudo ./run_benchmarks.sh laptop 30 60
#   sudo ./run_benchmarks.sh rpi5 30 60
#
# Prerequisites:
#   1. Run prepare_system.sh first
#   2. Generate certificates: cd ../python && python3 generate_certs.py
#   3. Build Rust benchmark: cd ../rust && cargo build --release
#   4. Install Python deps: pip install -r ../python/requirements.txt

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
PLATFORM="${1:-laptop}"
RUNS="${2:-30}"
DURATION="${3:-60}"
COOLDOWN=10
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="../results/results_${PLATFORM}_${TIMESTAMP}.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RUST_BIN="$PROJECT_DIR/rust/target/release/flexstack-bench"
PYTHON_BENCH="$PROJECT_DIR/python/benchmark.py"

# Python interpreters (adjust paths as needed)
CPYTHON="${CPYTHON:-$PROJECT_DIR/venv/bin/python3}"
PYPY="${PYPY:-pypy3}"

# CPU cores for process pinning
BENCH_CORES="${BENCH_CORES:-2,3}"

echo "============================================================"
echo "FlexStack Benchmark Orchestrator"
echo "============================================================"
echo "  Platform   : $PLATFORM"
echo "  Runs/cell  : $RUNS"
echo "  Duration   : ${DURATION}s"
echo "  Cooldown   : ${COOLDOWN}s"
echo "  Output     : $OUTPUT"
echo "  Rust binary: $RUST_BIN"
echo "  CPython    : $CPYTHON"
echo "  PyPy       : $PYPY"
echo "  Cores      : $BENCH_CORES"
echo "============================================================"
echo

# ── Validate prerequisites ──────────────────────────────────────────────────
if [ ! -f "$RUST_BIN" ]; then
  echo "ERROR: Rust benchmark binary not found at $RUST_BIN"
  echo "       Build it first: cd $PROJECT_DIR/rust && cargo build --release"
  exit 1
fi

if [ ! -f "$PROJECT_DIR/certs/root_ca.cert" ]; then
  echo "WARNING: Certificates not found. Security benchmarks will fail."
  echo "         Generate them: cd $PROJECT_DIR/python && python3 generate_certs.py"
fi

# ── Helper: run a single benchmark cell ─────────────────────────────────────
run_cell() {
  local IMPL="$1"
  local SECURITY="$2"
  local BENCH="$3"

  # Determine warm-up
  local WARMUP=5
  if [ "$IMPL" = "pypy" ]; then
    WARMUP=15
  fi

  for RUN in $(seq 1 "$RUNS"); do
    echo ""
    echo "──────────────────────────────────────────────────────────"
    echo "[$(date '+%H:%M:%S')] $IMPL | $SECURITY | $BENCH | run $RUN/$RUNS"
    echo "──────────────────────────────────────────────────────────"

    case "$IMPL" in
      rust)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$RUST_BIN" \
          --mode "$BENCH" --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" \
          2>&1 || echo "  [WARN] Rust benchmark exited with error"
        ;;
      cpython)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$CPYTHON" "$PYTHON_BENCH" \
          --mode "$BENCH" --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" \
          2>&1 || echo "  [WARN] CPython benchmark exited with error"
        ;;
      pypy)
        chrt -f 50 taskset -c "$BENCH_CORES" \
          "$PYPY" "$PYTHON_BENCH" \
          --mode "$BENCH" --security "$SECURITY" \
          --duration "$DURATION" --warmup "$WARMUP" \
          --output "$OUTPUT" --run-id "$RUN" \
          --platform "$PLATFORM" \
          2>&1 || echo "  [WARN] PyPy benchmark exited with error"
        ;;
    esac

    # Cool-down between runs
    if [ "$RUN" -lt "$RUNS" ]; then
      echo "  Cooling down (${COOLDOWN}s)..."
      sleep "$COOLDOWN"
    fi
  done
}

# ── Main benchmark matrix ───────────────────────────────────────────────────
TOTAL_START=$(date +%s)

echo "Starting benchmark matrix..."
echo

# B1: Full-stack TX throughput (loopback)
echo "================================================================"
echo "  B1: Full-Stack TX Throughput (Loopback)"
echo "================================================================"
for IMPL in rust cpython pypy; do
  for SEC in off on; do
    run_cell "$IMPL" "$SEC" "tx"
  done
done

# B2: Full-stack RX throughput (loopback)
echo "================================================================"
echo "  B2: Full-Stack RX Throughput (Loopback)"
echo "================================================================"
for IMPL in rust cpython pypy; do
  for SEC in off on; do
    run_cell "$IMPL" "$SEC" "rx"
  done
done

# B3: Concurrent TX/RX throughput
echo "================================================================"
echo "  B3: Concurrent TX/RX Throughput"
echo "================================================================"
for IMPL in rust cpython pypy; do
  for SEC in off on; do
    run_cell "$IMPL" "$SEC" "concurrent"
  done
done

# B4: ASN.1 Codec throughput (no security involvement)
echo "================================================================"
echo "  B4: ASN.1 Codec Throughput"
echo "================================================================"
for IMPL in rust cpython pypy; do
  run_cell "$IMPL" "off" "codec-encode"
  run_cell "$IMPL" "off" "codec-decode"
done

# B5: Security Layer throughput (sign + verify, in-memory)
echo "================================================================"
echo "  B5: Security Layer Throughput (Sign + Verify)"
echo "================================================================"
for IMPL in rust cpython pypy; do
  run_cell "$IMPL" "on" "security-sign"
  run_cell "$IMPL" "on" "security-verify"
done

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))
TOTAL_HOURS=$((TOTAL_ELAPSED / 3600))
TOTAL_MINS=$(( (TOTAL_ELAPSED % 3600) / 60 ))

echo
echo "============================================================"
echo "All benchmarks complete!"
echo "  Total time : ${TOTAL_HOURS}h ${TOTAL_MINS}m"
echo "  Results    : $OUTPUT"
echo "============================================================"
echo
echo "Next step: cd ../analysis && python3 analyze_results.py --input $OUTPUT"
