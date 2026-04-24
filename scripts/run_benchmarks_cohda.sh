#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# FlexStack Benchmark Orchestrator — Cohda MK6 (C-V2X)
#
# Runs the Rust C-V2X benchmark over the real C-V2X radio on Cohda MK6 hardware.
# The flexstack-bench-cv2x binary must be placed in the same directory as this
# script before running.
#
# Usage:
#   ./run_benchmarks_cohda.sh [platform] [runs] [duration]
#
# Examples:
#   ./run_benchmarks_cohda.sh mk6 30 60
#   ./run_benchmarks_cohda.sh mk6c 10 30
#
# Prerequisites:
#   1. Cross-compile: cd cohda-toolchain && ./build-cv2x.sh --release
#   2. Copy binary to device alongside this script:
#        scp rust/target/aarch64-unknown-linux-gnu/release/flexstack-bench-cv2x \
#            user@<MK6_IP>:/path/to/scripts/
#   3. On the device ensure cv2x-daemon is running:
#        ps aux | grep cv2x-daemon
#
# TX/RX note:
#   The tx and rx modes require two separate MK6 devices.
#   Device A (sender):   ./run_benchmarks_cohda.sh mk6 30 60 tx
#   Device B (receiver): ./run_benchmarks_cohda.sh mk6 30 60 rx

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
PLATFORM="${1:-mk6}"
RUNS="${2:-30}"
DURATION="${3:-60}"
MODE_FILTER="${4:-all}"   # all | tx | rx — limits which network modes to run
COOLDOWN=10
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="./results_${PLATFORM}_${TIMESTAMP}.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CV2X_BIN="${SCRIPT_DIR}/flexstack-bench-cv2x"
WARMUP=5

echo "============================================================"
echo "FlexStack Benchmark Orchestrator — Cohda MK6 (C-V2X)"
echo "============================================================"
echo "  Platform   : $PLATFORM"
echo "  Runs/cell  : $RUNS"
echo "  Duration   : ${DURATION}s"
echo "  Warm-up    : ${WARMUP}s"
echo "  Cooldown   : ${COOLDOWN}s"
echo "  Mode filter: $MODE_FILTER"
echo "  Output     : $OUTPUT"
echo "  Binary     : $CV2X_BIN"
echo "============================================================"
echo

# ── Validate prerequisites ───────────────────────────────────────────────────
if [ ! -f "$CV2X_BIN" ]; then
  echo "ERROR: C-V2X benchmark binary not found at $CV2X_BIN"
  echo "       Cross-compile it first:"
  echo "         cd cohda-toolchain && ./build-cv2x.sh --release"
  echo "       Then copy it here:"
  echo "         scp rust/target/aarch64-unknown-linux-gnu/release/flexstack-bench-cv2x \\"
  echo "             user@<MK6_IP>:${SCRIPT_DIR}/"
  exit 1
fi

# ── Helper: run a single benchmark cell ─────────────────────────────────────
run_cell() {
  local SECURITY="$1"
  local BENCH="$2"

  for RUN in $(seq 1 "$RUNS"); do
    echo ""
    echo "──────────────────────────────────────────────────────────"
    echo "[$(date '+%H:%M:%S')] rust-cv2x | $SECURITY | $BENCH | run $RUN/$RUNS"
    echo "──────────────────────────────────────────────────────────"

    "$CV2X_BIN" \
      --mode "$BENCH" --security "$SECURITY" \
      --duration "$DURATION" --warmup "$WARMUP" \
      --output "$OUTPUT" --run-id "$RUN" \
      --platform "$PLATFORM" \
      2>&1 || echo "  [WARN] C-V2X benchmark exited with error"

    # Cool-down between runs
    if [ "$RUN" -lt "$RUNS" ]; then
      echo "  Cooling down (${COOLDOWN}s)..."
      sleep "$COOLDOWN"
    fi
  done
}

# ── Main benchmark matrix ────────────────────────────────────────────────────
TOTAL_START=$(date +%s)

echo "Starting C-V2X benchmark matrix..."
echo

# B1: Full-stack TX throughput (C-V2X radio)
if [ "$MODE_FILTER" = "all" ] || [ "$MODE_FILTER" = "tx" ]; then
  echo "================================================================"
  echo "  B1: Full-Stack TX Throughput (C-V2X)"
  echo "================================================================"
  for SEC in off on; do
    run_cell "$SEC" "tx"
  done
fi

# B2: RX throughput (receive-only, requires remote sender)
if [ "$MODE_FILTER" = "all" ] || [ "$MODE_FILTER" = "rx" ]; then
  echo "================================================================"
  echo "  B2: RX Throughput (C-V2X — requires remote TX device)"
  echo "================================================================"
  for SEC in off on; do
    run_cell "$SEC" "rx"
  done
fi

# B3: ASN.1 Codec throughput (in-memory, no radio)
if [ "$MODE_FILTER" = "all" ]; then
  echo "================================================================"
  echo "  B3: ASN.1 Codec Throughput"
  echo "================================================================"
  run_cell "off" "codec-encode"
  run_cell "off" "codec-decode"

  # B4: Security Layer throughput (in-memory, no radio)
  echo "================================================================"
  echo "  B4: Security Layer Throughput (Sign + Verify)"
  echo "================================================================"
  run_cell "on" "security-sign"
  run_cell "on" "security-verify"
fi

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))
TOTAL_HOURS=$((TOTAL_ELAPSED / 3600))
TOTAL_MINS=$(( (TOTAL_ELAPSED % 3600) / 60 ))

echo
echo "============================================================"
echo "All C-V2X benchmarks complete!"
echo "  Total time : ${TOTAL_HOURS}h ${TOTAL_MINS}m"
echo "  Results    : $OUTPUT"
echo "============================================================"
