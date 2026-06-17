#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# build_cv2x.sh — Cross-compile the C-V2X benchmark for Cohda AArch64 platforms.
#
# Prerequisites:
#   Run RustFlexstack/cohda-toolchain/setup-toolchain.sh once before the first build.
#
# Usage:
#   BOARD=mk6c        ./build_cv2x.sh            # MK6C / MK6 ag15 (default)
#   BOARD=mk6-ag550   ./build_cv2x.sh            # MK6 ag550 (Quectel AG550)
#   ./build_cv2x.sh --release                    # release build

set -euo pipefail

[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="${SCRIPT_DIR}/rust"
TOOLCHAIN_DIR="${SCRIPT_DIR}/RustFlexstack/cohda-toolchain"

TARGET="aarch64-unknown-linux-gnu"

BOARD="${BOARD:-mk6}"

case "${BOARD}" in
    mk6c)
        SYSROOT_DIR="${TOOLCHAIN_DIR}/sysroot"
        BOARD_LABEL="MK6C / MK6 ag15 (mdm9150)"
        ;;
    mk6-ag550)
        SYSROOT_DIR="${TOOLCHAIN_DIR}/sysroot-mk6-ag550"
        BOARD_LABEL="MK6 ag550 (SA515M) — Snaptel SDK sysroot"
        ;;
    mk6)
        SYSROOT_DIR="${TOOLCHAIN_DIR}/sysroot-mk6"
        BOARD_LABEL="MK6 ag550 (SA515M) — device sysroot (v1.42.7)"
        ;;
    *)
        echo "ERROR: Unknown BOARD '${BOARD}'. Valid values: mk6c, mk6-ag550, mk6"
        exit 1
        ;;
esac

TELUX_LIB_DIR="${TELUX_LIB_DIR:-${SYSROOT_DIR}/lib}"
TELUX_INCLUDE_DIR="${TELUX_INCLUDE_DIR:-${SYSROOT_DIR}/include}"

echo "==> Validating environment..."
echo "    Board               : ${BOARD_LABEL}"

if [ ! -f "${TELUX_LIB_DIR}/libtelux_cv2x.so" ] && [ ! -f "${TELUX_LIB_DIR}/libv2x_radio.so" ]; then
    echo "ERROR: V2X libraries not found under ${TELUX_LIB_DIR}."
    echo "Run ${TOOLCHAIN_DIR}/setup-toolchain.sh first!"
    exit 1
fi

echo "    Target              : ${TARGET}"
echo "    Telux headers       : ${TELUX_INCLUDE_DIR}"
echo "    Telux libraries     : ${TELUX_LIB_DIR}"
echo ""

export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
export CXX_aarch64_unknown_linux_gnu="aarch64-linux-gnu-g++"
export AR_aarch64_unknown_linux_gnu="aarch64-linux-gnu-ar"

export TELUX_INCLUDE_DIR
export TELUX_LIB_DIR

# IMPORTANT: Provide the missing dynamic library linkages required by the final executable
# that are normally not transitively resolved by Rust Cargo when linking the binary.
# We also use --unresolved-symbols=ignore-in-shared-libs to ignore missing transitive dependencies
# inside the proprietary Telux shared libraries (like libqcmap_client.so).
export RUSTFLAGS="-l dylib=telux_data -l dylib=telux_qmi -l dylib=v2x_radio -C link-args=-Wl,--unresolved-symbols=ignore-in-shared-libs"

echo "==> Building flexstack-bench-cv2x for ${TARGET} ..."
echo "    cargo args: $*"
echo ""

cd "${BENCH_ROOT}"
cargo build \
    --target "${TARGET}" \
    --features cv2x \
    --bin flexstack-bench-cv2x \
    "$@"

BUILD_TYPE="debug"
for arg in "$@"; do
    [[ "${arg}" == "--release" ]] && BUILD_TYPE="release"
done

OUT_DIR="${BENCH_ROOT}/target/${TARGET}/${BUILD_TYPE}"
echo ""
echo "==> Build complete. Artifacts in:"
echo "    ${OUT_DIR}"
echo ""
ls -lh "${OUT_DIR}/flexstack-bench-cv2x" 2>/dev/null || true
echo ""
echo "NOTE: Copy the binary along with the shared libraries from ${TELUX_LIB_DIR} to the device."
