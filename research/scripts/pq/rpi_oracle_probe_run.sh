#!/usr/bin/env bash
# Build and run research/scripts/pq/rpi_oracle_probe.rs (topic rust-pqc-implementations).
# The probe is built in the scratch directory, never inside the Turing repository.
#
# Usage: rpi_oracle_probe_run.sh SCRATCH_PQ_DIR [build|SUBCOMMAND ARGS...]
#   SCRATCH_PQ_DIR  e.g. C:/Users/<you>/AppData/Local/Temp/turing/pq
#   build           copy sources and build only (release)
#   otherwise       run the built binary with the given subcommand (see the probe's usage line)
# Environment:
#   RPI_TARGET=DIR       cargo --target-dir (default SCRATCH/rpi/oracle-probe/target)
#   RPI_TOOLCHAIN=+NAME  rustup toolchain override, e.g. +stable-x86_64-pc-windows-msvc
#   RPI_LINUX=1          build for x86_64-unknown-linux-gnu with WSL gcc as C compiler, archiver and
#                        linker (research/scripts/pq/rpi_wsl_tool.py through .cmd wrappers in
#                        SCRATCH/rpi/wsl/), and run the binary inside WSL
#   RPI_FEATURES=awslc   also build the aws-lc-rs oracle
#   RPI_TIMEOUT=SECONDS  run timeout (default 1800)
# Every step is bounded with `timeout`.
set -euo pipefail
SC="$1"; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$SC/rpi/oracle-probe"
mkdir -p "$PROBE/src"
cp "$HERE/rpi_oracle_probe.Cargo.toml" "$PROBE/Cargo.toml"
cp "$HERE/rpi_oracle_probe.rs" "$PROBE/src/main.rs"
FEAT=()
if [ -n "${RPI_FEATURES:-}" ]; then FEAT=(--features "$RPI_FEATURES"); fi
# PQClean's compat.h includes glibc's <features.h> for any GCC build; MinGW-w64 has none. When the
# shim header exists (scratch rpi/shim/features.h, written by hand), put it on the C include path for
# the windows-gnu target only. Without it, pqcrypto-mlkem 0.1.1 fails to build on windows-gnu.
if [ -f "$SC/rpi/shim/features.h" ] && [ -z "${RPI_NO_SHIM:-}" ]; then
  export CFLAGS_x86_64_pc_windows_gnu="-I$SC/rpi/shim"
fi
TRIPLE=()
if [ -n "${RPI_LINUX:-}" ]; then
  W="$(cygpath -w "$SC/rpi/wsl")"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$W\\rpi-wsl-gcc.cmd"
  export CC_x86_64_unknown_linux_gnu="$W\\rpi-wsl-gcc.cmd"
  export AR_x86_64_unknown_linux_gnu="$W\\rpi-wsl-ar.cmd"
  TRIPLE=(--target x86_64-unknown-linux-gnu)
fi
TD="${RPI_TARGET:-$PROBE/target${RPI_FEATURES:+-$RPI_FEATURES}}"
if [ "${1:-build}" = "build" ]; then
  timeout 1500 cargo ${RPI_TOOLCHAIN:-} build --release --manifest-path "$PROBE/Cargo.toml" --target-dir "$TD" "${TRIPLE[@]}" "${FEAT[@]}"
  exit 0
fi
if [ -n "${RPI_LINUX:-}" ]; then
  BIN="$TD/x86_64-unknown-linux-gnu/release/rpi_oracle_probe"
  ARGS=()
  for a in "$@"; do
    case "$a" in
      [A-Za-z]:[/\\]*) d="$(echo "${a:0:1}" | tr 'A-Z' 'a-z')"; r="${a:3}"; ARGS+=("/mnt/$d/${r//\\//}") ;;
      *) ARGS+=("$a") ;;
    esac
  done
  B="$(cygpath -m "$BIN")"; bd="$(echo "${B:0:1}" | tr 'A-Z' 'a-z')"
  # MSYS_NO_PATHCONV stops Git Bash from rewriting /mnt/... arguments into Windows paths.
  MSYS_NO_PATHCONV=1 timeout "${RPI_TIMEOUT:-1800}" wsl.exe -e "/mnt/$bd/${B:3}" "${ARGS[@]}"
  exit $?
fi
BIN="$TD/release/rpi_oracle_probe"
[ -x "$BIN" ] || BIN="$BIN.exe"
timeout "${RPI_TIMEOUT:-1800}" "$BIN" "$@"
