#!/usr/bin/env bash
# Build Valgrind 3.26.0 with the KyberSlash "varlat" Memcheck patch, no root.
#
# Reproduces the tool of Bernstein et al., "KyberSlash", TCHES 2025(2),
# Sec. 7.1.1: Memcheck patched to report a secret (undefined) operand of a
# variable-latency instruction such as div/idiv. Upstream Valgrind does not
# contain it (checked: no "variable-latency" in memcheck/mc_main.c at HEAD on
# 2026-09-26). The patch is valgrind-varlat-patch-20250805.txt from
# https://kyberslash.cr.yp.to/papers.html (written against Valgrind git of
# 2025-08-05; here applied to the 3.26.0 release, Oct 2025).
#
# Usage (inside WSL):  bash build_valgrind_varlat.sh PATCH_FILE PREFIX
# Build tree: /tmp/turing-vg-build. Every step is bounded by `timeout`.
set -euo pipefail
PATCH=$1
PREFIX=$2
B=/tmp/turing-vg-build
mkdir -p "$B"
cd "$B"
if [ ! -f valgrind-3.26.0.tar.bz2 ]; then
  # --http1.1: sourceware's HTTP/2 stream reset once killed this download
  # (curl exit 92, 2026-09-27).
  timeout 300 curl -sSL --http1.1 --retry 3 --fail --max-time 280 -o valgrind-3.26.0.tar.bz2.tmp \
    https://sourceware.org/pub/valgrind/valgrind-3.26.0.tar.bz2
  mv valgrind-3.26.0.tar.bz2.tmp valgrind-3.26.0.tar.bz2
fi
sha256sum valgrind-3.26.0.tar.bz2
rm -rf valgrind-3.26.0
timeout 120 tar xjf valgrind-3.26.0.tar.bz2
cd valgrind-3.26.0
# Apply only the Memcheck source changes; skip .gitignore and the test-suite
# files (their Makefile.am hunks target git, not the release tarball).
# The patch file lists several files; split it and apply file by file.
for f in memcheck/mc_errors.c memcheck/mc_include.h memcheck/mc_main.c memcheck/mc_translate.c; do
  python3 - "$PATCH" "$f" > "/tmp/turing-vg-build/$(basename $f).diff" <<'PY'
import sys, re
text = open(sys.argv[1], encoding="utf-8").read()
want = sys.argv[2]
parts = re.split(r"(?m)^(?=diff --git )", text)
for p in parts:
    if p.startswith(f"diff --git a/{want} "):
        sys.stdout.write(p)
PY
done
git_apply_ok=1
for f in mc_errors.c mc_include.h mc_main.c mc_translate.c; do
  if ! timeout 60 patch -p1 --forward --no-backup-if-mismatch --dry-run -i "/tmp/turing-vg-build/$f.diff" > /dev/null; then
    echo "patch does not apply cleanly: $f"; git_apply_ok=0
  fi
done
[ "$git_apply_ok" = 1 ] || exit 3
for f in mc_errors.c mc_include.h mc_main.c mc_translate.c; do
  timeout 60 patch -p1 --forward --no-backup-if-mismatch -i "/tmp/turing-vg-build/$f.diff"
done
grep -c "variable-latency-errors" memcheck/mc_main.c
timeout 600 ./configure --prefix="$PREFIX" > configure.log 2>&1
timeout 1800 make -j"$(nproc)" > make.log 2>&1
# PREFIX must survive a WSL restart: /tmp is a tmpfs that WSL clears when the
# VM idles out, and the WSL home is read-only in the build sandbox, so the
# scratch directory on /mnt/c is used. On such a Windows-mounted prefix only
# the HTML manual copy fails ("File exists"); the tools install first, so
# the failure is reported and the checks below decide.
timeout 600 make install > install.log 2>&1 || echo "make install exit $? (see install.log)"
test -x "$PREFIX/libexec/valgrind/memcheck-amd64-linux"
"$PREFIX/bin/valgrind" --version
"$PREFIX/bin/valgrind" --tool=memcheck --help | grep -i "variable-latency"
