#!/bin/sh
# tcc_time_suite.sh - time Turing's existing test suite on a snapshot of one
# commit, to size the CI tiers in research/notes/pq/testing-ci-cd.md.
#
# What it reproduces, and from which source: the per-commit command in
# docs/13-version-2-and-hardening.md ("cargo test --release  # the whole
# suite"). It also demonstrates the `git archive` snapshot method of the
# notes (section 6.4): the committed tree of COMMIT is exported to OUTDIR, so
# the working tree and target/ of the repository are never touched and cargo
# never runs inside the repository.
#
# Usage (Git Bash): sh research/scripts/pq/tcc_time_suite.sh REPO COMMIT OUTDIR
# Prints wall-clock seconds for: clean release build of all test targets, and
# the full test run. Every cargo call is wrapped in `timeout 1500`.
set -eu
REPO=$1
COMMIT=$2
OUT=$3
rm -rf "$OUT/src" "$OUT/target"
mkdir -p "$OUT/src"
# core.autocrlf=false: export the committed bytes; Git for Windows' system
# config sets autocrlf=true, which makes `git archive` write CRLF text files.
git -c core.autocrlf=false -C "$REPO" archive --format=tar "$COMMIT" | tar -x -C "$OUT/src"
echo "snapshot of $(git -C "$REPO" rev-parse "$COMMIT"): $(find "$OUT/src" -type f | wc -l) files"
cd "$OUT/src"
export CARGO_TARGET_DIR="$OUT/target"
echo "cargo: $(cargo --version)"
t0=$(date +%s.%N)
timeout 1500 cargo test --release --locked --offline --workspace --no-run > "$OUT/build.log" 2>&1 || { echo "build failed, see $OUT/build.log"; tail -5 "$OUT/build.log"; exit 1; }
t1=$(date +%s.%N)
echo "clean release build of all test targets: $(echo "$t0 $t1" | awk '{printf "%.1f", $2-$1}') s"
timeout 1500 cargo test --release --locked --offline --workspace > "$OUT/test.log" 2>&1 || echo "test run exited non-zero (see test.log)"
t2=$(date +%s.%N)
echo "full test run (already built): $(echo "$t1 $t2" | awk '{printf "%.1f", $2-$1}') s"
grep -E "^test result:" "$OUT/test.log" | awk '{p+=$4; f+=$6; i+=$8} END {print "tests: passed " p ", failed " f ", ignored " i}'
