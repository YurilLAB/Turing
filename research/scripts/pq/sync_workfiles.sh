#!/usr/bin/env bash
# Copy the PQ research working files out of the temporary working
# directory (Windows Temp, which can be cleaned) into the repo's research
# folder, and the tools they built into D:\Dev\.toolchains.
#
#   research/workfiles/pq/   extracted paper text, web pages, test vectors,
#                            run logs, third-party sources (gitignored:
#                            local-only like research/papers/)
#   D:\Dev\.toolchains\valgrind-3.26.0-varlat\   Valgrind with the KyberSlash
#                            variable-latency Memcheck patch (built by
#                            research/scripts/pq/build_valgrind_varlat.sh)
#   D:\Dev\.toolchains\valgrind-3.26.0-ubuntu\   stock Ubuntu Valgrind .deb,
#                            unpacked without root
#
# Build outputs that are regenerated on demand are skipped: every directory
# whose name starts with "target" (the runs used target-a, target-b,
# target-linux, target-msvc, target2, ...; 1.47 GB on 2026-09-27) and
# sc-rust/build. Their logs and comparison results are kept. Usage: bash sync_workfiles.sh          one pass
#                 bash sync_workfiles.sh --loop   every 5 minutes, for at most 6 hours
set -u
export MSYS_NO_PATHCONV=1
SRC="${SYNC_SRC:?set SYNC_SRC to the working directory to copy from}"
DST='D:\Dev\Turing\research\workfiles'
TOOLS='D:\Dev\.toolchains'
RC='/R:1 /W:1 /NFL /NDL /NJH /NJS /NP'

one_pass() {
  # robocopy exit codes 0-7 mean success (8+ = failure).
  robocopy "$SRC\\pq" "$DST\\pq" /E $RC \
    /XD "$SRC\\pq\\sc-rust\\build" "$SRC\\pq\\vg-varlat" "$SRC\\pq\\vg\\root" 'target*' .git \
    /XF '*.deb' '*.tmp' > /dev/null
  a=$?
  robocopy "$SRC" "$DST\\pq\\session-misc" /LEV:1 $RC /XF wfcheck.js > /dev/null
  b=$?
  robocopy "$SRC\\pq\\vg-varlat" "$TOOLS\\valgrind-3.26.0-varlat" /E $RC > /dev/null
  c=$?
  robocopy "$SRC\\pq\\vg\\root" "$TOOLS\\valgrind-3.26.0-ubuntu" /E $RC > /dev/null
  d=$?
  echo "$(date '+%H:%M:%S') workfiles=$a misc=$b varlat=$c ubuntu=$d (robocopy codes; <8 is ok)"
}

if [ "${1:-}" = "--loop" ]; then
  end=$(( $(date +%s) + 6 * 3600 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    one_pass
    sleep 300
  done
else
  one_pass
fi
