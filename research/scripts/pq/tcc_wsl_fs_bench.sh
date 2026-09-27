#!/bin/sh
# tcc_wsl_fs_bench.sh - small-file I/O inside WSL 2: Windows drive (9p/drvfs)
# versus a Linux filesystem.
#
# What it reproduces, and from which source: Microsoft's guidance that files
# used from a Linux command line are fastest "in the WSL file system"
# (learn.microsoft.com/en-us/windows/wsl/filesystems, "File storage and
# performance across file systems"). It measures, on this machine:
#   read:  tar the Turing crates/ tree to /dev/null (stat + read of every file)
#   write: create, then delete, N small files
# once on the Windows side (/mnt/...) and once on a Linux filesystem.
# The Linux side is /tmp, whose filesystem type is printed (stat -f): on
# this machine it is tmpfs in the Ubuntu distro (whose root is read-only,
# see the notes) and ext4 on the WSL virtual disk in the parrot distro.
# tmpfs is RAM-backed and only an upper bound for ext4.
#
# Usage (from Windows):
#   wsl.exe -d Ubuntu -e sh /mnt/d/Dev/Turing/research/scripts/pq/tcc_wsl_fs_bench.sh \
#       /mnt/d/Dev/Turing/crates /mnt/c/.../Temp/turing/pq/wslbench 2000
# Arguments: SRC_TREE WIN_SCRATCH_DIR N_FILES. Writes only under
# WIN_SCRATCH_DIR and /tmp/tcc_bench.$$, and removes both afterwards.
# Every step is wrapped in `timeout 300`. Output: one line per timing.
set -eu
SRC=$1
WIN=$2
N=${3:-2000}
LIN=/tmp/tcc_bench.$$
mkdir -p "$WIN" "$LIN"
FST=$(stat -f -c %T /tmp)
echo "linux side: /tmp is $FST; windows side: $(stat -f -c %T "$WIN")"

now() { date +%s.%N; }
elapsed() { echo "$1 $2" | awk '{printf "%.3f", $2 - $1}'; }

# read test: the source tree in place (Windows side) and a copy on tmpfs
timeout 300 cp -r "$SRC" "$LIN/src"
for i in 1 2 3; do
  t0=$(now); timeout 300 tar -cf /dev/null -C "$SRC" .; t1=$(now)
  timeout 300 tar -cf /dev/null -C "$LIN/src" .; t2=$(now)
  echo "read  run $i: windows-drive $(elapsed "$t0" "$t1") s   linux-$FST $(elapsed "$t1" "$t2") s   ($(find "$SRC" -type f | wc -l) files)"
done

# write test: N small files, then delete them
for side in "$WIN" "$LIN"; do
  d="$side/w"
  mkdir -p "$d"
  t0=$(now)
  i=0
  while [ $i -lt "$N" ]; do echo "$i" > "$d/f$i"; i=$((i + 1)); done
  t1=$(now)
  timeout 300 rm -rf "$d"
  t2=$(now)
  echo "write $N files on $side: create $(elapsed "$t0" "$t1") s, delete $(elapsed "$t1" "$t2") s"
done
rm -rf "$LIN"
rmdir "$WIN" 2>/dev/null || true
