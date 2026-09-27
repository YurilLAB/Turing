#!/bin/sh
# tcc_repro_build.sh - is a Turing release build bit-for-bit reproducible?
#
# What it reproduces, and from which source: the reproducibility check
# proposed in research/notes/pq/testing-ci-cd.md (section 3, "Reproducible
# builds"), using the definition of reproducible-builds.org ("given the same
# source code, build environment and build instructions, any party can
# recreate bit-by-bit identical copies of all specified artifacts"), rustc's
# --remap-path-prefix and -C strip flags (`rustc --help -v`, `rustc -C help`)
# and GNU ld's --no-insert-timestamp option for PE targets (`ld --help` of
# the MinGW binutils that rustup ships for windows-gnu).
#
# Method. The committed tree of COMMIT is exported twice with `git archive`
# into two DIFFERENT directories under OUTDIR (src-a, src-b), so the only
# intended difference between the two builds is their absolute path (and
# the time at which they run). Each tree is built with
# `cargo build --release --locked --offline --workspace` into its own target
# directory, in three variants:
#   plain  : no RUSTFLAGS. Negative control: the path difference is expected
#            to leak into the artefacts, so this variant must show DIFF lines.
#   remap  : --remap-path-prefix for the source dir, the target dir and
#            CARGO_HOME.
#   strip  : remap + -C strip=symbols, and for *-windows-gnu also
#            -C link-arg=-Wl,--no-insert-timestamp.
#   eol    : the strip flags, but tree b is exported with core.autocrlf=true
#            (CRLF text files, what Git for Windows' default system config
#            gives) and tree a with core.autocrlf=false (the committed LF
#            bytes). Shows whether line endings leak into the artefacts,
#            i.e. whether a Windows-made and a Linux-made snapshot of one
#            commit can build the same binary.
# All other exports use `git -c core.autocrlf=false archive`, so the build
# input is the committed bytes whatever the local git configuration says.
# For each variant the final artefacts (bombe.exe / bombe, libbombe.rlib,
# libturing.rlib) of a and b are hashed with SHA-256 and compared; for a
# differing pair the number of differing bytes (cmp -l) is printed.
# With TRIPLE=x86_64-unknown-linux-gnu the build goes through the
# repository's own tools/wsl_linux.py (the copy inside the snapshot; used,
# never modified), so the Linux ELF is linked by WSL gcc.
#
# The repository itself is never touched: cargo runs only inside OUTDIR.
# Every cargo call is wrapped in `timeout 1200`.
#
# Usage (Git Bash): sh research/scripts/pq/tcc_repro_build.sh REPO COMMIT OUTDIR [TRIPLE]
# TRIPLE defaults to x86_64-pc-windows-gnu (the host toolchain here).
set -eu
REPO=$1
COMMIT=$2
OUT=$3
TRIPLE=${4:-x86_64-pc-windows-gnu}
FULL=$(git -C "$REPO" rev-parse "$COMMIT")
CARGO_HOME_W=$(cygpath -w "${CARGO_HOME:-$HOME/.cargo}")
echo "commit $FULL, target $TRIPLE, $(cargo --version), $(rustc --version)"

build() {  # build VARIANT NAME
    variant=$1; name=$2
    src="$OUT/$variant/src-$name"; tgt="$OUT/$variant/target-$name"
    rm -rf "$src" "$tgt"; mkdir -p "$src"
    crlf=false
    if [ "$variant" = eol ] && [ "$name" = b ]; then crlf=true; fi
    git -c core.autocrlf=$crlf -C "$REPO" archive --format=tar "$FULL" | tar -x -C "$src"
    echo "  $variant/$name: core.autocrlf=$crlf, CR bytes in Cargo.lock: $(tr -cd '\r' < "$src/Cargo.lock" | wc -c)"
    srcw=$(cygpath -w "$src"); tgtw=$(cygpath -w "$tgt")
    remap="--remap-path-prefix=$srcw=/build/src --remap-path-prefix=$tgtw=/build/target --remap-path-prefix=$CARGO_HOME_W=/cargo"
    case $variant in
        plain) RUSTFLAGS="" ;;
        remap) RUSTFLAGS="$remap" ;;
        strip|eol) RUSTFLAGS="$remap -C strip=symbols"
               case $TRIPLE in *-windows-gnu) RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--no-insert-timestamp" ;; esac ;;
    esac
    export RUSTFLAGS
    export CARGO_TARGET_DIR="$tgtw"
    (
        cd "$src"
        if [ "$TRIPLE" = x86_64-unknown-linux-gnu ]; then
            timeout 1200 python tools/wsl_linux.py build --release --locked --offline --workspace > "$OUT/$variant/build-$name.log" 2>&1
        else
            timeout 1200 cargo build --release --locked --offline --workspace --target "$TRIPLE" > "$OUT/$variant/build-$name.log" 2>&1
        fi
    ) || { echo "build $variant/$name failed, see $OUT/$variant/build-$name.log"; tail -5 "$OUT/$variant/build-$name.log"; exit 1; }
}

artefacts() {  # artefacts DIR -> basenames of the final artefacts present
    # Git Bash resolves "bombe" to bombe.exe, so pick the binary name by target.
    case $TRIPLE in *-windows-*) bin=bombe.exe ;; *) bin=bombe ;; esac
    for f in $bin libbombe.rlib libturing.rlib; do
        [ -f "$1/$f" ] && echo "$f"
    done
    return 0
}

for variant in plain remap strip eol; do
    mkdir -p "$OUT/$variant"
    build $variant a
    build $variant b
    da="$OUT/$variant/target-a/$TRIPLE/release"; db="$OUT/$variant/target-b/$TRIPLE/release"
    n=0; same=0
    : > "$OUT/$variant/compare.txt"
    for f in $(artefacts "$da"); do
        n=$((n + 1))
        ha=$(sha256sum "$da/$f" | awk '{print $1}' | tr -d '\\')
        hb=$(sha256sum "$db/$f" | awk '{print $1}' | tr -d '\\')
        if [ "$ha" = "$hb" ]; then
            same=$((same + 1))
            echo "  same  $f  $ha" >> "$OUT/$variant/compare.txt"
        else
            nd=$(cmp -l "$da/$f" "$db/$f" 2>/dev/null | wc -l)
            echo "  DIFF  $f  a=$(echo $ha | cut -c1-16) b=$(echo $hb | cut -c1-16)  differing bytes: $nd" >> "$OUT/$variant/compare.txt"
        fi
    done
    echo "[$variant] artefacts compared: $n, identical: $same"
    cat "$OUT/$variant/compare.txt"
done
