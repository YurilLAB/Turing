#!/bin/sh
# tcc_pq_sign_demo.sh - can Turing's release artefacts be signed with a
# post-quantum signature using tools already on this machine?
#
# What it reproduces, and from which source:
#   * OpenSSL 3.5.0 added "Support for PQC algorithms (ML-KEM, ML-DSA and
#     SLH-DSA)" (openssl/openssl NEWS.md, 3.4 -> 3.5.0 section, 8 Apr 2025).
#   * Signature and key sizes are compared by the notes with FIPS 204
#     Table 2 (ML-DSA) and FIPS 205 Table 2 (SLH-DSA).
# It generates throw-away keys in OUTDIR, signs a test file with ML-DSA-87 and
# SLH-DSA-SHAKE-256s using the OpenSSL on the Windows side (Git Bash), then
# verifies each signature with a second OpenSSL build inside WSL (Ubuntu),
# and runs a negative control (one flipped byte must fail verification).
# The keys are demonstration keys only and are deleted at the end.
#
# Usage (Git Bash):  sh research/scripts/pq/tcc_pq_sign_demo.sh OUTDIR
# Every openssl and wsl call is wrapped in `timeout 120`.
set -eu
OUT=$1
mkdir -p "$OUT"
cd "$OUT"
# a deterministic 1 MiB stand-in for a release archive
python -c "import hashlib,sys; sys.stdout.buffer.write(hashlib.shake_256(b'turing-release-demo').digest(1<<20))" > artefact.bin
WSLDIR=$(printf '%s' "$(pwd -W)" | sed -E 's#^([A-Za-z]):#/mnt/\L\1#')
echo "win openssl: $(timeout 120 openssl version)"
echo "wsl openssl: $(MSYS_NO_PATHCONV=1 timeout 120 wsl.exe -d Ubuntu -e openssl version)"
for alg in ML-DSA-87 SLH-DSA-SHAKE-256s; do
  t0=$(date +%s.%N)
  timeout 120 openssl genpkey -algorithm "$alg" -out "$alg.key" 2>/dev/null
  timeout 120 openssl pkey -in "$alg.key" -pubout -out "$alg.pub"
  t1=$(date +%s.%N)
  timeout 120 openssl pkeyutl -sign -inkey "$alg.key" -rawin -in artefact.bin -out "$alg.sig"
  t2=$(date +%s.%N)
  pubder=$(timeout 120 openssl pkey -pubin -in "$alg.pub" -outform DER | wc -c)
  echo "$alg: signature $(wc -c < "$alg.sig") bytes, public key DER $pubder bytes, keygen $(echo "$t0 $t1" | awk '{printf "%.2f", $2-$1}') s, sign $(echo "$t1 $t2" | awk '{printf "%.2f", $2-$1}') s"
  if MSYS_NO_PATHCONV=1 timeout 120 wsl.exe -d Ubuntu --cd "$WSLDIR" -e openssl pkeyutl -verify -pubin -inkey "$alg.pub" -rawin -in artefact.bin -sigfile "$alg.sig" >/dev/null 2>&1; then
    echo "[PASS] $alg signature from Windows OpenSSL verifies with WSL OpenSSL"
  else
    echo "[FAIL] $alg cross-verification"
  fi
  python -c "import sys; b=bytearray(open('artefact.bin','rb').read()); b[12345]^=1; open('tampered.bin','wb').write(b)"
  if MSYS_NO_PATHCONV=1 timeout 120 wsl.exe -d Ubuntu --cd "$WSLDIR" -e openssl pkeyutl -verify -pubin -inkey "$alg.pub" -rawin -in tampered.bin -sigfile "$alg.sig" >/dev/null 2>&1; then
    echo "[FAIL] negative control: $alg accepted a tampered file"
  else
    echo "[PASS] negative control: $alg rejects a file with one flipped bit"
  fi
done
rm -f ./*.key ./*.pub ./*.sig artefact.bin tampered.bin
