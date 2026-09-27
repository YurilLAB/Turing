"""Check that every expected value hard-coded in tcc_check_pq_vectors.py
appears in the primary source it was taken from.

What it reproduces, and from which source:
  * RFC 7748 Sec. 5.2 and 6.1 X25519 values: the RFC text
    (https://www.rfc-editor.org/rfc/rfc7748.txt, saved as SCRATCH/web/rfc7748.txt).
  * CCTV accumulated 10 000-test hashes: C2SP/CCTV ML-KEM/README.md
    (saved as SCRATCH/cctv-mlkem-README.now.md).
  * Go TestAccumulated hashes: golang/go src/crypto/mlkem/mlkem_test.go at
    commit afae85307206 (saved as SCRATCH/web/go-mlkem_test.go).

Usage:
    python research/scripts/pq/tcc_verify_sources.py SCRATCH_PQ_DIR

Deterministic; prints one line per constant; exits 1 on any miss. The last
line is a negative control: a value with one changed hex digit must NOT be
found.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tcc_check_pq_vectors as chk  # noqa: E402

RFC7748 = [
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
    "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
]


def flat(path):
    return re.sub(r"\s+", "", open(path, encoding="utf-8").read())


def main():
    root = sys.argv[1]
    misses = 0
    script = open(chk.__file__, encoding="utf-8").read()
    rfc = flat(os.path.join(root, "web", "rfc7748.txt"))
    for v in RFC7748:
        ok = v in rfc and v in script
        misses += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] RFC 7748 value {v[:16]}... in RFC text and in check script")
    readme = flat(os.path.join(root, "cctv-mlkem-README.now.md"))
    for name, v in chk.CCTV_ACC_10K.items():
        ok = v in readme
        misses += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] CCTV accumulated 10k {name} {v[:16]}... in README")
    go = open(os.path.join(root, "web", "go-mlkem_test.go"), encoding="utf-8").read()
    for n, v in chk.GO_ACC.items():
        ok = f'"{v}"' in go
        misses += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] Go TestAccumulated n={n} {v[:16]}... in mlkem_test.go")
    bad = "0" + chk.GO_ACC[10000][1:] if chk.GO_ACC[10000][0] != "0" else "1" + chk.GO_ACC[10000][1:]
    ok = bad not in go
    misses += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] negative control: altered Go value not found")
    sys.exit(1 if misses else 0)


if __name__ == "__main__":
    main()
