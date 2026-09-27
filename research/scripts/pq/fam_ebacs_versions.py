"""Which scheme versions do the eBACS/SUPERCOP KEM benchmarks measure?

Reproduces the "version" column behind the speed numbers in
research/notes/pq/pq-families-for-diversity.md (Section 7 and Open question 3).

eBACS (Bernstein and Lange, https://bench.cr.yp.to/) names each primitive and gives a one-line
description on its primitive list (https://bench.cr.yp.to/primitives-kem.html), for example
"HQC-192 (2020.04 version)" or "FrodoKEM-976-AES (NISTPQC round 2)". The per-machine page gives the
median cycle counts. This script reads both saved pages and prints, for every primitive of the
families in the notes, its description and its medians on the machine page, so the reader can see
whether a cycle count belongs to the current specification or to an older one.

Inputs (third-party pages, kept in the scratch directory, not in the repository):
    PRIMS  = saved https://bench.cr.yp.to/primitives-kem.html
    MACHINE = saved https://bench.cr.yp.to/results-kem/amd64-freshwrap,big.html
Optionally, with --supercop DIR (an unpacked SUPERCOP tree, e.g. supercop-20260831 from
https://bench.cr.yp.to/supercop.html, kept in scratch), it also reads crypto_kem/*/api.h and checks
the key and ciphertext sizes, which identify the specification version of each build.
Run:
    python fam_ebacs_versions.py PRIMS MACHINE [--supercop DIR] [--negative-control]
Deterministic (pure parsing). Reuses the table parser of ebacs_kem_extract.py (not edited here).
The checks at the end assert the facts quoted in the notes; --negative-control plants a wrong
expected description and must fail.
"""
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ebacs_kem_extract import parse  # noqa: E402

FAMILY = re.compile(r"^(hqc|frodokem|mlkem|kyber|sntrup|ntrulpr|ntruhps|ntruhrss|bike|mceliece|saber|lightsaber|firesaber)")


def descriptions(path):
    """Map primitive name -> description from the eBACS primitive list."""
    t = open(path, encoding="utf-8", errors="replace").read()
    txt = html.unescape(re.sub(r"<[^>]+>", "|", t))
    txt = re.sub(r"\|+", "|", re.sub(r"[ \t\r\n]+", " ", txt))
    out = {}
    for m in re.finditer(r"\|\s*([a-z0-9]+)\s*\|([^|]{0,200})\|", txt):
        name, desc = m.group(1), m.group(2).strip()
        if FAMILY.match(name) and name not in out and desc and not re.fullmatch(r"[a-z0-9-]+", desc):
            out[name] = desc
    return out


def main():
    argv = sys.argv[1:]
    supercop = None
    if "--supercop" in argv:
        i = argv.index("--supercop")
        supercop = argv[i + 1]
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    neg = "--negative-control" in argv
    desc = descriptions(args[0])
    machine, res = parse(args[1])
    print("machine:", re.sub(r"\s+", " ", machine))
    names = sorted(set(n for n in res if FAMILY.match(n)) | set(desc))
    print(f"{'primitive':20s} {'keygen':>12s} {'encaps':>10s} {'decaps':>10s}  description (eBACS primitive list)")
    for n in names:
        r = res.get(n, {})
        vals = [r.get(k, (None, ""))[0] for k in ("keygen", "enc", "dec")]
        fmt = lambda v: f"{v:,}" if v is not None else "-"
        print(f"{n:20s} {fmt(vals[0]):>12s} {fmt(vals[1]):>10s} {fmt(vals[2]):>10s}  {desc.get(n, '(no description)')}")

    expect = {
        "hqc192": "HQC-192 (2020.04 version)",
        "hqc256": "HQC-256 (2020.04 version)",
        "frodokem976aes": "FrodoKEM-976-AES (NISTPQC round 2)",
        "frodokem1344aes": "FrodoKEM-1344-AES (NISTPQC round 2)",
        "bikel3": "BIKE Level 3 (2020.05 version)",
    }
    if neg:
        expect["hqc192"] = "HQC-192 (2025.08 version)"
        print("NEGATIVE CONTROL: planted a wrong expected description for hqc192; expect FAIL")
    fails = []
    print()
    for n, want in expect.items():
        ok = desc.get(n) == want
        print(f"  [{'ok' if ok else 'FAIL'}] {n} described as {want!r} (page says {desc.get(n)!r})")
        if not ok:
            fails.append(n)
    if supercop:
        # api.h sizes in the SUPERCOP source tree identify the specification version.
        # Expected values: FrodoKEM round 2 = eFrodoKEM sizes of the 2025 proposal Table A.6
        # (ct 15744, sk 31296); FrodoKEM round 1 carried a 24-byte tag (ct 15768);
        # HQC round 4 (the version NIST evaluated in IR 8545) has a 64-byte shared secret, while
        # the 2025-08-22 specification (Table 6) has ek 4514, dk 4602, ct 8978 and K = 32 bytes.
        want_api = {
            "frodokem976aes/optimized": {"PUBLICKEY": 15632, "SECRETKEY": 31296, "CIPHERTEXT": 15744, "": 24},
            "frodokem976/optimized": {"PUBLICKEY": 15632, "SECRETKEY": 31272, "CIPHERTEXT": 15768, "": 24},
            "hqc192round4/avx": {"PUBLICKEY": 4522, "SECRETKEY": 4586, "CIPHERTEXT": 8978, "": 64},
            "hqc192/avx": {"PUBLICKEY": 5690, "SECRETKEY": 5730, "CIPHERTEXT": 11364, "": 64},
        }
        print(f"\nSUPERCOP api.h sizes ({supercop}):")
        for impl, want in want_api.items():
            path = os.path.join(supercop, "crypto_kem", impl, "api.h")
            txt = open(path, encoding="utf-8", errors="replace").read()
            got = {k: int(v) for k, v in re.findall(r"#define\s+CRYPTO_(PUBLICKEY|SECRETKEY|CIPHERTEXT|)BYTES\s+(\d+)", txt)}
            ok = got == want
            print(f"  [{'ok' if ok else 'FAIL'}] {impl}: pk {got.get('PUBLICKEY')}, sk {got.get('SECRETKEY')},"
                  f" ct {got.get('CIPHERTEXT')}, shared secret {got.get('')}")
            if not ok:
                fails.append(impl)
    if fails:
        print("FAILED:", fails)
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()
