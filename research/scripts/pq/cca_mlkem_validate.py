"""Validate cca_mlkem_ref.py (pure-Python FIPS 203) against public vectors,
with negative controls that show which vectors catch which skipped check.

Reproduces / checks:
  * NIST ACVP-Server sample vectors (github.com/usnistgov/ACVP-Server,
    gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json and
    ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json): keyGen,
    encapsulation, decapsulation (seed and expanded key formats; valid and
    "modified ciphertext" = implicit-rejection cases), encapsulationKeyCheck
    ("noisy linear system values too large") and decapsulationKeyCheck
    ("modified H"). Test descriptions: draft-celi-acvp-ml-kem-01, Sec. 6.
  * C2SP CCTV ML-KEM vectors (github.com/C2SP/CCTV/tree/main/ML-KEM):
    modulus/ (invalid encapsulation keys; every one must be rejected) and
    strcmp/ (ciphertexts that a strcmp()-style comparison would wrongly
    accept).
  * Negative controls: the same vectors run against deliberately broken
    variants (modulus check skipped, hash check skipped, strcmp-style
    comparison, FO re-encryption check skipped) must FAIL, proving the
    vectors can detect each bug.

Usage: python cca_mlkem_validate.py VECTOR_DIR
  VECTOR_DIR contains acvp/ML-KEM-keyGen-FIPS203/internalProjection.json,
  acvp/ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json and
  cctv/{modulus-ML-KEM-*.txt.gz, strcmp-ML-KEM-*.txt} (downloaded to the
  scratch directory, never the repo). Deterministic; prints one line per check.
"""
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cca_mlkem_ref as M  # noqa: E402

root = sys.argv[1]
failures = 0


def report(name, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def hx(s):
    return bytes.fromhex(s)


# ------------------------------------------------------------- ACVP keyGen
kg = json.load(open(os.path.join(root, "acvp/ML-KEM-keyGen-FIPS203/internalProjection.json")))
for g in kg["testGroups"]:
    p = M.PARAMS[g["parameterSet"]]
    ok = 0
    for t in g["tests"]:
        ek, dk = M.keygen_internal(hx(t["d"]), hx(t["z"]), p)
        ok += (ek == hx(t["ek"]) and dk == hx(t["dk"]))
    report(f"ACVP keyGen {g['parameterSet']}", ok == len(g["tests"]), f"{ok}/{len(g['tests'])}")

# ---------------------------------------------------- ACVP encapDecap (tr1)
ed = json.load(open(os.path.join(root, "acvp/ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json")))


def skip_fo_check(a, b):          # bug: accept every ciphertext
    return True


for g in ed["testGroups"]:
    ps, fn, fmt = g["parameterSet"], g["function"], g.get("keyFormat")
    p = M.PARAMS[ps]
    tests = g["tests"]
    if fn == "encapsulation":
        ok = 0
        for t in tests:
            ek = hx(t["ek"])
            K, c = M.encaps_internal(ek, hx(t["m"]), p)
            ok += (M.check_ek(ek, p) and K == hx(t["k"]) and c == hx(t["c"]))
        report(f"ACVP encaps {ps}", ok == len(tests), f"{ok}/{len(tests)}")
    elif fn == "decapsulation":
        ok = bad_ok = n_mod = 0
        for t in tests:
            if fmt == "seed":
                _, dk = M.keygen_internal(hx(t["d"]), hx(t["z"]), p)
            else:
                dk = hx(t["dk"])
            c = hx(t["c"])
            ok += (M.check_ct(c, p) and M.check_dk(dk, p)
                   and M.decaps_internal(dk, c, p) == hx(t["k"]))
            if t["reason"] == "modified ciphertext":
                n_mod += 1
                bad_ok += (M.decaps_internal(dk, c, p, compare=skip_fo_check) == hx(t["k"]))
        report(f"ACVP decaps {ps} keyFormat={fmt}", ok == len(tests), f"{ok}/{len(tests)}")
        report(f"  negative control (FO check skipped) {ps} {fmt}: modified-ciphertext cases must mismatch",
               bad_ok == 0, f"{n_mod - bad_ok}/{n_mod} caught")
    elif fn == "encapsulationKeyCheck":
        ok = caught_by_nocheck = n_bad = 0
        for t in tests:
            ek = hx(t["ek"])
            ok += (M.check_ek(ek, p) == t["testPassed"])
            if not t["testPassed"]:
                n_bad += 1
                caught_by_nocheck += (len(ek) != 384 * p[0] + 32)   # type check only
        report(f"ACVP encapsulationKeyCheck {ps}", ok == len(tests), f"{ok}/{len(tests)}")
        report(f"  negative control (modulus check skipped) {ps}: invalid keys accepted",
               caught_by_nocheck == 0, f"{n_bad - caught_by_nocheck}/{n_bad} would be accepted")
    elif fn == "decapsulationKeyCheck":
        ok = caught_by_nocheck = n_bad = 0
        for t in tests:
            dk = hx(t["dk"])
            ok += (M.check_dk(dk, p) == t["testPassed"])
            if not t["testPassed"]:
                n_bad += 1
                caught_by_nocheck += (len(dk) != 768 * p[0] + 96)   # type check only
        report(f"ACVP decapsulationKeyCheck {ps}", ok == len(tests), f"{ok}/{len(tests)}")
        report(f"  negative control (hash check skipped) {ps}: invalid keys accepted",
               caught_by_nocheck == 0, f"{n_bad - caught_by_nocheck}/{n_bad} would be accepted")

# -------------------------------------------------------- CCTV modulus/
for ps in M.PARAMS:
    p = M.PARAMS[ps]
    lines = gzip.open(os.path.join(root, f"cctv/modulus-{ps}.txt.gz"), "rt").read().split()
    rejected = sum(not M.check_ek(hx(x), p) for x in lines)
    report(f"CCTV modulus {ps}: all invalid keys rejected", rejected == len(lines), f"{rejected}/{len(lines)}")
    type_only = sum(len(hx(x)) != 384 * p[0] + 32 for x in lines)
    report(f"  negative control (type check only) {ps}", type_only == 0,
           f"{len(lines) - type_only}/{len(lines)} would be accepted without the modulus check")


# --------------------------------------------------------- CCTV strcmp/
def strcmp_like(a, b):
    """C strcmp(): compares until the first differing byte OR a zero byte."""
    for x, y in zip(a, b):
        if x != y:
            return False
        if x == 0:
            return True
    return len(a) == len(b)


for ps in M.PARAMS:
    p = M.PARAMS[ps]
    fields = {}
    for line in open(os.path.join(root, f"cctv/strcmp-{ps}.txt")):
        if "=" in line:
            k_, v_ = line.split("=", 1)
            fields[k_.strip()] = hx(v_.strip())
    dk, c, K = fields["dk"], fields["c"], fields["K"]
    good = M.decaps_internal(dk, c, p)
    report(f"CCTV strcmp {ps}: correct comparison gives expected K", good == K)
    bad = M.decaps_internal(dk, c, p, compare=strcmp_like)
    report(f"  negative control (strcmp-like comparison) {ps}: wrong K", bad != K)

print("TOTAL FAILURES:", failures)
sys.exit(1 if failures else 0)
