"""Run the pure-Python FIPS 203 reference (cca_mlkem_ref.py) against the
C2SP/Wycheproof ML-KEM test vectors, with negative controls that show which
vectors catch which skipped input check.

Vector source: github.com/C2SP/wycheproof, directory testvectors_v1,
files mlkem_{512,768,1024}_{test,encaps_test,semi_expanded_decaps_test,
keygen_seed_test}.json (last change to mlkem_768_test.json on main:
commit 3fa63dd0, 2026-09-02, checked 2026-09-27). Downloaded to the scratch
directory, never the repo.

Checks reproduce FIPS 203 (research/papers/nist-fips-203-ml-kem.pdf):
  * Alg. 16 key generation from the 64-byte seed d || z (keygen_seed, test);
  * Sec. 7.2 encapsulation-key type + modulus check (encaps_test: the
    'ModulusOverflow' vectors come from CCTV/modulus; 'Public key not
    reduced' vectors);
  * Sec. 7.3 decapsulation input checks: ciphertext length, dk length,
    hash check H(ek) = h (semi_expanded_decaps_test);
  * Alg. 18 implicit rejection, including the CCTV 'Strcmp' vector and the
    'MalleableCiphertext' vectors (test).
Negative controls (each must make at least one vector FAIL, proving the
vectors detect that bug):
  NC1 skip the modulus check          -> invalid encapsulation keys accepted
  NC2 skip the dk hash check          -> invalid decapsulation keys accepted
  NC3 strcmp()-style comparison       -> Strcmp vector gives the wrong K
  NC4 skip the FO comparison entirely -> MalleableCiphertext vectors give wrong K

Usage: python cca_wycheproof_check.py WYCHEPROOF_DIR   (deterministic)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cca_mlkem_ref as M  # noqa: E402

root = sys.argv[1]
fails = 0


def report(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def hx(s):
    return bytes.fromhex(s)


def load(name):
    with open(os.path.join(root, name), encoding="utf-8") as f:
        return json.load(f)


def strcmp_like(a, b):
    for x, y in zip(a, b):
        if x != y:
            return False
        if x == 0:
            return True
    return len(a) == len(b)


def accept_all(a, b):
    return True


def check_ek_type_only(ek, p):
    return len(ek) == 384 * p[0] + 32


def check_dk_type_only(dk, p):
    return len(dk) == 768 * p[0] + 96


for bits in (512, 768, 1024):
    ps = f"ML-KEM-{bits}"
    p = M.PARAMS[ps]
    k, _, _, du, dv = p

    # ---------------------------------------------------------- keygen_seed
    d = load(f"mlkem_{bits}_keygen_seed_test.json")
    ok = n = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            n += 1
            seed = hx(t["seed"])
            ek, dk = M.keygen_internal(seed[:32], seed[32:], p)
            ok += (ek == hx(t["ek"]) and dk == hx(t["dk"])) == (t["result"] == "valid")
    report(f"{ps} keygen_seed (d||z -> ek, dk)", ok == n, f"{ok}/{n}")

    # --------------------------------------------------------------- encaps
    d = load(f"mlkem_{bits}_encaps_test.json")
    ok = n = nc1_accepted = n_invalid = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            n += 1
            ek, m = hx(t["ek"]), hx(t["m"])
            valid = t["result"] == "valid"
            passed = M.check_ek(ek, p)
            if passed and valid:
                K, c = M.encaps_internal(ek, m, p)
                good = K == hx(t["K"]) and c == hx(t["c"])
            else:
                good = passed == valid
            ok += good
            if not valid:
                n_invalid += 1
                nc1_accepted += check_ek_type_only(ek, p)
    report(f"{ps} encaps (Sec 7.2 checks + Alg 17)", ok == n, f"{ok}/{n}")
    report(f"  NC1 modulus check skipped: invalid keys accepted", nc1_accepted > 0,
           f"{nc1_accepted}/{n_invalid} invalid encapsulation keys would be accepted")

    # ------------------------------------------------ semi-expanded decaps
    d = load(f"mlkem_{bits}_semi_expanded_decaps_test.json")
    ok = n = nc2_accepted = n_badkey = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            n += 1
            dk, c = hx(t["dk"]), hx(t["c"])
            valid = t["result"] == "valid"
            passed = M.check_ct(c, p) and M.check_dk(dk, p)
            if passed and valid:
                good = M.decaps_internal(dk, c, p) == hx(t["K"])
            else:
                good = passed == valid
            ok += good
            if "InvalidDecapsulationKey" in t.get("flags", []):
                n_badkey += 1
                nc2_accepted += M.check_ct(c, p) and check_dk_type_only(dk, p)
    report(f"{ps} semi_expanded_decaps (Sec 7.3 checks + Alg 18)", ok == n, f"{ok}/{n}")
    report(f"  NC2 dk hash check skipped: invalid dk accepted", nc2_accepted > 0,
           f"{nc2_accepted}/{n_badkey} InvalidDecapsulationKey vectors would be accepted")

    # ------------------------------------------------------------- test
    d = load(f"mlkem_{bits}_test.json")
    ok = n = 0
    strcmp_wrong = n_strcmp = fo_wrong = n_mall = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            n += 1
            seed, c = hx(t["seed"]), hx(t["c"])
            valid = t["result"] == "valid"
            if len(seed) != 64 or not M.check_ct(c, p):
                ok += not valid
                continue
            ek, dk = M.keygen_internal(seed[:32], seed[32:], p)
            if t.get("ek") and ek != hx(t["ek"]):
                ok += not valid
                continue
            K = M.decaps_internal(dk, c, p)
            ok += (K == hx(t["K"])) if valid else False
            flags = t.get("flags", [])
            if "Strcmp" in flags:
                n_strcmp += 1
                strcmp_wrong += M.decaps_internal(dk, c, p, compare=strcmp_like) != hx(t["K"])
            if "MalleableCiphertext" in flags:
                n_mall += 1
                fo_wrong += M.decaps_internal(dk, c, p, compare=accept_all) != hx(t["K"])
    report(f"{ps} test (seed keygen + Alg 18 implicit rejection)", ok == n, f"{ok}/{n}")
    report(f"  NC3 strcmp-style comparison: Strcmp vector wrong", strcmp_wrong == n_strcmp and n_strcmp > 0,
           f"{strcmp_wrong}/{n_strcmp}")
    report(f"  NC4 FO comparison skipped: MalleableCiphertext vectors wrong", fo_wrong == n_mall and n_mall > 0,
           f"{fo_wrong}/{n_mall}")

print("TOTAL FAILURES:", fails)
sys.exit(1 if fails else 0)
