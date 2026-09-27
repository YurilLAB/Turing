"""Check public PQ test-vector sets against two small independent oracles.

What it reproduces, and from which source:

  * NIST ACVP-Server sample JSON for ML-KEM (github.com/usnistgov/ACVP-Server,
    gen-val/json-files/ML-KEM-keyGen-FIPS203, ML-KEM-encapDecap-FIPS203,
    ML-KEM-encapDecap-FIPS203-tr1): every test case.
  * C2SP Wycheproof testvectors_v1/mlkem_{512,768,1024}_*.json and
    x25519_test.json (github.com/C2SP/wycheproof): every test case.
  * C2SP CCTV ML-KEM (github.com/C2SP/CCTV/tree/main/ML-KEM): intermediate/,
    unluckysample/, strcmp/, modulus/. Each keyed file is tried against the
    final FIPS 203 key generation and against the initial public draft
    (ipd) key generation, to find out which one it was generated with.
  * Go's crypto/mlkem TestAccumulated 100-iteration value for ML-KEM-768
    (src/crypto/mlkem/mlkem_test.go, expected
    1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415).
  * RFC 7748 Sec. 5.2 (X25519 vectors, 1 and 1000 iterations) and Sec. 6.1
    (Diffie-Hellman example).
  * draft-connolly-cfrg-xwing-kem-11 Appendix C test vectors.
  * Optional (--accumulated N): the CCTV "accumulated pq-crystals" hash for
    N = 10000 tests, computed with final and with ipd key generation.

The ML-KEM oracle is research/scripts/pq/tcc_mlkem_oracle.py (pure Python, FIPS 203).
X25519 is implemented below from RFC 7748 Sec. 5 (Montgomery ladder).

Usage (vectors are downloaded to the scratch directory, never the repo):
    python research/scripts/pq/tcc_check_pq_vectors.py VECTOR_ROOT [--accumulated N PARAMSET]
    python research/scripts/pq/tcc_check_pq_vectors.py VECTOR_ROOT --go-accumulated N
        (Go crypto/mlkem TestAccumulated for ML-KEM-768 with N tests, final
        and ipd key generation; expected values for N = 100, 10000, 1000000)

VECTOR_ROOT holds acvp/, cctv/, wycheproof/, xwing/ as laid out by the
download commands in research/notes/pq/testing-ci-cd.md. The script is
deterministic and prints one line per check.
"""
import gzip
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tcc_mlkem_oracle import MLKEM, PARAMS  # noqa: E402

FAILURES = []


def report(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        FAILURES.append(name)


def hx(s):
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# X25519, RFC 7748 Sec. 5
P25519 = 2**255 - 19
A24 = 121665


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar = int.from_bytes(k, "little")
    u = bytearray(u)
    u[31] &= 127
    x1 = int.from_bytes(u, "little") % P25519
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % P25519
        aa = a * a % P25519
        b = (x2 - z2) % P25519
        bb = b * b % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da = d * a % P25519
        cb = c * b % P25519
        x3 = (da + cb) ** 2 % P25519
        z3 = x1 * (da - cb) ** 2 % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + A24 * e) % P25519
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def check_rfc7748():
    v = [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ]
    for i, (k, u, out) in enumerate(v):
        report(f"RFC7748 5.2 vector {i + 1}", x25519(hx(k), hx(u)).hex() == out)
    k = u = BASE
    results = {}
    for it in range(1, 1001):
        k, u = x25519(k, u), k
        if it in (1, 1000):
            results[it] = k.hex()
    report("RFC7748 5.2 iterated x1", results[1] == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    report("RFC7748 5.2 iterated x1000", results[1000] == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    a = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = hx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    pa, pb = x25519(a, BASE), x25519(b, BASE)
    ok = (pa.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
          and pb.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
          and x25519(a, pb) == x25519(b, pa)
          and x25519(a, pb).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    report("RFC7748 6.1 Diffie-Hellman", ok)


def check_wycheproof_x25519(root):
    j = json.load(open(os.path.join(root, "wycheproof", "x25519_test.json"), encoding="utf-8"))
    n = bad = 0
    for g in j["testGroups"]:
        for t in g["tests"]:
            n += 1
            got = x25519(hx(t["private"]), hx(t["public"])).hex()
            if got != t["shared"]:
                bad += 1
    report("Wycheproof x25519_test.json", bad == 0, f"{n} tests, {bad} mismatches (valid and acceptable both compared)")


# ---------------------------------------------------------------------------
# NIST ACVP
def acvp_groups(path):
    j = json.load(open(path, encoding="utf-8"))
    if isinstance(j, list):
        j = [x for x in j if "testGroups" in x][0]
    return j["testGroups"]


def check_acvp(root):
    base = os.path.join(root, "acvp")
    d = os.path.join(base, "ML-KEM-keyGen-FIPS203")
    exp = {(g["tgId"], t["tcId"]): t for g in acvp_groups(os.path.join(d, "expectedResults.json")) for t in g["tests"]}
    n = bad = 0
    for g in acvp_groups(os.path.join(d, "prompt.json")):
        kem = MLKEM(g["parameterSet"])
        for t in g["tests"]:
            n += 1
            ek, dk = kem.keygen(hx(t["d"]), hx(t["z"]))
            x = exp[(g["tgId"], t["tcId"])]
            if ek != hx(x["ek"]) or dk != hx(x["dk"]):
                bad += 1
    report("ACVP ML-KEM-keyGen-FIPS203", bad == 0, f"{n} tests, {bad} mismatches")

    for rev in ("ML-KEM-encapDecap-FIPS203", "ML-KEM-encapDecap-FIPS203-tr1"):
        d = os.path.join(base, rev)
        exp = {(g["tgId"], t["tcId"]): t for g in acvp_groups(os.path.join(d, "expectedResults.json")) for t in g["tests"]}
        counts = {}
        for g in acvp_groups(os.path.join(d, "prompt.json")):
            kem = MLKEM(g["parameterSet"])
            fn = g["function"] + ("/" + g["keyFormat"] if "keyFormat" in g else "")
            c = counts.setdefault(fn, [0, 0])
            for t in g["tests"]:
                c[0] += 1
                x = exp[(g["tgId"], t["tcId"])]
                if g["function"] == "encapsulation":
                    K, ct = kem.encaps(hx(t["ek"]), hx(t["m"]))
                    ok = kem.ek_check(hx(t["ek"])) and K == hx(x["k"]) and ct == hx(x["c"])
                elif g["function"] == "decapsulation":
                    if g.get("keyFormat") == "seed":
                        _, dk = kem.keygen(hx(t["d"]), hx(t["z"]))
                    else:
                        dk = hx(t["dk"])
                    ok = kem.decaps(dk, hx(t["c"])) == hx(x["k"])
                elif g["function"] == "encapsulationKeyCheck":
                    ok = kem.ek_check(hx(t["ek"])) == x["testPassed"]
                elif g["function"] == "decapsulationKeyCheck":
                    ok = kem.dk_check(hx(t["dk"])) == x["testPassed"]
                else:
                    ok = False
                if not ok:
                    c[1] += 1
        for fn, (n, bad) in sorted(counts.items()):
            report(f"ACVP {rev} {fn}", bad == 0, f"{n} tests, {bad} mismatches")


# ---------------------------------------------------------------------------
# Wycheproof ML-KEM
def check_wycheproof_mlkem(root):
    base = os.path.join(root, "wycheproof")
    for bits in ("512", "768", "1024"):
        name = f"ML-KEM-{bits}"
        kem = MLKEM(name)
        # MLKEMTest: seed -> keygen (ek must match), then decaps(c) -> K.
        j = json.load(open(os.path.join(base, f"mlkem_{bits}_test.json"), encoding="utf-8"))
        n = bad = 0
        for g in j["testGroups"]:
            for t in g["tests"]:
                n += 1
                seed, c = hx(t["seed"]), hx(t["c"])
                if len(seed) != 64:
                    ok = t["result"] == "invalid"
                else:
                    ek, dk = kem.keygen(seed[:32], seed[32:])
                    if len(c) != kem.ct_len:
                        ok = t["result"] == "invalid"
                    else:
                        # every "invalid" case in these files is a length
                        # error, so a well-formed input must be "valid"
                        K = kem.decaps(dk, c)
                        ok = t["result"] == "valid" and ek == hx(t["ek"]) and K == hx(t["K"])
                if not ok:
                    bad += 1
        report(f"Wycheproof mlkem_{bits}_test.json", bad == 0, f"{n} tests, {bad} mismatches")
        # MLKEMEncapsTest: ek, m -> c, K; invalid when the ek check fails.
        j = json.load(open(os.path.join(base, f"mlkem_{bits}_encaps_test.json"), encoding="utf-8"))
        n = bad = 0
        for g in j["testGroups"]:
            for t in g["tests"]:
                n += 1
                ek = hx(t["ek"])
                if not kem.ek_check(ek):
                    ok = t["result"] == "invalid"
                else:
                    K, c = kem.encaps(ek, hx(t["m"]))
                    ok = t["result"] == "valid" and K == hx(t["K"]) and c == hx(t["c"])
                if not ok:
                    bad += 1
        report(f"Wycheproof mlkem_{bits}_encaps_test.json", bad == 0, f"{n} tests, {bad} mismatches")
        # MLKEMKeyGen seed format.
        j = json.load(open(os.path.join(base, f"mlkem_{bits}_keygen_seed_test.json"), encoding="utf-8"))
        n = bad = 0
        for g in j["testGroups"]:
            for t in g["tests"]:
                n += 1
                seed = hx(t["seed"])
                ek, dk = kem.keygen(seed[:32], seed[32:])
                if not (t["result"] == "valid" and ek == hx(t["ek"]) and dk == hx(t["dk"])):
                    bad += 1
        report(f"Wycheproof mlkem_{bits}_keygen_seed_test.json", bad == 0, f"{n} tests, {bad} mismatches")
        # Decaps validation with an expanded dk.
        j = json.load(open(os.path.join(base, f"mlkem_{bits}_semi_expanded_decaps_test.json"), encoding="utf-8"))
        n = bad = 0
        for g in j["testGroups"]:
            for t in g["tests"]:
                n += 1
                dk, c = hx(t["dk"]), hx(t["c"])
                if not kem.dk_check(dk) or len(c) != kem.ct_len:
                    ok = t["result"] == "invalid"
                else:
                    K = kem.decaps(dk, c)
                    ok = t["result"] == "valid" and ("K" not in t or K == hx(t["K"]))
                if not ok:
                    bad += 1
                    print("    mismatch:", t["tcId"], t.get("comment"), t["result"])
        report(f"Wycheproof mlkem_{bits}_semi_expanded_decaps_test.json", bad == 0, f"{n} tests, {bad} mismatches")


# ---------------------------------------------------------------------------
# C2SP CCTV ML-KEM
def parse_blocks(path):
    """'name = hex' lines; a blank line starts a new block."""
    blocks, cur = [], {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v.strip()
    if cur:
        blocks.append(cur)
    return blocks


def check_cctv(root):
    base = os.path.join(root, "cctv")
    for name in PARAMS:
        # intermediate values: which key generation produced rho, sigma, ek?
        b = parse_blocks(os.path.join(base, "intermediate", f"{name}.txt"))
        vals = {}
        for blk in b:
            for k, v in blk.items():
                vals.setdefault(k, v)
        d = hx(vals["d"])
        k = PARAMS[name][0]
        g_final = hashlib.sha3_512(d + bytes([k])).digest()
        g_ipd = hashlib.sha3_512(d).digest()
        rho_sigma = vals["ρ"] + vals["σ"]
        which = "final" if g_final.hex() == rho_sigma else "ipd" if g_ipd.hex() == rho_sigma else "neither"
        print(f"[INFO] CCTV intermediate/{name}: (rho, sigma) matches {which} FIPS 203 key generation")
        for mode in ("final", "ipd"):
            kem = MLKEM(name, ipd=(mode == "ipd"))
            ek, dk = kem.keygen(d, hx(vals["z"]))
            K, c = kem.encaps(ek, hx(vals["m"]))
            ok = ek.hex() == vals["ek"] and dk.hex() == vals["dk"] and K.hex() == vals["K"] and c.hex() == vals["c"]
            print(f"[INFO] CCTV intermediate/{name} full reproduction with {mode} key generation: {ok}")
            if mode == "ipd":
                report(f"CCTV intermediate/{name} consistent (ipd)", ok)

        # unlucky vectors
        for blk in parse_blocks(os.path.join(base, "unluckysample", f"{name}.txt")):
            for mode in ("final", "ipd"):
                kem = MLKEM(name, ipd=(mode == "ipd"))
                stats = []
                ek, dk = kem.keygen(hx(blk["d"]), hx(blk["z"]), stats)
                K, c = kem.encaps(ek, hx(blk["m"]))
                ok = ek.hex() == blk["ek"] and dk.hex() == blk["dk"] and K.hex() == blk["K"] and c.hex() == blk["c"]
                print(f"[INFO] CCTV unluckysample/{name} with {mode} key generation: reproduces={ok}, "
                      f"max SampleNTT XOF bytes over the matrix = {max(stats)}")
                if mode == "ipd":
                    report(f"CCTV unluckysample/{name} consistent (ipd)", ok)

        # strcmp vectors: decapsulation only (independent of key generation)
        kem = MLKEM(name)
        n = bad = 0
        for blk in parse_blocks(os.path.join(base, "strcmp", f"{name}.txt")):
            n += 1
            if kem.decaps(hx(blk["dk"]), hx(blk["c"])).hex() != blk["K"]:
                bad += 1
        report(f"CCTV strcmp/{name}", bad == 0, f"{n} vectors, {bad} mismatches (decapsulation only)")

        # modulus vectors: every line is an invalid encapsulation key
        n = accepted = 0
        with gzip.open(os.path.join(base, "modulus", f"{name}.txt.gz"), "rt") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                n += 1
                if kem.ek_check(hx(line)):
                    accepted += 1
        report(f"CCTV modulus/{name}", accepted == 0, f"{n} invalid keys, {accepted} wrongly accepted")


# ---------------------------------------------------------------------------
GO_ACC = {
    # golang/go src/crypto/mlkem/mlkem_test.go, TestAccumulated (ML-KEM-768,
    # final FIPS 203), read 2026-09-27 at commit afae85307206.
    100: "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415",
    10000: "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc",
    1000000: "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0",
}


def go_accumulated(n, ipd=False):
    """Go TestAccumulated: RNG = SHAKE-128(''); per test read seed = d || z
    (64 B), msg (32 B), ct1 (ct_len B); write ek, ct, k, Decaps(ct1)."""
    kem = MLKEM("ML-KEM-768", ipd=ipd)
    per = 64 + 32 + kem.ct_len
    stream = hashlib.shake_128(b"").digest(per * n)
    out = hashlib.shake_128()
    pos = 0
    ok_k = True
    for _ in range(n):
        seed = stream[pos:pos + 64]; pos += 64
        ek, dk = kem.keygen(seed[:32], seed[32:])
        msg = stream[pos:pos + 32]; pos += 32
        K, ct = kem.encaps(ek, msg)
        ok_k &= kem.decaps(dk, ct) == K
        ct1 = stream[pos:pos + kem.ct_len]; pos += kem.ct_len
        out.update(ek + ct + K + kem.decaps(dk, ct1))
    return ok_k, out.digest(32).hex()


def check_go_accumulated_100():
    kem = MLKEM("ML-KEM-768")
    n = 100
    per = 64 + 32 + kem.ct_len
    stream = hashlib.shake_128(b"").digest(per * n)
    out = bytearray()
    pos = 0
    ok_k = True
    for _ in range(n):
        seed = stream[pos:pos + 64]; pos += 64
        ek, dk = kem.keygen(seed[:32], seed[32:])
        out += ek
        msg = stream[pos:pos + 32]; pos += 32
        K, ct = kem.encaps(ek, msg)
        out += ct + K
        ok_k &= kem.decaps(dk, ct) == K
        ct1 = stream[pos:pos + kem.ct_len]; pos += kem.ct_len
        out += kem.decaps(dk, ct1)
    got = hashlib.shake_128(bytes(out)).digest(32).hex()
    report("Go crypto/mlkem TestAccumulated n=100 (ML-KEM-768)",
           ok_k and got == "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415", got)


def cctv_accumulated(name, n, ipd):
    """CCTV README: RNG = SHAKE-128(''); per test draw d, z, m, ct; write ek, dk, ct, k, k(random ct)."""
    kem = MLKEM(name, ipd=ipd)
    per = 32 * 3 + kem.ct_len
    stream = hashlib.shake_128(b"").digest(per * n)
    acc = hashlib.shake_128()
    pos = 0
    for _ in range(n):
        d = stream[pos:pos + 32]; pos += 32
        z = stream[pos:pos + 32]; pos += 32
        m = stream[pos:pos + 32]; pos += 32
        ctr = stream[pos:pos + kem.ct_len]; pos += kem.ct_len
        ek, dk = kem.keygen(d, z)
        K, ct = kem.encaps(ek, m)
        assert kem.decaps(dk, ct) == K
        acc.update(ek + dk + ct + K + kem.decaps(dk, ctr))
    return acc.digest(32).hex()


CCTV_ACC_10K = {
    "ML-KEM-512": "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
    "ML-KEM-768": "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
    "ML-KEM-1024": "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
}


# ---------------------------------------------------------------------------
def negative_controls(root):
    """Show that the checks above can fail: feed each oracle a known-wrong
    input and require a mismatch."""
    d = os.path.join(root, "acvp", "ML-KEM-keyGen-FIPS203")
    exp = {(g["tgId"], t["tcId"]): t for g in acvp_groups(os.path.join(d, "expectedResults.json")) for t in g["tests"]}
    n = caught = 0
    for g in acvp_groups(os.path.join(d, "prompt.json")):
        kem = MLKEM(g["parameterSet"], ipd=True)  # wrong (draft) key generation
        for t in g["tests"]:
            n += 1
            ek, _ = kem.keygen(hx(t["d"]), hx(t["z"]))
            caught += ek != hx(exp[(g["tgId"], t["tcId"])]["ek"])
    report("negative control: ipd key generation vs ACVP keyGen", caught == n, f"{caught}/{n} mismatches detected")
    j = json.load(open(os.path.join(root, "wycheproof", "mlkem_768_encaps_test.json"), encoding="utf-8"))
    kem = MLKEM("ML-KEM-768")
    t = next(t for g in j["testGroups"] for t in g["tests"] if t["result"] == "valid")
    m = bytearray(hx(t["m"]))
    m[0] ^= 1
    K, c = kem.encaps(hx(t["ek"]), bytes(m))
    report("negative control: one flipped bit of m changes (K, c)", K != hx(t["K"]) and c != hx(t["c"]))
    k = bytearray(hx("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"))
    k[5] ^= 0x10
    out = x25519(bytes(k), hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
    report("negative control: flipped scalar bit changes X25519 output",
           out.hex() != "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")


def check_xwing(root):
    path = os.path.join(root, "xwing", "draft-connolly-cfrg-xwing-kem-11.txt")
    text = open(path, encoding="utf-8").read()
    app = text[text.index("Appendix C.  Test vectors # TODO: replace with test vectors that re-use"):]
    app = app[:app.index("Appendix D.")]
    # drop page headers/footers, then collect "label hex..." records
    lines = [l for l in app.splitlines() if not l.startswith(("Connolly, et al.", "Internet-Draft"))]
    recs, cur_key = [], None
    for l in lines:
        m = re.match(r"^(seed|sk|pk|eseed|ct|ss)\s*([0-9a-f]*)\s*$", l)
        if m:
            cur_key = m.group(1)
            if cur_key == "seed":
                recs.append({})
            recs[-1][cur_key] = m.group(2)
        elif cur_key and re.match(r"^\s+[0-9a-f]+\s*$", l):
            recs[-1][cur_key] += l.strip()
    kem = MLKEM("ML-KEM-768")
    label = bytes.fromhex("5c2e2f2f5e5c")
    for i, r in enumerate(recs):
        sk = hx(r["sk"])
        exp = hashlib.shake_256(sk).digest(96)
        pk_m, sk_m = kem.keygen(exp[:32], exp[32:64])
        sk_x = exp[64:96]
        pk_x = x25519(sk_x, BASE)
        pk = pk_m + pk_x
        eseed = hx(r["eseed"])
        ek_x = eseed[32:64]
        ct_x = x25519(ek_x, BASE)
        ss_x = x25519(ek_x, pk_x)
        ss_m, ct_m = kem.encaps(pk_m, eseed[:32])
        ss = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + label).digest()
        ct = ct_m + ct_x
        ss_dec = hashlib.sha3_256(kem.decaps(sk_m, ct[:1088]) + x25519(sk_x, ct[1088:]) + ct[1088:] + pk_x + label).digest()
        ok = pk.hex() == r["pk"] and ct.hex() == r["ct"] and ss.hex() == r["ss"] and ss_dec == ss
        report(f"X-Wing draft-11 Appendix C vector {i + 1}", ok,
               f"(pk {len(pk)} B, ct {len(ct)} B, ss {len(ss)} B)")


def main():
    root = sys.argv[1]
    t0 = time.time()
    if "--go-accumulated" in sys.argv:
        n = int(sys.argv[sys.argv.index("--go-accumulated") + 1])
        for ipd in (False, True):
            ok_k, got = go_accumulated(n, ipd)
            tag = "ipd" if ipd else "final"
            print(f"[INFO] Go TestAccumulated ML-KEM-768 n={n} {tag} key generation: {got} "
                  f"decaps(ct)==K every time: {ok_k}; matches Go expected value: {GO_ACC.get(n) == got}")
        print(f"elapsed {time.time() - t0:.1f} s")
        return
    if "--accumulated" in sys.argv:
        i = sys.argv.index("--accumulated")
        n, name = int(sys.argv[i + 1]), sys.argv[i + 2]
        for ipd in (False, True):
            got = cctv_accumulated(name, n, ipd)
            tag = "ipd" if ipd else "final"
            match = n == 10000 and got == CCTV_ACC_10K[name]
            print(f"[INFO] CCTV accumulated {name} n={n} {tag} key generation: {got} "
                  f"matches README 10k hash: {match}")
        print(f"elapsed {time.time() - t0:.1f} s")
        return
    check_rfc7748()
    check_wycheproof_x25519(root)
    check_acvp(root)
    check_wycheproof_mlkem(root)
    check_cctv(root)
    check_go_accumulated_100()
    check_xwing(root)
    negative_controls(root)
    print(f"elapsed {time.time() - t0:.1f} s; failures: {FAILURES if FAILURES else 'none'}")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
