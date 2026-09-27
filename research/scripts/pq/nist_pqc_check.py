"""Recompute and cross-check numbers quoted in research/notes/pq/nist-pqc-standards.md.

What it reproduces, and from which source:
  1. FIPS 203 (ML-KEM), Section 8 Table 2 parameters -> Table 3 sizes, using the
     size formulas of Algorithms 16-18 (ek = 384k+32, dk = 768k+96,
     c = 32(du*k+dv), K = 32 bytes). Also the LWE dimension k*n.
  2. FIPS 203 Section 2.3 / 4.3: q = 3329 = 2^8*13+1 is prime, zeta = 17 is a
     primitive 256-th root of unity, there is no primitive 512-th root.
  3. FIPS 203 Appendix A: the two 128-entry tables zeta^BitRev7(i) and
     zeta^(2*BitRev7(i)+1), recomputed and compared with the numbers printed
     in research/papers/nist-fips-203-ml-kem.pdf (parsed with pymupdf).
  4. FIPS 203 Section 4.2.1: Compress_d(Decompress_d(y)) = y for all y, d < 12,
     and the worst-case rounding error of Decompress_d(Compress_d(x)).
  5. FIPS 203 Section 7.2 modulus check: a 12-bit field holding 3329 fails
     ByteEncode12(ByteDecode12(.)) == input; a field holding 3328 passes.
  6. FIPS 203 Appendix B Table 4: SampleNTT with a 280-iteration limit fails
     with probability about 2^-261 (binomial tail, mpmath).
  7. FIPS 203 Section 4.2.2: the centered binomial distribution CBD_eta,
     its probabilities and variance eta/2.
  8. NIST PQC Call for Proposals (2016, Section 4.A.5) and the 2022 additional
     signatures call: category gate counts; quantum gates for AES key search
     at MAXDEPTH = 2^40, 2^64, 2^96.
  9. Kyber round-3 specification Table 4: margin (in bits) of the refined
     classical gate counts over the AES gate counts of the 2022 call.
 10. Noise-to-modulus comparison of ML-KEM and FrodoKEM (FIPS 203 Table 2;
     FrodoKEM standard proposal 2025-09-29 Table A.1 and A.3).
 11. FIPS 203 errata spreadsheet dates: Excel serial numbers -> calendar dates.
 12. FIPS 204 (ML-DSA) Table 2 sizes from Table 1 parameters, using the output
     lengths of Algorithms 22, 24, 26 (pkEncode, skEncode, sigEncode).
 13. FIPS 205 (SLH-DSA) Table 2 pk/sig sizes from its parameters, using
     Equations 5.1-5.3 (w, len1, len2) and Figure 17 (signature layout
     R || SIG_FORS || SIG_HT = (1 + k(1+a) + h + d*len) * n bytes; pk = 2n).
 14. FIPS 203 Section 7.3 decapsulation-key hash check, demonstrated on a
     synthetic dk layout (dk_PKE || ek || H(ek) || z) with hashlib.sha3_256:
     an intact dk passes; flipping one bit of the stored ek fails.

Deterministic; prints every check and exits non-zero if any check fails.
Run from the repo root:
    timeout 300 python research/scripts/pq/nist_pqc_check.py
Negative control (plants four errors: a wrong FIPS 203 Table 3 size, one wrong
zeta, a 250-iteration SampleNTT limit, a wrong SLH-DSA-128s signature size;
exits 0 only if all four are caught):
    timeout 300 python research/scripts/pq/nist_pqc_check.py --negative-control
"""
import datetime
import math
import re
import sys
from pathlib import Path

import mpmath

sys.stdout.reconfigure(encoding="utf-8")
FAILS = []
# --negative-control injects three known errors; the run passes only if all
# three are caught (proves the checks can fail).
NEG = "--negative-control" in sys.argv


def check(label, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(label)


# ---------------------------------------------------------------- 1. sizes
print("== 1. FIPS 203 Table 2 -> Table 3 sizes")
N, Q = 256, 3329
PARAMS = {  # name: (k, eta1, eta2, du, dv, rbg_bits)   FIPS 203 Table 2
    "ML-KEM-512": (2, 3, 2, 10, 4, 128),
    "ML-KEM-768": (3, 2, 2, 10, 4, 192),
    "ML-KEM-1024": (4, 2, 2, 11, 5, 256),
}
TABLE3 = {  # ek, dk, ct, ss   FIPS 203 Table 3 (bytes)
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
    "ML-KEM-1024": (1568, 3168, 1568, 32),
}
if NEG:
    TABLE3["ML-KEM-768"] = (1184, 2432, 1088, 32)  # injected error 1
for name, (k, eta1, eta2, du, dv, rbg) in PARAMS.items():
    ek = 384 * k + 32
    dk = 768 * k + 96
    ct = 32 * (du * k + dv)
    got = (ek, dk, ct, 32)
    check(f"{name} sizes ek/dk/ct/K = {got}", got == TABLE3[name], f"Table 3 says {TABLE3[name]}")
    print(f"      {name}: LWE secret dimension k*n = {k}*{N} = {k * N}; "
          f"PRF output for CBD = 64*eta bytes = {64 * eta1} (eta1), {64 * eta2} (eta2)")

# ---------------------------------------------------------------- 2. ring
print("== 2. q = 3329 and zeta = 17")
check("q is prime", all(Q % p for p in range(2, int(Q ** 0.5) + 1)))
check("q = 2^8*13 + 1", Q == 2 ** 8 * 13 + 1)
check("17^128 = -1 mod q (so 17 has order 256)", pow(17, 128, Q) == Q - 1)
order = next(e for e in range(1, Q) if pow(17, e, Q) == 1)
check("order of 17 mod q is exactly 256", order == 256, f"order = {order}")
check("512 does not divide q-1 (no primitive 512-th root)", (Q - 1) % 512 != 0, f"q-1 = {Q - 1}")


# ---------------------------------------------------------------- 3. tables
def bitrev7(r):
    return int(f"{r:07b}"[::-1], 2)


zetas = [pow(17, bitrev7(i), Q) for i in range(128)]
if NEG:
    zetas[5] = (zetas[5] + 1) % Q  # injected error 2
gammas = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]
print("== 3. FIPS 203 Appendix A tables vs recomputation")
pdf = Path("research/papers/nist-fips-203-ml-kem.pdf")
if pdf.exists():
    import pymupdf

    doc = pymupdf.open(pdf)
    # physical pages 53 and 54 hold Appendix A (logical pages 44 and 45)
    t53 = doc[52].get_text("text")
    t54 = doc[53].get_text("text")
    # the prose also contains "{0,...,127}", so take the longest {...} block
    body53 = max(re.findall(r"\{([^{}]*)\}", t53, flags=re.S), key=len)
    body54 = max(re.findall(r"\{([^{}]*)\}", t54, flags=re.S), key=len)
    printed_z = [int(x) for x in re.findall(r"-?\d+", body53)]
    printed_g = [int(x) for x in re.findall(r"-?\d+", body54)]
    check("Appendix A zeta^BitRev7(i) table: 128 values match", printed_z == zetas,
          f"{len(printed_z)} parsed; first 5 {printed_z[:5]}")
    # The second table is printed as signed pairs (g, -g); recomputation gives
    # zeta^(2BitRev7(i)+1) mod q in [0, q). Compare modulo q.
    check("Appendix A zeta^(2BitRev7(i)+1) table: 128 values match mod q",
          [x % Q for x in printed_g] == gammas,
          f"{len(printed_g)} parsed; printed as +/- pairs, e.g. {printed_g[:4]}")
    check("errata row 1: the zeta table includes 1 for i = 0", printed_z[0] == 1 == zetas[0])
else:
    check("FIPS 203 PDF present for Appendix A check", False, str(pdf))


# ---------------------------------------------------------------- 4. compress
def compress(x, d):
    # round((2^d / q) * x) mod 2^d with ties rounded up, integer arithmetic
    return ((x << d) * 2 + Q) // (2 * Q) % (1 << d)


def decompress(y, d):
    return (y * Q * 2 + (1 << d)) // (1 << (d + 1))


def centered(v):
    v %= Q
    return v - Q if v > Q // 2 else v


print("== 4. Compress / Decompress (FIPS 203 eq. 4.7, 4.8)")
for d in (1, 4, 5, 10, 11):
    ok = all(compress(decompress(y, d), d) == y for y in range(1 << d))
    err = max(abs(centered(decompress(compress(x, d), d) - x)) for x in range(Q))
    check(f"d = {d}: Compress(Decompress(y)) = y for all y", ok)
    bound = round(Q / 2 ** (d + 1))
    check(f"d = {d}: max |Decompress(Compress(x)) - x| = round(q/2^(d+1)) = {bound}", err == bound,
          f"measured {err}; q/2^(d+1) = {Q / 2 ** (d + 1):.2f}")
spacing = sorted({decompress(y + 1, 10) - decompress(y, 10) for y in range((1 << 10) - 1)})
check("d = 10: Decompress steps are 3 or 4 (Kyber r3 spec, Section 4.4)", spacing == [3, 4], str(spacing))


# ---------------------------------------------------------------- 5. modulus check
def byte_encode12(f):
    bits = []
    for a in f:
        for j in range(12):
            bits.append((a >> j) & 1)
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def byte_decode12(b):
    bits = [(b[i // 8] >> (i % 8)) & 1 for i in range(8 * len(b))]
    return [sum(bits[12 * i + j] << j for j in range(12)) % Q for i in range(len(bits) // 12)]


print("== 5. Encapsulation-key modulus check (FIPS 203 Section 7.2)")
good = [3328] + [0] * 255
raw = bytearray(byte_encode12(good))
raw_bad = bytearray(raw)
# overwrite the first 12-bit field with 3329 (= q), which ByteEncode12 never produces
raw_bad[0] = 3329 & 0xFF
raw_bad[1] = (raw_bad[1] & 0xF0) | (3329 >> 8)
check("field 3328 passes: ByteEncode12(ByteDecode12(x)) == x",
      byte_encode12(byte_decode12(bytes(raw))) == bytes(raw))
check("field 3329 fails the check (decodes to 0, re-encodes differently)",
      byte_encode12(byte_decode12(bytes(raw_bad))) != bytes(raw_bad),
      f"decoded first coefficient = {byte_decode12(bytes(raw_bad))[0]}")

# ---------------------------------------------------------------- 6. SampleNTT
print("== 6. SampleNTT loop bound (FIPS 203 Appendix B, Table 4)")
mpmath.mp.dps = 80
p = mpmath.mpf(Q) / 4096
iters = 250 if NEG else 280  # injected error 3 (wrong loop limit)
cands = 2 * iters
tail = mpmath.fsum(mpmath.binomial(cands, i) * p ** i * (1 - p) ** (cands - i) for i in range(256))
lg = float(mpmath.log(tail, 2))
check(f"SampleNTT: P(fewer than 256 of {cands} candidates < q) is about 2^-261", abs(lg + 261) < 1.0,
      f"log2 P = {lg:.2f}; acceptance rate per 12-bit candidate = {float(p):.4f}; "
      f"expected iterations = {256 / (2 * float(p)):.1f}")

# ---------------------------------------------------------------- 7. CBD
print("== 7. Centered binomial distribution CBD_eta (FIPS 203 Algorithm 8)")
for eta in (2, 3):
    probs = {}
    for xb in range(1 << eta):
        for yb in range(1 << eta):
            v = bin(xb).count("1") - bin(yb).count("1")
            probs[v] = probs.get(v, 0) + 1
    tot = 4 ** eta
    var = sum(v * v * c for v, c in probs.items()) / tot
    dist = ", ".join(f"{v}:{c}/{tot}" for v, c in sorted(probs.items()))
    check(f"CBD_{eta} variance = eta/2 = {eta / 2}", abs(var - eta / 2) < 1e-12, dist)

# ---------------------------------------------------------------- 8. categories
print("== 8. NIST security categories: gate counts (log2)")
CFP2016 = {"AES-128": (170, 143), "AES-192": (233, 207), "AES-256": (298, 272)}
CFP2022 = {"AES-128": (157, 143), "AES-192": (221, 207), "AES-256": (285, 272)}
SHA3 = {"SHA3-256": 146, "SHA3-384": 210, "SHA3-512": 274}
for label, table in (("2016 call", CFP2016), ("2022 call", CFP2022)):
    for aes, (qnum, classical) in table.items():
        row = ", ".join(f"MAXDEPTH 2^{m}: 2^{qnum - m}" for m in (40, 64, 96))
        print(f"      {label} {aes}: quantum 2^{qnum}/MAXDEPTH -> {row}; classical 2^{classical}")
check("category order: AES-128 key search (2^143) < SHA3-256 collision (2^146) classical gates",
      143 < SHA3["SHA3-256"])
check("category order: AES-192 (2^207) < SHA3-384 collision (2^210)", 207 < SHA3["SHA3-384"])
check("category order: AES-256 (2^272) < SHA3-512 collision (2^274)", 272 < SHA3["SHA3-512"])

# ---------------------------------------------------------------- 9. Kyber margins
print("== 9. Kyber round-3 Table 4 refined classical gates vs AES thresholds")
KYBER = {"Kyber512": (151.5, 143, 1), "Kyber768": (215.1, 207, 3), "Kyber1024": (287.3, 272, 5)}
for name, (gates, thr, cat) in KYBER.items():
    check(f"{name} (category {cat}) log2 gates {gates} >= {thr}", gates >= thr,
          f"margin {gates - thr:.1f} bits")

# ---------------------------------------------------------------- 10. q / sigma
print("== 10. Dimension, modulus and noise: ML-KEM vs FrodoKEM")
rows = [
    # name, LWE dimension n, q, secret/error std dev sigma, claimed category
    ("ML-KEM-512", 512, 3329, math.sqrt(3 / 2), 1),
    ("ML-KEM-768", 768, 3329, math.sqrt(2 / 2), 3),
    ("ML-KEM-1024", 1024, 3329, math.sqrt(2 / 2), 5),
    ("FrodoKEM-640", 640, 32768, 2.8, 1),
    ("FrodoKEM-976", 976, 65536, 2.3, 3),
    ("FrodoKEM-1344", 1344, 65536, 1.4, 5),
]
for name, n, q, sigma, cat in rows:
    print(f"      {name:14s} n = {n:4d}  log2 q = {math.log2(q):5.2f}  sigma = {sigma:4.2f}  "
          f"log2(q/sigma) = {math.log2(q / sigma):5.2f}  claimed category {cat}")
# Was check(..., True, ...), which could never fail (found by the
# fact-check of 2026-09-27 and by tools/mathaudit.py's lint): now the
# categories of the sets with n in [900, 1100] are actually compared.
near_1000 = {name: cat for name, n, q, sigma, cat in rows if 900 <= n <= 1100}
check("an LWE dimension near 1000 appears in category 3 (FrodoKEM-976) and category 5 (ML-KEM-1024)",
      near_1000.get("FrodoKEM-976") == 3 and near_1000.get("ML-KEM-1024") == 5 and len(set(near_1000.values())) > 1,
      "dimension alone does not fix the category; q and sigma matter")

# ---------------------------------------------------------------- 11. errata dates
print("== 11. FIPS 203 errata spreadsheet: Excel serial dates")
base = datetime.date(1899, 12, 30)
for serial, what in ((45517, "released"), (45747, "row 1 identified"), (45947, "row 2 identified")):
    print(f"      {serial} -> {base + datetime.timedelta(days=serial)} ({what})")
check("45517 is 2024-08-13 (FIPS 203 publication date)", base + datetime.timedelta(days=45517) == datetime.date(2024, 8, 13))


# ---------------------------------------------------------------- 12. FIPS 204 sizes
def bitlen(x):
    return x.bit_length()


print("== 12. FIPS 204 Table 1 -> Table 2 sizes (Algorithms 22, 24, 26)")
Q_DSA, D_DSA = 8380417, 13
DSA = {  # name: (k, l, eta, gamma1, omega, lambda)   FIPS 204 Table 1
    "ML-DSA-44": (4, 4, 2, 2 ** 17, 80, 128),
    "ML-DSA-65": (6, 5, 4, 2 ** 19, 55, 192),
    "ML-DSA-87": (8, 7, 2, 2 ** 19, 75, 256),
}
DSA_T2 = {  # private key, public key, signature   FIPS 204 Table 2 (bytes)
    "ML-DSA-44": (2560, 1312, 2420),
    "ML-DSA-65": (4032, 1952, 3309),
    "ML-DSA-87": (4896, 2592, 4627),
}
for name, (k, l, eta, g1, omega, lam) in DSA.items():
    pk = 32 + 32 * k * (bitlen(Q_DSA - 1) - D_DSA)
    sk = 32 + 32 + 64 + 32 * ((k + l) * bitlen(2 * eta) + D_DSA * k)
    sig = lam // 4 + l * 32 * (1 + bitlen(g1 - 1)) + omega + k
    check(f"{name} sk/pk/sig = {(sk, pk, sig)}", (sk, pk, sig) == DSA_T2[name], f"Table 2 says {DSA_T2[name]}")

# ---------------------------------------------------------------- 13. FIPS 205 sizes
print("== 13. FIPS 205 Table 2 pk/sig sizes (Eq. 5.1-5.3, Figure 17)")
SLH = {  # name: (n, h, d, a, k, lg_w, pk bytes, sig bytes)   FIPS 205 Table 2
    "128s": (16, 63, 7, 12, 14, 4, 32, 7856),
    "128f": (16, 66, 22, 6, 33, 4, 32, 17088),
    "192s": (24, 63, 7, 14, 17, 4, 48, 16224),
    "192f": (24, 66, 22, 8, 33, 4, 48, 35664),
    "256s": (32, 64, 8, 14, 22, 4, 64, 29792),
    "256f": (32, 68, 17, 9, 35, 4, 64, 49856),
}
if NEG:
    SLH["128s"] = (16, 63, 7, 12, 14, 4, 32, 7872)  # injected error 4
for name, (n, h, d, a, k, lgw, pk_t, sig_t) in SLH.items():
    w = 2 ** lgw                                       # Eq. 5.1
    len1 = (8 * n + lgw - 1) // lgw                    # Eq. 5.2
    len2 = ((len1 * (w - 1)).bit_length() - 1) // lgw + 1  # Eq. 5.3: floor(log2(len1(w-1))/lg_w) + 1
    ln = len1 + len2
    sig = (1 + k * (1 + a) + h + d * ln) * n
    check(f"SLH-DSA-{name}: pk = 2n = {2 * n}, sig = {sig} (len = {len1}+{len2})",
          (2 * n, sig) == (pk_t, sig_t), f"Table 2 says pk {pk_t}, sig {sig_t}")

# ---------------------------------------------------------------- 14. dk hash check
print("== 14. FIPS 203 Section 7.3 decapsulation-key hash check (synthetic dk)")
import hashlib  # noqa: E402

k = 3  # ML-KEM-768 layout
ek = bytes((7 * i + 1) % 256 for i in range(384 * k + 32))    # stand-in bytes, not a real key
dk_pke = bytes((11 * i + 5) % 256 for i in range(384 * k))
z = bytes(range(32))
dk = dk_pke + ek + hashlib.sha3_256(ek).digest() + z
check(f"dk length = 768k + 96 = {768 * k + 96}", len(dk) == 768 * k + 96)


def hash_check(dk_bytes):
    return hashlib.sha3_256(dk_bytes[384 * k:768 * k + 32]).digest() == dk_bytes[768 * k + 32:768 * k + 64]


check("intact dk passes H(dk[384k:768k+32]) == dk[768k+32:768k+64]", hash_check(dk))
bad = bytearray(dk)
bad[384 * k + 10] ^= 0x01  # flip one bit inside the stored ek
check("dk with one flipped bit in the stored ek fails the hash check", not hash_check(bytes(bad)))

print()
if NEG:
    expected = {"ML-KEM-768 sizes", "zeta^BitRev7(i) table", "SampleNTT", "SLH-DSA-128s"}
    caught = {e for e in expected if any(e in f or (e == "SampleNTT" and f.startswith("SampleNTT")) for f in FAILS)}
    print(f"NEGATIVE CONTROL: {len(FAILS)} failure(s) reported; injected errors caught: {sorted(caught)}")
    ok = caught == expected
    print("NEGATIVE CONTROL OK" if ok else "NEGATIVE CONTROL FAILED: a planted error was not caught")
    sys.exit(0 if ok else 1)
print("ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} CHECK(S) FAILED: {FAILS}")
sys.exit(1 if FAILS else 0)
