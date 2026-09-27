"""Recompute the multi-target (multi-ciphertext) numbers quoted in the notes
research/notes/pq/cca-transforms-and-binding.md, Section 8.

Reproduces arithmetic from:
  * Glabush-Hovelmanns-Stebila, "On the multi-target security of
    post-quantum KEMs", IACR CiC 3(1), 2026 (ePrint 2025/343)
    (research/papers/2025-glabush-hovelmanns-stebila-tight-multi-challenge-kem.pdf),
    Sec. 6.1 (bound (5) collision term for |M| = 2^128, len_salt = 256,
    n_c = 2^64, n_u = 2^32 gives 2^-224) and Sec. 6.2 (ML-KEM: 2^128
    encryptions vs 2^64 challenges collide with probability ~2^-64; QROM
    terms 4*sqrt(n_c q/|M|) = 2^-74 unsalted and 4*sqrt(t q/|M|) = 2^-105
    salted with t = 4, q = 2^40).
  * Glabush-Longa-Naehrig-Peikert-Stebila-Virdia, "FrodoKEM: a CCA-secure
    LWE KEM" (research/papers/2025-alkim-et-al-frodokem-cic-practical-lwe-kem.pdf),
    Sec. 1.3: collision probability ~ n_c N / |M|; |M| = 2^128, n_c = 2^40
    needs N ~ 2^88 encryptions.
  * FrodoKEM preliminary standardization proposal, rev. 2025-09-29, Table A.2:
    len_salt = len_SE = 256 / 384 / 512 = 2 * len_sec (128 / 192 / 256).

This script only evaluates published formulas with exact rational
arithmetic (fractions + log2); it contains no attack code.
Usage: python cca_multitarget_bounds.py   (deterministic)
"""
from fractions import Fraction
import math

fails = 0


def log2(x):
    x = Fraction(x)
    return math.log2(x.numerator) - math.log2(x.denominator)


def check(name, got_log2, want_log2, tol=0.01):
    global fails
    ok = abs(got_log2 - want_log2) <= tol
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: log2 = {got_log2:.3f} (paper: {want_log2})")


# GHS Sec. 6.1, bound (5), second term n_u n_c (n_c - 1) / (|M| 2^len_salt)
M, salt, nc, nu = 2 ** 128, 2 ** 256, 2 ** 64, 2 ** 32
check("GHS (5) salted collision term n_u*n_c*(n_c-1)/(|M|*2^len_salt)",
      log2(Fraction(nu * nc * (nc - 1), M * salt)), -224, tol=0.001)

# GHS Sec. 6.1, bound (6) (Duman et al. adapted), collision term n_u n_c^2 / |M| ~ 1 or larger
v = log2(Fraction(nu * nc * nc, M))
ok = v >= 0
fails += not ok
print(f"[{'PASS' if ok else 'FAIL'}] GHS (6) unsalted term n_u*n_c^2/|M|: log2 = {v:.3f} >= 0, "
      f"so the bound is vacuous (paper says the term is 'approx 1', i.e. dominant)")

# GHS Sec. 6.2: ML-KEM-1024 aiming at 256 bits: 2^128 encryptions vs 2^64 challenges
check("GHS 6.2 ML-KEM: collision prob 2^128 * 2^64 / 2^256", log2(Fraction(2 ** 128 * 2 ** 64, 2 ** 256)), -64)

# GHS Sec. 6.2 QROM term 4*sqrt(x q / |M|), q = 2^40, |M| = 2^256
q, M256 = 2 ** 40, 2 ** 256
check("GHS 6.2 QROM unsalted 4*sqrt(n_c q/|M|), n_c = 2^64", 2 + 0.5 * log2(Fraction(2 ** 64 * q, M256)), -74)
check("GHS 6.2 QROM salted 4*sqrt(t q/|M|), t = 4", 2 + 0.5 * log2(Fraction(4 * q, M256)), -105)

# FrodoKEM CiC Sec. 1.3: n_c N / |M| ~ 1 with |M| = 2^128, n_c = 2^40 -> N = 2^88
check("Frodo CiC 1.3: N = |M| / n_c", log2(Fraction(2 ** 128, 2 ** 40)), 88)

# FrodoKEM proposal Table A.1/A.2: salted sets use len_salt = len_SE = 2 * len_sec
for name, lensec, lensalt, lense in [("640", 128, 256, 256), ("976", 192, 384, 384), ("1344", 256, 512, 512)]:
    ok = lensalt == 2 * lensec and lense == 2 * lensec
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] FrodoKEM-{name}: len_salt = len_SE = 2*len_sec ({lensalt}, {lense}, {lensec})")

print("TOTAL FAILURES:", fails)
raise SystemExit(1 if fails else 0)
