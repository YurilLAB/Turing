"""dfr_perfect_correctness.py - what q makes a Module-LWE KEM of dimension ~1000 perfectly correct?

What it reproduces, and from where
----------------------------------
Nothing numeric is reproduced from a paper. It makes concrete a trade-off stated in two primary
sources: the Kyber round-3 specification ("Allowing decapsulation failures", PDF page 13: zero
failure probability needs less noise or a larger dimension) and NIST IR 8413 (PDF pages 47 and
49: the NTRU and NTRU Prime parameter sets are perfectly correct).

Model (ML-KEM-style K-PKE, FIPS 203 Algorithms 13-15, with general k, n, q, eta1, eta2, du, dv):
decryption error  err = <e,r> + e2 + cv - <s, e1 + cu>.  Every term has bounded support, so
    |err| <= B = k*n*eta1*eta1 + k*n*eta1*(eta2 + max|cu|) + eta2 + max|cv|.
B is attained when all terms align, so it is the worst case of this expression (whether honest
encryption can realise the worst cu and cv together does not matter: B is an upper bound).
Decoding: bit b is encoded as Decompress_1(b) and read with Compress_1 (FIPS 203 rounding, ties
up). safe_radius(q) is the largest t such that every err in [-t, t] decodes correctly for both
bit values (direct evaluation). Perfect correctness holds iff B <= safe_radius(q). The maximum
compression errors are computed exactly for each q by enumerating Z_q; a d-bit compression with
2^d >= q is treated as no compression.

For each (k, eta1, eta2, du, dv) it reports the smallest q found that is perfectly correct (a
doubling-then-bisection search, confirmed by a scan of the 4096 values below it), and the next
primes q = 1 mod 256 and q = 1 mod 512 (NTT-friendly for n = 256; ML-KEM's 3329 = 13*256 + 1).
Security of any such q is NOT assessed here (sibling topic attack-cost-estimation): a larger q at
the same noise weakens LWE.

Usage: python dfr_perfect_correctness.py        (deterministic, well under a minute)
"""
import math
import sys

import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
LIMIT = 1 << 22


def compress_arr(x, d, q):
    return ((2 * (1 << d) * x + q) // (2 * q)) % (1 << d)


def decompress_arr(y, d, q):
    return (2 * q * y + (1 << d)) // (2 * (1 << d))


def max_comp_err(q: int, d) -> int:
    if d is None or (1 << d) >= q:
        return 0
    x = np.arange(q, dtype=np.int64)
    z = decompress_arr(compress_arr(x, d, q), d, q)
    e = np.mod(z - x, q)
    e = np.where(e > q // 2, e - q, e)
    return int(np.abs(e).max())


def safe_radius(q: int) -> int:
    mu1 = int(decompress_arr(np.array([1]), 1, q)[0])
    t = np.arange(1, q // 2 + 1, dtype=np.int64)
    ok = ((compress_arr(np.mod(t, q), 1, q) == 0) & (compress_arr(np.mod(-t, q), 1, q) == 0)
          & (compress_arr(np.mod(mu1 + t, q), 1, q) == 1)
          & (compress_arr(np.mod(mu1 - t, q), 1, q) == 1))
    bad = np.nonzero(~ok)[0]
    return int(t[bad[0]] - 1) if len(bad) else q // 2


def worst_error(q, k, n, eta1, eta2, du, dv) -> int:
    return (k * n * eta1 * eta1 + k * n * eta1 * (eta2 + max_comp_err(q, du)) + eta2
            + max_comp_err(q, dv))


def good(q, cfg) -> bool:
    return worst_error(q, *cfg) <= safe_radius(q)


def smallest_q(cfg):
    k, n, eta1, eta2, du, dv = cfg
    lo = max(257, 4 * (k * n * eta1 * (eta1 + eta2) + eta2) - 8)   # no q below this can work
    hi = lo
    while not good(hi, cfg):
        hi *= 2
        if hi > LIMIT:
            return None
    while hi - lo > 1:                   # bisection, assuming the condition is monotone
        mid = (lo + hi) // 2
        if good(mid, cfg):
            hi = mid
        else:
            lo = mid
    for q in range(max(257, hi - 4096), hi):       # confirm: nothing smaller nearby works
        if good(q, cfg):
            return q
    return hi


def is_prime(m: int) -> bool:
    if m < 2:
        return False
    i = 2
    while i * i <= m:
        if m % i == 0:
            return False
        i += 1
    return True


def next_prime_1_mod(m: int, mod: int) -> int:
    q = m + ((1 - m) % mod)
    while not is_prime(q):
        q += mod
    return q


print("Sanity checks (ML-KEM, FIPS 203 parameters):")
r3329 = safe_radius(3329)
w768 = worst_error(3329, 3, 256, 2, 2, 10, 4)
print(f"  safe radius at q = 3329 for both bits: {r3329} (bit 0 alone decodes when |err| <= 832,"
      f" dfr.py; bit 1 = 1665 + err needs err <= 831; FIPS 203 / Barbosa et al. fail at > 831)")
print(f"  ML-KEM-768 worst case B = {w768} (max|cu| = {max_comp_err(3329, 10)}, max|cv| = "
      f"{max_comp_err(3329, 4)}) > {r3329}: not perfectly correct, as expected")
ok = r3329 == 831 and w768 > r3329 and max_comp_err(3329, 4) == 104
print(f"  [{'PASS' if ok else 'FAIL'}] radius 831; max|cv| = 104 for dv = 4 (Barbosa et al. use "
      f"104); ML-KEM-768 not perfectly correct")

print("\nSmallest perfectly correct q, n = 256 (B = worst-case |err| at that q):")
print("   k eta1 eta2   du   dv |        B    min q  log2 | prime 1 mod 256 | prime 1 mod 512")
rows = [(4, 2, 2, None, None), (4, 2, 2, 13, 13), (4, 2, 2, 11, 5), (4, 1, 1, None, None),
        (4, 1, 1, 12, 6), (4, 1, 1, 11, 5), (3, 2, 2, None, None), (4, 3, 3, None, None)]
for k, e1, e2, du, dv in rows:
    cfg = (k, 256, e1, e2, du, dv)
    q0 = smallest_q(cfg)
    if q0 is None:
        print(f"   {k} {e1:4d} {e2:4d} {str(du):>4s} {str(dv):>4s} | none below 2^22 "
              f"(worst-case compression error grows with q as fast as q/4)")
        continue
    B = worst_error(q0, *cfg)
    print(f"   {k} {e1:4d} {e2:4d} {str(du):>4s} {str(dv):>4s} | {B:8d} {q0:8d} {math.log2(q0):5.2f} |"
          f" {next_prime_1_mod(q0, 256):15d} | {next_prime_1_mod(q0, 512):15d}")
print("\nReading: without compression B = k*n*eta1*(eta1 + eta2) + eta2, and q must be about 4B:")
print("tens of thousands at eta = 2 and about 8,200 at eta = 1 for dimension 1024, against 3329")
print("in ML-KEM. Compressing u to du bits adds k*n*eta1*max|cu| with max|cu| about q/2^(du+1),")
print("which grows with q; if k*n*eta1/2^(du+1) >= 1/4 no q works at all.")
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
