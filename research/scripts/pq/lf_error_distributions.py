"""Error distributions used by real lattice KEMs, recomputed from their definitions.

Reproduces / checks:
  A. ML-KEM centred binomial CBD(eta): FIPS 203 Algorithm 8 (SamplePolyCBD: x - y with x, y
     sums of eta bits). Exact pmf, variance eta/2, standard deviation, support.
     File: research/papers/nist-fips-203-ml-kem.pdf (Sec. 4.2.2, PDF p.32).
  B. FrodoKEM error tables: FrodoKEM round-3 spec Table 3 (p.25) = 2025 proposal Table A.3
     (probabilities of 0, +-1, ..., in multiples of 2^-16) and the sampling tables T_chi
     (2025 proposal Table A.4). Checks: the table sums to 2^16, its standard deviation is close
     to the stated sigma, T_chi is the cumulative table (T(0) = P(0)/2 - 1, T(i) = T(i-1) + P(+-i),
     in units of 2^-15), and the Renyi divergence D_alpha(P || Psi) from the rounded Gaussian
     of standard deviation sigma (r3 spec Def. 5.4 and Sec. 2.2.4, p.23-24) matches the table's
     last column.  Files: research/papers/2021-alkim-et-al-frodokem-round3-specification-20210604.pdf,
     research/papers/2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf
  C. NewHope's safeguard: R_9(psi_16 || xi) ~ 1.00063 where xi is the rounded Gaussian of
     sigma = sqrt(8), and R_9^(5n) <= 2^6 for n = 1024 (Alkim-Ducas-Poppelmann-Schwabe,
     USENIX Security 2016, Sec. 4 Thm 4.1 and App. B; this R_a is the Bai et al. form, the
     (a-1)-th root of the sum, without a logarithm).
     File: research/papers/2016-alkim-ducas-poppelmann-schwabe-newhope.pdf
  D. Saber secret distribution beta_mu (Saber r3 spec Sec. 2.1: pmf mu!/((mu/2+x)!(mu/2-x)!) 2^-mu)
     and the deterministic rounding error of Module-LWR from q = 2^13 to p = 2^10 (Table 2).
     File: research/papers/2020-danvers-et-al-saber-round3-specification.pdf
  E. Standard deviations side by side, and the sqrt(n)/(2 pi) threshold quoted by FrodoKEM
     (r3 spec Sec. 1.2.2, p.6) for the iterative quantum reductions.

Deterministic; exact arithmetic where possible (fractions, mpmath at 50 digits).
Prints every check; exits non-zero on failure.

Run: python research/scripts/pq/lf_error_distributions.py
"""
import math
import sys
from fractions import Fraction
from math import comb

import mpmath as mp

mp.mp.dps = 50
failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


def moments(pmf):
    mean = sum(Fraction(x) * p for x, p in pmf.items())
    var = sum(Fraction(x) ** 2 * p for x, p in pmf.items()) - mean ** 2
    return mean, var


# ---------------------------------------------------------------- A. CBD
print("=== A. ML-KEM centred binomial CBD(eta) (FIPS 203 Alg. 8) ===")


def cbd_pmf(eta):
    """Exact pmf of x - y, x and y each a sum of eta fair bits: P(k) = C(2eta, eta+k) / 4^eta."""
    return {k: Fraction(comb(2 * eta, eta + k), 4 ** eta) for k in range(-eta, eta + 1)}


def cbd_by_enumeration(eta):
    """Enumerate all 2^(2 eta) bit strings exactly as Algorithm 8 lines 3-5 do."""
    counts = {}
    for bits in range(1 << (2 * eta)):
        x = sum((bits >> j) & 1 for j in range(eta))
        y = sum((bits >> (eta + j)) & 1 for j in range(eta))
        counts[x - y] = counts.get(x - y, 0) + 1
    return {k: Fraction(c, 1 << (2 * eta)) for k, c in counts.items()}


for eta in (2, 3):
    pmf = cbd_pmf(eta)
    mean, var = moments(pmf)
    print(f"CBD({eta}): support [-{eta}, {eta}], pmf " +
          ", ".join(f"{k}:{p}" for k, p in sorted(pmf.items())) +
          f"; mean {mean}, variance {var}, std {math.sqrt(var):.4f}")
    check(f"CBD({eta}) formula equals enumeration of Algorithm 8", pmf == cbd_by_enumeration(eta))
    check(f"CBD({eta}) has mean 0 and variance eta/2 = {Fraction(eta, 2)}", mean == 0 and var == Fraction(eta, 2))

# ---------------------------------------------------------------- B. FrodoKEM tables
print()
print("=== B. FrodoKEM error tables (r3 Table 3 = 2025 Table A.3; 2025 Table A.4) ===")
FRODO = {
    # name: (sigma stated, [P(0), P(+-1), ...] in units of 2^-16 (each sign), Renyi order, stated D_alpha, T_chi table)
    "Frodo-640": (2.8, [9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1], 200, 0.324e-4,
                  [4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767]),
    "Frodo-976": (2.3, [11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1], 500, 0.140e-4,
                  [5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767]),
    "Frodo-1344": (1.4, [18286, 14320, 6876, 2023, 364, 40, 2], 1000, 0.264e-4,
                   [9142, 23462, 30338, 32361, 32725, 32765, 32767]),
}


def rounded_gaussian(sigma, x):
    """P(round(N(0, sigma^2)) = x) = Phi((x+1/2)/sigma) - Phi((x-1/2)/sigma)."""
    s = mp.mpf(sigma)
    return mp.ncdf((x + mp.mpf(1) / 2) / s) - mp.ncdf((x - mp.mpf(1) / 2) / s)


def renyi_frodo(P, sigma, alpha):
    """FrodoKEM r3 Def. 5.4: D_alpha(P||Q) = 1/(alpha-1) ln sum_x P(x) (P(x)/Q(x))^(alpha-1)."""
    total = mp.mpf(0)
    for x, p in P.items():
        p = mp.mpf(p.numerator) / p.denominator
        total += p * (p / rounded_gaussian(sigma, x)) ** (alpha - 1)
    return mp.log(total) / (alpha - 1)


for name, (sigma, table, alpha, d_stated, tchi) in FRODO.items():
    pmf = {0: Fraction(table[0], 1 << 16)}
    for k, c in enumerate(table[1:], start=1):
        pmf[k] = pmf[-k] = Fraction(c, 1 << 16)
    total = table[0] + 2 * sum(table[1:])
    mean, var = moments(pmf)
    std = math.sqrt(var)
    print(f"{name}: support [-{len(table)-1}, {len(table)-1}], table total {total} (2^16 = 65536), "
          f"std of table {std:.4f} vs stated sigma {sigma}")
    check(f"{name}: probabilities sum to exactly 1", total == 1 << 16)
    # The target is the ROUNDED Gaussian of parameter sigma, whose own standard deviation is
    # about sqrt(sigma^2 + 1/12) (rounding adds variance ~1/12); compare against that exactly.
    rg_var = sum(mp.mpf(x) ** 2 * rounded_gaussian(sigma, x) for x in range(-60, 61))
    rg_std = float(mp.sqrt(rg_var))
    print(f"{name}: std of the rounded Gaussian target = {rg_std:.4f} (sqrt(sigma^2 + 1/12) = "
          f"{math.sqrt(sigma**2 + 1/12):.4f})")
    check(f"{name}: table std within 0.5% of the rounded-Gaussian target std", abs(std - rg_std) / rg_std < 0.005)
    cum = [table[0] // 2 - 1]
    for c in table[1:]:
        cum.append(cum[-1] + c)
    check(f"{name}: T_chi (Table A.4) is the cumulative table in units of 2^-15 ending at 2^15 - 1",
          cum == tchi and tchi[-1] == (1 << 15) - 1)
    d = renyi_frodo(pmf, sigma, alpha)
    print(f"{name}: D_{alpha}(table || rounded Gaussian sigma={sigma}) = {mp.nstr(d, 4)}; stated {d_stated:.3e}")
    check(f"{name}: recomputed Renyi divergence agrees with the table to the 3 printed digits",
          abs(float(d) - d_stated) <= 0.0005e-4 + 1e-12)

# ---------------------------------------------------------------- C. NewHope Renyi safeguard
print()
print("=== C. NewHope: centred binomial psi_16 vs rounded Gaussian sigma = sqrt(8) ===")
psi16 = cbd_pmf(16)
a = 9


def renyi_bai(P, sigma, a):
    """Bai et al. / NewHope form: R_a(P||Q) = (sum_x P(x)^a / Q(x)^(a-1))^(1/(a-1))."""
    total = mp.mpf(0)
    for x, p in P.items():
        p = mp.mpf(p.numerator) / p.denominator
        total += p ** a / rounded_gaussian(sigma, x) ** (a - 1)
    return total ** (mp.mpf(1) / (a - 1))


r9 = renyi_bai(psi16, math.sqrt(8), a)
print(f"R_9(psi_16 || xi) = {mp.nstr(r9, 8)} (paper prints ~1.00063)")
check("R_9(psi_16 || xi) agrees with the paper's ~1.00063 to within 1e-5", abs(float(r9) - 1.00063) < 0.00001)
big = r9 ** (5 * 1024)
print(f"R_9^(5n) with n = 1024: {mp.nstr(big, 6)} (paper: <= 2^6 = 64)")
check("R_9^(5n) <= 2^6", big <= 64)
print("Reading: a success probability p against the binomial version implies at least p^(9/8)/2^6 "
      "against the Gaussian one (NewHope Thm 4.1). The loss is ignored in practice because known "
      "attacks depend on the standard deviation, not the shape (NewHope App. B; Kyber r3 Sec. 1.5).")

# ---------------------------------------------------------------- D. Saber
print()
print("=== D. Saber: beta_mu secrets and the rounding error of Module-LWR ===")
for mu in (10, 8, 6):
    pmf = {x: Fraction(math.factorial(mu), math.factorial(mu // 2 + x) * math.factorial(mu // 2 - x) * 2 ** mu)
           for x in range(-mu // 2, mu // 2 + 1)}
    mean, var = moments(pmf)
    check(f"beta_{mu} sums to 1, mean 0, variance mu/4 = {Fraction(mu, 4)} (std {math.sqrt(mu/4):.4f})",
          sum(pmf.values()) == 1 and mean == 0 and var == Fraction(mu, 4))
q, p = 2 ** 13, 2 ** 10
# Rounding x in Z_q to p: the error (q/p)*round_p(x) - x, as x runs over Z_q, takes each of q/p
# consecutive values equally often. Enumerate exactly with the centred rounding floor(x*p/q + 1/2).
errs = {}
for x in range(q):
    r = (x * p + q // 2) // q        # round(p x / q)
    e = r * (q // p) - x             # error in units of Z_q
    errs[e] = errs.get(e, 0) + 1
pmf = {e: Fraction(c, q) for e, c in errs.items()}
mean, var = moments(pmf)
print(f"LWR rounding q = 2^13 -> p = 2^10: error takes values {sorted(errs)} (units of Z_q), "
      f"mean {float(mean)}, variance {float(var):.4f}, std {math.sqrt(var):.4f}")
check("rounding error is uniform on q/p = 8 consecutive integers, variance ((q/p)^2 - 1)/12 = 63/12",
      len(errs) == q // p and len(set(errs.values())) == 1 and var == Fraction(63, 12))
print("Saber's constant vector h (Saber spec) re-centres this error; its variance does not change.")

# ---------------------------------------------------------------- E. comparison
print()
print("=== E. Standard deviations (units of Z_q) and the sqrt(n)/(2 pi) reduction threshold ===")
rows = [
    ("ML-KEM-512  secret/error CBD(3)", math.sqrt(1.5), 512),
    ("ML-KEM-768/1024 CBD(2)", 1.0, 1024),
    ("FrodoKEM-640 table", 2.8, 640),
    ("FrodoKEM-976 table", 2.3, 976),
    ("FrodoKEM-1344 table", 1.4, 1344),
    ("NewHope1024 psi_8 (variance 4)", 2.0, 1024),
    ("Saber secret beta_6 (FireSaber)", math.sqrt(1.5), 1024),
    ("Saber rounding error 2^13 -> 2^10", math.sqrt(63 / 12), 1024),
]
for name, sd, nlat in rows:
    thr = math.sqrt(nlat) / (2 * math.pi)
    print(f"  {name:36s} std {sd:5.3f}; LWE dimension {nlat:5d}; sqrt(n)/(2 pi) = {thr:5.2f}; "
          f"{'meets' if sd >= thr else 'below'} the quantum-reduction width")
check("every deployed error distribution above is narrower than sqrt(n)/(2 pi): the full quantum "
      "reductions do not cover them", all(sd < math.sqrt(nl) / (2 * math.pi) for _, sd, nl in rows))

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
