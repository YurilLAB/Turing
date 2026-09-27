"""acs_rhf.py - worked examples for the attack-cost-estimation notes.

Reproduces, for a learner:
  1. The BKZ root Hermite factor delta(b) in its exact limiting form
         delta = (v_b^(-1/b))^(1/(b-1)),  v_b = volume of the unit ball in dim b,
     and the usual approximation
         delta ~ ((b / (2 pi e)) (pi b)^(1/b))^(1/(2(b-1)))
     both as printed in Albrecht-Player-Scott 2015, eq. (1), PDF p. 9
     (research/papers/2015-albrecht-player-scott-concrete-hardness-lwe.pdf),
     citing Chen's 2013 thesis. The Kyber round-3 spec (PDF p. 26) uses the
     approximation.
  2. The Geometric Series Assumption (GSA) profile log ||b*_i|| of a
     BKZ-b reduced basis, and the ADPS16 primal success test
         sigma * sqrt(b) <= delta^(2b - d - 1) * q^(m/d)
     on the Kyber512 lattice (n = 512, q = 3329, sigma = sqrt(3/2), m = 486),
     printing the two sides near the threshold b = 406.
  3. Why "core-SVP" counts only one SVP call: the number of calls in
     progressive BKZ, C (d - b) with C = 1/(1 - 2^-0.292) (Kyber round-3 spec
     Sec. 5.2.1, PDF p. 27-28), in bits.

Usage: python acs_rhf.py      (deterministic, < 1 s)
"""
import math


def log_unit_ball(b):
    """ln of the volume of the unit ball in dimension b: pi^(b/2) / Gamma(b/2 + 1)."""
    return (b / 2.0) * math.log(math.pi) - math.lgamma(b / 2.0 + 1.0)


def delta_exact(b):
    return math.exp((-log_unit_ball(b) / b) / (b - 1))


def delta_approx(b):
    return ((b / (2 * math.pi * math.e)) * (math.pi * b) ** (1.0 / b)) ** (1.0 / (2.0 * (b - 1)))


print("1. Root Hermite factor delta(b): exact limiting form vs approximation")
print(f"{'b':>5} {'exact':>10} {'approx':>10} {'rel.diff':>10} {'0.292b':>7} {'0.265b':>7}")
for b in (50, 100, 200, 300, 406, 500, 626, 878, 1000):
    de, da = delta_exact(b), delta_approx(b)
    print(f"{b:5d} {de:10.6f} {da:10.6f} {(da - de) / (de - 1):10.2e} "
          f"{math.log2(math.sqrt(1.5)) * b:7.1f} {math.log2(math.sqrt(13 / 9)) * b:7.1f}")
print("   (rel.diff is relative to delta - 1, the part that matters.)")
print("   A shortest-vector-sized output of BKZ-b in dimension d has length about")
print("   delta^d * Vol^(1/d): smaller delta = stronger reduction = larger b.\n")

print("2. GSA profile and the primal success test for Kyber512 (m = 486, d = n + m + 1 = 999)")
n, q, s, m = 512, 3329, math.sqrt(1.5), 486
d = n + m + 1
log_vol = m * math.log(q)
for b in (380, 400, 405, 406, 420):
    dl = math.log(delta_approx(b))
    # GSA: ln ||b*_i|| = (d - 2i - 1) ln delta + ln Vol / d, i = 0..d-1 (0-based)
    first = (d - 1) * dl + log_vol / d
    at = (d - 2 * (d - b) - 1) * dl + log_vol / d     # i = d - b
    lhs = math.log(s * math.sqrt(b))
    cap = "above q: the q-ary profile caps it" if math.exp(first) > q else "below q, so GSA applies"
    print(f"   b={b}: ||b*_0|| = {math.exp(first):8.1f} ({cap}), "
          f"||b*_(d-b)|| = {math.exp(at):7.3f}, sigma*sqrt(b) = {math.exp(lhs):7.3f} -> "
          f"{'success' if lhs <= at else 'fail'}")
print("   The unique short vector (s, e, 1) projected on the last b coordinates has length")
print("   ~ sigma*sqrt(b); BKZ finds it once that is below the b*_(d-b) predicted by the GSA.\n")

print("3. What core-SVP leaves out: progressive-BKZ SVP calls C (d - b)")
C = 1.0 / (1.0 - 2.0 ** -0.292)
for name, dd, b in (("Kyber512", 1025, 413), ("Kyber768", 1467, 637), ("Kyber1024", 1918, 894)):
    calls = C * (dd - b)
    print(f"   {name}: C (d - b) = {C:.2f} * {dd - b} = {calls:7.0f} calls = 2^{math.log2(calls):.1f}")
print("   (d, b from the refined estimate of Kyber round-3 Table 4, PDF p. 21.)")
