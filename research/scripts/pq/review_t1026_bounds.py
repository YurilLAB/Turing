"""Independent check of docs/16's two headline numbers for Turing-1026.

Written from the published formulas, not from coresvp.py, dfr.py or Bombe's
ports, as a review of the Turing-1026 commit (574a107), 2026-09-27.

1. Primal uSVP block size, 2016 estimate (Alkim, Ducas, Poppelmann, Schwabe,
   NewHope, USENIX Security 2016): with d = m + n + 1, success when
       sigma * sqrt(b) <= delta(b)^(2b - d - 1) * q^(m / d),
       delta(b) = ((pi b)^(1/b) * b / (2 pi e))^(1 / (2 (b - 1))),
   minimised over m <= m_max; cost 0.292 b classical, 0.265 b quantum.
   Control: FrodoKEM-976 must land on the 206.5 that docs/16 reproduces
   from FrodoKEM's own tables.

2. Decryption failures by an exact Chernoff bound. Each coefficient of
   S'E - E'S + E'' is a sum of 2n products of independent CBD(eta) samples
   plus one CBD(eta) sample. The MGF of CBD(eta) is cosh(t/2)^(2 eta), so
       E[exp(l a b)] = sum_a P(a) cosh(l a / 2)^(2 eta), and
       P(|X| >= q/4) <= 2 min_l M_prod(l)^(2n) M_cbd(l) exp(-l q/4).
   This is a proven upper bound. By Cramer's theorem the exact tail sits a
   few bits below it (a polynomial factor), so the exact figures of docs/16
   should be a similar, small distance below this bound for every width.

Result on 2026-09-27: b = 869 (253.7 classical) against docs/16's 868
(253.9); FrodoKEM-976 206.4 against 206.5. Bound 2^-268.3 per coefficient
and 2^-260.3 per ciphertext against docs/16's exact 2^-274.06 / 2^-266.06;
the gap is 5.6-6.2 bits for CBD(14), (16), (18) and (20) alike, as expected.
Even the proven bound alone (2^-260.3) stays below the attack cost 2^-252.4.

    python research/scripts/pq/review_t1026_bounds.py      (about a minute)
"""
import math
from math import comb

import mpmath as mp

mp.mp.dps = 60


def delta(b):
    return ((math.pi * b) ** (1 / b) * b / (2 * math.pi * math.e)) ** (1 / (2 * (b - 1)))


def primal_b(n, q, sigma, m_max):
    for b in range(50, 1500):
        lhs = math.log(sigma) + 0.5 * math.log(b)
        for m in range(max(1, b - n), m_max + 1, 2):
            d = m + n + 1
            if b > d:
                continue
            if lhs <= (2 * b - d - 1) * math.log(delta(b)) + (m / d) * math.log(q):
                return b
    return None


def cbd_pmf(eta):
    return {v: mp.mpf(comb(2 * eta, eta + v)) / mp.mpf(4) ** eta for v in range(-eta, eta + 1)}


def log2_fail_bound(n, log_q, eta, coeffs):
    p = cbd_pmf(eta)
    t = mp.mpf(2) ** log_q / 4

    def log_bound(l):
        l = mp.mpf(l)
        mprod = sum(pa * mp.cosh(l * a / 2) ** (2 * eta) for a, pa in p.items())
        return 2 * n * mp.log(mprod) + 2 * eta * mp.log(mp.cosh(l / 2)) - l * t

    lo, hi = mp.mpf("1e-6"), mp.mpf("0.5")  # the optimum is near 0.05
    for _ in range(200):  # golden-section search; log_bound is convex in l
        m1, m2 = lo + (hi - lo) * 0.382, lo + (hi - lo) * 0.618
        if log_bound(m1) < log_bound(m2):
            hi = m2
        else:
            lo = m1
    per_coeff = (log_bound((lo + hi) / 2) + mp.log(2)) / mp.log(2)
    return float(per_coeff), float(per_coeff + mp.log(coeffs, 2))


if __name__ == "__main__":
    print("primal uSVP, 2016 estimate")
    for name, n, q, sigma, m_max, claim in [
        ("FrodoKEM-976 (control)", 976, 2 ** 16, 2.3, 976 + 8, 206.5),
        ("Turing-1026, ciphertext instance", 1026, 2 ** 15, 3.0, 1026 + 32, 253.9),
    ]:
        b = primal_b(n, q, sigma, m_max)
        print(f"  {name}: b = {b}, classical {0.292 * b:.1f} (docs/16: {claim}), quantum {0.265 * b:.1f}")
    print("failure rate, proven Chernoff upper bound vs docs/16's exact value (per ciphertext)")
    for eta, exact in [(14, -425.5), (16, -332.2), (18, -266.06), (20, -217.5)]:
        pc, ct = log2_fail_bound(1026, 15, eta, 256)
        print(f"  CBD({eta}): bound 2^{ct:.1f} (per coefficient 2^{pc:.2f}); exact 2^{exact}; gap {ct - exact:.1f} bits")
