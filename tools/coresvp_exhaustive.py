"""Core-SVP cost of the primal and dual lattice attacks on LWE, searched
exhaustively (tools/CI.md, "math-audit").

Written from the formulas of Alkim, Ducas, Poppelmann and Schwabe (NewHope,
USENIX Security 2016, sections 6.3-6.4; research/papers/
2016-alkim-ducas-poppelmann-schwabe-newhope.pdf), not from the repo's
coresvp.py, Bombe's coresvp.rs or the lattice-estimator:

  primal (6.3): d = m + n + 1; BKZ-b succeeds when
      sigma * sqrt(b) <= delta(b)^(2b - d - 1) * q^(m/d),
      delta(b) = ((pi b)^(1/b) * b / (2 pi e))^(1 / (2 (b - 1)));
  dual (6.4):   d = m + n; a vector of length l = delta^(d-1) q^(n/d) gives
      advantage eps = exp(-2 pi^2 tau^2), tau = l sigma / q; the sieve
      yields 2^(0.2075 b) vectors, so the attack repeats
      R = max(1, 1 / (2^(0.2075 b) eps^2)) times. The paper's text writes
      eps = 4 exp(-2 pi^2 tau^2) (a bound on the statistical distance), but
      its own script (newhope_PQsecurity.py) and pq-crystals' MLWE_security.py
      use exp(-2 pi^2 tau^2), and Table 1 was made with the script; that is
      the convention of every published core-SVP table, so it is the default
      here. eps_factor=4 gives the text's version, about 1 bit cheaper;
  cost: 0.292 b classical and 0.265 b quantum core-SVP, plus log2 R.

Every (m, b) pair is evaluated. No greedy or early-abort search: lattice-
estimator issue #219 (open, 2026-07-09) shows such a search can stop at a
local rise and overstate the cost by up to 7.98 bits (FrodoKEM-976).

    python tools/coresvp_exhaustive.py             # ADPS16 Table 1, reproduced
"""
import math

import numpy as np

CLASSICAL, QUANTUM, SIEVE_VECTORS = 0.292, 0.265, 0.2075


def delta(b):
    b = np.asarray(b, dtype=float)
    return ((math.pi * b) ** (1 / b) * b / (2 * math.pi * math.e)) ** (1 / (2 * (b - 1)))


def primal(n, q, sigma, m_max, b_max=2000):
    """Smallest b for which some m in 1..m_max succeeds, and that m."""
    m = np.arange(1, m_max + 1, dtype=float)
    for b in range(50, b_max + 1):
        d = m + n + 1
        ok = (b <= d) & (math.log(sigma) + 0.5 * math.log(b) <= (2 * b - d - 1) * math.log(delta(b)) + (m / d) * math.log(q))
        if ok.any():
            return b, int(m[ok.argmax()])
    raise ValueError("no block size up to b_max")


def dual(n, q, sigma, m_max, b_max=2000, eps_factor=1.0):
    """Minimum over every (m, b) of 0.292 b + log2 R; returns (cost, b, m,
    quantum cost at that (m, b))."""
    m = np.arange(1, m_max + 1, dtype=float)
    d = m + n
    best = None
    for b in range(50, b_max + 1):
        log_l = (d - 1) * math.log(delta(b)) + (n / d) * math.log(q)
        tau2 = np.exp(2 * (log_l + math.log(sigma) - math.log(q)))
        ln_eps = math.log(eps_factor) - 2 * math.pi**2 * tau2
        log2_r = np.maximum(0.0, -SIEVE_VECTORS * b - 2 * ln_eps / math.log(2))
        cost = CLASSICAL * b + log2_r
        i = int(cost.argmin())
        if best is None or cost[i] < best[0]:
            best = (float(cost[i]), b, int(m[i]), QUANTUM * b + float(log2_r[i]))
        if CLASSICAL * b > best[0]:
            break  # every larger b costs more than the best already found
    return best


# ADPS16 Table 1: (name, n, q, sigma, primal m, primal b, primal classical,
# primal quantum, dual m, dual b, dual classical, dual quantum). m may be
# chosen between 0 and 2n (section 6.3).
ADPS16_TABLE_1 = [
    ("BCNS", 1024, 2**32 - 1, 3.192, 1062, 296, 86, 78, 1055, 296, 86, 78),
    ("NTRU Encrypt", 743, 2**12, math.sqrt(2 / 3), 613, 603, 176, 159, 635, 600, 175, 159),
    ("JarJar", 512, 12289, math.sqrt(12), 623, 449, 131, 119, 602, 448, 131, 118),
    ("NewHope", 1024, 12289, math.sqrt(8), 1100, 967, 282, 256, 1099, 962, 281, 255),
]

if __name__ == "__main__":
    print("ADPS16 Table 1 (published) against this implementation (computed):")
    for name, n, q, s, pm, pb, pc, pq, dm, db, dc, dq in ADPS16_TABLE_1:
        b, m = primal(n, q, s, 2 * n)
        cost, b2, m2, quantum = dual(n, q, s, 2 * n)
        print(f"  {name:13s} primal b {pb} vs {b} (m {pm} vs {m}), {pc}/{pq} vs {CLASSICAL * b:.1f}/{QUANTUM * b:.1f};"
              f" dual b {db} vs {b2} (m {dm} vs {m2}), {dc}/{dq} vs {cost:.1f}/{quantum:.1f}")
