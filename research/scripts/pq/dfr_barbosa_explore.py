"""dfr_barbosa_explore.py - probe why the provable ML-KEM-1024 bound of Barbosa et al. differs from
dfr.py's reproduction by about one bit.

What it reproduces, and from where
----------------------------------
Barbosa, Kannwischer, Lim, Schwabe, Strub, "Formally verified correctness bounds for lattice-based
cryptography", ACM CCS 2025 (ePrint 2025/1562): Table 1 (PDF page 13) lists the provable bound
2^-95 for ML-KEM-1024 with optimal t_cu = 240 and "partial error probabilities of 2^-96 and 2^-97"
(section 5.5, PDF page 12). dfr.py provable gets 2^-96.16 (parts 2^-96.60 and 2^-98.10).
This script prints the two partial probabilities of the split bound for ML-KEM-768 and -1024
under a few alternative readings of the experiment:
  * threshold convention: ">" (as in their Figure 3/4) versus ">="
  * t_max_cv: the true maximum |cv| versus the dv = 4 value 104
  * cu law: rounding error of a uniform element with FIPS rounding (dfr.py) versus ties-to-even
It changes nothing in dfr.py; it only reports which reading matches the paper's numbers.

Usage: python dfr_barbosa_explore.py     (deterministic, about a minute)
"""
import sys

import numpy as np

import dfr

sys.stdout.reconfigure(encoding="utf-8")


def parts(P, tcu, tmax_cv, strict=True, rounding="fips"):
    s, e1 = dfr.cbd(P.eta1), dfr.cbd(P.eta2)
    n1 = s.times(s).power(P.k * P.n).conv(s.times(e1).power(P.k * P.n)).conv(e1)
    cu = dfr.compression_error_law(P.q, P.du, rounding)
    n2 = s.times(cu).power(P.k * P.n)
    T = P.q // 4 - 1
    t1 = T - tmax_cv - tcu
    if strict:
        p1 = P.n * n1.prob(lambda x: np.abs(x) > t1)
        p2 = P.n * n2.prob(lambda x: np.abs(x) > tcu)
    else:
        p1 = P.n * n1.prob(lambda x: np.abs(x) >= t1)
        p2 = P.n * n2.prob(lambda x: np.abs(x) >= tcu)
    return dfr.lg(p1), dfr.lg(p2), dfr.lg(p1 + p2)


for P, tcu in ((dfr.MLKEM[1], 296), (dfr.MLKEM[2], 240)):
    cv = dfr.compression_error_law(P.q, P.dv)
    cu = dfr.compression_error_law(P.q, P.du)
    print(f"{P.name}: cv support {cv.lo}..{cv.hi}; cu support {cu.lo}..{cu.hi}; "
          f"cu law {dict(zip(cu.support().tolist(), np.round(cu.p, 5).tolist()))}")
    for tm in sorted({int(max(-cv.lo, cv.hi)), 104}):
        for strict in (True, False):
            for rnd in ("fips", "python3"):
                a, b, c = parts(P, tcu, tm, strict, rnd)
                print(f"   t_cu={tcu} t_max_cv={tm:3d} {'>' if strict else '>='} {rnd:7s}: "
                      f"parts 2^{a:.2f} + 2^{b:.2f} = 2^{c:.2f}")
