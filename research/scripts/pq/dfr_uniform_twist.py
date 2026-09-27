"""dfr_uniform_twist.py - what happens to the DFR when a "twist" swaps ML-KEM's noise distribution.

What it reproduces, and from where
----------------------------------
Shao, Liu, Zhou, Shao, "On the Security of LWE-based KEMs under Various Distributions: A Case
Study of Kyber", IACR ePrint 2024/1979 (preprint), Table 4 (PDF page 7): the decryption failure
probability of Kyber when the centred binomial secret and error distributions are replaced by the
uniform distribution over the same range:
    CBD      2^-139.1  2^-165.2  2^-175.2   (Kyber512 / 768 / 1024)
    uniform  2^-25.4   2^-50.3   2^-47.5
Their CBD row equals the pq-crystals script run under Python 3 (dfr.py validate explains why this
is 0.3-0.4 bit below FIPS 203 Table 1), so this script prints both the Python-3 reading (tail from
833, ties-to-even rounding in the compression law) and the FIPS 203 reading (tail from 832).
The paper then reports a practical key recovery for uniform-noise Kyber512 from 3,000 failures at
about 2^37 work (abstract and PDF page 10); that attack is quoted, not reproduced.

Method: exactly dfr.py's convolution model, with cbd(eta) replaced by the uniform law on
[-eta, eta] for s, e, r (eta1) and e1, e2 (eta2).

Usage: python dfr_uniform_twist.py      (deterministic, under a minute)
"""
import sys

import numpy as np

import dfr

sys.stdout.reconfigure(encoding="utf-8")

PAPER = {"ML-KEM-512": (-139.1, -25.4), "ML-KEM-768": (-165.2, -50.3), "ML-KEM-1024": (-175.2, -47.5)}


def uniform(eta: int) -> dfr.Law:
    return dfr.Law(-eta, [1.0 / (2 * eta + 1)] * (2 * eta + 1))


def error_law(P, dist, rounding, sign_dv):
    s, e1 = dist(P.eta1), dist(P.eta2)
    du = dfr.compression_error_law(P.q, P.du, rounding)
    dv = dfr.compression_error_law(P.q, P.dv, rounding)
    if sign_dv < 0:
        dv = dv.scale(-1)
    return s.times(s).power(P.k * P.n).conv(s.times(e1.conv(du)).power(P.k * P.n)).conv(e1.conv(dv))


ok = True
print("  set          dist     sigma(s)  Python-3 reading   FIPS 203 reading   paper Table 4")
for P in dfr.MLKEM:
    for idx, (name, dist) in enumerate((("CBD", dfr.cbd), ("uniform", uniform))):
        law_py3 = error_law(P, dist, "python3", -1)
        v_py3 = dfr.lg(P.n * dfr.symmetric_tail(law_py3, P.q / 4))
        law_f = error_law(P, dist, "fips", +1)
        v_f = dfr.lg(P.n * law_f.prob(lambda x: np.abs(x) >= 832))
        sd = dist(P.eta1).var() ** 0.5
        ref = PAPER[P.name][idx]
        good = abs(v_py3 - ref) < 0.1
        ok &= good
        print(f"  {P.name:11s}  {name:7s}  {sd:7.3f}   2^{v_py3:8.2f}        2^{v_f:8.2f}        "
              f"2^{ref}   [{'PASS' if good else 'FAIL'}] Python-3 reading within 0.1 bit")
print("\n  Negative control: uniform noise on [-(eta+1), eta+1] must not match the uniform row")
P = dfr.MLKEM[1]
law = error_law(P, lambda eta: uniform(eta + 1), "python3", -1)
v = dfr.lg(P.n * dfr.symmetric_tail(law, P.q / 4))
moved = abs(v - PAPER[P.name][1]) > 1
ok &= moved
print(f"  ML-KEM-768 with uniform [-3, 3]: 2^{v:.2f}  [{'PASS' if moved else 'FAIL'}] differs by > 1 bit")
print("\nReading: at the same range the uniform law has a larger variance (eta = 2: 2 against 1;")
print("eta = 3: 4 against 1.5) and flat tails, so the DFR collapses from 2^-139..2^-175 to")
print("2^-25..2^-50 - practical failure attacks. Any noise 'twist' needs a fresh exact DFR.")
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
