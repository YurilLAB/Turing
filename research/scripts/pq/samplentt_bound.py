"""Recompute FIPS 203 Appendix B, Table 4: SampleNTT loop limit 280, 2^-261.

SampleNTT (FIPS 203, Algorithm 7) squeezes 3 bytes per iteration, forms two
12-bit candidates and keeps each one that is < q = 3329, until 256 are kept.
So each candidate is kept with probability p = 3329/4096, independently
(standard XOF assumption, as in FIPS 203 App. B). After L iterations 2L
candidates have been tried; the loop is still running iff fewer than 256
were kept. Hence

    P(reach limit L) = P(Binomial(2L, p) <= 255).

The script prints log2 of that for L = 280 (FIPS 203 says 2^-261), the mean
and standard deviation of the iteration count, and a Monte Carlo check of
the mean with a fixed seed.

Why this matters for side channels: the iteration count depends only on the
seed rho, which is part of the public encapsulation key, so timing that
reveals it reveals nothing secret. The same loop seeded with a secret (as in
HQC's and BIKE's re-encryption, Guo et al., TCHES 2022(3)) leaks.
"""
import random

import mpmath as mp

mp.mp.dps = 60
q, n = 3329, 256
p = mp.mpf(q) / 4096


def p_reach(limit):
    trials = 2 * limit
    return mp.fsum(mp.binomial(trials, k) * p**k * (1 - p) ** (trials - k) for k in range(n))


for L in (200, 250, 280, 300):
    print(f"L={L}: P(still running after L iterations) = 2^{float(mp.log(p_reach(L), 2)):.2f}")

# Distribution of the number of iterations T: P(T > t) = P(Bin(2t,p) <= 255).
mean = mp.fsum(p_reach(t) for t in range(0, 2000))  # E[T] = sum_{t>=0} P(T > t)
second = mp.fsum((2 * t + 1) * p_reach(t) for t in range(0, 2000))  # E[T^2]
sd = mp.sqrt(second - mean**2)
print(f"E[iterations] = {float(mean):.3f}, sd = {float(sd):.3f} (256 / (2p) = {float(256 / (2 * p)):.3f})")

rng = random.Random(20260926)
runs = 20000
tot = 0
for _ in range(runs):
    j = it = 0
    while j < n:
        it += 1
        d1, d2 = rng.getrandbits(12), rng.getrandbits(12)
        if d1 < q:
            j += 1
        if d2 < q and j < n:
            j += 1
    tot += it
print(f"Monte Carlo mean over {runs} runs (seed 20260926): {tot / runs:.3f}")
