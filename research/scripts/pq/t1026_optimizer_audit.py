"""t1026_optimizer_audit.py - check the lattice-estimator's optimizers instead of trusting them (docs/16).

The estimator's MATZOV dual-hybrid search (estimator/lwe_dual.py, MATZOV.__call__)
steps the guessing dimension zeta and the FFT dimension t by 10 and stops at the
first cost increase (util.early_abort_range). Issue #219 of malb/lattice-estimator
(opened 2026-07-09) reports that this misses the optimum: full enumeration finds
lower costs for all three ML-KEM sets, 1.08 bits lower for ML-KEM-1024 (zeta = 34
instead of 0). Issue #149 (2025-03-26) reports that primal_bdd and primal_hybrid
search beta only up to the uSVP optimum + 1.

This script replaces those searches with exhaustive ones and prints both:

  matzov   p = 2..P, every zeta and t on a step-S grid (then step 1 around the
           best), beta minimised at each point by a coarse scan and a local
           refinement, and the final optimum checked by scanning every beta.
  primal   primal_bdd with the beta range widened as issue #149 proposes.

Validation first: on the estimator's Kyber1024 (= ML-KEM-1024 as LWE) the
exhaustive MATZOV search must find about 1.08 bits below the default, at zeta
near 34, as issue #219 reports. Then Turing-1026.

Usage: ACS_ESTIMATOR=/path/to/lattice-estimator python t1026_optimizer_audit.py [matzov|primal] [kyber|turing]
Needs mpmath 1.3.0 for the SageMath stand-in (see t1026_estimator.py).
"""
import math
import os
import sys
import time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
EST = os.environ["ACS_ESTIMATOR"]
sys.path.insert(0, os.path.join(HERE, "acs_sage_shim"))
sys.path.insert(1, EST)
from estimator import LWE, ND, schemes  # noqa: E402
from estimator.lwe_dual import MATZOV  # noqa: E402
from estimator.lwe_parameters import LWEParameters  # noqa: E402


def instance(which):
    if which == "kyber":
        return schemes.Kyber1024.normalize()
    return LWEParameters(n=1026, q=2 ** 15, Xs=ND.CenteredBinomial(18), Xe=ND.CenteredBinomial(18),
                         m=1026 + 32, tag="Turing-1026 ciphertext").normalize()


def lg(c):
    return float(math.log2(float(c["rop"])))


def cost(params, beta, p, z, t):
    return lg(MATZOV.cost(beta, params, p=p, k_enum=z, k_fft=t))


def max_beta(params, z, t):
    # the estimator's own upper limit for beta at this (zeta, t)
    return max(min(params.m - z - t, 2 * params.n), 41)


def best_beta(params, p, z, t, window):
    """Minimum over every integer beta in `window` (a full scan: the cost's
    optimum in (zeta, t) sits at the edge of a cliff where the FFT term takes
    over, and a warm-started local search stepped over it in a first version
    of this script)."""
    hi = max_beta(params, z, t)
    return min((cost(params, b, p, z, t), b) for b in window if 40 <= b <= hi)


def sweep_p(args):
    which, p, zetas, ts, window = args
    params = instance(which)
    out = []
    for z in zetas:
        for t in ts:
            if z + t >= params.n - 40:
                continue
            c, b = best_beta(params, p, z, t, window)
            out.append((c, p, z, t, b))
    return out


def matzov(which):
    params = instance(which)
    t0 = time.time()
    default = LWE.dual_hybrid(params)
    print(f"{params.tag}: estimator default 2^{lg(default):.2f} at p={default['p']}, zeta={default['zeta']}, "
          f"t={default['t']}, beta={default['beta']} [{time.time() - t0:.1f}s]", flush=True)
    window = range(default["beta"] - 100, default["beta"] + 61)
    t0 = time.time()
    zetas, ts = list(range(0, 61)), list(range(0, 141, 2))
    jobs = [(which, p, zetas, ts, window) for p in range(2, 9)]
    with Pool(4) as pool:
        rows = [r for part in pool.map(sweep_p, jobs) for r in part]
    rows.sort()
    print(f"  every zeta 0..60, t 0..140 step 2, p 2..8, every beta in [{window.start}, {window.stop - 1}]: "
          f"{len(rows)} points, best 2^{rows[0][0]:.2f} at p={rows[0][1]}, zeta={rows[0][2]}, t={rows[0][3]}, "
          f"beta={rows[0][4]} [{time.time() - t0:.0f}s]", flush=True)
    t0 = time.time()
    c, p, z, t, b = rows[0]
    fine = sweep_p((which, p, [z], list(range(max(0, t - 3), t + 4)), window))
    fine.sort()
    c, p, z, t, b = fine[0]
    full = min((cost(params, bb, p, z, t), bb) for bb in range(40, max_beta(params, z, t) + 1))
    print(f"  t at step 1 there: 2^{c:.2f} at t={t}; every beta 40..max scanned: 2^{full[0]:.2f} at beta "
          f"{full[1]} [{time.time() - t0:.0f}s]", flush=True)
    print(f"  exhaustive minus default: {min(c, full[0]) - lg(default):+.2f} bits", flush=True)
    edge = max(r[2] for r in rows[:20])
    print(f"  the 20 best points have zeta <= {edge} (search range ends at 60)", flush=True)


def primal(which):
    """primal_bdd as the estimator runs it (beta at most the uSVP optimum + 2,
    then d optimised), and the same cost function with beta scanned from
    uSVP - 80 to uSVP + 80 and d re-optimised at the best beta (issue #149).
    m = m + n samples when the secret is no wider than the error, as
    primal_hybrid does (Bai-Galbraith)."""
    from estimator.lwe_primal import PrimalHybrid
    params = instance(which)
    m = params.m + params.n if params.Xs <= params.Xe else params.m
    t0 = time.time()
    usvp = LWE.primal_usvp(params)
    bdd = LWE.primal_bdd(params)
    print(f"{params.tag}: usvp 2^{lg(usvp):.2f} (beta {usvp['beta']}), bdd 2^{lg(bdd):.2f} "
          f"(beta {bdd['beta']}, eta {bdd['eta']}, d {bdd['d']}) [{time.time() - t0:.1f}s]", flush=True)

    def f(beta, d=None):
        return PrimalHybrid.cost(beta=beta, params=params, zeta=0, babai=False, mitm=False, m=m, d=d)

    t0 = time.time()
    scan = [(lg(f(b)), b) for b in range(max(40, usvp["beta"] - 80), usvp["beta"] + 81)
            if f(b)["rop"] < float("inf")]
    c, b = min(scan)
    best = f(b)
    # re-optimise the dimension at that beta over the whole admissible range
    for d in range(params.n, best["d"] + 1):
        cd = f(b, d)
        if cd["rop"] < best["rop"]:
            best = cd
    print(f"  bdd with every beta from uSVP-80 to uSVP+80 and d re-optimised: 2^{lg(best):.2f} at beta "
          f"{best['beta']}, eta {best.get('eta')}, d {best.get('d')} [{time.time() - t0:.0f}s]", flush=True)
    print(f"  scanned minus estimator: {lg(best) - lg(bdd):+.2f} bits", flush=True)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "matzov"
    which = sys.argv[2] if len(sys.argv) > 2 else "turing"
    {"matzov": matzov, "primal": primal}[mode](which)
