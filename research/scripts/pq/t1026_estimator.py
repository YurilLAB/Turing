"""t1026_estimator.py - the lattice-estimator's attacks on Turing-1026 (docs/16).

Runs the lattice-estimator (github.com/malb/lattice-estimator, commit 53da598,
2026-08-19, LGPLv3+, not vendored: clone it and point ACS_ESTIMATOR at it)
through acs_sage_shim, on Turing-1026's two LWE instances (the key, m = n;
a ciphertext, m = n + 32) and, with "refs", on FrodoKEM-1344 and Kyber1024
as the estimator defines them. Validate the shim first:
    python research/scripts/pq/acs_estimator_run.py validate
The shim needs mpmath 1.3.0: under mpmath 1.4.1 the dual, BKW and hybrid
attacks die with RecursionError (mpmath's reflected operators call back into
the shim's), and the validation reports 2 of 10 published outputs missing.

Usage: ACS_ESTIMATOR=/path/to/lattice-estimator python t1026_estimator.py [main|refs]
Each attack prints log2 of its cost ("rop") in the estimator's default model
(RC.MATZOV); "rough" rows are its core-SVP model (RC.ADPS16).
"""
import math, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
EST = os.environ["ACS_ESTIMATOR"]
sys.path.insert(0, os.path.join(HERE, "acs_sage_shim"))
sys.path.insert(1, EST)
from estimator import LWE, ND, RC, schemes
from estimator.lwe_parameters import LWEParameters

def lg(x):
    return float(math.log2(float(x["rop"])))

which = sys.argv[1] if len(sys.argv) > 1 else "main"
cands = []
if which == "main":
    cands.append(LWEParameters(n=1026, q=2**15, Xs=ND.CenteredBinomial(18), Xe=ND.CenteredBinomial(18), m=1026 + 32, tag="Turing-1026 ct (m=n+32)"))
    cands.append(LWEParameters(n=1026, q=2**15, Xs=ND.CenteredBinomial(18), Xe=ND.CenteredBinomial(18), m=1026, tag="Turing-1026 pk (m=n)"))
elif which == "refs":
    cands.append(schemes.Frodo1344)
    cands.append(schemes.Kyber1024)
attacks = (("usvp", lambda p: LWE.primal_usvp(p)),
           ("bdd", lambda p: LWE.primal_bdd(p)),
           ("dual", lambda p: LWE.dual(p)),
           ("dual_hybrid", lambda p: LWE.dual_hybrid(p)),
           ("bkw", lambda p: LWE.coded_bkw(p)),
           ("rough usvp", lambda p: LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")),
           ("rough dual_hybrid", lambda p: LWE.dual_hybrid(p, red_cost_model=RC.ADPS16)),
           ("bdd_hybrid", lambda p: LWE.primal_hybrid(p, mitm=False, babai=False)),
           ("bdd_mitm_hybrid", lambda p: LWE.primal_hybrid(p, mitm=True, babai=True)))
for p in cands:
    print(f"\n{p!r}", flush=True)
    best = (float("inf"), "")
    for a, fn in attacks:
        t0 = time.time()
        try:
            c = fn(p)
            v = lg(c)
            extra = ", ".join(f"{k}={int(c[k])}" for k in ("beta", "eta", "d", "zeta") if k in c and c[k] is not None and not isinstance(c[k], str))
            print(f"  {a:18s} log2 rop {v:7.1f}   {extra}   [{time.time() - t0:.0f}s]", flush=True)
            if not a.startswith("rough") and v < best[0]:
                best = (v, a)
        except Exception as exc:
            print(f"  {a:18s} ERROR {type(exc).__name__}: {exc}  [{time.time() - t0:.0f}s]", flush=True)
    print(f"  -> cheapest (default MATZOV model): {best[1]} 2^{best[0]:.1f}", flush=True)
