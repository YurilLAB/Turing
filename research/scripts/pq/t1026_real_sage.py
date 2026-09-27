"""t1026_real_sage.py - the lattice-estimator under real SageMath, on Turing-1026 (docs/16).

Everything else in this directory runs the estimator through acs_sage_shim, a
numeric stand-in for SageMath. This runs the same pinned estimator
(github.com/malb/lattice-estimator, commit 53da598) under SageMath itself:

  1. the estimator's own published outputs (README.rst and
     docs/schemes/nist-pqc-round-3.rst), as acs_estimator_run.py checks them;
  2. LWE.estimate on Turing-1026's two instances, every default attack
     including Arora-Groebner, in the default (MATZOV) model and in the
     core-SVP model (RC.ADPS16);
  3. the same for the estimator's Kyber1024 and Frodo1344.

Usage: ACS_ESTIMATOR=/path/to/lattice-estimator sage -python t1026_real_sage.py
(SageMath 10.7 from conda-forge was used: micromamba create -c conda-forge sage.)
"""
import math
import os
import subprocess
import sys
import time

EST = os.environ["ACS_ESTIMATOR"]
sys.path.insert(0, EST)
from sage.all import version  # noqa: E402
from estimator import LWE, ND, RC, schemes  # noqa: E402
from estimator.lwe_parameters import LWEParameters  # noqa: E402


def lg(c):
    return float(math.log2(float(c["rop"])))


def main():
    commit = subprocess.run(["git", "-C", EST, "log", "-1", "--format=%h %ad", "--date=short"],
                            capture_output=True, text=True).stdout.strip()
    print(f"{version()}; lattice-estimator {commit}\n", flush=True)
    k512 = schemes.Kyber512
    checks = [
        ("Kyber512 primal_usvp", lambda: LWE.primal_usvp(k512), 143.8, {"beta": 406, "d": 998}),
        ("Kyber512 primal_bdd", lambda: LWE.primal_bdd(k512), 140.2, {"beta": 389, "eta": 422, "d": 1005}),
        ("Kyber512 dual", lambda: LWE.dual(k512), 149.9, {"beta": 424, "d": 1024}),
        ("Kyber512 dual_hybrid", lambda: LWE.dual_hybrid(k512), 139.7, {"beta": 387}),
        ("Kyber512 coded_bkw", lambda: LWE.coded_bkw(k512), 178.8, {}),
        ("Kyber512 rough usvp", lambda: LWE.primal_usvp(k512, red_cost_model=RC.ADPS16, red_shape_model="gsa"), 118.6, {"beta": 406}),
        ("Kyber512 rough dual_hybrid", lambda: LWE.dual_hybrid(k512, red_cost_model=RC.ADPS16), 115.5, {"beta": 395}),
        ("Kyber768 primal_bdd", lambda: LWE.primal_bdd(schemes.Kyber768), 201.0, {"beta": 606, "eta": 640, "d": 1420}),
        ("Kyber1024 primal_bdd", lambda: LWE.primal_bdd(schemes.Kyber1024), 270.7, {"beta": 855, "eta": 889, "d": 1867}),
        ("LightSaber primal_bdd", lambda: LWE.primal_bdd(schemes.LightSaber), 139.9, {"beta": 388, "eta": 421, "d": 1021}),
    ]
    ok = 0
    print("1. Published outputs of the estimator", flush=True)
    for name, fn, want, fields in checks:
        c = fn()
        good = abs(lg(c) - want) <= 0.05 and all(int(c[k]) == v for k, v in fields.items())
        ok += good
        print(f"  {name:28s} 2^{lg(c):.2f} (published {want}) "
              + " ".join(f"{k}={int(c[k])}" for k in fields) + f"  {'PASS' if good else 'FAIL'}", flush=True)
    print(f"  -> {ok} of {len(checks)} reproduced\n", flush=True)

    cands = [
        LWEParameters(n=1026, q=2 ** 15, Xs=ND.CenteredBinomial(18), Xe=ND.CenteredBinomial(18), m=1026 + 32,
                      tag="Turing-1026 ciphertext (m = n + 32)"),
        LWEParameters(n=1026, q=2 ** 15, Xs=ND.CenteredBinomial(18), Xe=ND.CenteredBinomial(18), m=1026,
                      tag="Turing-1026 key (m = n)"),
        schemes.Kyber1024,
        schemes.Frodo1344,
    ]
    for p in cands:
        for model, kw in (("default model", {}), ("core-SVP model", {"red_cost_model": RC.ADPS16, "red_shape_model": "gsa"})):
            t0 = time.time()
            res = LWE.estimate(p, jobs=1, **kw)
            finite = {k: lg(v) for k, v in res.items() if v["rop"] != float("inf") and math.isfinite(lg(v))}
            best = min(finite, key=finite.get)
            print(f"2. {p.tag}, {model}: " + ", ".join(f"{k} {v:.1f}" for k, v in sorted(finite.items(), key=lambda kv: kv[1]))
                  + f"  -> cheapest {best} 2^{finite[best]:.1f} [{time.time() - t0:.0f}s]\n", flush=True)
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
