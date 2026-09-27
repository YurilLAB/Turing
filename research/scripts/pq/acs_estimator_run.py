"""acs_estimator_run.py - run the lattice-estimator WITHOUT SageMath (through acs_sage_shim)
and validate it against the estimator's own published outputs before trusting it.

WHAT IT REPRODUCES
  The lattice-estimator (M. Albrecht et al., github.com/malb/lattice-estimator; successor of
  Albrecht-Player-Scott, "On the concrete hardness of Learning with Errors", JMC 2015), at commit
  53da598 (2026-08-19). Its README.rst ("Usage examples") and docs/schemes/nist-pqc-round-3.rst
  print reference outputs, computed by the authors under SageMath:
      Kyber512  primal_usvp  rop 2^143.8, beta 406, d 998
      Kyber512  primal_bdd   rop 2^140.2, beta 389, eta 422, d 1005
      Kyber512  dual         rop 2^149.9, beta 424, d 1024
      Kyber512  dual_hybrid  rop 2^139.7, beta 387
      Kyber512  coded_bkw    rop 2^178.8
      Kyber512  rough usvp   rop 2^118.6, beta 406;  rough dual_hybrid rop 2^115.5, beta 395
      Kyber768  primal_bdd   rop 2^201.0, beta 606, eta 640, d 1420
      Kyber1024 primal_bdd   rop 2^270.7, beta 855, eta 889, d 1867
      LightSaber primal_bdd  rop 2^139.9, beta 388, eta 421, d 1021
  "validate" recomputes each under the shim and requires |log2 rop difference| <= 0.05 and the
  same beta (and eta, d where printed). NEGATIVE CONTROLS: (a) the same checks with Kyber512's
  n changed to 500 must fail; (b) a subprocess re-runs one check with the shim's pi perturbed by
  1 % (ACS_SHIM_PERTURB=1) and it must fail.

  "turing" then runs the estimator's attacks on ~1000-dimension Turing candidates (plain LWE
  n = 976/1024 and Module-LWE rank 4) and prints log2 costs next to coresvp.py's core-SVP.

USAGE
  python acs_estimator_run.py validate      # about 10-30 minutes (mpmath is slower than MPFR)
  python acs_estimator_run.py turing        # longer; run in the background with a timeout
  python acs_estimator_run.py smoke         # one quick call
  Environment: ACS_ESTIMATOR = path of the lattice-estimator clone (default: the copy in research/workfiles/pq/attack-cost).
  Deterministic. Exit code 0 iff every validation check passes (validate mode).
"""
import math
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EST = os.path.normpath(os.path.join(
    HERE, "..", "..", "workfiles", "pq", "attack-cost", "lattice-estimator"))
EST = os.environ.get("ACS_ESTIMATOR", DEFAULT_EST)
sys.path.insert(0, os.path.join(HERE, "acs_sage_shim"))
sys.path.insert(1, EST)
sys.stdout.reconfigure(encoding="utf-8")

if os.environ.get("ACS_SHIM_PERTURB") == "1":      # negative control (b)
    import sage.all as _sa
    _sa.pi = _sa.pi * 1.01

from estimator import LWE, ND, RC, schemes          # noqa: E402
from estimator.lwe_parameters import LWEParameters  # noqa: E402


def lg(x):
    return float(math.log2(float(x["rop"])))


def commit():
    try:
        return subprocess.run(["git", "-C", EST, "log", "-1", "--format=%h %ad", "--date=short"],
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as exc:                          # pragma: no cover
        return f"unknown ({exc})"


# name, callable, expected log2 rop, expected fields
def targets(kyber512):
    return [
        ("Kyber512 primal_usvp", lambda: LWE.primal_usvp(kyber512), 143.8, {"beta": 406, "d": 998}),
        ("Kyber512 primal_bdd", lambda: LWE.primal_bdd(kyber512), 140.2,
         {"beta": 389, "eta": 422, "d": 1005}),
        ("Kyber512 dual", lambda: LWE.dual(kyber512), 149.9, {"beta": 424, "d": 1024}),
        ("Kyber512 dual_hybrid", lambda: LWE.dual_hybrid(kyber512), 139.7, {"beta": 387}),
        ("Kyber512 coded_bkw", lambda: LWE.coded_bkw(kyber512), 178.8, {}),
        ("Kyber512 rough usvp", lambda: LWE.primal_usvp(kyber512, red_cost_model=RC.ADPS16,
                                                          red_shape_model="gsa"), 118.6,
         {"beta": 406}),
        ("Kyber512 rough dual_hybrid",
         lambda: LWE.dual_hybrid(kyber512, red_cost_model=RC.ADPS16), 115.5, {"beta": 395}),
    ]


TARGETS_OTHER = [
    ("Kyber768 primal_bdd", lambda: LWE.primal_bdd(schemes.Kyber768), 201.0,
     {"beta": 606, "eta": 640, "d": 1420}),
    ("Kyber1024 primal_bdd", lambda: LWE.primal_bdd(schemes.Kyber1024), 270.7,
     {"beta": 855, "eta": 889, "d": 1867}),
    ("LightSaber primal_bdd", lambda: LWE.primal_bdd(schemes.LightSaber), 139.9,
     {"beta": 388, "eta": 421, "d": 1021}),
]


def run_checks(rows, quiet=False):
    ok_all = True
    for name, fn, want, fields in rows:
        t0 = time.time()
        try:
            c = fn()
            got = lg(c)
            ok = abs(got - want) <= 0.05
            detail = []
            for k, v in fields.items():
                g = int(c.get(k, -1))
                ok = ok and g == v
                detail.append(f"{k}={g} (pub {v})")
            msg = f"log2 rop {got:.2f} (pub {want})"
        except Exception as exc:
            ok, msg, detail = False, f"ERROR {type(exc).__name__}: {exc}", []
        ok_all = ok_all and ok
        if not quiet:
            print(f"  {name:28s} {msg}  {' '.join(detail)}  [{time.time() - t0:.0f}s] "
                  f"{'PASS' if ok else 'FAIL'}", flush=True)
    return ok_all


def validate():
    print(f"lattice-estimator at {EST}\n  commit {commit()}; SageMath replaced by acs_sage_shim\n")
    print("== 1. Estimator's published outputs (README.rst, docs/schemes/nist-pqc-round-3.rst) ==")
    ok1 = run_checks(targets(schemes.Kyber512) + TARGETS_OTHER)
    print(f"  -> {'all reproduced' if ok1 else 'NOT all reproduced'}\n")

    print("== 2. Negative control (a): Kyber512 with n = 500 must NOT reproduce ==")
    k500 = LWEParameters(n=500, q=3329, Xs=schemes.Kyber512.Xs, Xe=schemes.Kyber512.Xe, m=500,
                         tag="Kyber512-n500")
    rows = targets(k500)[:2]
    bad = run_checks(rows)
    ok2 = not bad
    print(f"  -> control {'failed as expected' if ok2 else 'PASSED (bad control!)'}\n")

    print("== 3. Negative control (b): shim pi perturbed by 1 % must NOT reproduce ==")
    env = dict(os.environ, ACS_SHIM_PERTURB="1")
    r = subprocess.run([sys.executable, "-X", "utf8", os.path.abspath(__file__), "perturbed"],
                       capture_output=True, text=True, timeout=1800, env=env)
    print("  " + r.stdout.strip().replace("\n", "\n  "))
    ok3 = r.returncode == 1
    print(f"  -> control {'failed as expected' if ok3 else 'PASSED (bad control!)'}\n")

    print("SUMMARY:")
    for k, v in (("1 published outputs", ok1), ("2 n-perturbed control", ok2),
                 ("3 shim-perturbed control", ok3)):
        print(f"  {k:28s} {'PASS' if v else 'FAIL'}")
    return ok1 and ok2 and ok3


def doctests(modules=("lwe_primal", "lwe_dual", "lwe_bkw", "lwe_guess", "lwe", "reduction")):
    """Run the estimator's own docstring examples under the shim. For every example whose
    expected output contains 'rop:' (a cost), compare each 'rop: ≈2^X' and 'β: N' printed by the
    authors (under SageMath) with what we print. Other examples are executed but not scored
    (their output is SageMath number formatting, not a cost)."""
    import doctest
    import importlib
    import re
    pat_rop = re.compile(r"rop: ≈2\^([0-9.]+)")
    pat_beta = re.compile(r"β:\s+([0-9]+)")
    scored = passed = 0
    fails = []
    for mname in modules:
        mod = importlib.import_module(f"estimator.{mname}")
        finder = doctest.DocTestFinder(exclude_empty=True)
        for test in finder.find(mod):
            globs = dict(test.globs)
            for ex in test.examples:
                out = []
                runner_stdout = sys.stdout

                class _Cap:
                    def write(self, s):
                        out.append(s)

                    def flush(self):
                        pass
                sys.stdout = _Cap()
                err = None
                try:
                    code = compile(ex.source, "<doctest>", "single")
                    exec(code, globs)
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"
                finally:
                    sys.stdout = runner_stdout
                want_rops = pat_rop.findall(ex.want)
                if not want_rops:
                    continue
                got = "".join(out)
                got_rops = pat_rop.findall(got)
                want_b, got_b = pat_beta.findall(ex.want), pat_beta.findall(got)
                scored += 1
                ok = (err is None and len(got_rops) == len(want_rops)
                      and all(abs(float(a) - float(b)) <= 0.05 for a, b in zip(got_rops, want_rops))
                      and want_b == got_b[:len(want_b)])
                passed += ok
                if not ok:
                    fails.append(f"{test.name}: {ex.source.strip()[:70]!r}\n      want rop {want_rops} "
                                 f"β {want_b}\n      got  rop {got_rops} β {got_b[:len(want_b)]} {err or ''}")
    print(f"  estimator doctests with a cost in the expected output: {passed}/{scored} reproduced")
    for f in fails:
        print("   MISMATCH " + f)
    return passed, scored


def perturbed():
    ok = run_checks(targets(schemes.Kyber512)[:1])
    return 0 if ok else 1


def smoke():
    print(schemes.Kyber512)
    t0 = time.time()
    print(LWE.primal_usvp(schemes.Kyber512), f"[{time.time() - t0:.1f}s]")


def turing():
    """Estimator attacks on ~1000-dimension candidates (see coresvp.py table for core-SVP)."""
    print(f"lattice-estimator commit {commit()} under acs_sage_shim; default models "
          f"(RC.MATZOV, GSA). All values log2(rop). 'rough' = RC.ADPS16 core-SVP model.\n")
    which = os.environ.get("ACS_CANDIDATES", "")
    cands = []
    for n, lq, s in ((976, 16, 2.3), (1024, 16, 2.8), (1024, 15, 2.8), (1024, 16, 1.4),
                     (1024, 13, 1.0)):
        cands.append(LWEParameters(n=n, q=2 ** lq, Xs=ND.DiscreteGaussian(s),
                                   Xe=ND.DiscreteGaussian(s), m=n + 8,
                                   tag=f"LWE n{n} q2^{lq} s{s}"))
    cands.append(LWEParameters(n=1024, q=2 ** 15, Xs=ND.Uniform(-1, 1), Xe=ND.DiscreteGaussian(2.8),
                               m=1032, tag="LWE n1024 q2^15 ternary-s e2.8"))
    cands.append(LWEParameters(n=1024, q=3329, Xs=ND.CenteredBinomial(3), Xe=ND.CenteredBinomial(3),
                               m=1024, tag="MLWE k4 q3329 eta3"))
    cands.append(schemes.Kyber1024)
    cands.append(schemes.Frodo976)
    if which:
        keep = set(which.split(","))
        cands = [c for i, c in enumerate(cands) if str(i) in keep]
    # the attack set of LWE.estimate (lwe.py) minus arora-gb, same arguments; rough = lwe.py rough
    attacks = (("usvp", lambda p: LWE.primal_usvp(p)),
               ("bdd", lambda p: LWE.primal_bdd(p)),
               ("bdd_hybrid", lambda p: LWE.primal_hybrid(p, mitm=False, babai=False)),
               ("bdd_mitm_hybrid", lambda p: LWE.primal_hybrid(p, mitm=True, babai=True)),
               ("dual", lambda p: LWE.dual(p)),
               ("dual_hybrid", lambda p: LWE.dual_hybrid(p)),
               ("bkw", lambda p: LWE.coded_bkw(p)),
               ("rough usvp", lambda p: LWE.primal_usvp(p, red_cost_model=RC.ADPS16,
                                                        red_shape_model="gsa")),
               ("rough dual_hybrid", lambda p: LWE.dual_hybrid(p, red_cost_model=RC.ADPS16)))
    only = os.environ.get("ACS_ATTACKS", "")
    if only:
        keep_a = set(only.split(","))
        attacks = tuple(a for a in attacks if a[0] in keep_a)
    for p in cands:
        print(f"\n{p!r}", flush=True)
        best = (float("inf"), "")
        for a, fn in attacks:
            t0 = time.time()
            try:
                c = fn(p)
                v = lg(c)
                extra = ", ".join(f"{k}={int(c[k])}" for k in ("beta", "eta", "d", "zeta") if k in c
                                  and c[k] not in (None,) and not isinstance(c[k], str))
                print(f"  {a:18s} log2 rop {v:7.1f}   {extra}   [{time.time() - t0:.0f}s]", flush=True)
                if not a.startswith("rough") and v < best[0]:
                    best = (v, a)
            except Exception as exc:
                print(f"  {a:18s} ERROR {type(exc).__name__}: {exc}  [{time.time() - t0:.0f}s]",
                      flush=True)
        print(f"  -> cheapest (default MATZOV model): {best[1]} 2^{best[0]:.1f}", flush=True)


def main(argv):
    mode = argv[1] if len(argv) > 1 else "validate"
    if mode == "validate":
        ok = validate()
        print("OVERALL:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if mode == "perturbed":
        return perturbed()
    if mode == "doctests":
        mods = tuple(argv[2:]) or ("lwe_primal", "lwe_dual", "lwe_bkw", "lwe_guess", "lwe", "reduction")
        p, s = doctests(mods)
        return 0 if p == s else 1
    if mode == "smoke":
        smoke()
        return 0
    if mode == "turing":
        turing()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
