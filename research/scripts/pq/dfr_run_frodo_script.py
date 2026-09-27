"""dfr_run_frodo_script.py - run FrodoKEM's own failure-probability code and compare with dfr.py.

What it reproduces, and from where
----------------------------------
FrodoKEM round-3 specification (2021-06-04), Table 2 (PDF page 24): failure rates
Frodo-640 2^-138.7, Frodo-976 2^-199.6, Frodo-1344 2^-252.5 (repeated in the 2025 ISO
preliminary standardization proposal, Table A.9, PDF page 19).

The submission package (NIST round-3 zip, FrodoKEM-20200930/Additional_Implementations/
Parameter_Search_Scripts/) contains failure_prob_pke.py, whose exact_failure_prob_pke() is what
print_tables_pke.py uses to print Table 2. This driver imports that file unchanged, feeds it the
error tables of round-3 Table 3 (PDF page 25) = 2025 Table A.3 (PDF page 15), and prints the
result next to the two rules that research/scripts/pq/dfr.py implements:
  * exact decode rule      : an entry fails iff e is outside [-q/2^(B+1), q/2^(B+1))
                             (round-3 spec Lemma 2.18 and section 2.2.7, PDF pages 18-19)
  * symmetric (script) rule: an entry fails iff |e| >= q/2^(B+1)
The official function folds x -> min(x, q - x) before testing -b/2 <= x < b/2, which makes its
test the symmetric rule; this driver shows that numerically.

The official code uses numpy.float128, which Windows numpy does not provide. On such platforms
the driver aliases numpy.float128 to numpy.longdouble (float64 on Windows) and says so; the
comparison threshold (0.01 bit) is far above float64 rounding.

Usage: python dfr_run_frodo_script.py PATH_TO/Parameter_Search_Scripts
Deterministic; no network.
"""
import os
import sys
from math import log2

import numpy as np

sys.stdout.reconfigure(encoding="utf-8")
script_dir = sys.argv[1]
if not hasattr(np, "float128"):
    print("note: numpy.float128 missing on this platform; aliasing it to numpy.longdouble "
          f"(machine epsilon {np.finfo(np.longdouble).eps:.1e})")
    np.float128 = np.longdouble
sys.path.insert(0, script_dir)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from failure_prob_pke import exact_failure_prob_pke  # noqa: E402  (official code, unchanged)
from discrete_distr import pdf_product  # noqa: E402
import dfr  # noqa: E402

PUBLISHED = {"Frodo-640": -138.7, "Frodo-976": -199.6, "Frodo-1344": -252.5}
ok = True
for P in dfr.FRODO:
    # one-sided law as print_tables_pke.py stores it: {0: P(0), i: P(+i) + P(-i)}
    half = {0: P.table[0] / 2.0 ** 16}
    for i in range(1, len(P.table)):
        half[i] = 2 * P.table[i] / 2.0 ** 16
    sym = pdf_product(half, {+1: .5, -1: .5})          # exactly as print_tables_pke.py line 204
    official = exact_failure_prob_pke(sym, P.q, P.n, P.B, 8 * 8 * P.B)
    law, p_exact, dfr_exact = dfr.frodo_dfr(P)
    h = P.q >> (P.B + 1)
    dfr_sym = 64 * law.prob(lambda x: np.abs(x) >= h)
    print(f"{P.name}: official exact_failure_prob_pke = 2^{log2(official):.4f}; "
          f"dfr.py symmetric rule = 2^{log2(dfr_sym):.4f}; dfr.py exact decode rule = "
          f"2^{log2(dfr_exact):.4f}; published 2^{PUBLISHED[P.name]}")
    same = abs(log2(official) - log2(dfr_sym)) < 0.01
    ok &= same
    print(f"    [{'PASS' if same else 'FAIL'}] official code equals the symmetric rule to 0.01 bit")
    rounds = round(log2(official), 1) == PUBLISHED[P.name]
    ok &= rounds
    print(f"    [{'PASS' if rounds else 'FAIL'}] official code rounds to the published value")
    # negative control: the official code with a changed B must not give the published value
    ctrl = exact_failure_prob_pke(sym, P.q, P.n, P.B + 1, 8 * 8 * (P.B + 1))
    moved = abs(log2(ctrl) - PUBLISHED[P.name]) > 1
    ok &= moved
    print(f"    [{'PASS' if moved else 'FAIL'}] negative control: B = {P.B + 1} gives "
          f"2^{log2(ctrl):.2f}, far from the published value")
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
