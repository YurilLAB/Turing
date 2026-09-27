"""dfr_run_pqcrystals.py - run the failure part of pq-crystals/security-estimates and dump its law.

What it reproduces, and from where
----------------------------------
FIPS 203 section 3.2, Table 1 (PDF page 24) cites "the scripts in [15]" = Ducas and Schanck,
github.com/pq-crystals/security-estimates, for the ML-KEM decapsulation failure rates. This driver
imports that repository's Kyber_failure.py unchanged (tested at commit 75c26949a902, 2021-03-16),
runs p2_cyclotomic_error_probability() on the three parameter sets exactly as its Kyber.py
__main__ defines them, prints log2 of the result, and writes the per-coefficient error law to JSON
so that `python dfr.py validate OUT_JSON` can compare dfr.py against it value by value.

Note: the repository was written for Python 2. Under Python 3, `ps.q/4` is 832.25 (not 832) and
round() rounds ties to even, so the numbers printed here are what the script gives under
Python 3; dfr.py explains and reproduces both behaviours.

Usage: python dfr_run_pqcrystals.py SECURITY_ESTIMATES_DIR OUT_JSON
Deterministic; no network.
"""
import json
import sys
import time
from math import log

sys.path.insert(0, sys.argv[1])
from Kyber import KyberParameterSet  # noqa: E402
from Kyber_failure import p2_cyclotomic_error_probability  # noqa: E402

sets = {
    # exactly as in Kyber.py __main__ of the pq-crystals repository
    "ML-KEM-512": KyberParameterSet(256, 2, 3, 3, 3329, 2**12, 2**10, 2**4, ke_ct=2),
    "ML-KEM-768": KyberParameterSet(256, 3, 2, 2, 3329, 2**12, 2**10, 2**4),
    "ML-KEM-1024": KyberParameterSet(256, 4, 2, 2, 3329, 2**12, 2**11, 2**5),
}
out = {}
for name, ps in sets.items():
    t0 = time.time()
    F, f = p2_cyclotomic_error_probability(ps)
    out[name] = {"failure": f, "log2": log(f) / log(2), "law": {str(k): v for k, v in F.items()},
                 "seconds": time.time() - t0}
    print(f"{name}: script failure = 2^{log(f)/log(2):.4f}  ({time.time()-t0:.1f} s)", flush=True)
with open(sys.argv[2], "w") as fh:
    json.dump(out, fh)
print(f"law written to {sys.argv[2]}")
