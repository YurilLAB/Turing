"""t1026_weak_keys.py - the failure probability of individual Turing-1026 keys (docs/16).

The failure rate docs/16 quotes, 2^-266.1, is the average over all keys. An
attacker faces one key, so this draws random keys (S, E: 1026 x 32, CBD(18))
and computes each key's own rate exactly: for column j of the key, the error
of a coefficient is sum_k E[k][j] S'[i][k] - S[k][j] E'[i][k] + E''[i][j]
with S', E', E'' fresh, whose law dfr.keyed_sum builds from the column's
value counts; the key's rate is the union bound over 8 rows x 32 columns.

Usage: python research/scripts/pq/t1026_weak_keys.py [KEYS [SEED]]
       (numpy; about 20 s per key)
"""
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np  # noqa: E402
import dfr  # noqa: E402

N, Q, ETA, NBAR, MBAR = 1026, 2 ** 15, 18, 32, 8
H = Q >> 2


def main(argv):
    keys = int(argv[1]) if len(argv) > 1 else 12
    rng = np.random.default_rng(int(argv[2]) if len(argv) > 2 else 1)
    chi = dfr.cbd(ETA)

    def cbd(shape):
        return rng.integers(0, 2, size=shape + (ETA,)).sum(-1) - rng.integers(0, 2, size=shape + (ETA,)).sum(-1)

    def column_failure(s_col, e_col):
        ce, cs_ = {}, {}
        for v in np.abs(e_col):
            ce[int(v)] = ce.get(int(v), 0) + 1
        for v in np.abs(s_col):
            cs_[int(v)] = cs_.get(int(v), 0) + 1
        law = dfr.keyed_sum(ce, chi).conv(dfr.keyed_sum(cs_, chi)).conv(chi)
        return law.prob(lambda x: (x < -H) | (x >= H))

    vals = []
    for k in range(keys):
        t0 = time.time()
        s, e = cbd((N, NBAR)), cbd((N, NBAR))
        ps = [column_failure(s[:, j], e[:, j]) for j in range(NBAR)]
        d = MBAR * math.fsum(ps)
        vals.append(dfr.lg(d))
        print(f"key {k}: 2^{dfr.lg(d):.1f} (worst column x 8 rows 2^{dfr.lg(8 * max(ps)):.1f}) [{time.time() - t0:.0f}s]", flush=True)
    v = np.sort(np.array(vals))
    print(f"{keys} keys: min 2^{v[0]:.1f}, median 2^{np.median(v):.1f}, max 2^{v[-1]:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
