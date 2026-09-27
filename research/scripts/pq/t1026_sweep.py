"""t1026_sweep.py - how Turing-1026's noise and modulus were chosen (docs/16).

For plain LWE in dimension n = 1026 with one message bit per coefficient
(256 coefficients), sweeps q = 2^14, 2^15, 2^16 and centred-binomial noise
CBD(eta) for secret and error alike, and prints for each point:
  - the exact decryption-failure probability (dfr.py's convolution, union
    bound over 256 coefficients, decoding window [-q/4, q/4));
  - classical and quantum core-SVP of the primal and dual attacks
    (coresvp.py, newhope and frodo conventions, m_max = n + 32).
Both depend on sigma^2 / q only (attack-cost-estimation.md, finding 10):
the rows with equal sigma^2 / q agree across q. Turing-1026 takes the
largest noise whose failure probability stays below 2^-(weakest attack):
q = 2^15, eta = 18 (sigma = 3), 2^-266.1 against 2^-252.4.

Usage: python research/scripts/pq/t1026_sweep.py   (numpy; about a minute)
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coresvp as cs  # noqa: E402
import dfr  # noqa: E402

N, COEFFS = 1026, 256


def failure(eta, q):
    chi = dfr.cbd(eta)
    law = chi.times(chi).power(2 * N).conv(chi)
    h = q >> 2
    return dfr.lg(COEFFS * law.prob(lambda x: (x < -h) | (x >= h)))


def main():
    print(f"n = {N}, B = 1 (256 coefficients), secret and error CBD(eta), m_max = n + 32")
    print(f"{'q':>5} {'eta':>4} {'sigma':>6} {'s2/q':>9} | {'DFR':>8} | {'primal C':>8} {'Q':>6} {'dual C':>7} | {'frodo C':>7}")
    for lq in (14, 15, 16):
        q = 2 ** lq
        for eta in range({14: 6, 15: 10, 16: 20}[lq], 60, 2):
            d = failure(eta, q)
            if d > -200:
                print(f"2^{lq:<3} {eta:4d}  failure rate 2^{d:.1f}: above 2^-200, stop")
                break
            s = math.sqrt(eta / 2)
            e = cs.estimate(N, q, s, None, N + 32, "newhope")
            f = cs.estimate(N, q, s, None, N + 32, "frodo")
            print(f"2^{lq:<3} {eta:4d} {s:6.3f} {s * s / q:9.2e} | 2^{d:6.1f} | {e['primal']['C']:8.1f} "
                  f"{e['primal']['Q']:6.1f} {e['dual']['C']:7.1f} | {f['primal']['C']:7.1f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
