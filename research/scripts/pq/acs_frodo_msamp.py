"""acs_frodo_msamp.py - which sample bound m_max reproduces FrodoKEM round-3 Table 10?

The FrodoKEM round-3 specification (research/papers/
2021-alkim-et-al-frodokem-round3-specification-20210604.pdf, Sec. 5.2.1, p. 41)
only says the attacker has "msamp ~ n" samples; it does not print msamp.
The published 2016 script (lwe-frodo/parameter-selection pqsec.py) loops
m over range(max(1, b - n), max_m), i.e. m <= max_m - 1.

This script recomputes the Table 10 numbers (spec p. 43) with coresvp.py's
"frodo" convention for several sample bounds and prints which bounds give
the published values. Deterministic; about 1-2 minutes.

Usage: python acs_frodo_msamp.py
"""
import math
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")
import coresvp as cs  # noqa: E402

TABLE10 = {  # Frodo round-3 spec Table 10, p. 43: (primal C,Q,P), (dual C,Q,P)
    640: (2 ** 15, 2.8, (150.8, 137.6, 109.6), (149.6, 136.5, 108.7)),
    976: (2 ** 16, 2.3, (216.0, 196.7, 156.0), (214.5, 195.4, 154.9)),
    1344: (2 ** 16, 1.4, (281.6, 256.3, 202.6), (279.8, 254.7, 201.4)),
}

for n, (q, s, pub_p, pub_d) in TABLE10.items():
    print(f"Frodo-{n}: q={q} sigma={s}  published primal={pub_p} dual={pub_d}")
    for label, m_max in (("n+7", n + 7), ("n+8", n + 8), ("n+15", n + 15),
                         ("n+16", n + 16), ("2n", 2 * n)):
        e = cs.estimate(n, q, s, None, m_max, "frodo")
        p = tuple(round(e["primal"][k], 1) for k in "CQP")
        d = tuple(round(e["dual"][k], 1) for k in "CQP")
        okp = all(abs(a - b) < 0.051 for a, b in zip(p, pub_p))
        okd = all(abs(a - b) < 0.051 for a, b in zip(d, pub_d))
        print(f"  m_max={label:5s} primal={p} m={e['primal']['m']} {'MATCH' if okp else 'differs'}"
              f" | dual={d} m={e['dual']['m_C']} {'MATCH' if okd else 'differs'}")
