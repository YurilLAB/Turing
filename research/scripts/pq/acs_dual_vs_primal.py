"""acs_dual_vs_primal.py - how far the best published dual-hybrid attacks sit below the primal
attack for Kyber/ML-KEM, in the core-SVP model (C0) and in the RAM gate model (CC), and how the
gap grows with the dimension.

All inputs are published numbers (VERIFIED in the notes' claim ledger); this script only
subtracts. Sources:
  primal core-SVP  Kyber round-3 spec Table 4, PDF p. 21 (unrounded b * log2 sqrt(3/2) for
                   b = 406 / 626 / 878, as coresvp.py computes)
  primal RAM gates lattice-estimator commit 53da598 (MATZOV cost model): Kyber512 bdd 140.2 and
                   usvp 143.8 (README.rst); Kyber768 bdd 201.0, Kyber1024 bdd 270.7
                   (docs/schemes/nist-pqc-round-3.rst)
  dual-hybrid      MATZOV as recomputed in Albrecht-Shen [AS22] and Carrier-Meyer-Hilfiger-Shen-
                   Tillich (CRYPTO 2025, ePrint 2022/1750) Table 5.1, PDF p. 27;
                   Ogilvie (ePrint 2026/279, CRYPTO 2026 merged paper) Table 2, PDF p. 30.

Usage: python acs_dual_vs_primal.py   (deterministic, no inputs; prints the table)
"""
import math

C = math.log2(math.sqrt(1.5))
PRIMAL_B = {"Kyber512": 406, "Kyber768": 626, "Kyber1024": 878}
PRIMAL_RAM = {"Kyber512": 140.2, "Kyber768": 201.0, "Kyber1024": 270.7}   # estimator bdd
# (C0, CC) pairs
DUAL = {
    "MATZOV [AS22]": {"Kyber512": (115.4, 139.2), "Kyber768": (173.7, 196.1), "Kyber1024": (241.8, 262.4)},
    "Carrier et al. 2025": {"Kyber512": (121.8, 139.5), "Kyber768": (173.0, 195.1), "Kyber1024": (239.0, 259.7)},
    "Ogilvie 2026 (+rotations)": {"Kyber512": (118.8, 137.1), "Kyber768": (170.2, 192.7),
                                  "Kyber1024": (234.8, 257.2)},
}
NIST = {"Kyber512": 143, "Kyber768": 207, "Kyber1024": 272}

print("Primal vs dual-hybrid, log2 cost. C0 = core-SVP model, CC = RAM gate model.")
print(f"{'set':>10} | {'primal C0':>9} {'primal CC':>9} | {'attack':>26} {'C0':>6} {'CC':>6} | "
      f"{'C0 gap':>6} {'CC gap':>6} | {'NIST':>4} {'CC-NIST':>7}")
for s in ("Kyber512", "Kyber768", "Kyber1024"):
    p0 = C * PRIMAL_B[s]
    pc = PRIMAL_RAM[s]
    for name, tab in DUAL.items():
        d0, dc = tab[s]
        print(f"{s:>10} | {p0:9.1f} {pc:9.1f} | {name:>26} {d0:6.1f} {dc:6.1f} | "
              f"{p0 - d0:6.1f} {pc - dc:6.1f} | {NIST[s]:4d} {dc - NIST[s]:7.1f}")
print("\ngap = primal minus dual (positive = dual cheaper). The best gap at each size:")
for s in ("Kyber512", "Kyber768", "Kyber1024"):
    p0 = C * PRIMAL_B[s]
    pc = PRIMAL_RAM[s]
    g0 = max(p0 - t[s][0] for t in DUAL.values())
    gc = max(pc - t[s][1] for t in DUAL.values())
    print(f"  {s:>10}: dimension {256 * (2 + ('768' in s) + 2 * ('1024' in s))}: "
          f"C0 gap {g0:5.1f} bits, CC gap {gc:5.1f} bits")
