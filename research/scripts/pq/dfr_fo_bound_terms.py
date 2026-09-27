"""dfr_fo_bound_terms.py - size of the decryption-failure terms in FO security bounds.

What it reproduces, and from where
----------------------------------
Nothing published is reproduced; it evaluates two published formulas at published DFRs:
  * Kyber round-3 specification, Theorem 2 (classical ROM): the failure term is 4 * q_RO * delta;
    Theorem 3 (QROM): 8 * q_RO^2 * delta (both quoted in section 5.5, PDF page 31).
  * DFRs: FIPS 203 Table 1 (PDF page 24) and FrodoKEM round-3 Table 2 (PDF page 24).
For each scheme it prints log2 of the failure term for q_RO = 2^64, 2^96, 2^128, and the q_RO at
which the term reaches 1 (the bound says nothing beyond it). Real attacks need not reach these
bounds (the q^2 is a proof artefact in part; see Kyber spec section 5.5), so this shows what the
PROOF guarantees, not what attacks achieve.

Usage: python dfr_fo_bound_terms.py      (deterministic, instant)
"""
import sys

sys.stdout.reconfigure(encoding="utf-8")
DFR = {  # log2 delta as published
    "ML-KEM-512": -138.8, "ML-KEM-768": -164.8, "ML-KEM-1024": -174.8,
    "Frodo-640": -138.7, "Frodo-976": -199.6, "Frodo-1344": -252.5,
}
LEVEL = {"ML-KEM-512": 128, "ML-KEM-768": 192, "ML-KEM-1024": 256,
         "Frodo-640": 128, "Frodo-976": 192, "Frodo-1344": 256}
print("log2 of failure term;  classical 4*q*delta  |  quantum 8*q^2*delta")
print(f"{'scheme':12s} {'lambda':>6s} {'log2 d':>7s} {'lambda+log2 d':>13s} | "
      f"{'C q=2^64':>8s} {'C q=2^128':>9s} | {'Q q=2^64':>8s} {'Q q=2^96':>8s} {'Q q=2^128':>9s}"
      f" | q where C=1 | q where Q=1")
for name, ld in DFR.items():
    c = lambda lq: 2 + lq + ld
    qq = lambda lq: 3 + 2 * lq + ld
    print(f"{name:12s} {LEVEL[name]:6d} {ld:7.1f} {LEVEL[name] + ld:13.1f} | {c(64):8.1f} {c(128):9.1f} | "
          f"{qq(64):8.1f} {qq(96):8.1f} {qq(128):9.1f} | 2^{-(2 + ld):6.1f}   | 2^{-(3 + ld) / 2:6.1f}")
print("\nReading: 'lambda + log2 d' < 0 means delta <= 2^-lambda (the FrodoKEM/HQC-style target).")
print("The quantum term stays below 1 only while q_RO < sqrt(1/(8 delta)).")
