"""Worked examples: plug numbers into published FO security bounds.

Purpose (research/notes/pq/cca-transforms-and-binding.md, Section 3.4): show a
learner what the generic ROM / QROM theorems for the Fujisaki-Okamoto
transform actually say for ML-KEM-sized numbers, and where they stop saying
anything. Nothing here is a security estimate for a real scheme: every bound
is a generic upper bound on an attacker's advantage, and the inputs marked
"hypothetical" are illustrations, not measured values.

Formulas reproduced (each checked against the rendered/extracted PDF):
  [HHK17-ROM]  HHK17 (ePrint 2017/604, 2021 version) Sec. 3.3, PDF p. 22:
               Adv_IND-CCA <= q*delta + 3*q/|M| + 3*Adv_IND-CPA
  [HHK17-QROM] HHK17 Sec. 4.4 table, PDF p. 34:
               Adv_IND-CCA <= 8q*( sqrt(q^2*delta + q*sqrt(Adv_OW-CPA)) + q*delta )
  [HHM22]      Hovelmanns-Hulsing-Majenz, ASIACRYPT 2022 (ePrint 2022/365),
               Corollary 9, PDF p. 38 (only the terms that need no extra
               parameters): 4*sqrt((d+qD)*Adv_IND-CPA) + 8(q+qD)/sqrt(|M|)
               and the plain failure part (qD+1)*delta
  [BH23]       Barbosa-Hulsing (ePrint 2023/755) Theorem 1, PDF p. 4:
               collision term C*(q+qdec+1)^3/|C_H| (C = unknown universal
               constant of Zhandry's collision bound; C = 1 used here)
  delta values: FIPS 203 Sec. 3.2 Table 1 (2^-138.8, 2^-164.8, 2^-174.8).

Usage: python cca_fo_bound_examples.py     (deterministic; prints PASS/FAIL)
"""
from mpmath import mp, mpf, log, sqrt

mp.dps = 60


def lg(x):
    return float(log(x, 2))


def two(e):
    return mpf(2) ** e


fails = 0


def check(label, got, expected, tol=0.05):
    global fails
    ok = abs(got - expected) <= tol
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] {label}: log2 = {got:.2f} (hand-derived: {expected})")


M = two(256)  # ML-KEM message space: 256-bit m (FIPS 203)
DELTA = {"ML-KEM-512": two(-138.8), "ML-KEM-768": two(-164.8), "ML-KEM-1024": two(-174.8)}

print("1. HHK17 ROM bound, failure term q*delta (FIPS 203 Table 1 delta), q = 2^64 hash queries")
for name, exp in (("ML-KEM-512", -74.8), ("ML-KEM-768", -100.8), ("ML-KEM-1024", -110.8)):
    check(f"   {name}: q*delta", lg(two(64) * DELTA[name]), exp)
print("   ... and the message-guessing term 3q/|M| at q = 2^64:")
check("   3*q/|M|", lg(3 * two(64) / M), round(lg(3), 2) - 192)
print("   Reading: in the classical ROM the FO wrapper costs almost nothing; the")
print("   bound is dominated by 3*Adv_IND-CPA, i.e. by the lattice problem.")

print()
print("2. HHK17 QROM bound 8q(sqrt(q^2 d + q sqrt(e)) + q d) with the lattice made")
print("   'perfect': e = Adv_OW-CPA = 2^-256 (the chance of guessing a 256-bit m)")
e = two(-256)
d = DELTA["ML-KEM-768"]


def hhk17_qrom(q, delta, eps):
    return 8 * q * (sqrt(q * q * delta + q * sqrt(eps)) + q * delta)


for qexp in (32, 40, 41, 64):
    b = hhk17_qrom(two(qexp), d, e)
    print(f"   q = 2^{qexp}: bound = 2^{lg(b):.2f}{'  (>= 1: says nothing)' if b >= 1 else ''}")
# Dominant part 8 q^1.5 e^(1/4) = 8 q^1.5 2^-64 reaches 1 at q = 2^(61/1.5)
check("   q where 8*q^1.5*2^-64 = 1", 61 / 1.5, 40.67)
print("   Reading: this generic QROM theorem stops saying anything near 2^41")
print("   quantum queries even if the lattice were unbreakable. Parameters are")
print("   therefore set by cryptanalysis, not by this bound (FIPS 203 Sec. 3.2).")

print()
print("3. HHM22 Corollary 9 (explicit rejection, QROM), parameter-free terms,")
print("   q = d = qD = 2^64, |M| = 2^256, hypothetical Adv_IND-CPA values")
q = two(64)
qD = two(64)
depth = two(64)
msg_term = 8 * (q + qD) / sqrt(M)
check("   8(q+qD)/sqrt(|M|)", lg(msg_term), -60)
for eexp in (-128, -192, -256):
    t = 4 * sqrt((depth + qD) * two(eexp))
    print(f"   Adv_IND-CPA = 2^{eexp}: 4*sqrt((d+qD)*Adv) = 2^{lg(t):.2f}")
check("   4*sqrt(2^65 * 2^-192)", lg(4 * sqrt(two(65) * two(-192))), -61.5)
check("   (qD+1)*delta for ML-KEM-768", lg((qD + 1) * d), -100.8)
# 8(q+qD)/2^128 with q = qD reaches 1 at q = 2^124
check("   q (= qD) where 8*2q/2^128 = 1", 128 - 4, 124)
print("   Reading: the parameter-free terms of this newer bound stay below 1 up to")
print("   about 2^124 queries for a 256-bit message space, against about 2^41 in")
print("   example 2. The two theorems cover related but different transforms")
print("   (QFO_m with an extra hash vs. FO_m with explicit rejection), and the")
print("   FFP-NG and variance terms of HHM22 need scheme-specific analysis, so this")
print("   compares proof techniques, not schemes.")

print()
print("4. Barbosa-Hulsing collision term C(q+1)^3/|C_H| for round-3 Kyber (H2 = SHA3-256)")
for qexp in (64, 80, 85.33, 90):
    t = (two(qexp) + 1) ** 3 / two(256)
    print(f"   q = 2^{qexp}: C * 2^{lg(t):.2f}")
check("   q where q^3 = 2^256", 256 / 3, 85.33)
print("   Reading: with a 256-bit ciphertext hash the term reaches 1 near 2^85")
print("   queries, which is why BH23 say levels III and V 'cannot be justified by")
print("   the proven bound'. This fits the Kyber team's stated reason for dropping")
print("   H(c) from the key derivation (it complicated QROM proofs).")

print()
print(f"TOTAL FAILURES: {fails}")
