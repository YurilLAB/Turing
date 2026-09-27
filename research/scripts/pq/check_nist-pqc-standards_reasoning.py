"""Independent reasoning check of research/notes/pq/nist-pqc-standards.md.

Written by the mathematics-and-reasoning fact-checker. It does NOT import or reuse
the author's nist_pqc_check.py: every number is recomputed a different way.

Checks (each prints PASS/FAIL; a FAIL here means the NOTES' claim is contradicted,
or, for the items marked "finding", that the notes' reasoning is incomplete):

 1. ML-KEM sizes, derived bit by bit from the byte layouts of Alg. 13/14/16
    (not from the closed formulas), compared with the formulas and Table 3.
 2. The dk byte layout offsets used by the FIPS 203 Sec. 7.3 hash check.
 3. Exhaustive modulus check over all 4096 12-bit field values: the check
    rejects exactly the values >= q. Negative control: without the mod-q
    reduction in ByteDecode12 the check would accept everything.
 4. SampleNTT (FIPS 203 App. B): P(T > 280) computed with log-space lgamma sums
    (independent of the mpmath binomial loop) and E[T] computed from the
    negative-binomial law of the index of the 256th accepted candidate.
    Negative control: a 250-iteration limit must NOT give about 2^-261.
 5. CBD_eta: std dev for eta = 2 is 1 (notes 6.4).
 6. Category gate counts: 2016 - 2022 differences, 2^93 at MAXDEPTH 2^64, and
    the RANGE of validity of G/MAXDEPTH for AES-128 using the unrestricted
    Grover G-cost 1.69 * 2^83 from Jaques et al. 2020 (Sec. 6).
 7. Kyber/ML-KEM-512 margin: round-3 spec (151.5) vs NIST FAQ on Kyber512
    (Dec 2023): best estimate 2^147 (2^145 with very large memory), window
    2^135 .. 2^158.
 8. ML-DSA: zeta = 1753 has order 512 mod q; beta = tau*eta; gamma2 values;
    sizes from component bit counts; FIPS 204 App. C loop limit (2^-256 target)
    from the expected-repetition numbers, old (5.1 -> 814) and errata (5.14 -> 821).
 9. SLH-DSA: h' = h/d and m = ceil(k*a/8) + ceil((h - h/d)/8) + ceil(h/(8d)).
10. Arithmetic in the notes' worked examples (ML-KEM-768 ek and ct).

Deterministic. Run from the repo root:
    timeout 300 python research/scripts/pq/check_nist-pqc-standards_reasoning.py
"""
import math
import sys
from fractions import Fraction

sys.stdout.reconfigure(encoding="utf-8")
FAILS = []


def check(label, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(label)


N, Q = 256, 3329

# ------------------------------------------------------------------ 1. sizes bit by bit
print("== 1. ML-KEM sizes from the byte layouts (bits of each component)")
PARAMS = {"ML-KEM-512": (2, 10, 4), "ML-KEM-768": (3, 10, 4), "ML-KEM-1024": (4, 11, 5)}
TABLE3 = {"ML-KEM-512": (800, 1632, 768), "ML-KEM-768": (1184, 2400, 1088), "ML-KEM-1024": (1568, 3168, 1568)}
for name, (k, du, dv) in PARAMS.items():
    bits_that = k * N * 12            # ByteEncode12(t_hat): k polys x 256 coeffs x 12 bits
    ek = bits_that // 8 + 32           # + rho (32 bytes)
    dk_pke = k * N * 12 // 8           # ByteEncode12(s_hat)
    dk = dk_pke + ek + 32 + 32         # dk_PKE || ek || H(ek) || z
    ct = (k * N * du + N * dv) // 8    # c1 = k polys at du bits, c2 = 1 poly at dv bits
    formula = (384 * k + 32, 768 * k + 96, 32 * (du * k + dv))
    check(f"{name}: layout gives ek/dk/ct = {(ek, dk, ct)}", (ek, dk, ct) == formula == TABLE3[name],
          f"formula {formula}, Table 3 {TABLE3[name]}")

# ------------------------------------------------------------------ 2. dk offsets
print("== 2. dk layout offsets for the Sec. 7.3 hash check")
for k in (2, 3, 4):
    off_ek, off_h, off_z, end = 384 * k, 384 * k + 384 * k + 32, 768 * k + 64, 768 * k + 96
    check(f"k = {k}: ek = dk[{off_ek}:{off_h}], H(ek) = dk[{off_h}:{off_h + 32}], z = dk[{off_z}:{end}]",
          off_h == 768 * k + 32 and off_h + 32 == off_z and end - off_z == 32)


# ------------------------------------------------------------------ 3. modulus check, exhaustive
print("== 3. Encapsulation-key modulus check over every 12-bit value")


def pack12(vals):
    acc, nbits, out = 0, 0, bytearray()
    for v in vals:
        acc |= v << nbits
        nbits += 12
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    return bytes(out)


def unpack12(b, reduce=True):
    acc = int.from_bytes(b, "little")
    vals = [(acc >> (12 * i)) & 0xFFF for i in range(len(b) * 8 // 12)]
    return [v % Q for v in vals] if reduce else vals


rejected = [v for v in range(4096) if pack12(unpack12(pack12([v, 0]))) != pack12([v, 0])]
check("check rejects exactly the 12-bit values 3329..4095", rejected == list(range(Q, 4096)),
      f"{len(rejected)} rejected, smallest {rejected[0]}")
# negative control: a decoder WITHOUT mod-q reduction makes the check vacuous
rej_nored = [v for v in range(4096) if pack12(unpack12(pack12([v, 0]), reduce=False)) != pack12([v, 0])]
check("negative control: without mod-q in ByteDecode12 the check rejects nothing", rej_nored == [],
      "so the check's power comes entirely from the mod-q reduction (FIPS 203 Alg. 6)")

# ------------------------------------------------------------------ 4. SampleNTT
print("== 4. SampleNTT loop bound, independent method")
p = Q / 4096.0
lp, lq = math.log(p), math.log1p(-p)


def log2_tail(limit):
    """log2 P(Bin(2*limit, p) <= 255) with lgamma log-sum-exp."""
    m = 2 * limit
    terms = [math.lgamma(m + 1) - math.lgamma(i + 1) - math.lgamma(m - i + 1) + i * lp + (m - i) * lq
             for i in range(256)]
    mx = max(terms)
    return (mx + math.log(sum(math.exp(t - mx) for t in terms))) / math.log(2)


l280 = log2_tail(280)
check("P(SampleNTT needs > 280 iterations) ~ 2^-261", abs(l280 + 261) < 0.5, f"log2 P = {l280:.3f}")
l250 = log2_tail(250)
check("negative control: 250 iterations is NOT ~2^-261", abs(l250 + 261) > 5, f"log2 P = {l250:.3f}")

# E[T]: the 256th acceptance happens at candidate index N_c = 256 + F, F ~ NegBin(256, p)
# (F = number of rejections). The loop ends at iteration ceil(N_c / 2).
pf = Fraction(3329, 4096)
ET = 0.0
ET2 = 0.0
logp256 = 256 * math.log(p)
for f in range(0, 2000):
    lpmf = math.lgamma(256 + f) - math.lgamma(f + 1) - math.lgamma(256) + logp256 + f * lq
    pr = math.exp(lpmf)
    t = math.ceil((256 + f) / 2)
    ET += pr * t
    ET2 += pr * t * t
sd = math.sqrt(ET2 - ET ** 2)
check("E[iterations] = 157.74 (notes: 'expected 157.7')", abs(ET - 157.741) < 0.01, f"E[T] = {ET:.3f}, sd = {sd:.3f}")
print(f"      note: 256/(2p) = {256 / (2 * p):.3f} is the crude mean the author's nist_pqc_check.py prints;"
      f" the exact mean is {ET:.3f}")

# ------------------------------------------------------------------ 5. CBD
print("== 5. CBD_eta standard deviation")
VARS = {}
for eta in (2, 3):
    var = Fraction(0)
    for a in range(1 << eta):
        for b in range(1 << eta):
            v = bin(a).count("1") - bin(b).count("1")
            var += Fraction(v * v, 4 ** eta)
    VARS[eta] = var
    print(f"      CBD_{eta}: variance {var}, std {math.sqrt(var):.4f}")
check("CBD_2 std dev is exactly 1 (notes 6.4)", VARS[2] == 1, f"variance {VARS[2]}")
check("negative control: CBD_3 std dev is not 1", VARS[3] != 1, f"variance {VARS[3]}")

# ------------------------------------------------------------------ 6. MAXDEPTH
print("== 6. Category gate counts and the range of G/MAXDEPTH")
c16 = {"AES-128": 170, "AES-192": 233, "AES-256": 298}
c22 = {"AES-128": 157, "AES-192": 221, "AES-256": 285}
diffs = [c16[a] - c22[a] for a in c16]
check("2022 quantum figures are 13 / 12 / 13 bits below 2016", diffs == [13, 12, 13], str(diffs))
check("2022 AES-128 at MAXDEPTH 2^64 = 2^93", c22["AES-128"] - 64 == 93)
# Jaques-Naehrig-Roetteler-Virdia 2020, Sec. 6: unrestricted AES-128 Grover G-cost 1.69 * 2^83
g_full = 83 + math.log2(1.69)
d_switch = c22["AES-128"] - g_full   # MAXDEPTH above which G/MAXDEPTH < unrestricted Grover cost
print(f"      unrestricted AES-128 Grover G-cost = 2^{g_full:.2f}; 2^157/MAXDEPTH falls below it for MAXDEPTH > 2^{d_switch:.2f}")
for m in (40, 64, 96):
    formula = c22["AES-128"] - m
    true_lb = max(formula, g_full)
    print(f"      MAXDEPTH 2^{m}: formula 2^{formula}, valid cost >= 2^{true_lb:.2f}"
          + ("   <-- formula OUTSIDE its range" if formula < g_full else ""))
check("finding: the grid value 2^61 (AES-128, MAXDEPTH 2^96, 2022 call) understates AES-128 by > 20 bits",
      g_full - (c22["AES-128"] - 96) > 20,
      "2022 call footnote 5: estimates 'may understate the quantum security of AES for very large values of MAXDEPTH'")
# consistency of JNRV with the 2022 formula where it applies: 2^40 -> 1.08*2^118, 2^64 -> ~2^10 * 1.69*2^83
check("JNRV MAXDEPTH 2^40 figure 1.08*2^118 within 1.2 bit of 2^(157-40)",
      abs(118 + math.log2(1.08) - 117) < 1.2, f"{118 + math.log2(1.08):.2f} vs 117")

# ------------------------------------------------------------------ 7. Kyber512 margin
print("== 7. ML-KEM-512 margin over AES-128 (2^143 classical gates)")
spec = 151.5
faq_best, faq_bigmem, lo, hi = 147, 145, 135, 158
print(f"      round-3 spec refined estimate: margin {spec - 143:+.1f} bits (what the notes report)")
print(f"      NIST FAQ on Kyber512 (Dec 2023) best estimate 2^{faq_best}: margin {faq_best - 143:+d} bits;"
      f" with > 2^105-bit memories 2^{faq_bigmem}: margin {faq_bigmem - 143:+d};"
      f" uncertainty window {lo - 143:+d} .. {hi - 143:+d} bits")
check("finding: the notes' 8.5-bit margin exceeds NIST's current best-estimate margin by >= 4.5 bits",
      (spec - 143) - (faq_best - 143) >= 4.5)
check("finding: NIST's window for ML-KEM-512 includes costs below 2^143", lo < 143)

# ------------------------------------------------------------------ 8. ML-DSA
print("== 8. ML-DSA (FIPS 204)")
QD = 8380417
order = 1
x = 1753
while pow(x, order, QD) != 1:
    order *= 2
    if order > 1 << 23:
        break
check("zeta = 1753 has multiplicative order 512 mod 8380417", order == 512 and pow(1753, 256, QD) == QD - 1,
      f"order {order}")
DSA = {  # k, l, eta, tau, gamma1, gamma2, beta, omega, lambda, (sk, pk, sig)
    "ML-DSA-44": (4, 4, 2, 39, 2 ** 17, (QD - 1) // 88, 78, 80, 128, (2560, 1312, 2420)),
    "ML-DSA-65": (6, 5, 4, 49, 2 ** 19, (QD - 1) // 32, 196, 55, 192, (4032, 1952, 3309)),
    "ML-DSA-87": (8, 7, 2, 60, 2 ** 19, (QD - 1) // 32, 120, 75, 256, (4896, 2592, 4627)),
}
for name, (k, l, eta, tau, g1, g2, beta, omega, lam, sizes) in DSA.items():
    check(f"{name}: beta = tau*eta = {tau * eta}", beta == tau * eta)
    # pk: rho (256 bits) + t1 (k polys, 10 bits each: 23-bit q minus d = 13)
    pk_bits = 256 + k * 256 * (23 - 13)
    # sk: rho, K, tr (256+256+512 bits) + s1, s2 (bits for [-eta, eta]) + t0 (13 bits)
    eta_bits = (2 * eta).bit_length()
    sk_bits = 256 + 256 + 512 + (l + k) * 256 * eta_bits + k * 256 * 13
    # sig: c~ (2*lambda bits) + z (l polys, 1+log2(gamma1) bits) + hint (omega + k bytes)
    sig_bits = 2 * lam + l * 256 * (1 + int(math.log2(g1))) + 8 * (omega + k)
    got = (sk_bits // 8, pk_bits // 8, sig_bits // 8)
    check(f"{name}: sizes sk/pk/sig from component bits = {got}", got == sizes, f"Table 2 {sizes}")
# FIPS 204 App. C Table 3: loop limits for failure probability ~2^-256.
for reps, stated in ((5.1, 814), (5.14, 821)):
    pr = 1 / reps
    L = math.ceil(256 / -math.log2(1 - pr))
    check(f"signing loop limit for 2^-256 with max repetitions {reps} = {L} (stated {stated})", L == stated)
# expected repetitions, heuristic formula of the Dilithium spec: exp(256*beta*(l/gamma1 + k/gamma2))
for name, (k, l, eta, tau, g1, g2, beta, omega, lam, sizes) in DSA.items():
    approx = math.exp(256 * beta * (l / g1 + k / g2))
    exact_zr = 1 / (((2 * (g1 - beta) - 1) / (2 * g1)) ** (256 * l) * ((2 * (g2 - beta) - 1) / (2 * g2)) ** (256 * k))
    print(f"      {name}: exp-approx repetitions {approx:.3f}; z and r0 conditions exactly {exact_zr:.3f}"
          " (FIPS 204 Table 1 said 4.25/5.1/3.85, errata 4.36/5.14/3.91; the errata values are higher than"
          " both, plausibly because they also count the hint-weight and ct0 rejections: NOT verified here)")

# ------------------------------------------------------------------ 9. SLH-DSA
print("== 9. SLH-DSA Table 2 internal consistency")
SLH = {  # n, h, d, h', a, k, m
    "128s": (16, 63, 7, 9, 12, 14, 30), "128f": (16, 66, 22, 3, 6, 33, 34),
    "192s": (24, 63, 7, 9, 14, 17, 39), "192f": (24, 66, 22, 3, 8, 33, 42),
    "256s": (32, 64, 8, 8, 14, 22, 47), "256f": (32, 68, 17, 4, 9, 35, 49),
}
for name, (n, h, d, hp, a, k, m) in SLH.items():
    m_calc = -(-k * a // 8) + -(-(h - h // d) // 8) + -(-h // (8 * d))
    check(f"SLH-DSA-{name}: h' = h/d = {h // d}, m = {m_calc}", h % d == 0 and h // d == hp and m_calc == m)

# ------------------------------------------------------------------ 10. worked examples
print("== 10. Worked examples in notes Sec. 1.3")
check("ML-KEM-768 ek: 768 coeffs x 12 bits = 1152 bytes, + 32 = 1184", 768 * 12 // 8 == 1152 and 1152 + 32 == 1184)
check("ML-KEM-768 ct: 768 x 10 bits = 960 bytes, 256 x 4 bits = 128 bytes, total 1088",
      768 * 10 // 8 == 960 and 256 * 4 // 8 == 128 and 960 + 128 == 1088)
check("Kyber r3 margins as printed in the notes: 8.5 / 8.1 / 15.3",
      [round(151.5 - 143, 1), round(215.1 - 207, 1), round(287.3 - 272, 1)] == [8.5, 8.1, 15.3])

# ------------------------------------------------------------------ 11. q/sigma alone?
print("== 11. Does q/sigma alone fix the reduction needed? (Lindner-Peikert 2011 Sec. 5 heuristic)")
# LP11: delta = 2^( lg^2(beta) / (4 n lg q) ), beta ~ (q/s) * const for the distinguishing attack.
# The constant is dropped here (same for all rows), so only the comparison is meaningful.


def lg_delta(n, q, sigma):
    return math.log2(q / sigma) ** 2 / (4 * n * math.log2(q))


rows = [("ML-KEM-512", 512, 3329, math.sqrt(1.5)), ("ML-KEM-768", 768, 3329, 1.0),
        ("ML-KEM-1024", 1024, 3329, 1.0), ("FrodoKEM-976", 976, 65536, 2.3), ("FrodoKEM-1344", 1344, 65536, 1.4)]
for name, n, q, s in rows:
    print(f"      {name:14s} lg(q/sigma) = {math.log2(q / s):5.2f}  heuristic lg(delta) = {lg_delta(n, q, s):.5f}")
# same n, same ratio q/sigma, different q
a = lg_delta(1000, 2 ** 16, 2 ** 16 / 2 ** 13)
b = lg_delta(1000, 2 ** 12, 2 ** 12 / 2 ** 13)  # sigma = 0.5, ratio 2^13 in both
check("finding: same n and same q/sigma but different q give different required delta (heuristic)",
      abs(a - b) / a > 0.2, f"lg delta {a:.5f} (q = 2^16) vs {b:.5f} (q = 2^12)")

print()
findings = [f for f in FAILS if not f.startswith("negative control")]
print("ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} CHECK(S) FAILED: {FAILS}")
sys.exit(1 if FAILS else 0)
