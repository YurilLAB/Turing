"""Independent reasoning checks for research/notes/pq/lattice-foundations.md.

Written by the mathematics-and-reasoning fact-checker, 2026-09-27. Independent code:
nothing is imported from the author's scripts. Deterministic (fixed seeds). Every
check prints PASS/FAIL and what it checks. Each part has a negative control.

Run: timeout 600 python research/scripts/pq/check_lattice-foundations_reasoning.py
"""
import math
import random
import sys
from fractions import Fraction

sys.stdout.reconfigure(encoding="utf-8")
fails = 0


def check(label, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        fails += 1


# ---------------------------------------------------------------------------
print("=== 1. The 2-D worked example (notes Sec. 1-2) ===")
good = [(5, 1), (-2, 6)]
U = [[7, 3], [9, 4]]
bad = [tuple(U[i][0] * good[0][k] + U[i][1] * good[1][k] for k in range(2)) for i in range(2)]
check("U x good (rows) = [(29,25),(37,33)]", bad == [(29, 25), (37, 33)])
check("det U = 1", U[0][0] * U[1][1] - U[0][1] * U[1][0] == 1)
det = good[0][0] * good[1][1] - good[0][1] * good[1][0]
check("det(good) = 32", det == 32)
# brute-force successive minima
vecs = []
for x in range(-30, 31):
    for y in range(-30, 31):
        if (x, y) != (0, 0):
            v = (x * 5 + y * -2, x * 1 + y * 6)
            vecs.append((math.hypot(*v), v))
vecs.sort()
l1, v1 = vecs[0]
l2 = next(n for n, v in vecs if v[0] * v1[1] - v[1] * v1[0] != 0)
print(f"  lambda_1 = {l1:.4f} ({v1}), lambda_2 = {l2:.4f}")
check("lambda_1 = sqrt(26) = 5.0990, lambda_2 = sqrt(40) = 6.3246", abs(l1 - 26 ** 0.5) < 1e-9 and abs(l2 - 40 ** 0.5) < 1e-9)
check("(19,-9) = 3*(5,1) - 2*(-2,6) is a lattice point", (3 * 5 - 2 * -2, 3 * 1 - 2 * 6) == (19, -9))
check("negative control: (20,-9) is not a lattice point (solve 5x-2y=20, x+6y=-9 has no integer solution)",
      not any(5 * x - 2 * y == 20 and x + 6 * y == -9 for x in range(-50, 50) for y in range(-50, 50)))

# ---------------------------------------------------------------------------
print()
print("=== 2. Root-Hermite factor delta(b) (Kyber r3 Sec. 5.1.2 formula) and what b = 878 means ===")


def delta(b):
    return ((math.pi * b) ** (1 / b) * b / (2 * math.pi * math.e)) ** (1 / (2 * (b - 1)))


for b in (50, 100, 180, 270, 406, 626, 707, 878):
    print(f"  b = {b:4d}: delta = {delta(b):.5f}; core-SVP classical 0.292 b = {0.292 * b:6.1f} bits")
b005 = next(b for b in range(60, 2000) if delta(b) <= 1.005)
b0219 = next((b for b in range(40, 2000) if delta(b) <= 1.0219), None)
print(f"  smallest b with delta <= 1.005: {b005} (0.292 b = {0.292 * b005:.1f} bits)")
check("delta(878) is about 1.0023, i.e. far below 1.005", 1.0022 < delta(878) < 1.0024)
check("delta = 1.005 needs b ~ 270-300 in the GSA model, i.e. ~2^80 core-SVP operations (not 'within reach')",
      250 <= b005 <= 310)
check("negative control: delta is decreasing in b over [50, 900]",
      all(delta(b + 1) < delta(b) for b in range(50, 900)))
# small-dimension Hermite factor: GH exact-ball ratio in dimension 10 explains delta_0 < 1
gh10 = math.exp(math.lgamma(10 / 2 + 1) / 10) / math.sqrt(math.pi)
print(f"  dim 10: exact-ball GH / vol^(1/10) = {gh10:.3f}, so a shortest vector alone gives delta_0 = {gh10 ** 0.1:.4f}")
check("delta_0 < 1 at dimension 10 is expected (GH/vol^(1/n) < 1): small-dimension delta is not comparable to 1.0219",
      gh10 < 1)

# ---------------------------------------------------------------------------
print()
print("=== 3. Independent primal-uSVP GSA estimator (Kyber r3 eq. 9; FrodoKEM r3 eq. 7) ===")


def primal_b(n_lwe, q, sigma, m_max, b_range=range(50, 1500)):
    """Minimal b (over m <= m_max) with sigma*sqrt(b) <= delta^(2b-d-1) * q^(m/d), d = m + n + 1."""
    lq = math.log(q)
    best = None
    for b in b_range:
        ld = math.log(delta(b))
        lhs = math.log(sigma) + 0.5 * math.log(b)
        for m in range(max(b - n_lwe, 1), m_max + 1):
            d = m + n_lwe + 1
            if d <= b:
                continue
            if lhs <= (2 * b - d - 1) * ld + (m / d) * lq:
                best = (b, m, d)
                return best
    return best


for name, nl, q, sig, mmax, spec in (("ML-KEM-512 key", 512, 3329, math.sqrt(1.5), 512, 406),
                                      ("ML-KEM-768 key", 768, 3329, 1.0, 768, 626),
                                      ("ML-KEM-1024 key", 1024, 3329, 1.0, 1024, 878),
                                      ("Frodo-976", 976, 65536, 2.3, 984, 707)):
    b, m, d = primal_b(nl, q, sig, mmax)
    print(f"  {name:16s}: b = {b}, m = {m}, d = {d}  (reference b = {spec})")
    check(f"{name}: independent GSA block size within 1% of reference {spec}", abs(b - spec) <= 0.01 * spec + 1)
b_wide, _, _ = primal_b(1024, 3329, 2.0, 1024)
check("negative control: doubling sigma for ML-KEM-1024 raises b substantially (> 1.2x)", b_wide > 1.2 * 878)
# Frodo cost model reproduces Table 10 row with b = 707
for c, tgt in ((0.292, 216.0), (0.265, 196.7), (0.2075, 156.0)):
    print(f"  Frodo-976 b = 707: {c} b + log2 b = {c * 707 + math.log2(707):.1f} (Table 10: {tgt})")
check("FrodoKEM cost model c*b + log2(b) at b = 707 matches Table 10 C/Q/P 216.0/196.7/156.0 within 0.5",
      all(abs(c * 707 + math.log2(707) - t) < 0.5 for c, t in ((0.292, 216.0), (0.265, 196.7), (0.2075, 156.0))))
check("Kyber core-SVP at b = 878: 0.292 b = 256.4 and 0.265 b = 232.7 (Table 4: 256 / 232)",
      int(0.292 * 878) == 256 and int(0.265 * 878) == 232)

# ---------------------------------------------------------------------------
print()
print("=== 4. Regev toy: per-key failure probability vs the key-averaged value (notes Sec. 6) ===")
Q, HALF, M = 97, 48, 20


def centred(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def regev_dec_ok(v, bit):
    x = (v + bit * HALF) % Q
    out = 0 if abs(centred(x)) < abs(centred(x - HALF)) else 1
    return out == bit


def cbd(eta):
    d = {}
    for i in range(2 ** eta):
        for j in range(2 ** eta):
            k = bin(i).count("1") - bin(j).count("1")
            d[k] = d.get(k, 0) + Fraction(1, 4 ** eta)
    return d


def conv(a, b):
    out = {}
    for x, p in a.items():
        for y, r in b.items():
            out[x + y] = out.get(x + y, 0) + p * r
    return out


def fail_from_noise(noise):
    return sum(p for v, p in noise.items() for bit in (0, 1) if not regev_dec_ok(v, bit)) / 2


def per_key_fail(errs):
    """Exact failure prob for a FIXED key with errors errs: noise = sum over a uniform random subset."""
    dist = {0: 1.0}
    for e in errs:
        nd = {}
        for x, p in dist.items():
            nd[x] = nd.get(x, 0) + p / 2
            nd[x + e] = nd.get(x + e, 0) + p / 2
        dist = nd
    return fail_from_noise(dist)


rng = random.Random(97)
for eta in (1, 3, 4):
    c = cbd(eta)
    term = {k: p / 2 for k, p in c.items()}
    term[0] = term.get(0, 0) + Fraction(1, 2)
    avg_noise = {0: Fraction(1)}
    for _ in range(M):
        avg_noise = conv(avg_noise, term)
    avg = float(fail_from_noise(avg_noise))
    vals, weights = list(c.keys()), [float(p) for p in c.values()]
    keys = [per_key_fail([rng.choices(vals, weights)[0] for _ in range(M)]) for _ in range(4000)]
    keys.sort()
    mean = sum(keys) / len(keys)
    zero = sum(k == 0 for k in keys) / len(keys)
    print(f"  eta={eta}: key-averaged exact = {avg:.3e}; over 4000 keys: mean {mean:.3e}, "
          f"median {keys[2000]:.3e}, 99th pct {keys[3960]:.3e}, max {keys[-1]:.3e}; keys with failure 0: {zero:.1%}")
    if eta == 1:
        check("eta=1 (negative control): every key has failure 0", keys[-1] == 0 and avg == 0)
    else:
        check(f"eta={eta}: the mean of per-key failure probabilities estimates the key-averaged value (within 30%)",
              abs(mean - avg) <= 0.3 * avg)
        check(f"eta={eta}: per-key failure probabilities spread over orders of magnitude (max > 20 x average, "
              f"and most keys are far below the average)", keys[-1] > 20 * avg and keys[2000] < 0.5 * avg)
check("author's value 5.446e-07 for eta = 4 is the key-averaged probability (reproduced)",
      abs(float(fail_from_noise(avg_noise)) - 5.446e-07) < 0.001e-07)

# ---------------------------------------------------------------------------
print()
print("=== 5. Width thresholds of the reductions (notes Sec. 5 and 9) ===")
for n in (512, 976, 1024):
    print(f"  n = {n}: FrodoKEM's improved c > 1/(2 pi): {math.sqrt(n) / (2 * math.pi):5.2f};  "
          f"original constant c = sqrt(2/pi) (Regev alpha q > 2 sqrt n, std alpha q/sqrt(2 pi)): {math.sqrt(2 / math.pi) * math.sqrt(n):5.2f}")
check("Regev's published condition alpha q > 2 sqrt(n) means std > sqrt(2/pi) sqrt(n) (~25 at n = 976)",
      abs(2 * math.sqrt(976) / math.sqrt(2 * math.pi) - math.sqrt(2 / math.pi) * math.sqrt(976)) < 1e-9)
print("  LS15 Thm 4.7 (M-LWE): alpha q > 2 sqrt(d) omega(sqrt(log n)), d = module rank, n = ring degree;")
print("  the notes instead use sqrt(k*n)/(2 pi) for ML-KEM, NewHope and Saber (5.09 at k*n = 1024).")
check("negative control: the two forms differ (sqrt(1024)/(2 pi) != 2 sqrt(4) * sqrt(ln 256))",
      abs(math.sqrt(1024) / (2 * math.pi) - 2 * 2 * math.sqrt(math.log(256))) > 1)

# ---------------------------------------------------------------------------
print()
print("=== 6. Standard deviations of deployed small secrets (notes: 'every deployed scheme uses std 1.0-2.8') ===")
ternary = {
    "sntrup761 (OpenSSH, RFC 9941): weight 286 of 761": math.sqrt(286 / 761),
    "sntrup1013 (notes' own table): weight 448 of 1013": math.sqrt(448 / 1013),
    "ntruhps4096821 g: T(q/8-2), 510 non-zero of 820": math.sqrt(510 / 820),
    "NTRU f, r uniform ternary T": math.sqrt(2 / 3),
}
for k, v in ternary.items():
    print(f"  {k}: std {v:.3f}")
check("NTRU-family secrets have std < 1.0, outside the notes' '1.0-2.8' range", all(v < 1 for v in ternary.values()))
check("negative control: CBD(2) std is exactly 1 (inside the range)",
      sum(float(p) * k * k for k, p in cbd(2).items()) == 1.0)

# ---------------------------------------------------------------------------
print()
print("=== 7. Renyi-divergence argument: does it transfer from NewHope's psi_16 to ML-KEM's CBD(2)? ===")


def rounded_gauss(sigma, lo=-40, hi=40):
    ps = {}
    for x in range(lo, hi + 1):
        ps[x] = 0.5 * (math.erf((x + 0.5) / (sigma * math.sqrt(2))) - math.erf((x - 0.5) / (sigma * math.sqrt(2))))
    return ps


def renyi(P, Qd, a):
    s = sum(p ** a / Qd[x] ** (a - 1) for x, p in P.items() if p > 0)
    return s ** (1 / (a - 1))


def cbd_float(eta):
    return {k: float(v) for k, v in cbd(eta).items()}


R16 = renyi(cbd_float(16), rounded_gauss(math.sqrt(8)), 9)
print(f"  psi_16 vs rounded Gaussian sigma = sqrt(8): R_9 = {R16:.7f}; R_9^(5*1024) = {R16 ** 5120:.2f}")
check("reproduces NewHope's R_9 ~ 1.00063 and R_9^5120 <= 64", abs(R16 - 1.00063) < 2e-5 and R16 ** 5120 <= 64)
best = None
for a in (1.5, 2, 3, 5, 9, 17, 33):
    for sig in (0.90, 0.93, 0.95, 0.97, 1.0):
        r = renyi(cbd_float(2), rounded_gauss(sig), a)
        # log2 of the multiplicative loss over (k+1) n = 1280 samples
        loss = 1280 * math.log2(r)
        if best is None or loss < best[0]:
            best = (loss, a, sig, r)
print(f"  CBD(2) vs rounded Gaussian: best over orders/widths tried: a = {best[1]}, sigma = {best[2]}, "
      f"R_a = {best[3]:.5f}, R_a^1280 = 2^{best[0]:.1f}")
check("for ML-KEM's CBD(2) the NewHope-style bound over (k+1)n = 1280 samples is vacuous (loss > 2^20)",
      best[0] > 20)
check("negative control: R_a(P || P) = 1", abs(renyi(cbd_float(2), cbd_float(2), 9) - 1) < 1e-12)

# ---------------------------------------------------------------------------
print()
print("=== 8. NTT facts and an NTRU-type ring near 1000 (NTRU+: x^n - x^(n/2) + 1, q = 3457) ===")


def is_prime(x):
    if x < 2:
        return False
    i = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += 1
    return True


def order(a, mod):
    k, v = 1, a % mod
    while v != 1:
        v = v * a % mod
        k += 1
    return k


check("18433 is prime and = 1 mod 2048", is_prime(18433) and 18433 % 2048 == 1)
check("ord(3329 mod 1024) = 4 and ord(3329 mod 2048) = 8 (x^512+1: 128 x deg 4; x^1024+1: 128 x deg 8)",
      order(3329, 1024) == 4 and order(3329, 2048) == 8)
check("primes = 1 mod 256 up to 3329 are exactly 257, 769, 3329",
      [p for p in range(257, 3330, 256) if is_prime(p)] == [257, 769, 3329])
check("NTRU+ q = 3457 is prime and 3457 = 1 mod 3456 = 2^7 * 3^3 (Phi_3456 = x^1152 - x^576 + 1 has degree 1152)",
      is_prime(3457) and 3457 % 3456 == 1 and 3456 * 1 // 2 * 2 // 3 == 1152)
check("negative control: 3329 is not = 1 mod 512 (no complete NTT at n = 256)", 3329 % 512 != 1)

# ---------------------------------------------------------------------------
print()
print("=== 9. NTRU fatigue ratios (DvW21: q ~ 0.004 n^2.484) ===")
ratios = {}
for nm, n, q in (("hps2048509", 509, 2048), ("hps2048677", 677, 2048), ("hrss701", 701, 8192), ("hps4096821", 821, 4096)):
    f = 0.004 * n ** 2.484
    ratios[nm] = f / q
    print(f"  {nm}: fatigue {f:,.0f}, q {q}, ratio {f / q:.1f}")
check("ratios span 5.7 to 21.0 ('about 6 to 21')", 5.6 < min(ratios.values()) < 5.8 and 20.9 < max(ratios.values()) < 21.1)

# ---------------------------------------------------------------------------
print()
print("=== 10. ACPS normal form: the transform consumes n samples (notes: 'as hard as a uniform one') ===")
q, n = 97, 5
rng = random.Random(5)
while True:
    A1 = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]  # columns a_1..a_n: A1[row][col]
    # invert mod q by Gauss-Jordan
    Mx = [row[:] + [int(i == j) for j in range(n)] for i, row in enumerate(A1)]
    ok = True
    for c in range(n):
        piv = next((r for r in range(c, n) if Mx[r][c] % q), None)
        if piv is None:
            ok = False
            break
        Mx[c], Mx[piv] = Mx[piv], Mx[c]
        inv = pow(Mx[c][c], q - 2, q)
        Mx[c] = [x * inv % q for x in Mx[c]]
        for r in range(n):
            if r != c and Mx[r][c]:
                f = Mx[r][c]
                Mx[r] = [(x - f * y) % q for x, y in zip(Mx[r], Mx[c])]
    if ok:
        A1inv = [row[n:] for row in Mx]
        break
s = [rng.randrange(q) for _ in range(n)]
x = [rng.choice((-1, 0, 0, 1)) for _ in range(n)]
# b1_i = <a_i, s> + x_i where a_i is column i of A1: b1 = A1^T s + x
b1 = [(sum(A1[r][i] * s[r] for r in range(n)) + x[i]) % q for i in range(n)]
good_all = True
for _ in range(300):
    a = [rng.randrange(q) for _ in range(n)]
    e = rng.choice((-1, 0, 0, 1))
    b = (sum(ai * si for ai, si in zip(a, s)) + e) % q
    ap = [(-sum(A1inv[i][j] * a[j] for j in range(n))) % q for i in range(n)]
    bp = (b + sum(api * bi for api, bi in zip(ap, b1))) % q
    good_all &= (bp - sum(api * xi for api, xi in zip(ap, x)) - e) % q == 0
check("ACPS transform: b' = <a', x> + e with x the kept errors (300 samples)", good_all)
bp_bad = (b + sum(api * bi for api, bi in zip([(v + 1) % q for v in ap], b1))) % q
check("negative control: perturbing a' breaks the identity",
      (bp_bad - sum(((v + 1) % q) * xi for v, xi in zip(ap, x)) - e) % q != 0 or all(xi == 0 for xi in x))

print()
print("all checks passed" if fails == 0 else f"{fails} check(s) FAILED")
