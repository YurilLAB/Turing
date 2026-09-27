"""lis_toys.py - small, deterministic checks for the note
research/notes/pq/lattices-inside-symmetric-primitives.md

Every section prints what it checks and PASS/FAIL. Run:
    python research/scripts/pq/lis_toys.py
Pure Python + math (no numpy needed), fixed seeds, runs in about a second.

A. LWR rounding (Banerjee-Peikert-Rosen, EUROCRYPT 2012, eq. 2.1, PDF p. 8):
   toy q=64, p=8, n=4 sample; the rounding error is what rounding drops;
   q=257, p=2 gives bias exactly 1/257 (SPRING, FSE 2014, PDF p. 4 and p. 7).
B. SPRING-BCH bias bound (SPRING PDF p. 4 and p. 7):
   (1/q)^d * sqrt(2^m) / 2 with q=257, d=22, m=64  ->  about 2^-145.
C. SPRING attack costs as printed in SPRING section 4 (PDF p. 13-14):
   lattice N >= n lg(p/2) >= 896, 2^(0.48N), 2^(0.18N); Arora-Ge N=C(n+d,n);
   birthday attack on SPRING-CRT: time 2^(n/t) q^(4t)/(2t),
   queries 2^(n/(2t)) q^(4t)/(4n).  Shows the 2^119 vs 2^87 discrepancy.
D. SWIFFT linearity (SWIFFT, FSE 2008, section 4.3, PDF p. 9):
   f(x1) + f(x2) = f(x1 + x2) for binary x1, x2 with disjoint supports,
   on a toy ring Z_17[a]/(a^8+1); a random function fails the same test.
E. BPR zero-product pitfall (BPR PDF p. 7): in R_q with q = 1 mod 2n, a
   product of k uniform ring elements is 0 with probability
   (1 - (1-1/q)^k)^n; checked by simulation in the NTT domain (q=17, n=8).
F. XOR-combiner pitfalls (section 7 of the note): the XOR of two keystreams
   is only as good as the independence of their keys: with the SAME function
   and key the XOR is all-zero; a nonce repeated across messages leaks
   m1 XOR m2 whatever the components.
"""
import hashlib
import math
import random
import sys

sys.stdout.reconfigure(encoding="utf-8")
ALL_OK = True


def check(label, cond):
    global ALL_OK
    ALL_OK &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def round_p(x, q, p):
    """BPR eq. 2.1: round((p/q) * x) mod p, x in Z_q (round half up)."""
    return ((p * (x % q) * 2 + q) // (2 * q)) % p


# ---------------------------------------------------------------- A
print("A. LWR rounding toy (BPR eq. 2.1)")
rng = random.Random(1)
q, p, n = 64, 8, 4
s = [rng.randrange(q) for _ in range(n)]
a = [rng.randrange(q) for _ in range(n)]
ip = sum(x * y for x, y in zip(a, s)) % q
b = round_p(ip, q, p)
err = (ip - b * (q // p)) % q
err = err - q if err > q // 2 else err
print(f"  s={s} a={a} <a,s> mod 64 = {ip}  ->  LWR output b = {b} (3 bits)")
print(f"  (q/p)*b = {b * (q // p)}; the dropped 'error' <a,s>-(q/p)b = {err}")
check("|error| <= q/(2p) = 4", abs(err) <= q // (2 * p))
# error distribution over all x in Z_q when p | q: uniform on q/p values
errs = sorted({((x - round_p(x, q, p) * (q // p) + q // 2) % q) - q // 2 for x in range(q)})
print(f"  error values over all x in Z_64: {errs}")
check("p | q: error takes exactly q/p = 8 values", len(errs) == q // p)
# bias when p does not divide q: q = 257, p = 2
q2 = 257
ones = sum(round_p(x, q2, 2) for x in range(q2))
zeros = q2 - ones
bias = abs(zeros - ones) / q2
print(f"  q=257, p=2: #0 = {zeros}, #1 = {ones}, bias = {zeros - ones}/257 = {bias:.6f}")
check("bias is exactly 1/257 (SPRING PDF p. 4, 7)", zeros - ones == 1)

# ---------------------------------------------------------------- B
print("\nB. SPRING-BCH bias bound (1/q)^d * sqrt(2^m) / 2")
qb, d, m = 257, 22, 64
lg = -d * math.log2(qb) + m / 2 - 1
print(f"  q={qb}, d={d}, m={m}: log2(bound) = {lg:.2f}")
check("bound is about 2^-145 (SPRING PDF p. 4)", round(lg) == -145)
print(f"  bias after the code, (1/q)^d = 2^{-d * math.log2(qb):.1f} (slides p. 10 say 1/q^22 ~ 2^-176)")
check("(1/257)^22 ~ 2^-176", round(-d * math.log2(qb)) == -176)

# ---------------------------------------------------------------- C
print("\nC. SPRING attack-cost arithmetic (SPRING section 4, PDF p. 13-14)")
nS, pS = 128, 257
N = nS * math.log2(pS / 2)
print(f"  lattice: N = n lg(p/2) = {N:.1f}; 0.48N = {0.48 * N:.1f}; 0.18N = {0.18 * N:.1f}")
check("N >= 896, 2^(0.48N) >= 2^430, 2^(0.18N) >= 2^160",
      N >= 896 and 0.48 * N >= 430 and 0.18 * N >= 160)
for dset in (128, 129):
    lN = math.log2(math.comb(nS + dset, nS))
    print(f"  Arora-Ge with d = {dset}: log2 C(n+d, n) = {lN:.1f}, N^2 = 2^{2 * lN:.1f}")
check("Arora-Ge N^2 >= 2^384 for n = 128, d = p/2", 2 * math.log2(math.comb(nS + 128, nS)) >= 384)
lq = math.log2(257)
for t in (1, 2, 4):
    lt = nS / t + 4 * t * lq - math.log2(2 * t)
    lquery = nS / (2 * t) + 4 * t * lq - math.log2(4 * nS)
    print(f"  birthday attack t={t}: time 2^{lt:.1f}, queries/space by the formula 2^{lquery:.1f}")
t2_time = nS / 2 + 8 * lq - 2
t2_query_formula = nS / 4 + 8 * lq - math.log2(4 * nS)
t2_query_text = nS / 2 + 8 * lq - math.log2(4 * nS)
check("t=2 time is about 2^126 as printed", round(t2_time) == 126)
print(f"  t=2 queries: formula 2^(n/4) q^8/(4n) = 2^{t2_query_formula:.1f};"
      f" text's 2^(n/2) q^8/(4n) = 2^{t2_query_text:.1f}")
check("the printed '2^119' matches 2^(n/2) q^8/(4n), not the derived 2^(n/4) q^8/(4n)",
      round(t2_query_text) == 119 and round(t2_query_formula) == 87)

# ---------------------------------------------------------------- D
print("\nD. SWIFFT linearity on a toy ring Z_17[a]/(a^8 + 1), m = 4 multipliers")
pw, nw, mw = 17, 8, 4


def negacyclic_mul(u, v, n=nw, mod=pw):
    r = [0] * n
    for i in range(n):
        for j in range(n):
            k = i + j
            if k < n:
                r[k] = (r[k] + u[i] * v[j]) % mod
            else:
                r[k - n] = (r[k - n] - u[i] * v[j]) % mod
    return r


rng = random.Random(2)
A = [[rng.randrange(pw) for _ in range(nw)] for _ in range(mw)]


def swifft(x):  # x: list of m binary polynomials
    out = [0] * nw
    for ai, xi in zip(A, x):
        out = [(o + t) % pw for o, t in zip(out, negacyclic_mul(ai, xi))]
    return out


ok = True
for trial in range(200):
    x1 = [[rng.randrange(2) for _ in range(nw)] for _ in range(mw)]
    x2 = [[0 if x1[i][j] else rng.randrange(2) for j in range(nw)] for i in range(mw)]  # disjoint support
    x12 = [[x1[i][j] + x2[i][j] for j in range(nw)] for i in range(mw)]  # still binary
    lhs = [(u + v) % pw for u, v in zip(swifft(x1), swifft(x2))]
    ok &= lhs == swifft(x12)
check("f(x1) + f(x2) = f(x1 + x2) in 200 random trials (SWIFFT PDF p. 9)", ok)
table = {}
def rand_fn(x):  # a lazily sampled random function with the same range
    key = str(x)
    if key not in table:
        table[key] = [rng.randrange(pw) for _ in range(nw)]
    return table[key]
hits = 0
for trial in range(200):
    x1 = [[rng.randrange(2) for _ in range(nw)] for _ in range(mw)]
    x2 = [[0 if x1[i][j] else rng.randrange(2) for j in range(nw)] for i in range(mw)]
    x12 = [[x1[i][j] + x2[i][j] for j in range(nw)] for i in range(mw)]
    hits += [(u + v) % pw for u, v in zip(rand_fn(x1), rand_fn(x2))] == rand_fn(x12)
print(f"  random function passes the same test {hits}/200 times (expected ~ 200/17^8)")
check("a random function fails the linearity test", hits == 0)

# ---------------------------------------------------------------- E
print("\nE. BPR zero-product pitfall in R_q, q = 17, n = 8 (NTT domain = 8 slots of Z_17)")
qe, ne = 17, 8
rng = random.Random(3)
for k in (10, 40, 100):
    trials = 20000
    zero = 0
    for _ in range(trials):
        prod = [1] * ne
        for _ in range(k):
            prod = [(c * rng.randrange(qe)) % qe for c in prod]  # uniform element = uniform slots
        zero += all(c == 0 for c in prod)
    pred = (1 - (1 - 1 / qe) ** k) ** ne
    print(f"  k={k:3d}: simulated Pr[product = 0] = {zero / trials:.4f}, predicted {pred:.4f}")
    check(f"k={k}: simulation within 0.02 of (1-(1-1/q)^k)^n", abs(zero / trials - pred) < 0.02)
print("  (with k ~ q log n the rounded subset-product returns 0 on input 1...1, so the")
print("   seeds must be units; SPRING indexes its key by units a, s_i in R_p^*, PDF p. 3)")

# ---------------------------------------------------------------- F
print("\nF. XOR-combiner pitfalls (toy PRF = SHA-256(key || nonce || counter))")


def prf(key, nonce, ctr):
    return hashlib.sha256(key + nonce + ctr.to_bytes(8, "big")).digest()


def ks(key, nonce, nblocks):
    return b"".join(prf(key, nonce, i) for i in range(nblocks))


def xor(u, v):
    return bytes(x ^ y for x, y in zip(u, v))


k1, k2 = b"K" * 32, b"L" * 32
nonce = b"N" * 12
same = xor(ks(k1, nonce, 2), ks(k1, nonce, 2))
check("same function, same key: combined keystream is all zero", same == bytes(64))
indep = xor(ks(k1, nonce, 2), ks(k2, nonce, 2))
check("independent keys: combined keystream is not zero", indep != bytes(64))
m1, m2 = b"attack at dawn!!" * 2, b"retreat at nine!" * 2
c1 = xor(m1, xor(ks(k1, nonce, 1), ks(k2, nonce, 1)))
c2 = xor(m2, xor(ks(k1, nonce, 1), ks(k2, nonce, 1)))
check("nonce reused: c1 XOR c2 = m1 XOR m2 (combiner does not help)", xor(c1, c2) == xor(m1, m2))

print("\nOVERALL:", "PASS" if ALL_OK else "FAIL")
sys.exit(0 if ALL_OK else 1)
