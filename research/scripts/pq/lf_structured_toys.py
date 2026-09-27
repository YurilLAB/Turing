"""Toy versions of three structured ideas: LWE normal form, learning with rounding, and NTRU.

Reproduces, at toy size:
  A. Applebaum-Cash-Peikert-Sahai, CRYPTO 2009, Lemma 2 (Sec. 3.1): a deterministic transformation
     maps LWE samples with an arbitrary secret s to LWE samples whose secret x-bar is drawn from the
     error distribution ("normal form"), with x-bar = -A-bar^T s + b-bar. The transformation takes n
     samples with an invertible A-bar and rewrites each fresh (a, b) as a' = -A-bar^(-1) a,
     b' = b + <a', b-bar>.  File: research/papers/2009-applebaum-cash-peikert-sahai-circular-secure-lwe.pdf
  B. Banerjee-Peikert-Rosen, EUROCRYPT 2012, Def. 3.1 and eq. 2.1: LWR samples b = round((p/q)<a,s>)
     mod p. Shows that p-scaled LWR equals LWE with a deterministic error of size < q/(2p), and that
     LWR is deterministic in (a, s).  File: research/papers/2012-banerjee-peikert-rosen-pseudorandom-functions-lattices.pdf
  C. Hoffstein-Pipher-Silverman, ANTS 1998, Sec. 1.2-1.5: NTRU key generation h = Fq*g, encryption
     e = p phi*h + m, decryption a = f*e mod q (centred), m = Fp*a mod p, and why it works (all
     coefficients of p phi*g + f*m inside (-q/2, q/2)); a failure when q is too small; and the NTRU
     lattice {(u, v): v = u*h mod q} of dimension 2N, in which LLL finds (f, g) or a rotation of it.
     File: research/papers/1998-hoffstein-pipher-silverman-ntru-ring-based-pkc.pdf

Deterministic (fixed seeds). Toy parameters are NOT secure. Prints each check; exits non-zero on failure.
Run: python research/scripts/pq/lf_structured_toys.py
"""
import math
import random
import sys

import numpy as np
import sympy

failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


def centred(x, q):
    x %= q
    return x - q if x > q // 2 else x


def cbd(rng, eta):
    return sum(rng.getrandbits(1) for _ in range(eta)) - sum(rng.getrandbits(1) for _ in range(eta))


# ---------------------------------------------------------------- A. normal form
print("=== A. LWE normal form (ACPS 2009, Lemma 2): secret moved into the error distribution ===")
q, n = 97, 6
rng = random.Random(2009)
s = [rng.randrange(q) for _ in range(n)]            # arbitrary (uniform) secret


def lwe_sample():
    a = [rng.randrange(q) for _ in range(n)]
    e = cbd(rng, 2)
    return a, (sum(x * y for x, y in zip(a, s)) + e) % q, e


# Stage 1: collect n samples whose a-vectors are linearly independent mod q.
kept, errs = [], []
while len(kept) < n:
    a, b, e = lwe_sample()
    M = sympy.Matrix([k[0] for k in kept] + [a])
    if M.rank(iszerofunc=lambda x: x % q == 0) == len(kept) + 1 and \
            (len(kept) + 1 < n or sympy.Matrix([k[0] for k in kept] + [a]).det() % q != 0):
        kept.append((a, b))
        errs.append(e)
Abar = sympy.Matrix([k[0] for k in kept]).T          # columns are the kept a-vectors (n x n)
bbar = sympy.Matrix([k[1] for k in kept])
xbar = [centred(v, q) for v in (bbar - Abar.T * sympy.Matrix(s))]
print(f"uniform secret s = {s}")
print(f"new secret x-bar = b-bar - A-bar^T s = {xbar}  (these are the errors of the {n} kept samples: {errs})")
check("x-bar equals the kept samples' errors, so it is drawn from the error distribution", xbar == errs)
Ainv = Abar.inv_mod(q)
ok = True
for _ in range(200):
    a, b, e = lwe_sample()
    a2 = [int(v) % q for v in (-Ainv * sympy.Matrix(a))]
    b2 = (b + sum(x * y for x, y in zip(a2, [int(v) for v in bbar]))) % q
    ok &= centred(b2 - sum(x * y for x, y in zip(a2, xbar)), q) == e
check("every transformed sample (a', b') satisfies b' = <a', x-bar> + e with the ORIGINAL error e (200 samples)", ok)
print("Why: b' = <a,s> + e + <a', A-bar^T s + x-bar> and A-bar a' = -a, so the s terms cancel.")
print("a -> a' is a bijection of Z_q^n, so uniform samples stay uniform (Lemma 2's second claim).")

# ---------------------------------------------------------------- B. LWR
print()
print("=== B. Learning with rounding (BPR 2012, Def. 3.1): deterministic error ===")
q, p, n = 256, 32, 8
rng = random.Random(2012)
s = [rng.randrange(q) for _ in range(n)]


def round_p(x):
    """BPR12 eq. 2.1: round((p/q) x) mod p, with round-half-up."""
    return ((x % q) * p + q // 2) // q % p


ok_err = ok_det = True
max_err = 0
for _ in range(500):
    a = [rng.randrange(q) for _ in range(n)]
    ip = sum(x * y for x, y in zip(a, s)) % q
    b = round_p(ip)
    err = centred(b * (q // p) - ip, q)           # (q/p) b = <a,s> + err (mod q)
    max_err = max(max_err, abs(err))
    ok_err &= -q // (2 * p) <= err < q // (2 * p) + 1
    ok_det &= round_p(ip) == b
print(f"q = {q}, p = {p}: (q/p) * b - <a, s> ranges over errors with |err| <= {max_err} (q/(2p) = {q // (2 * p)})")
check("scaled LWR sample (q/p) b = <a, s> + err with |err| <= q/(2p): an LWE sample with deterministic error", ok_err)
check("LWR is deterministic: the same (a, s) always gives the same b (no sampled noise)", ok_det)
print("This determinism is why LWR suits PRFs (BPR12 title) and removes the noise sampler, and why")
print("its proofs need either a super-polynomial q/p (BPR12 Thm 3.2) or a bounded number of samples")
print("(Alwen et al. 2013; Bogdanov et al. 2016).")

# ---------------------------------------------------------------- C. NTRU
print()
print("=== C. NTRU (HPS 1998) at toy size ===")
X = sympy.symbols("X")


def conv(a, b, N):
    """Cyclic convolution in Z[X]/(X^N - 1) (HPS98's star product)."""
    out = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[(i + j) % N] += x * y
    return out


def inv_mod_prime(f, N, p):
    P = sympy.Poly(list(reversed(f)), X, modulus=p)
    M = sympy.Poly(X ** N - 1, X, modulus=p)
    try:
        inv = sympy.invert(P, M)
    except (sympy.polys.polyerrors.NotInvertible, Exception):
        return None
    c = [int(v) % p for v in reversed(inv.all_coeffs())]
    return c + [0] * (N - len(c))


def inv_mod_pow2(f, N, q):
    F = inv_mod_prime(f, N, 2)
    if F is None:
        return None
    mod = 2
    while mod < q:                                    # Newton lifting: F <- F (2 - f F)
        mod = min(mod * mod, q)
        fF = conv(f, F, N)
        two_minus = [(-c) % mod for c in fF]
        two_minus[0] = (two_minus[0] + 2) % mod
        F = [c % mod for c in conv(F, two_minus, N)]
    return F


def ternary(rng, N, d_plus, d_minus):
    idx = rng.sample(range(N), d_plus + d_minus)
    v = [0] * N
    for i in idx[:d_plus]:
        v[i] = 1
    for i in idx[d_plus:]:
        v[i] = -1
    return v


def ntru_keygen(rng, N, p, q, df, dg):
    while True:
        f = ternary(rng, N, df + 1, df)
        Fp, Fq = inv_mod_prime(f, N, p), inv_mod_pow2(f, N, q)
        if Fp is not None and Fq is not None:
            break
    g = ternary(rng, N, dg, dg)
    h = [c % q for c in conv(Fq, g, N)]
    return f, g, Fp, Fq, h


def ntru_encrypt(rng, h, m, N, p, q, dr):
    phi = ternary(rng, N, dr, dr)
    e = [(p * c + mi) % q for c, mi in zip(conv(phi, h, N), m)]
    return e, phi


def ntru_decrypt(f, Fp, e, N, p, q):
    a = [centred(c, q) for c in conv(f, e, N)]
    return [centred(c, p) for c in conv(Fp, a, N)], a


N, p, q, df, dg, dr = 17, 3, 64, 3, 3, 3
print(f"(printed as N = {N}, p = {p}, q = {q}; f has {df + 1} ones and {df} minus ones, g and phi {dg} of each)")
rng = random.Random(1998)
f, g, Fp, Fq, h = ntru_keygen(rng, N, p, q, df, dg)
print(f"f = {f}\ng = {g}\nh = Fq*g mod q = {h}")
check("Fq * f = 1 (mod q) and Fp * f = 1 (mod p)  (HPS98 eq. 1)",
      [c % q for c in conv(Fq, f, N)] == [1] + [0] * (N - 1) and
      [c % p for c in conv(Fp, f, N)] == [1] + [0] * (N - 1))
ok, worst = True, 0
for t in range(300):
    m = [rng.randrange(p) - 1 for _ in range(N)]
    e, phi = ntru_encrypt(rng, h, m, N, p, q, dr)
    got, a = ntru_decrypt(f, Fp, e, N, p, q)
    true_a = [p * x + y for x, y in zip(conv(phi, g, N), conv(f, m, N))]   # p phi*g + f*m over Z
    worst = max(worst, max(abs(c) for c in true_a))
    ok &= a == true_a and got == m
print(f"300 encryptions: largest |coefficient| of p phi*g + f*m over Z = {worst} vs q/2 = {q / 2}")
check("f*e mod q (centred) equals p phi*g + f*m exactly, and decryption recovers m, in all 300 trials "
      "(HPS98 Sec. 1.5)", ok and worst < q / 2)

q_small, fails = 16, 0
f2, g2, Fp2, Fq2, h2 = ntru_keygen(random.Random(7), N, p, q_small, df, dg)
rng2 = random.Random(8)
for t in range(300):
    m = [rng2.randrange(p) - 1 for _ in range(N)]
    e, _ = ntru_encrypt(rng2, h2, m, N, p, q_small, dr)
    fails += ntru_decrypt(f2, Fp2, e, N, p, q_small)[0] != m
print(f"same weights with q = {q_small}: {fails}/300 decryption failures (coefficients wrap past q/2 = {q_small // 2})")
check("with q too small for the weights, decryption fails often", fails > 30)


# NTRU lattice and a toy key-recovery attack by LLL
def lll(B, delta=0.99):
    B = [list(map(int, r)) for r in B]
    k, nrows = 1, len(B)

    def gso(B):
        Bs, mu = [], [[0.0] * len(B) for _ in B]
        for i, b in enumerate(B):
            v = np.array(b, dtype=float)
            for j in range(i):
                mu[i][j] = float(np.dot(b, Bs[j]) / np.dot(Bs[j], Bs[j]))
                v = v - mu[i][j] * Bs[j]
            Bs.append(v)
        return Bs, mu

    Bs, mu = gso(B)
    while k < nrows:
        for j in range(k - 1, -1, -1):
            r = round(mu[k][j])
            if r:
                B[k] = [x - r * y for x, y in zip(B[k], B[j])]
                Bs, mu = gso(B)
        if np.dot(Bs[k], Bs[k]) >= (delta - mu[k][k - 1] ** 2) * np.dot(Bs[k - 1], Bs[k - 1]):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bs, mu = gso(B)
            k = max(k - 1, 1)
    return B


basis = []
for i in range(N):                                   # rows (e_i, X^i * h mod q)
    xi = [0] * N
    xi[i] = 1
    basis.append(xi + [c % q for c in conv(xi, h, N)])
for j in range(N):                                   # rows (0, q e_j)
    basis.append([0] * N + [q if t == j else 0 for t in range(N)])
det = abs(sympy.Matrix(basis).det())
fg = f + g
in_lattice = all((c - v) % q == 0 for c, v in zip(conv(f, h, N), g))
print(f"NTRU lattice: dimension 2N = {2 * N}, determinant = {det} = {q}^{N}: {det == q ** N}")
check("(f, g) lies in the NTRU lattice {(u, v): v = u*h mod q}, whose volume is q^N", in_lattice and det == q ** N)
gh = math.sqrt(2 * N / (2 * math.pi * math.e)) * math.sqrt(q)
print(f"|(f, g)| = {math.sqrt(sum(c * c for c in fg)):.2f}; Gaussian heuristic for this lattice ~ {gh:.2f}")
R = lll(basis)
# Any short (f', g') in the lattice with f' invertible mod p is an equivalent decryption key.
R_sorted = sorted(R, key=lambda r: sum(c * c for c in r))
key_ok = False
for r in R_sorted[:5]:
    f_alt = r[:N]
    Fp_alt = inv_mod_prime(f_alt, N, p)
    if Fp_alt is None:
        continue
    good = 0
    rng3 = random.Random(99)
    for _ in range(100):
        m = [rng3.randrange(p) - 1 for _ in range(N)]
        e, _ = ntru_encrypt(rng3, h, m, N, p, q, dr)
        good += ntru_decrypt(f_alt, Fp_alt, e, N, p, q)[0] == m
    print(f"LLL vector of norm {math.sqrt(sum(c * c for c in r)):.2f} used as a key decrypts {good}/100 messages")
    key_ok = good == 100
    break
check("a short vector found by LLL decrypts every test message: the toy key is recovered", key_ok)
rots = set()
for i in range(N):
    fr = [f[(t - i) % N] for t in range(N)]
    gr = [g[(t - i) % N] for t in range(N)]
    rots.add(tuple(fr + gr))
    rots.add(tuple(-c for c in fr + gr))
found = [r for r in R if tuple(r) in rots]
print(f"LLL output: {len(found)} of {2 * N} basis vectors are rotations X^i*(f, g) (up to sign); "
      f"shortest output norm {min(math.sqrt(sum(c * c for c in r)) for r in R):.2f}")
print("(At this tiny size the lattice holds other vectors as short as (f, g) or shorter, so LLL need not return")
print(" a rotation of (f, g) itself; any short enough (f', g') with f' invertible mod p decrypts, as checked above.)")
print("The N rotations X^i*(f, g) are all short: an NTRU lattice has a dense sublattice of short vectors,")
print("the structure behind the overstretched-NTRU attacks (Kirchner-Fouque 2017, Ducas-van Woerden 2021).")

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
