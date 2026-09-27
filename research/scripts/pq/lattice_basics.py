"""Lattice basics by computation: bases, determinant, Gram-Schmidt, successive minima,
Minkowski's bound, the Gaussian heuristic, LLL, Babai rounding (CVP/BDD), and the
primal (Kannan-embedding) attack on a toy LWE instance.

Reproduces, at small size, statements from:
  - Lenstra, Lenstra, Lovasz 1982, Section 1: reduced basis (1.4) |mu_ij| <= 1/2 and
    (1.5) Lovasz condition with 3/4; (1.9) |b1| <= 2^((n-1)/4) d(L)^(1/n);
    d(L) = prod |b_i*|.  File: research/papers/1982-lenstra-lenstra-lovasz-factoring-polynomials.pdf
  - Kirchner, Fouque 2017, Theorem 1 (Minkowski): lambda_1 <= sqrt(n) vol(L)^(1/n).
    File: research/papers/2017-kirchner-fouque-revisiting-overstretched-ntru.pdf
  - Albrecht, Player, Scott 2015, Section 2: Gaussian heuristic
    lambda_1 ~ sqrt(m/(2 pi e)) vol(L)^(1/m); Section 3: root-Hermite factor delta_0.
    File: research/papers/2015-albrecht-player-scott-concrete-hardness-lwe.pdf
  - Kyber round-3 spec, Section 5.1.2 / FrodoKEM round-3 spec, Section 5.2.2: primal attack
    lattice {x in Z^(m+n+1) : (A | I_m | -b) x = 0 mod q}, dimension d = m + n + 1,
    volume q^m, unique short vector (s, e, 1).
    Files: research/papers/2021-avanzi-et-al-kyber-round3-specification.pdf,
           research/papers/2021-alkim-et-al-frodokem-round3-specification-20210604.pdf

The LLL here is the textbook floating-point algorithm (delta = 0.99) and is only meant
for dimensions below ~100. Deterministic (fixed seeds). Prints each check; exits
non-zero on failure.

Run: python research/scripts/pq/lattice_basics.py
"""
import itertools
import math
import random
import sys
import time

import numpy as np

failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


# ---------------------------------------------------------------- core routines
def gram_schmidt(B):
    """Rows of B are basis vectors. Returns (Bstar, mu) in float64."""
    B = np.array(B, dtype=float)
    n = B.shape[0]
    Bs = np.zeros_like(B)
    mu = np.zeros((n, n))
    for i in range(n):
        v = B[i].copy()
        for j in range(i):
            mu[i, j] = B[i] @ Bs[j] / (Bs[j] @ Bs[j])
            v -= mu[i, j] * Bs[j]
        Bs[i] = v
        mu[i, i] = 1.0
    return Bs, mu


def lll(B, delta=0.99):
    """Textbook LLL (Cohen, Alg. 2.6.3 style). Rows are basis vectors (Python ints kept exact)."""
    B = [list(map(int, r)) for r in B]
    n = len(B)
    Bs, mu = gram_schmidt(B)
    Bn = [float(Bs[i] @ Bs[i]) for i in range(n)]
    mu = mu.tolist()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            r = round(mu[k][j])
            if r:
                B[k] = [x - r * y for x, y in zip(B[k], B[j])]
                for i in range(j):
                    mu[k][i] -= r * mu[j][i]
                mu[k][j] -= r
        if Bn[k] >= (delta - mu[k][k - 1] ** 2) * Bn[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            m_ = mu[k][k - 1]
            b_ = Bn[k] + m_ * m_ * Bn[k - 1]
            mu[k][k - 1] = m_ * Bn[k - 1] / b_
            Bn[k] = Bn[k - 1] * Bn[k] / b_
            Bn[k - 1] = b_
            for j in range(k - 1):
                mu[k - 1][j], mu[k][j] = mu[k][j], mu[k - 1][j]
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - m_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(k - 1, 1)
    return B


def is_lll_reduced(B, delta=0.99, tol=1e-6):
    Bs, mu = gram_schmidt(B)
    n = len(B)
    size_ok = all(abs(mu[i, j]) <= 0.5 + tol for i in range(n) for j in range(i))
    lov_ok = all(Bs[i] @ Bs[i] >= (delta - mu[i, i - 1] ** 2) * (Bs[i - 1] @ Bs[i - 1]) - tol for i in range(1, n))
    return size_ok and lov_ok


def det_abs(B):
    return abs(round(np.linalg.det(np.array(B, dtype=float))))


def shortest_vector(B):
    """Exact SVP by Fincke-Pohst enumeration on an LLL-reduced basis (small dimension only)."""
    B = lll(B)
    Bs, mu = gram_schmidt(B)
    n = len(B)
    bn = [float(Bs[i] @ Bs[i]) for i in range(n)]
    best = [float(np.dot(B[0], B[0])), list(B[0])]
    x = [0] * n

    def rec(i, partial):
        c = -sum(x[j] * mu[j, i] for j in range(i + 1, n))
        r = math.sqrt(max(best[0] - partial, 0) / bn[i])
        for xi in range(math.ceil(c - r), math.floor(c + r) + 1):
            x[i] = xi
            p = partial + (xi - c) ** 2 * bn[i]
            if p > best[0] + 1e-9:
                continue
            if i == 0:
                if any(x):
                    v = [sum(x[j] * B[j][t] for j in range(n)) for t in range(len(B[0]))]
                    nv = float(np.dot(v, v))
                    if nv < best[0] - 1e-9:
                        best[0], best[1] = nv, v
            else:
                rec(i - 1, p)
        x[i] = 0

    rec(n - 1, 0.0)
    return math.sqrt(best[0]), best[1]


def gh_ball(vol, n):
    """Gaussian heuristic with the exact ball volume: radius r with V_n r^n = vol."""
    vn = math.pi ** (n / 2) / math.gamma(n / 2 + 1)
    return (vol / vn) ** (1 / n)


def gh_asym(vol, n):
    """APS15 form: sqrt(n / (2 pi e)) vol^(1/n)."""
    return math.sqrt(n / (2 * math.pi * math.e)) * vol ** (1 / n)


# ---------------------------------------------------------------- Part A
print("=== Part A: a 2-D lattice, two bases, determinant, Gram-Schmidt, minima ===")
good = [[5, 1], [-2, 6]]
U = [[7, 3], [9, 4]]                      # unimodular: det = 28 - 27 = 1
bad = (np.array(U) @ np.array(good)).tolist()
print("good basis rows:", good, " bad basis rows:", bad, " U =", U)
check("U is unimodular (det = +-1)", abs(round(np.linalg.det(np.array(U, dtype=float)))) == 1)
check("both bases have the same |det| = 32", det_abs(good) == det_abs(bad) == 32)
for name, Bx in (("good", good), ("bad", bad)):
    Bs, mu = gram_schmidt(Bx)
    norms = [float(np.linalg.norm(v)) for v in Bs]
    print(f"{name}: Gram-Schmidt lengths {norms[0]:.3f}, {norms[1]:.3f}; product = {norms[0]*norms[1]:.3f}; mu_21 = {mu[1,0]:.3f}")
    check(f"{name}: det = product of Gram-Schmidt lengths (LLL82 proof of 1.6)", abs(norms[0] * norms[1] - 32) < 1e-9)
# successive minima by brute force over small coefficients
vecs = []
for a, b in itertools.product(range(-20, 21), repeat=2):
    if (a, b) != (0, 0):
        v = (a * good[0][0] + b * good[1][0], a * good[0][1] + b * good[1][1])
        vecs.append((math.hypot(*v), v))
vecs.sort()
l1, v1 = vecs[0]
l2, v2 = next((L, v) for L, v in vecs if v[0] * v1[1] - v[1] * v1[0] != 0)
print(f"lambda_1 = {l1:.4f} at {v1}; lambda_2 = {l2:.4f} at {v2}")
check("Minkowski: lambda_1 <= sqrt(n) det^(1/n) = sqrt(2)*sqrt(32) = 8", l1 <= math.sqrt(2) * math.sqrt(32))
print(f"Gaussian heuristic in dimension 2: exact-ball {gh_ball(32, 2):.3f}, sqrt(n/2pi e) form {gh_asym(32, 2):.3f} "
      "(a high-dimension heuristic; poor in dimension 2)")
red = lll(bad)
print("LLL applied to the bad basis gives:", red)
check("LLL output spans the same lattice (same |det|) and is LLL-reduced", det_abs(red) == 32 and is_lll_reduced(red))
check("LLL recovered a shortest vector in dimension 2", abs(math.hypot(*red[0]) - l1) < 1e-9)

# ---------------------------------------------------------------- Part B
print()
print("=== Part B: CVP / BDD with Babai rounding: a good basis decodes, a bad one does not ===")
rng = random.Random(11)
lat_pt = np.array([3, -2]) @ np.array(good)
target = lat_pt + np.array([1.2, -0.9])          # a point close to the lattice (a BDD instance)


def babai_round(Bx, t):
    Bm = np.array(Bx, dtype=float)
    coeffs = np.rint(np.linalg.solve(Bm.T, t))
    return (coeffs @ np.array(Bx)).astype(int)


print("lattice point", lat_pt.tolist(), "target", target.tolist())
print("Babai rounding, good basis ->", babai_round(good, target).tolist())
print("Babai rounding, bad basis  ->", babai_round(bad, target).tolist())
check("good basis decodes the BDD target to the right lattice point",
      babai_round(good, target).tolist() == lat_pt.tolist())
check("bad basis (same lattice) decodes to a wrong point: the basis is the trapdoor",
      babai_round(bad, target).tolist() != lat_pt.tolist())

# ---------------------------------------------------------------- Part C
print()
print("=== Part C: Gaussian heuristic vs exact lambda_1 on random q-ary lattices ===")
print("Lambda_q(A) = {y in Z^m : y = A^T s mod q}, m=12, n=6, q=97, vol = q^(m-n) (Micciancio-Regev 2009 Sec. 2-3)")
q, n, m = 97, 6, 12
ratios = []
rng = random.Random(12)
for trial in range(12):
    A = [[rng.randrange(q) for _ in range(m)] for _ in range(n)]
    # basis of Lambda_q(A) with A = [A1 | A2], A1 invertible: rows [I_n | A1^-1 A2] and [0 | q I_{m-n}]
    A1 = np.array([r[:n] for r in A])
    import sympy
    M1 = sympy.Matrix(A1.tolist())
    if M1.det() % q == 0:
        continue
    A1inv = M1.inv_mod(q)
    A2 = sympy.Matrix([r[n:] for r in A])
    H = (A1inv * A2).applyfunc(lambda x: x % q)
    basis = [[1 if j == i else 0 for j in range(n)] + [int(H[i, j]) for j in range(m - n)] for i in range(n)]
    basis += [[0] * n + [q if j == i else 0 for j in range(m - n)] for i in range(m - n)]
    vol = det_abs(basis)
    lam, _ = shortest_vector(basis)
    ratios.append(lam / gh_ball(vol, m))
print("lambda_1 / GH(exact ball) over", len(ratios), "lattices:", " ".join(f"{r:.2f}" for r in ratios))
avg = sum(ratios) / len(ratios)
print(f"mean ratio {avg:.3f}")
check("vol(Lambda_q(A)) = q^(m-n) for the constructed basis", vol == q ** (m - n))
check("the Gaussian heuristic predicts lambda_1 within 25% on average at m = 12", abs(avg - 1) < 0.25)

# ---------------------------------------------------------------- Part D
print()
print("=== Part D: LLL quality: Hermite factor and the LLL82 bound (1.9) ===")
rng = random.Random(13)
for dim in (10, 20, 30, 40):
    Bx = [[rng.randrange(-10 ** 6, 10 ** 6) for _ in range(dim)] for _ in range(dim)]
    t0 = time.time()
    R = lll(Bx)
    dt = time.time() - t0
    logvol = float(np.linalg.slogdet(np.array(R, dtype=float))[1])
    b1 = float(np.linalg.norm(R[0]))
    root_hermite = math.exp((math.log(b1) - logvol / dim) / dim)
    bound = 2 ** ((dim - 1) / 4) * math.exp(logvol / dim)
    print(f"dim {dim}: |b1| / vol^(1/n) = {b1/math.exp(logvol/dim):.3f}, root-Hermite delta_0 = {root_hermite:.4f}, "
          f"LLL82 bound 2^((n-1)/4) = {2**((dim-1)/4):.1f}, time {dt:.2f}s")
    check(f"dim {dim}: output is LLL-reduced and satisfies |b1| <= 2^((n-1)/4) vol^(1/n)",
          is_lll_reduced(R) and b1 <= bound)
print("APS15 Sec. 3.1 reports delta_0 ~ 1.0219 for LLL in practice [GN08]; small dimensions give smaller values.")

# ---------------------------------------------------------------- Part E
print()
print("=== Part E: the primal attack on toy LWE: lattice dimension d = m + n + 1 ===")


def primal_embedding(A, b, q):
    """Rows: [e_i | -A^T row i | 0] for secret coords, [0 | q e_j | 0], [0 | b | 1].
    The lattice is {(x_s, x_e, t) : x_e = t*b - A x_s mod q}, contains (s, e, 1) when b = A s + e."""
    m_, n_ = len(A), len(A[0])
    rows = []
    for i in range(n_):
        rows.append([1 if j == i else 0 for j in range(n_)] + [(-A[r][i]) % q for r in range(m_)] + [0])
    for j in range(m_):
        rows.append([0] * n_ + [q if r == j else 0 for r in range(m_)] + [0])
    rows.append([0] * n_ + list(b) + [1])
    return rows


def cbd_sample(rng, eta):
    return sum(rng.getrandbits(1) for _ in range(eta)) - sum(rng.getrandbits(1) for _ in range(eta))


rng = random.Random(14)
q = 97
for n_, m_ in ((8, 16), (10, 20), (16, 32), (24, 48), (32, 64), (40, 80), (48, 96)):
    wins, tries, t0 = 0, 3, time.time()
    for _ in range(tries):
        A = [[rng.randrange(q) for _ in range(n_)] for _ in range(m_)]
        s = [cbd_sample(rng, 1) for _ in range(n_)]
        e = [cbd_sample(rng, 1) for _ in range(m_)]
        b = [(sum(a * x for a, x in zip(row, s)) + ei) % q for row, ei in zip(A, e)]
        L = primal_embedding(A, b, q)
        R = lll(L)
        target = s + e + [1]
        wins += any(r == target or [-x for x in r] == target for r in R[:3])
    d = m_ + n_ + 1
    tnorm = math.sqrt(0.5 * (n_ + m_) + 1)
    gh = gh_asym(q ** m_, d)
    print(f"n={n_:2d}, m={m_:2d}: d = m+n+1 = {d:3d}, volume q^m, target (s,e,1) norm ~ {tnorm:.2f}, "
          f"GH ~ {gh:.1f}, gap GH/target ~ {gh/tnorm:.1f}; LLL recovered (s,e,1) in {wins}/{tries} "
          f"({time.time()-t0:.1f}s)")
    if n_ <= 10:
        check(f"n={n_}: the embedding lattice has dimension m+n+1 = {d} and LLL finds (s, e, 1)",
              len(L) == d and wins == tries)
print("With m = 2n the gap GH/target stays near 7, but what LLL can resolve shrinks as d grows")
print("(its output quality degrades like delta_0^d), so plain LLL stops finding (s, e, 1) somewhere")
print("between d ~ 100 and d ~ 150 here. Kyber r3 spec eq. (9) states the success condition for BKZ-b.")
print("At n ~ 1000 the attacker needs BKZ with block size in the hundreds (Kyber r3 spec Table 4:")
print("d = 1885, beta = 878 for Kyber1024). Costs: see research/notes/pq/attack-cost-estimation.md.")

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
