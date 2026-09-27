"""Tiny Module-LWE: one sample worked by hand, its plain-LWE unrolling, NTTs, and a
Kyber-shaped encryption (no compression) at toy size.

Reproduces, at toy size, the structure described in:
  - Langlois, Stehle, "Worst-case to average-case reductions for module lattices",
    DCC 2015 (Module-LWE definition; rank k over R_q, lattice dimension k*n).
    File: research/papers/2015-langlois-stehle-worst-case-module-lattices.pdf
  - NIST FIPS 203 (ML-KEM), Section 3.2 (MLWE), Section 4.3 (NTT over
    Z_q[X]/(X^n+1) splitting into quadratic factors because only n | q-1),
    Section 5 (K-PKE: t = A s + e; u = A^T y + e1; v = t^T y + e2 + Decompress_1(m)).
    File: research/papers/nist-fips-203-ml-kem.pdf
  - Kyber round-3 spec, Section 5.1.2: primal lattice dimension d = m + k*n + 1.
    File: research/papers/2021-avanzi-et-al-kyber-round3-specification.pdf

Deterministic (fixed seeds). Prints every check; exits non-zero on failure.
Toy parameters are NOT secure.

Run: python research/scripts/pq/toy_mlwe.py
"""
import random
import sys

failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


def polymul_negacyclic(a, b, q):
    """Schoolbook product in Z_q[X]/(X^n + 1): X^n = -1."""
    n = len(a)
    out = [0] * n
    for i in range(n):
        for j in range(n):
            k = i + j
            if k < n:
                out[k] += a[i] * b[j]
            else:
                out[k - n] -= a[i] * b[j]
    return [x % q for x in out]


def negacyclic_matrix(a, q):
    """n x n integer matrix M with M @ coeffs(s) = coeffs(a*s mod X^n+1)."""
    n = len(a)
    M = [[0] * n for _ in range(n)]
    for j in range(n):          # column j = coefficients of a * X^j
        xj = [0] * n
        xj[j] = 1
        col = polymul_negacyclic(a, xj, q)
        for i in range(n):
            M[i][j] = col[i]
    return M


def centred(x, q):
    x %= q
    return x - q if x > q // 2 else x


def cbd(rng, eta, n):
    return [sum(rng.getrandbits(1) for _ in range(eta)) - sum(rng.getrandbits(1) for _ in range(eta)) for _ in range(n)]


def padd(a, b, q):
    return [(x + y) % q for x, y in zip(a, b)]


def psub(a, b, q):
    return [(x - y) % q for x, y in zip(a, b)]


# ---------------------------------------------------------------------------
print("=== Part A: one Module-LWE sample, rank k=2 over R_q = Z_17[X]/(X^4+1) ===")
q, n, k = 17, 4, 2
rng = random.Random(7)
A = [[[rng.randrange(q) for _ in range(n)] for _ in range(k)] for _ in range(k)]
s = [cbd(rng, 1, n) for _ in range(k)]      # normal form: secret from the error distribution
e = [cbd(rng, 1, n) for _ in range(k)]
b = []
for i in range(k):
    acc = [0] * n
    for j in range(k):
        acc = padd(acc, polymul_negacyclic(A[i][j], [x % q for x in s[j]], q), q)
    b.append(padd(acc, [x % q for x in e[i]], q))


def show_poly(p):
    return " + ".join(f"{c}*X^{i}" if i else f"{c}" for i, c in enumerate(p))


for i in range(k):
    for j in range(k):
        print(f"A[{i}][{j}] = {show_poly(A[i][j])}")
for j in range(k):
    print(f"s[{j}] = {s[j]}   e[{j}] = {e[j]}")
for i in range(k):
    print(f"b[{i}] = sum_j A[{i}][j]*s[j] + e[{i}] = {b[i]}")

# Unroll into plain LWE: an (k*n) x (k*n) integer matrix of negacyclic blocks.
big = [[0] * (k * n) for _ in range(k * n)]
for i in range(k):
    for j in range(k):
        M = negacyclic_matrix(A[i][j], q)
        for r in range(n):
            for c in range(n):
                big[i * n + r][j * n + c] = M[r][c]
s_flat = [x for poly in s for x in poly]
e_flat = [x for poly in e for x in poly]
b_flat = [(sum(big[r][c] * s_flat[c] for c in range(k * n)) + e_flat[r]) % q for r in range(k * n)]
print("plain-LWE view: b = A_big * s + e with A_big of size", f"{k*n} x {k*n}:")
for row in big:
    print("   ", row)
check("the MLWE sample equals a plain LWE sample of dimension k*n = 8 with a block-negacyclic matrix",
      b_flat == [x for poly in b for x in poly])
print("A_big has only k*k*n = 16 free entries instead of (k*n)^2 = 64: this is the 'structure'.")
print("Each block is negacyclic: every column is the previous one rotated down by one place with")
print("the wrapped entry negated (X^n = -1).")
col_ok = all(
    big[(r + 1) % n][c + 1] == (big[r][c] if r + 1 < n else (-big[r][c]) % q)
    for r in range(n) for c in range(n - 1))
check("block (0,0) is negacyclic (rotate and negate the wrapped entry)", col_ok)

m_samples = k  # number of R_q samples in this instance
print(f"primal embedding dimension for this instance: m*n + k*n + 1 = {m_samples*n} + {k*n} + 1 = "
      f"{m_samples*n + k*n + 1} (Kyber r3 spec 5.1.2 counts m in Z-samples: d = m + kn + 1)")

# ---------------------------------------------------------------------------
print()
print("=== Part B: full NTT when 2n | q-1 (q=17, n=4) and incomplete NTT when only n | q-1 (q=13) ===")
# q = 17: psi = 2 has order 8 = 2n, psi^n = -1, so X^4+1 = prod (X - psi^(2i+1)).
q, n = 17, 4
psi = 2
check("psi = 2 has multiplicative order 8 mod 17 and psi^4 = -1",
      pow(psi, 8, q) == 1 and pow(psi, 4, q) == q - 1)
roots = [pow(psi, 2 * i + 1, q) for i in range(n)]
print("roots of X^4+1 mod 17:", roots)
check("each root satisfies r^4 + 1 = 0 mod 17", all((pow(r, 4, q) + 1) % q == 0 for r in roots))
rng = random.Random(8)
f = [rng.randrange(q) for _ in range(n)]
g = [rng.randrange(q) for _ in range(n)]


def ev(p, x, q):
    return sum(c * pow(x, i, q) for i, c in enumerate(p)) % q


ntt_prod = [ev(f, r, q) * ev(g, r, q) % q for r in roots]
direct = polymul_negacyclic(f, g, q)
check("pointwise product of evaluations = evaluations of the negacyclic product (full NTT)",
      ntt_prod == [ev(direct, r, q) for r in roots])

# q = 13: 13-1 = 12, n=4 divides 12 but 2n=8 does not. zeta = 5 has order 4, zeta^2 = -1.
q = 13
zeta = 5
check("q=13: 8 does not divide 12, so Z_13 has no primitive 8th root of unity",
      all(pow(x, 8, q) != 1 or pow(x, 4, q) == 1 for x in range(1, q)))
check("zeta = 5 is a primitive 4th root mod 13 (zeta^2 = -1)", pow(zeta, 2, q) == q - 1)
# X^4 + 1 = (X^2 - zeta)(X^2 + zeta) = (X^2 - 5)(X^2 - 8) mod 13
lhs = [1, 0, 0, 0, 1]
prod = [0] * 5
fa, fb = [(-zeta) % q, 0, 1], [zeta % q, 0, 1]
for i, x in enumerate(fa):
    for j, y in enumerate(fb):
        prod[i + j] = (prod[i + j] + x * y) % q
check("X^4 + 1 = (X^2 - 5)(X^2 - 8) mod 13: two quadratic factors, like ML-KEM's 128", prod == lhs)


def mod_quadratic(p, c, q):
    """p mod (X^2 - c): X^2 = c."""
    r0, r1 = 0, 0
    for i, coef in enumerate(p):
        if i % 2 == 0:
            r0 = (r0 + coef * pow(c, i // 2, q)) % q
        else:
            r1 = (r1 + coef * pow(c, i // 2, q)) % q
    return r0, r1


def basecase(a, b, c, q):
    """(a0 + a1 X)(b0 + b1 X) mod (X^2 - c): FIPS 203 Algorithm 12 shape."""
    return ((a[0] * b[0] + a[1] * b[1] * c) % q, (a[0] * b[1] + a[1] * b[0]) % q)


rng = random.Random(9)
f = [rng.randrange(q) for _ in range(4)]
g = [rng.randrange(q) for _ in range(4)]
direct = polymul_negacyclic(f, g, q)
ok = True
for c in (zeta, (-zeta) % q):
    ok &= basecase(mod_quadratic(f, c, q), mod_quadratic(g, c, q), c, q) == mod_quadratic(direct, c, q)
check("incomplete NTT: products in each quadratic factor match the negacyclic product", ok)

# ---------------------------------------------------------------------------
print()
print("=== Part C: Kyber-shaped encryption (K-PKE without compression), k=2, n=8, q=97 ===")
q, n, k, eta = 97, 8, 2, 1
rng = random.Random(10)


def mat_vec(M, v, transpose=False):
    out = []
    for i in range(k):
        acc = [0] * n
        for j in range(k):
            a = M[j][i] if transpose else M[i][j]
            acc = padd(acc, polymul_negacyclic(a, [x % q for x in v[j]], q), q)
        out.append(acc)
    return out


def dot(u, v):
    acc = [0] * n
    for j in range(k):
        acc = padd(acc, polymul_negacyclic(u[j], [x % q for x in v[j]], q), q)
    return acc


A = [[[rng.randrange(q) for _ in range(n)] for _ in range(k)] for _ in range(k)]
s = [cbd(rng, eta, n) for _ in range(k)]
e = [cbd(rng, eta, n) for _ in range(k)]
t = [padd(x, [c % q for c in y], q) for x, y in zip(mat_vec(A, s), e)]        # t = A s + e
msg = [rng.getrandbits(1) for _ in range(n)]
y = [cbd(rng, eta, n) for _ in range(k)]
e1 = [cbd(rng, eta, n) for _ in range(k)]
e2 = cbd(rng, eta, n)
u = [padd(x, [c % q for c in z], q) for x, z in zip(mat_vec(A, y, transpose=True), e1)]   # u = A^T y + e1
v = padd(padd(dot(t, y), [c % q for c in e2], q), [bit * ((q + 1) // 2) for bit in msg], q)  # + round(q/2)*m
w = psub(v, dot(u, s), q)                                                     # v - s^T u
dec = [1 if abs(centred(c, q)) > q // 4 else 0 for c in w]
print("message bits :", msg)
print("decrypted    :", dec)
# noise identity from FIPS 203 structure: v - s^T u = e^T y + e2 - s^T e1 + round(q/2) m
ety = dot([[c % q for c in poly] for poly in e], y)
se1 = dot([[c % q for c in poly] for poly in s], e1)
noise = psub(padd(ety, [c % q for c in e2], q), se1, q)
print("noise e^T y + e2 - s^T e1 (centred):", [centred(c, q) for c in noise])
check("v - s^T u = e^T y + e2 - s^T e1 + round(q/2)*m (the K-PKE decryption identity)",
      w == padd(noise, [bit * ((q + 1) // 2) for bit in msg], q))
check("toy K-PKE decrypts correctly (all |noise| < q/4)", dec == msg)
bound = 2 * k * n * eta * eta + eta
rel = "<" if bound < q / 4 else ">="
print(f"worst-case |noise| per coefficient = 2*k*n*eta^2 + eta = {bound} {rel} q/4 = {q/4:.2f}: "
      f"{'failure impossible' if bound < q / 4 else 'failures possible but rare (see toy_lwe.py for exact rates)'}")
print(f"LWE dimension of this toy = k*n = {k*n}; ML-KEM-1024 uses k*n = 4*256 = 1024.")

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
