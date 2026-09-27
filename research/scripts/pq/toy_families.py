"""Toy (insecure) worked examples of three post-quantum KEM families, for learning only.

Reproduces the worked examples in research/notes/pq/pq-families-for-diversity.md:

  1. FrodoPKE-style plain-LWE encryption (Lindner-Peikert shape used by FrodoKEM; FrodoKEM
     proposal 2025-09-29, Sections 7.3 and 8): B bits are packed into each entry of an
     nbar x nbar matrix by multiplying by q/2^B; decryption rounds C - B'S back.  The script
     measures the largest decryption noise over many trials and shows the failure threshold
     q/2^(B+1).  Error samples use the real FrodoKEM-640 table (Table A.4) with the Section
     7.5 inversion sampler.
  2. NTRU-style encryption in Z_q[x]/(x^n - 1) (the textbook form summarised in NIST IR 8413,
     Section 4.3.2): h = g * f^-1 mod q, c = 3*h*r + m mod q, decryption a = c*f mod q, lift
     to (-q/2, q/2], then m = a * f^-1 mod 3.  The script checks the correctness condition
     (every coefficient of 3*g*r + f*m inside (-q/2, q/2)).
  3. Niederreiter (the "dual" McEliece used by Classic McEliece, spec Section 4) with the
     [7,4] Hamming code, t = 1: the secret parity-check matrix H is hidden as H_pub = S*H*P;
     a ciphertext is the syndrome s = H_pub * e of a weight-1 error e.

The parameters are tiny and offer no security; they only show the mechanics.
Deterministic (fixed seeds).  Run:  python toy_families.py   (exits non-zero on failure)
"""
import sys

import numpy as np

FAIL = []


def expect(label, cond):
    print(f"  [{'ok' if cond else 'FAIL'}] {label}")
    if not cond:
        FAIL.append(label)


# ----------------------------------------------------------------------------------------
# 1. Toy FrodoPKE
# ----------------------------------------------------------------------------------------
T640 = [4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767]


def frodo_sample(rng, shape):
    """FrodoKEM Section 7.5 inversion sampler with the FrodoKEM-640 table."""
    r = rng.integers(0, 1 << 16, size=shape, dtype=np.int64)
    t = r >> 1
    e = np.zeros(shape, dtype=np.int64)
    for Ti in T640[:-1]:
        e += (t > Ti)
    return np.where(r & 1, -e, e)


def toy_frodo():
    n, nbar, D = 64, 2, 12
    q = 1 << D
    print(f"1. Toy FrodoPKE (plain LWE), n={n}, nbar={nbar}, q=2^{D}; B = 2 and B = 4 bits per entry")
    rng = np.random.default_rng(20260926)
    A = rng.integers(0, q, size=(n, n), dtype=np.int64)
    S = frodo_sample(rng, (n, nbar))
    E = frodo_sample(rng, (n, nbar))
    Bpk = (A @ S + E) % q                      # public key: B = A S + E
    trials = 2000
    worst = 0
    fails = {2: 0, 4: 0}
    for _ in range(trials):
        S1 = frodo_sample(rng, (nbar, n))
        E1 = frodo_sample(rng, (nbar, n))
        E2 = frodo_sample(rng, (nbar, nbar))
        B1 = (S1 @ A + E1) % q                 # c1 = S'A + E'
        noise = (S1 @ E + E2 - E1 @ S)          # what decryption is left with besides the message
        worst = max(worst, int(np.abs(noise).max()))
        for B in (2, 4):
            msg = rng.integers(0, 1 << B, size=(nbar, nbar), dtype=np.int64)
            C = (S1 @ Bpk + E2 + msg * (q >> B)) % q      # c2 = S'B + E'' + Encode(msg)
            M = (C - B1 @ S) % q                            # = Encode(msg) + noise  (mod q)
            dec = ((M + (1 << (D - B - 1))) >> (D - B)) % (1 << B)   # Decode: nearest multiple of q/2^B
            fails[B] += int((dec != msg).sum())
    print(f"      decryption noise S'E + E'' - E'S: largest |coefficient| over {trials} trials = {worst}")
    for B in (2, 4):
        thr = q >> (B + 1)
        print(f"      B = {B}: an entry decodes correctly while |noise| < q/2^(B+1) = {thr};"
              f" wrong entries: {fails[B]} of {trials * nbar * nbar}")
    expect("B = 2: every toy decryption correct (noise below q/8)", fails[2] == 0 and worst < (q >> 3))
    expect("B = 4: failures appear once the threshold q/32 is below the noise", fails[4] > 0)


# ----------------------------------------------------------------------------------------
# 2. Toy NTRU in Z_q[x]/(x^n - 1)
# ----------------------------------------------------------------------------------------
def pmul(a, b, n, mod=None):
    res = np.zeros(n, dtype=object)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    res[(i + j) % n] += ai * bj
    if mod is not None:
        res = np.array([int(x) % mod for x in res], dtype=object)
    return res


def pinv_mod_prime(a, n, p):
    """Inverse of a in F_p[x]/(x^n - 1) by solving the circulant linear system (small n only)."""
    import sympy
    M = sympy.Matrix(n, n, lambda i, j: int(a[(i - j) % n]) % p)
    try:
        Minv = M.inv_mod(p)
    except ValueError:
        return None
    e0 = sympy.Matrix([1] + [0] * (n - 1))
    col = (Minv * e0).applyfunc(lambda x: x % p)
    return np.array([int(x) for x in col], dtype=object)


def pinv_mod_pow2(a, n, q):
    """Inverse mod 2 lifted to mod q = 2^k by Newton iteration b <- b(2 - ab)."""
    b = pinv_mod_prime(a, n, 2)
    if b is None:
        return None
    mod = 2
    while mod < q:
        mod = min(mod * mod, q)
        ab = pmul(a, b, n, mod)
        two_minus = np.array([(-int(x)) % mod for x in ab], dtype=object)
        two_minus[0] = (two_minus[0] + 2) % mod
        b = pmul(b, two_minus, n, mod)
    return b


def centered(v, q):
    return np.array([((int(x) + q // 2) % q) - q // 2 for x in v], dtype=object)


def ternary(rng, n, ones, minus):
    v = np.zeros(n, dtype=object)
    idx = rng.permutation(n)
    v[idx[:ones]] = 1
    v[idx[ones:ones + minus]] = -1
    return v


def toy_ntru():
    print("2. Toy NTRU, n=11, q=64, p=3 (textbook form of NIST IR 8413 Sec. 4.3.2)")
    n, q = 11, 64
    rng = np.random.default_rng(7)
    while True:
        f = ternary(rng, n, 4, 3)
        fq = pinv_mod_pow2(f, n, q)
        f3 = pinv_mod_prime(f, n, 3)
        if fq is not None and f3 is not None:
            break
    g = ternary(rng, n, 3, 3)
    h = pmul(g, fq, n, q)                      # public key h = g / f mod q
    expect("f * f^-1 = 1 mod q", list(pmul(f, fq, n, q)) == [1] + [0] * (n - 1))
    expect("f * f^-1 = 1 mod 3", list(pmul(f, f3, n, 3)) == [1] + [0] * (n - 1))
    good = 0
    trials = 200
    worst = 0
    for _ in range(trials):
        m = np.array([int(x) for x in rng.integers(-1, 2, size=n)], dtype=object)
        r = ternary(rng, n, 3, 3)
        c = (pmul(np.array([3 * int(x) for x in h], dtype=object), r, n) + m) % q
        c = np.array([int(x) % q for x in c], dtype=object)
        a = centered(pmul(c, f, n, q), q)       # = 3 g r + f m exactly, if no wrap-around
        worst = max(worst, max(abs(int(x)) for x in (pmul(np.array([3 * int(x) for x in g], dtype=object), r, n) + pmul(f, m, n))))
        mm = centered(pmul(np.array([int(x) % 3 for x in a], dtype=object), f3, n, 3), 3)
        good += list(mm) == list(m)
    print(f"      largest |coefficient| of 3gr + fm over {trials} trials = {worst}; must stay < q/2 = {q // 2}")
    expect(f"{good}/{trials} toy NTRU decryptions correct", good == trials)
    expect("correctness bound respected", worst < q // 2)


# ----------------------------------------------------------------------------------------
# 3. Toy Niederreiter with the [7,4] Hamming code
# ----------------------------------------------------------------------------------------
def gf2_inv(M):
    n = M.shape[0]
    A = np.concatenate([M.copy() % 2, np.eye(n, dtype=np.int64)], axis=1)
    for col in range(n):
        piv = next((r for r in range(col, n) if A[r, col]), None)
        if piv is None:
            return None
        A[[col, piv]] = A[[piv, col]]
        for r in range(n):
            if r != col and A[r, col]:
                A[r] ^= A[col]
    return A[:, n:]


def toy_niederreiter():
    print("3. Toy Niederreiter (McEliece dual) with the [7,4] Hamming code, t = 1")
    rng = np.random.default_rng(1978)
    # Secret: parity-check matrix whose j-th column is the binary expansion of j+1.
    H = np.array([[((j + 1) >> b) & 1 for j in range(7)] for b in range(3)], dtype=np.int64)
    while True:
        S = rng.integers(0, 2, size=(3, 3))
        Sinv = gf2_inv(S)
        if Sinv is not None:
            break
    perm = rng.permutation(7)
    P = np.eye(7, dtype=np.int64)[:, perm]
    Hpub = (S @ H @ P) % 2
    print("      public H_pub =", Hpub.tolist())
    ok = True
    for pos in range(7):
        e = np.zeros(7, dtype=np.int64)
        e[pos] = 1
        s = (Hpub @ e) % 2                     # ciphertext = syndrome of the weight-1 error
        s_sec = (Sinv @ s) % 2                 # = H (P e): undo the scrambler
        j = int(s_sec[0] + 2 * s_sec[1] + 4 * s_sec[2]) - 1   # Hamming decoding: column index
        e_perm = np.zeros(7, dtype=np.int64)
        e_perm[j] = 1
        e_rec = (P.T @ e_perm) % 2              # P is a permutation matrix: P^-1 = P^T
        ok &= bool(np.array_equal(e_rec, e))
    expect("all 7 weight-1 errors recovered from their syndromes with the secret (S, H, P)", ok)
    print("      real Classic McEliece uses binary Goppa codes with t = 64..128 errors, where the"
          " attacker must solve syndrome decoding for a random-looking code (information-set decoding)")


if __name__ == "__main__":
    toy_frodo()
    toy_ntru()
    toy_niederreiter()
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("All toy checks passed.")
