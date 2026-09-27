"""NTT arithmetic behind ML-KEM's choice n = 256, q = 3329, which moduli allow NTTs for other
dimensions, NTRU Prime's inert field, and the lattice dimensions an attacker actually reduces.

Reproduces / checks:
  A. FIPS 203 Sec. 4.3 (PDF p.33-34): q = 3329 = 2^8*13 + 1 is prime; there are 128 primitive
     256-th roots of unity and none of order 512; zeta = 17 is a primitive 256-th root, zeta^128 = -1;
     X^256 + 1 = prod_{i<128} (X^2 - zeta^(2 BitRev7(i) + 1)) mod q (eq. 4.10), and each quadratic
     is irreducible, so T_q is a product of 128 fields of size q^2.
  B. FIPS 203 Algorithms 9-12 (NTT, NTT^-1, MultiplyNTTs, BaseCaseMultiply), implemented from the
     text, agree with schoolbook multiplication in Z_q[X]/(X^256 + 1).
     File: research/papers/nist-fips-203-ml-kem.pdf
  C. For x^n + 1 (n a power of 2) over a prime q, the number of irreducible factors is n/d with
     d = multiplicative order of q modulo 2n (standard finite-field fact: the roots are the primitive
     2n-th roots of unity). Tabulated for ML-KEM's q, NewHope's q = 12289 (NewHope r2 spec Sec. 2:
     "smallest prime for which it holds that q = 1 mod 2n"), and candidate dimensions near 1000.
  D. NTRU Prime r3 spec Sec. 3 (PDF p.22-23): sntrup761 (p=761, q=4591) and sntrup1013
     (p=1013, q=7177) use x^p - x - 1, required irreducible mod q (spec p.8). Checked with Rabin's
     test: for prime degree p, f is irreducible over F_q iff x^(q^p) = x mod f and
     gcd(x^q - x, f) = 1.  File: research/papers/2020-bernstein-et-al-ntru-prime-round3-specification.pdf
  E. The primal-attack lattice {x in Z^(m+kn+1): (A | I_m | -b) x = 0 mod q} of dimension
     d = m + kn + 1 and volume q^m (Kyber r3 spec Sec. 5.1.2, eq. 9, p.26); minimising the BKZ
     block size b over m under the GSA success condition. Compared with Kyber r3 spec Table 4
     (Kyber1024: d = 1885, b = 878, core-SVP 256 / 232) and FrodoKEM r3 spec Table 10 (Frodo-976
     primal core-SVP 216.0 classical). This is a cross-check of the stated dimensions only; full
     cost estimation belongs to attack-cost-estimation.md.
  F. NTRU fatigue point q ~ 0.004 n^2.484 (Ducas-van Woerden, ASIACRYPT 2021, abstract) evaluated
     at the NTRU round-3 dimensions (NTRU r3 spec Sec. 1.6), versus the q they use.

Deterministic. Prints every check; exits non-zero on failure.
Run: python research/scripts/pq/lf_ntt_and_dimensions.py      (about 1 minute)
"""
import math
import random
import sys
import time

import numpy as np
import sympy

failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


# ---------------------------------------------------------------- A. structure of q = 3329
print("=== A. q = 3329 and the 256-th roots of unity (FIPS 203 Sec. 4.3) ===")
Q, N = 3329, 256
check("3329 is prime and 3329 = 2^8 * 13 + 1", sympy.isprime(Q) and Q == 2 ** 8 * 13 + 1)
order17 = sympy.n_order(17, Q)
check(f"17 has multiplicative order {order17} = 256 mod 3329, and 17^128 = -1", order17 == 256 and pow(17, 128, Q) == Q - 1)
prim256 = [x for x in range(1, Q) if sympy.n_order(x, Q) == 256]
check(f"number of primitive 256-th roots of unity = {len(prim256)} = phi(256) = 128", len(prim256) == 128)
check("no element of order 512 (512 does not divide q - 1 = 3328)", (Q - 1) % 512 != 0)


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


gammas = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]
# product of the 128 quadratics X^2 - gamma_i, as a coefficient list (low degree first)
prod = [1]
for g in gammas:
    new = [0] * (len(prod) + 2)
    for k, c in enumerate(prod):
        new[k] = (new[k] - g * c) % Q
        new[k + 2] = (new[k + 2] + c) % Q
    prod = new
target = [1] + [0] * 255 + [1]
check("prod_{i<128} (X^2 - 17^(2 BitRev7(i)+1)) = X^256 + 1 mod 3329 (eq. 4.10)", prod == target)
check("the 128 constants gamma_i are distinct", len(set(gammas)) == 128)
check("every gamma_i is a quadratic non-residue, so each X^2 - gamma_i is irreducible (a field of q^2 elements)",
      all(pow(g, (Q - 1) // 2, Q) == Q - 1 for g in gammas))

# ---------------------------------------------------------------- B. FIPS 203 Algorithms 9-12
print()
print("=== B. FIPS 203 Algorithms 9-12 vs schoolbook negacyclic multiplication ===")
ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]


def ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def base_case(a0, a1, b0, b1, gamma):
    return (a0 * b0 + a1 * b1 * gamma) % Q, (a0 * b1 + a1 * b0) % Q


def multiply_ntts(fh, gh):
    h = [0] * 256
    for i in range(128):
        h[2 * i], h[2 * i + 1] = base_case(fh[2 * i], fh[2 * i + 1], gh[2 * i], gh[2 * i + 1], gammas[i])
    return h


def schoolbook(a, b):
    c = np.convolve(np.array(a, dtype=np.int64), np.array(b, dtype=np.int64))
    out = c[:256].copy()
    out[: len(c) - 256] -= c[256:]
    return [int(x) % Q for x in out]


check("128^-1 mod q = 3303 (the scale factor in Algorithm 10)", 128 * 3303 % Q == 1)
rng = random.Random(3329)
ok_roundtrip = ok_mul = True
for _ in range(20):
    f = [rng.randrange(Q) for _ in range(256)]
    g = [rng.randrange(Q) for _ in range(256)]
    ok_roundtrip &= ntt_inv(ntt(f)) == f
    ok_mul &= ntt_inv(multiply_ntts(ntt(f), ntt(g))) == schoolbook(f, g)
check("NTT^-1(NTT(f)) = f for 20 random f", ok_roundtrip)
check("NTT^-1(MultiplyNTTs(NTT(f), NTT(g))) = f*g in Z_q[X]/(X^256+1) for 20 random pairs", ok_mul)
check("NTT output coordinate pair i equals f mod (X^2 - gamma_i) (eq. 4.12-4.13), checked for one f",
      all((ntt(f)[2 * i], ntt(f)[2 * i + 1]) ==
          (sum(f[2 * k] * pow(gammas[i], k, Q) for k in range(128)) % Q,
           sum(f[2 * k + 1] * pow(gammas[i], k, Q) for k in range(128)) % Q) for i in range(128)))

# ---------------------------------------------------------------- C. other dimensions / moduli
print()
print("=== C. How x^n + 1 splits mod prime q: n/d factors of degree d, d = ord(q mod 2n) ===")


def split_degree(q, n):
    return sympy.n_order(q % (2 * n), 2 * n)


print(f"{'q':>6} {'n':>5}  factors x degree   comment")
for q, n, note in [(3329, 256, "ML-KEM: 128 quadratics (incomplete NTT)"),
                   (3329, 128, "complete NTT would need n = 128"),
                   (3329, 512, "q = 3329 with n = 512"),
                   (3329, 1024, "q = 3329 with n = 1024"),
                   (12289, 1024, "NewHope1024: complete NTT"),
                   (12289, 512, "NewHope512"),
                   (7681, 256, "Kyber round-1 modulus (q = 1 mod 512)"),
                   (18433, 1024, "a prime = 1 mod 2048, for comparison")]:
    d = split_degree(q, n)
    print(f"{q:6d} {n:5d}  {n // d:4d} x {d:<3d}         {note}")
check("q = 3329, n = 256: 128 factors of degree 2 (matches FIPS 203)", split_degree(3329, 256) == 2)
small = [q for q in range(257, 3330, 256) if sympy.isprime(q)]
print(f"primes q = 1 mod 256 up to 3329: {small} (Kyber r3 spec Sec. 1.4: 'two smaller primes ... 257 and 769')")
check("the only primes q < 3329 with 256 | q - 1 are 257 and 769; 3329 is the next", small == [257, 769, 3329])
check("q = 12289, n = 1024: 1024 linear factors (12289 = 1 mod 2048, NewHope r2 spec Sec. 2)",
      split_degree(12289, 1024) == 1 and 12289 % 2048 == 1 and sympy.isprime(12289))
check("12289 is the smallest prime q with q = 1 mod 2048 (NewHope r2 spec: 'smallest prime ... q = 1 mod 2n')",
      next(q for q in range(2049, 20000, 2048) if sympy.isprime(q)) == 12289)
print("Power-of-two moduli (Saber 2^13, NTRU 2^11..2^13, FrodoKEM 2^15..2^16): Z_q is not a field and has no")
print("roots of unity of even order > 2 in the needed sense, so these schemes multiply with Toom-Cook/Karatsuba or,")
print("for FrodoKEM, plain matrix products. NTRU and NTRU Prime do not use x^n + 1 at all.")
check("x^8 + 1 = (x + 1)^8 mod 2: no splitting into distinct factors for any power-of-two modulus",
      sympy.Poly(sympy.symbols('x') ** 8 + 1, modulus=2) == sympy.Poly((sympy.symbols('x') + 1) ** 8, modulus=2))

# ---------------------------------------------------------------- D. NTRU Prime fields
print()
print("=== D. NTRU Prime: x^p - x - 1 is irreducible mod q (inert modulus: no NTT at all) ===")


def polymulmod(a, b, p, q):
    """(a*b) mod (x^p - x - 1, q); a, b int64 arrays of length p."""
    c = np.convolve(a, b) % q                # length 2p - 1; entries < q^2 * p fit in int64
    low, high = c[:p].copy(), c[p:]          # high holds coefficients of x^p .. x^(2p-2)
    low[: len(high)] += high                 # x^p = x + 1: high * 1
    low[1: len(high) + 1] += high            #             + high * x (degree <= p - 1)
    return low % q


def x_pow_q(f, p, q):
    """f^q mod (x^p - x - 1) by square-and-multiply."""
    result = np.zeros(p, dtype=np.int64)
    result[0] = 1
    base = f.copy()
    e = q
    while e:
        if e & 1:
            result = polymulmod(result, base, p, q)
        base = polymulmod(base, base, p, q)
        e >>= 1
    return result


for p, q, name in [(761, 4591, "sntrup761"), (1013, 7177, "sntrup1013")]:
    t0 = time.time()
    x = np.zeros(p, dtype=np.int64)
    x[1] = 1
    xq = x_pow_q(x, p, q)                    # x^q
    cur = xq.copy()
    for _ in range(p - 1):                   # x^(q^p) by applying the Frobenius p times
        cur = x_pow_q(cur, p, q)
    frob_ok = np.array_equal(cur, x)
    X = sympy.symbols('x')
    f_poly = sympy.Poly(X ** p - X - 1, X, modulus=q)
    g_poly = sympy.Poly(sum(int(c) * X ** i for i, c in enumerate(xq)) - X, X, modulus=q)
    gcd_ok = sympy.gcd(f_poly, g_poly).degree() == 0
    print(f"{name}: p = {p}, q = {q}: x^(q^p) = x mod f: {frob_ok}; gcd(x^q - x, f) = 1: {gcd_ok} "
          f"({time.time() - t0:.1f}s)")
    check(f"{name}: q = {q} and p = {p} are prime, and x^{p} - x - 1 is irreducible mod {q} (Rabin test)",
          sympy.isprime(p) and sympy.isprime(q) and frob_ok and gcd_ok)

# ---------------------------------------------------------------- E. attack lattice dimensions
print()
print("=== E. The lattice an attacker reduces (primal uSVP embedding, GSA condition, Kyber r3 eq. 9) ===")


def log_delta(b):
    return math.log(((math.pi * b) ** (1 / b)) * b / (2 * math.pi * math.e)) / (2 * (b - 1))


def primal_min_block(n_lwe, q, sigma, m_max):
    """Smallest b over m in [0, m_max] with sigma*sqrt(b) <= delta^(2b-d-1) q^(m/d), d = m + n_lwe + 1."""
    best = None
    for m in range(0, m_max + 1, 1):
        d = m + n_lwe + 1
        for b in range(50, d + 1):
            if b < 60 and best is not None and b >= best[0]:
                break
            lhs = math.log(sigma) + 0.5 * math.log(b)
            rhs = (2 * b - d - 1) * log_delta(b) + (m / d) * math.log(q)
            if lhs <= rhs:
                if best is None or b < best[0]:
                    best = (b, m, d)
                break
    return best


t0 = time.time()
b, m, d = primal_min_block(1024, 3329, 1.0, 1024)
print(f"Kyber1024 / ML-KEM-1024 key: n_LWE = k*n = 1024, sigma = 1 (CBD(2)), m <= (k+1)n - kn = 1024 samples used:")
print(f"   minimal block size b = {b} at m = {m}, lattice dimension d = m + kn + 1 = {d}; "
      f"0.292 b = {0.292 * b:.1f}, 0.265 b = {0.265 * b:.1f}  ({time.time()-t0:.1f}s)")
print("   Kyber r3 spec Table 4 (primal, core-SVP): d = 1885, b = 878, classical 256, quantum 232")
print("   (The official script simulates the BKZ profile including the unreduced q-vectors and scans b and m")
print("    on a grid; this pure-GSA version is a simplification, so agreement within ~1% is what to expect.)")
check("pure-GSA Kyber1024 primal: core-SVP 0.2925 b within 2 bits of 256 and d within 25 of 1885",
      abs(0.2925 * b - 256) <= 2 and abs(d - 1885) <= 25)
t0 = time.time()
b, m, d = primal_min_block(976, 2 ** 16, 2.3, 976 + 8)
cost = math.log2(math.sqrt(1.5)) * b + math.log2(b)
print(f"FrodoKEM-976: n_LWE = 976, sigma = 2.3, m <= n + 8 samples: b = {b} at m = {m}, d = {d}; "
      f"FrodoKEM cost model 0.2925 b + log2 b = {cost:.1f}  ({time.time()-t0:.1f}s)")
print("   FrodoKEM r3 spec Table 10: Frodo-976 primal classical 216.0 (their script adds log2 b to 0.2925 b)")
check("pure-GSA Frodo-976 primal: classical cost within 1 bit of Table 10's 216.0", abs(cost - 216.0) <= 1)

print()
print("Dimension summary (secret dimension vs attack-lattice dimension):")
rows = [
    ("ML-KEM-1024", "k*n = 4*256 = 1024", "1885 (Kyber r3 Table 4, core-SVP primal); 1918 refined"),
    ("ML-KEM-768", "3*256 = 768", "1419; 1467 refined"),
    ("FrodoKEM-976", "n = 976", "1969 (FrodoKEM r3 Table 11, refined estimate)"),
    ("NewHope1024", "n = 1024 (ring degree)", "not tabulated here"),
    ("ntruhps4096821", "n = 821 (ring degree)", "(n - 1) + m after projection (NTRU r3 Sec. 6.4.2); b = 612"),
    ("sntrup1013", "p = 1013 (ring degree)", "see NTRU Prime r3 spec Sec. 6"),
]
for r in rows:
    print(f"   {r[0]:16s} secret dim {r[1]:26s} attack lattice {r[2]}")

# ---------------------------------------------------------------- F. NTRU fatigue point
print()
print("=== F. NTRU fatigue point q ~ 0.004 n^2.484 (Ducas-van Woerden 2021) vs the q actually used ===")
for name, n, q in [("ntruhps2048509", 509, 2048), ("ntruhps2048677", 677, 2048),
                   ("ntruhrss701", 701, 8192), ("ntruhps4096821", 821, 4096)]:
    fat = 0.004 * n ** 2.484
    print(f"   {name:16s} n = {n}: fatigue q ~ {fat:9.0f}; scheme q = {q:5d}; ratio {fat / q:5.1f}; q/n = {q / n:.2f}")
check("all NTRU round-3 parameter sets sit at least 5x below the estimated fatigue point",
      all(0.004 * n ** 2.484 >= 5 * q for n, q in [(509, 2048), (677, 2048), (701, 8192), (821, 4096)]))
print("   (DvW21's estimate is for ternary NTRU; applying it to ntru-hrss's non-fixed-weight secrets or to")
print("    NTRU Prime is an extrapolation, not a claim of the paper.)")

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
