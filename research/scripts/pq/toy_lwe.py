"""Toy LWE: why the noise matters, Regev encryption, Lindner-Peikert encryption.

Reproduces, at toy size (q = 97, n = 3..16), the constructions and the q/4
decryption rule from:
  - Regev, "On lattices, learning with errors, random linear codes, and
    cryptography", J. ACM 2009, Section 5 (public-key cryptosystem, Lemma 5.1).
    File: research/papers/2009-regev-lattices-lwe-random-linear-codes-cryptography.pdf
  - Lindner, Peikert, "Better key sizes (and attacks) for LWE-based encryption",
    CT-RSA 2011, Section 3.1 (Gen/Enc/Dec, encode m*floor(q/2), decode with
    tolerance t = floor(q/4)), Lemma 3.1 (correctness).
    File: research/papers/2011-lindner-peikert-better-key-sizes-lwe.pdf

Error distribution: the centred binomial distribution CBD(eta) used by
ML-KEM (FIPS 203, Algorithm 8): sum of eta coin flips minus eta coin flips.

Everything is deterministic (fixed seeds). The script prints each check and
exits non-zero if an assertion fails. Toy parameters are NOT secure.

Run: python research/scripts/pq/toy_lwe.py
"""
import itertools
import random
import sys
from fractions import Fraction
from math import comb

Q = 97
HALF = Q // 2          # floor(q/2) = 48, the encoding of bit 1
TOL = Q // 4           # floor(q/4) = 24, the decoding tolerance t


def centred(x, q=Q):
    """Representative of x mod q in [-(q-1)/2, (q-1)/2] (q odd)."""
    x %= q
    return x - q if x > q // 2 else x


def cbd_sample(rng, eta):
    return sum(rng.getrandbits(1) for _ in range(eta)) - sum(rng.getrandbits(1) for _ in range(eta))


def cbd_dist(eta):
    """Exact CBD(eta) as {value: Fraction}. P(k) = C(2eta, eta+k) / 4^eta."""
    return {k: Fraction(comb(2 * eta, eta + k), 4 ** eta) for k in range(-eta, eta + 1)}


def convolve(d1, d2):
    out = {}
    for a, pa in d1.items():
        for b, pb in d2.items():
            out[a + b] = out.get(a + b, 0) + pa * pb
    return out


def product_dist(d1, d2):
    out = {}
    for a, pa in d1.items():
        for b, pb in d2.items():
            out[a * b] = out.get(a * b, 0) + pa * pb
    return out


def power_conv(d, k):
    out = {0: Fraction(1)}
    for _ in range(k):
        out = convolve(out, d)
    return out


def decode_bit(x):
    """Lindner-Peikert decode (LP11 Sec. 3.1): 0 if centred(x) in [-floor(q/4), floor(q/4)), else 1."""
    c = centred(x)
    return 0 if -TOL <= c < TOL else 1


def regev_decode_bit(x):
    """Regev 2009 Sec. 5 decode: 0 if x is closer to 0 than to floor(q/2) modulo q, else 1."""
    return 0 if abs(centred(x)) < abs(centred(x - HALF)) else 1


def exact_fail(noise, decoder):
    """Exact failure probability, averaged over bit 0 and bit 1, for a given noise distribution
    {integer noise value: probability} and decoder. Reduces mod q, so wrap-around is handled."""
    total = 0
    for bit in (0, 1):
        total += sum(p for v, p in noise.items() if decoder((v + bit * HALF) % Q) != bit)
    return total / 2


def solve_mod_q(A, b, q=Q):
    """Gaussian elimination mod prime q on the first n independent rows. Returns s or None."""
    n = len(A[0])
    rows = [list(r) + [bi] for r, bi in zip(A, b)]
    piv_rows = []
    for col in range(n):
        piv = next((r for r in rows if r not in piv_rows and r[col] % q != 0), None)
        if piv is None:
            return None
        inv = pow(piv[col], q - 2, q)
        for j in range(n + 1):
            piv[j] = piv[j] * inv % q
        for r in rows:
            if r is not piv and r[col] % q:
                f = r[col]
                for j in range(n + 1):
                    r[j] = (r[j] - f * piv[j]) % q
        piv_rows.append(piv)
    s = [0] * n
    for r in piv_rows:
        col = next(j for j in range(n) if r[j] == 1)
        s[col] = r[n]
    return s


failures = 0


def check(label, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures += 1


# ---------------------------------------------------------------------------
print("=== Part A: without noise LWE is linear algebra; with noise it is a search ===")
rng = random.Random(20260926)
n, m = 3, 12
s = [rng.randrange(Q) for _ in range(n)]
A = [[rng.randrange(Q) for _ in range(n)] for _ in range(m)]
b_clean = [sum(a * x for a, x in zip(row, s)) % Q for row in A]
e = [cbd_sample(rng, 1) for _ in range(m)]
b_noisy = [(bc + ei) % Q for bc, ei in zip(b_clean, e)]
print(f"secret s = {s}, errors e = {e}")
s_clean = solve_mod_q(A, b_clean)
s_noisy = solve_mod_q(A, b_noisy)
print(f"Gaussian elimination on b = As      -> {s_clean}")
print(f"Gaussian elimination on b = As + e  -> {s_noisy}")
check("noise-free system is solved exactly by elimination", s_clean == s)
check("the same elimination on the noisy system returns a wrong secret", s_noisy != s)
# Exhaustive search over all q^n = 97^3 = 912,673 secrets: pick the one with the smallest residuals.
best, second = None, None
for cand in itertools.product(range(Q), repeat=n):
    r = sum(abs(centred(bi - sum(a * x for a, x in zip(row, cand)))) for row, bi in zip(A, b_noisy))
    if best is None or r < best[0]:
        second, best = best, (r, list(cand))
    elif second is None or r < second[0]:
        second = (r, list(cand))
print(f"exhaustive search over {Q**n:,} candidates: best residual sum {best[0]} at {best[1]}, "
      f"runner-up {second[0]}")
check("exhaustive search (cost q^n) recovers s from the noisy system", best[1] == s)
print(f"cost of this search grows as q^n: n=3 -> {Q**3:.3g}, n=8 -> {Q**8:.3g}, n=976 -> 10^{976*2:.0f} (log10 97 = 1.99)")

# ---------------------------------------------------------------------------
print()
print("=== Part B: Regev encryption (J. ACM 2009, Section 5) at n=8, q=97, m=20 ===")
n, m = 8, 20
rng = random.Random(1)


def regev_keygen(rng, eta):
    s = [rng.randrange(Q) for _ in range(n)]
    pk = []
    for _ in range(m):
        a = [rng.randrange(Q) for _ in range(n)]
        pk.append((a, (sum(x * y for x, y in zip(a, s)) + cbd_sample(rng, eta)) % Q))
    return s, pk


def regev_enc(rng, pk, bit):
    S = [i for i in range(m) if rng.getrandbits(1)]
    a = [sum(pk[i][0][j] for i in S) % Q for j in range(n)]
    b = (sum(pk[i][1] for i in S) + bit * HALF) % Q
    return a, b


def regev_dec(s, ct):
    a, b = ct
    return regev_decode_bit(b - sum(x * y for x, y in zip(a, s)))


def regev_noise_dist(eta):
    """Exact distribution of sum_{i in S} e_i, S a uniform random subset of [m], e_i ~ CBD(eta)."""
    term = {k: p / 2 for k, p in cbd_dist(eta).items()}
    term[0] = term.get(0, 0) + Fraction(1, 2)
    return power_conv(term, m)


def fail_prob(noise):
    """Exact failure probability of the LP decoder (used in Parts C and D)."""
    return exact_fail(noise, decode_bit)


print("Why q/4: decrypting bit 0 sees noise v, bit 1 sees v + floor(q/2) = v + 48 (mod 97).")
ok0 = [v for v in range(-60, 61) if regev_decode_bit(v % Q) == 0]
ok1 = [v for v in range(-60, 61) if regev_decode_bit((v + HALF) % Q) == 1]
print(f"  Regev rule: bit 0 decodes correctly for noise v in [{min(ok0)}, {max(ok0)}]; "
      f"bit 1 for v in [{min(ok1)}, {max(ok1)}] (checked for |v| <= 60)")
check("Lemma 5.1 condition |noise| < floor(q/2)/2 = 24 suffices for both bits, and nothing beyond "
      "|noise| = 24 decodes correctly (for |v| <= 60): the window is q/4 on each side",
      set(range(-23, 24)) <= set(ok0) & set(ok1) and all(abs(v) <= 24 for v in ok0 + ok1))
for eta in (1, 2, 3, 4):
    noise = regev_noise_dist(eta)
    exact = exact_fail(noise, regev_decode_bit)
    s_key, pk = regev_keygen(rng, eta)
    trials, bad = 20000, 0
    for t in range(trials):
        bit = t & 1
        bad += regev_dec(s_key, regev_enc(rng, pk, bit)) != bit
    var = Fraction(eta, 2) * m / 2
    print(f"CBD eta={eta}: noise max |sum| = {m*eta:3d} vs tolerance {TOL}; variance = {float(var):5.1f}; "
          f"exact failure = {float(exact):.3e}; measured {bad}/{trials} = {bad/trials:.3e}")
    if eta == 1:
        check("eta=1: |noise| <= m*eta = 20 < q/4 = 24.25, so failure is impossible", exact == 0 and bad == 0)
    else:
        sd = (float(exact) * (1 - float(exact)) / trials) ** 0.5
        check(f"eta={eta}: measured failure rate within 5 sigma of the exact value", abs(bad / trials - float(exact)) <= 5 * sd + 1e-12)
check("failure probability rises with the noise width (eta 2 -> 3 -> 4)",
      exact_fail(regev_noise_dist(2), regev_decode_bit) < exact_fail(regev_noise_dist(3), regev_decode_bit)
      < exact_fail(regev_noise_dist(4), regev_decode_bit))

# ---------------------------------------------------------------------------
print()
print("=== Part C: Lindner-Peikert encryption (CT-RSA 2011, Section 3.1), n1 = n2 = n, one bit ===")
# Gen: P = R1 - Abar R2 ; Enc: c1 = e1^T Abar + e2^T, c2 = e1^T P + e3 + encode(m)
# Dec: c1 R2 + c2 = e1.R1 + e2.R2 + e3 + encode(m): the noise is <e, r>, a sum of 2n products plus one term.


def lp_noise_dist(nn, eta):
    prod = product_dist(cbd_dist(eta), cbd_dist(eta))
    return convolve(power_conv(prod, 2 * nn), cbd_dist(eta))


def lp_trial(rng, nn, eta, bit):
    Abar = [[rng.randrange(Q) for _ in range(nn)] for _ in range(nn)]
    R1 = [cbd_sample(rng, eta) for _ in range(nn)]
    R2 = [cbd_sample(rng, eta) for _ in range(nn)]
    P = [(R1[i] - sum(Abar[i][j] * R2[j] for j in range(nn))) % Q for i in range(nn)]
    e1 = [cbd_sample(rng, eta) for _ in range(nn)]
    e2 = [cbd_sample(rng, eta) for _ in range(nn)]
    e3 = cbd_sample(rng, eta)
    c1 = [(sum(e1[i] * Abar[i][j] for i in range(nn)) + e2[j]) % Q for j in range(nn)]
    c2 = (sum(e1[i] * P[i] for i in range(nn)) + e3 + bit * HALF) % Q
    v = (sum(c1[j] * R2[j] for j in range(nn)) + c2) % Q
    noise = sum(e1[i] * R1[i] for i in range(nn)) + sum(e2[j] * R2[j] for j in range(nn)) + e3
    assert centred(v - bit * HALF) == centred(noise), "decryption identity c1.R2 + c2 = <e,r> + encode(m) broken"
    return decode_bit(v)


rng = random.Random(2)
for nn, eta in ((8, 1), (16, 1), (16, 2), (32, 2)):
    exact = fail_prob(lp_noise_dist(nn, eta))
    trials = 6000
    bad = sum(lp_trial(rng, nn, eta, t & 1) != (t & 1) for t in range(trials))
    print(f"n={nn:2d} eta={eta}: max |noise| = {2*nn*eta*eta + eta:3d}; exact failure = {float(exact):.3e}; "
          f"measured {bad}/{trials}")
    if 2 * nn * eta * eta + eta < TOL:
        check(f"n={nn} eta={eta}: worst-case noise below q/4, failure impossible", exact == 0 and bad == 0)
    else:
        sd = (float(exact) * (1 - float(exact)) / trials) ** 0.5
        check(f"n={nn} eta={eta}: measured rate within 5 sigma of exact", abs(bad / trials - float(exact)) <= 5 * sd + 1e-12)
print("The decryption identity c1*R2 + c2 = <e, r> + encode(m) was asserted on every trial above.")

print()
print("=== Part D: watch decryption fail when the noise passes q/4 (n=64, eta=3, q=97) ===")
nn, eta = 64, 3
exact = fail_prob(lp_noise_dist(nn, eta))
rng = random.Random(3)
shown = 0
trials, bad = 3000, 0
for t in range(trials):
    bit = t & 1
    # repeat one trial with the noise exposed, to print a concrete failure
    st = rng.getstate()
    got = lp_trial(rng, nn, eta, bit)
    if got != bit:
        bad += 1
        if shown < 2:
            rng2 = random.Random()
            rng2.setstate(st)
            Abar = [[rng2.randrange(Q) for _ in range(nn)] for _ in range(nn)]
            R1 = [cbd_sample(rng2, eta) for _ in range(nn)]
            R2 = [cbd_sample(rng2, eta) for _ in range(nn)]
            e1 = [cbd_sample(rng2, eta) for _ in range(nn)]
            e2 = [cbd_sample(rng2, eta) for _ in range(nn)]
            e3 = cbd_sample(rng2, eta)
            noise = sum(a * b for a, b in zip(e1, R1)) + sum(a * b for a, b in zip(e2, R2)) + e3
            print(f"trial {t}: sent bit {bit}, noise <e,r> = {noise} (|noise| > {TOL}), decrypted {got}")
            shown += 1
print(f"exact failure probability = {float(exact):.4f}; measured {bad}/{trials} = {bad/trials:.4f}")
sd = (float(exact) * (1 - float(exact)) / trials) ** 0.5
check("n=64 eta=3: failures are frequent and match the exact noise distribution",
      bad > 0 and abs(bad / trials - float(exact)) <= 5 * sd)
print("Reading: at fixed q, a larger dimension n or a wider error both push the noise past q/4.")
print("Real schemes (ML-KEM, FrodoKEM) raise q and compute this failure probability exactly;")
print("see research/notes/pq/decryption-failures.md for that computation at real sizes.")

print()
print(f"{failures} check(s) failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
