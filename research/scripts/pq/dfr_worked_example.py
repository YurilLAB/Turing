"""dfr_worked_example.py - small worked examples for the decryption-failure notes.

Reproduces nothing published; it illustrates, with numbers small enough to check by hand, the
four ideas the notes explain (research/notes/pq/decryption-failures.md, sections 1, 2 and 4):

  1. The law of a product of two small random numbers, and of a sum of such products, is built
     exactly by convolution (checked against exhaustive enumeration with exact fractions).
  2. The failure probability of one coefficient is a tail sum of that law; a Gaussian with the
     same variance can be far off in either direction.
  3. The union bound turns a per-coefficient failure rate into a message failure rate.
  4. Failure boosting: an attacker who keeps only "heavy" ciphertext randomness raises the
     failure rate of each query, at the price of discarding most candidates.

Toy error:  e = a1*b1 + a2*b2 + a3*b3 + a4*b4 + c  with every a_i, b_i, c ~ CBD(2)
(CBD(2) = centred binomial with eta = 2, the law FIPS 203 uses for ML-KEM-768/1024 secrets).
In a real scheme a = secret key, b = encryption randomness, c = extra noise.

Deterministic (fixed seed). Runs in seconds. Usage: python dfr_worked_example.py
"""
import itertools
import math
import sys
from fractions import Fraction

import numpy as np

sys.stdout.reconfigure(encoding="utf-8")


def cbd(eta):
    return {k - eta: Fraction(math.comb(2 * eta, k), 4 ** eta) for k in range(2 * eta + 1)}


def product(A, B):
    out = {}
    for a, pa in A.items():
        for b, pb in B.items():
            out[a * b] = out.get(a * b, 0) + pa * pb
    return out


def conv(A, B):
    out = {}
    for a, pa in A.items():
        for b, pb in B.items():
            out[a + b] = out.get(a + b, 0) + pa * pb
    return out


def show(name, D):
    print(f"  {name}: " + ", ".join(f"{k}:{v}" for k, v in sorted(D.items())))


ok = True
X = cbd(2)
print("1. Building the law of the error exactly")
show("CBD(2)  P(x)", X)
XY = product(X, X)
show("a*b     P(x)", XY)
law = {0: Fraction(1)}
for _ in range(4):
    law = conv(law, XY)
law = conv(law, X)
var = sum(k * k * p for k, p in law.items())
print(f"  e = 4 products + 1 CBD(2): support {min(law)}..{max(law)}, total mass {sum(law.values())},"
      f" variance {var} (= 4*1*1 + 1)")

# exhaustive check: enumerate all 5^9 inputs with their probabilities
brute = {}
vals = list(X.items())
for combo in itertools.product(vals, repeat=9):
    xs = [c[0] for c in combo]
    p = Fraction(1)
    for c in combo:
        p *= c[1]
    z = xs[0] * xs[1] + xs[2] * xs[3] + xs[4] * xs[5] + xs[6] * xs[7] + xs[8]
    brute[z] = brute.get(z, 0) + p
same = brute == law
ok &= same
print(f"  [{'PASS' if same else 'FAIL'}] convolution law equals exhaustive enumeration of all "
      f"5^9 = {5 ** 9} inputs, exactly (fractions)")

print("\n2. Failure of one coefficient = tail probability; Gaussian comparison")
sd = math.sqrt(float(var))
for t in (6, 8, 10, 12):
    tail = sum(p for k, p in law.items() if abs(k) >= t)
    g = math.erfc((t - 0.5) / (sd * math.sqrt(2)))
    print(f"  P(|e| >= {t:2d}) exact = {float(tail):.3e} = 2^{math.log2(tail):6.2f};  Gaussian "
          f"(same variance {float(var)}) = 2^{math.log2(g):6.2f}")
rng = np.random.default_rng(1)
N = 2_000_000
s = lambda size: rng.integers(0, 2, size=(size, 2)).sum(1) - rng.integers(0, 2, size=(size, 2)).sum(1)
e = sum(s(N) * s(N) for _ in range(4)) + s(N)
emp = np.count_nonzero(np.abs(e) >= 8) / N
exact8 = float(sum(p for k, p in law.items() if abs(k) >= 8))
z = (emp - exact8) / math.sqrt(exact8 * (1 - exact8) / N)
good = abs(z) < 4
ok &= good
print(f"  [{'PASS' if good else 'FAIL'}] Monte Carlo, {N} samples: P(|e| >= 8) = {emp:.4e} vs exact "
      f"{exact8:.4e} (z = {z:+.2f})")

print("\n3. Union bound: a message of 8 such coefficients, threshold 10")
p = float(sum(p for k, p in law.items() if abs(k) >= 10))
print(f"  per coefficient p = {p:.3e}; union bound 8p = {8 * p:.3e}; if independent "
      f"1-(1-p)^8 = {1 - (1 - p) ** 8:.3e}. The bound needs no independence assumption.")

print("\n4. Failure boosting on the toy: attacker keeps only randomness b with large ||b||^2")
# condition on the squared norm of b = (b1..b4); the key a is unknown to the attacker
bdist = {}
for combo in itertools.product(vals, repeat=4):
    n2 = sum(c[0] ** 2 for c in combo)
    pr = math.prod(c[1] for c in combo)
    bdist.setdefault(n2, []).append((tuple(c[0] for c in combo), pr))
t = 10
print(f"  threshold |e| >= {t}; alpha = P(||b||^2 >= k) (fraction of candidates kept), "
      f"beta = failure rate of a kept query")
print("   k  log2(1/alpha)  log2(beta)  log2(work = 1/(alpha*beta))")
rows = []
for kmin in sorted(bdist):
    keep = [(b, pr) for k2, lst in bdist.items() if k2 >= kmin for (b, pr) in lst]
    alpha = sum(pr for _, pr in keep)
    beta_num = Fraction(0)
    for b, pr in keep:
        # law of sum_i a_i*b_i + c for this fixed b, a_i ~ CBD(2), c ~ CBD(2)
        L = {0: Fraction(1)}
        for bi in b:
            L = conv(L, {a * bi: pa for a, pa in X.items()} if bi else {0: Fraction(1)})
        L = conv(L, X)
        beta_num += pr * sum(q for k, q in L.items() if abs(k) >= t)
    beta = beta_num / alpha
    if beta > 0:
        rows.append((kmin, alpha, beta))
        print(f"  {kmin:2d} {math.log2(1 / alpha):14.2f} {math.log2(beta):11.2f} "
              f"{math.log2(1 / (alpha * beta)):14.2f}")
print("  Reading: selection never lowers total work 1/(alpha*beta) in this toy, but it lowers the")
print("  number of decryption QUERIES 1/beta. When queries are limited (NIST's call allows 2^64")
print("  decapsulation queries), boosting is what makes a failure reachable at all:")
for budget_bits in (10, 8, 6):
    fits = [r for r in rows if math.log2(1 / r[2]) <= budget_bits]
    if fits:
        b = min(fits, key=lambda r: 1 / (r[1] * r[2]))
        print(f"    query budget 2^{budget_bits}: keep ||b||^2 >= {b[0]}, queries "
              f"2^{math.log2(1 / b[2]):.2f}, offline work 2^{math.log2(1 / (b[1] * b[2])):.2f}")
    else:
        print(f"    query budget 2^{budget_bits}: no selection in this toy reaches it")
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
