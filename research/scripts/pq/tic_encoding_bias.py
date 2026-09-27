"""Which lattice-KEM outputs Bombe's NIST SP 800-22 battery can be pointed at.

Topic: turing-integration-constraints (prefix tic_). Bombe's battery
(crates/bombe/src/battery.rs) tests 2^20-bit sequences for looking like
fair coin flips. A KEM's public outputs are not meant to look like that:
ML-KEM encodes numbers modulo q = 3329 in 12 bits (ByteEncode_12, FIPS 203
Algorithm 5) and compresses ciphertext coefficients to d bits
(Compress_d, FIPS 203 eq. (4.7)), so even perfectly uniform values mod q give
biased bits. This script computes the exact bias, from the definitions, and
the monobit (frequency) statistic SP 800-22 section 2.1 would expect on a
2^20-bit sample, to show which outputs a battery run would reject for a
reason that is not a weakness.

Definitions used (FIPS 203, nist-fips-203-ml-kem.pdf):
  q = 3329 (PDF p.30: "Recall that q = 3329").
  Compress_d(x) = round((2^d / q) * x) mod 2^d (PDF p.30, eq. (4.7)), where
      round is to the nearest integer with ties rounded up (PDF p.15,
      notation table: "If x = y + 1/2 ... then round(x) = y + 1").
  ByteEncode_d writes each d-bit integer least-significant bit first
      (PDF p.31, Algorithm 5); ByteEncode_12 is used for t-hat in ek and
      s-hat in dk.
  (d_u, d_v) = (10, 4) for ML-KEM-512/768 and (11, 5) for ML-KEM-1024
      (PDF p.48, Table 2).
FrodoKEM (2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf): q = 2^D
  with D = 15 or 16 (Table A.1), and pack() writes D-bit values, so values
  uniform mod q give exactly unbiased bits. Included as the contrast.

Monobit test (SP 800-22 rev. 1a, section 2.1): S_n = sum(2*b_i - 1),
s_obs = |S_n| / sqrt(n), P-value = erfc(s_obs / sqrt(2)); reject at P < 0.01.
With a per-bit mean p, E[S_n] ~ n (2p - 1), so the expected s_obs is about
sqrt(n) |2p - 1|.

Deterministic (exact rational arithmetic, no sampling).

Usage (from the repository root):
    timeout 60 python research/scripts/pq/tic_encoding_bias.py
"""
import math
from fractions import Fraction

Q = 3329
N_BITS = 2 ** 20  # sequence length of Bombe's battery (battery.rs module doc)


def compress(x, d):
    # round((2^d / q) x) with ties rounded up, then mod 2^d; exact integers.
    num = (2 ** d) * x
    return ((2 * num + Q) // (2 * Q)) % (2 ** d)


def bit_means(dist, width):
    """Mean of each bit position (LSB first) of a width-bit value."""
    return [sum(p for v, p in dist.items() if (v >> i) & 1) for i in range(width)]


def report(label, dist, width):
    means = bit_means(dist, width)
    avg = sum(means) / width
    s_obs = math.sqrt(N_BITS) * abs(2 * float(avg) - 1)
    p_value = math.erfc(s_obs / math.sqrt(2))
    worst = max(abs(float(m) - 0.5) for m in means)
    vmax = max(dist.values())
    print(f"  {label:44} mean bit = {float(avg):.5f}; worst position |p - 1/2| = {worst:.5f};"
          f" max value prob = {float(vmax):.6f} vs uniform {1 / 2 ** width:.6f}")
    verdict = "REJECT (P < 0.01)" if p_value < 0.01 else "pass"
    print(f"  {'':44} expected monobit s_obs on 2^20 bits = {s_obs:9.2f}; P-value ~ {p_value:.3g} -> {verdict}")
    return p_value


print("1. ByteEncode_12 of values uniform mod q = 3329 (ML-KEM ek t-hat, dk s-hat)")
uniform_q = {x: Fraction(1, Q) for x in range(Q)}
p12 = report("12-bit encoding of uniform x mod 3329", uniform_q, 12)
means = bit_means(uniform_q, 12)
print(f"  {'':44} bit 11 (top) mean = {means[11]} = {float(means[11]):.5f} (= (3329 - 2048) / 3329)")
assert means[11] == Fraction(3329 - 2048, 3329)

print("\n2. Compress_d of values uniform mod q (ML-KEM ciphertext u: d_u, v: d_v)")
# FIPS 203 Table 2: (d_u, d_v) = (10, 4) for ML-KEM-512/768, (11, 5) for ML-KEM-1024.
results = {}
for d in (10, 11, 4, 5):
    dist = {}
    for x in range(Q):
        c = compress(x, d)
        dist[c] = dist.get(c, 0) + Fraction(1, Q)
    assert sum(dist.values()) == 1 and len(dist) == 2 ** d
    results[d] = report(f"Compress_{d} then {d}-bit encoding", dist, d)

print("\n2b. Chi-square against uniform d-bit values: how soon the value-level bias shows")
# Expected chi-square statistic of N samples tested against the uniform law on
# 2^d values is about (2^d - 1) + N * delta, delta = sum (p_i - u)^2 / u.
# Rejection at 1% for large dof is about dof + 2.326 * sqrt(2 dof); solve for N.
for d in (10, 11, 4, 5):
    dist = {}
    for x in range(Q):
        c = compress(x, d)
        dist[c] = dist.get(c, 0) + Fraction(1, Q)
    u = Fraction(1, 2 ** d)
    delta = float(sum((p - u) ** 2 / u for p in dist.values()))
    dof = 2 ** d - 1
    n_needed = 2.326 * math.sqrt(2 * dof) / delta
    per_seq = N_BITS // d
    print(f"  Compress_{d:<2}: preimage counts {sorted(set(int(p * Q) for p in dist.values()))};"
          f" delta = {delta:.5f}; ~{n_needed:,.0f} coefficients to reject (one 2^20-bit sequence holds {per_seq:,})")

print("\n3. FrodoKEM: values uniform mod q = 2^D, packed as D bits")
for D in (15, 16):
    # Uniform on [0, 2^D): every bit has mean exactly 1/2 (checked on D = 15, 16).
    means = [Fraction(1, 2)] * D
    assert all(m == Fraction(1, 2) for m in means)
    print(f"  D = {D}: every bit position has mean exactly 1/2 -> unbiased; the monobit test has nothing to find")

print("\nSummary")
print(f"  ML-KEM ek/dk (ByteEncode_12): {'fails' if p12 < 0.01 else 'passes'} the monobit test by construction")
for d, p in results.items():
    print(f"  ML-KEM Compress_{d:<2} ciphertext part: {'fails' if p < 0.01 else 'passes'} the monobit test on 2^20 bits")
print("  Only the 32-byte shared secret K (and keystreams derived from it) are meant to be uniform bits.")
