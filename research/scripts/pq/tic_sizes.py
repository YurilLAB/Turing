"""Sizes, page counts and secret-coefficient entropies that decide how a
lattice layer fits Turing's memory machinery (SecretBox, burn_stack, memscan).

Topic: turing-integration-constraints (prefix tic_). Inputs are parameters
read from primary sources (each cited next to it); everything printed is
derived from them here, and every derived size is compared with the size the
source itself prints, so a transcription error shows as MISMATCH.

  1. ML-KEM sizes from FIPS 203's formulas (Algorithms 19-21: ek is
     384k+32 bytes, dk 768k+96, ciphertext 32(d_u k + d_v)) against Table 3.
  2. X-Wing sizes (draft-connolly-cfrg-xwing-kem-11, section 5.1): ML-KEM-768
     plus 32 bytes of X25519 in the key and in the ciphertext.
  3. FrodoKEM sizes (standard proposal 2025-09-29, Tables A.1, A.2, A.5)
     from the layout pk = seedA || b, sk = s || pk || S^T || pkh,
     ct = c1 || c2 || salt, against Table A.5.
  4. Pages each secret takes in a SecretBox (one page-aligned allocation per
     secret; 4096-byte pages as in crates/turing/src/memory.rs l.149).
  5. Working-set sizes that bound stack use: an n x nbar matrix of 16-bit
     entries, FrodoKEM's n x n matrix A, ML-KEM's k x k matrix A-hat.
  6. Entropy per coefficient of the small secrets (ML-KEM CBD_eta, FIPS 203
     SamplePolyCBD; FrodoKEM's table sampler, proposal section 7.5 and Table
     A.4), and how many bytes of an int16 array memscan must match to see 64
     bits of entropy; plus the chance that an 8-byte fragment of s (four
     coefficients) is all zero, which zeroed memory matches everywhere.
  7. The three concrete hybrids of draft-irtf-cfrg-concrete-hybrid-kems-04
     (6 July 2026; sections 3.1 and 4.1-4.3): Nek and Nct recomputed as the
     ML-KEM size plus the group element size, and the KEM-ciphertext bytes
     one recipient stanza would carry for X-Wing, MLKEM1024-P384 and X-Wing
     plus a FrodoKEM component.

Deterministic; exits 1 on any MISMATCH.

Usage (from the repository root):
    timeout 60 python research/scripts/pq/tic_sizes.py
"""
import math
import sys
from fractions import Fraction

PAGE = 4096
BURN_BYTES = 32 * 1024  # crates/turing/src/memory.rs l.124
mismatches = 0


def check(label, computed, published):
    global mismatches
    ok = computed == published
    mismatches += not ok
    print(f"  {label:44} computed {computed:>9,}  published {published:>9,}  {'OK' if ok else 'MISMATCH'}")


def pages(nbytes):
    return -(-nbytes // PAGE)


print("1. ML-KEM sizes (FIPS 203 Algorithms 19-21 vs Table 3, PDF p.48)")
# Table 2 (PDF p.48): k, du, dv.  Table 3: ek, dk, ct, ss.
MLKEM = {"ML-KEM-512": (2, 10, 4, 800, 1632, 768), "ML-KEM-768": (3, 10, 4, 1184, 2400, 1088),
         "ML-KEM-1024": (4, 11, 5, 1568, 3168, 1568)}
for name, (k, du, dv, ek, dk, ct) in MLKEM.items():
    check(f"{name} encapsulation key 384k+32", 384 * k + 32, ek)
    check(f"{name} decapsulation key 768k+96", 768 * k + 96, dk)
    check(f"{name} ciphertext 32(du k + dv)", 32 * (du * k + dv), ct)

print("\n2. X-Wing sizes (draft-11 section 5.1: 32 / 1216 / 1120 / 32)")
check("X-Wing encapsulation key = ek768 + 32", 1184 + 32, 1216)
check("X-Wing ciphertext = ct768 + 32", 1088 + 32, 1120)

print("\n3. FrodoKEM sizes (proposal Tables A.1, A.2 -> A.5)")
# Table A.1: D, n, nbar, len_sec (bits); Table A.2: len_salt (bits); lenA = 128.
FRODO = {"FrodoKEM-640": (15, 640, 8, 128, 256, 19888, 9616, 9752, 16),
         "FrodoKEM-976": (16, 976, 8, 192, 384, 31296, 15632, 15792, 24),
         "FrodoKEM-1344": (16, 1344, 8, 256, 512, 43088, 21520, 21696, 32)}
for name, (D, n, nb, lsec, lsalt, sk, pk, ct, ss) in FRODO.items():
    pk_c = 128 // 8 + D * n * nb // 8
    sk_c = lsec // 8 + pk_c + 2 * n * nb + lsec // 8
    ct_c = D * nb * n // 8 + D * nb * nb // 8 + lsalt // 8
    check(f"{name} pk = seedA + D n nbar/8", pk_c, pk)
    check(f"{name} sk = s + pk + 2 n nbar + pkh", sk_c, sk)
    check(f"{name} ct = D nbar n/8 + D nbar^2/8 + salt", ct_c, ct)
    check(f"{name} shared secret = len_sec/8", lsec // 8, ss)

print("\n4. SecretBox pages per secret (4096-byte pages)")
for label, size in [("Turing round keys + checksum (26 x 16)", 26 * 16), ("Turing key / X-Wing seed (32)", 32),
                    ("ShieldedKey prekey (16 KB)", 16 * 1024), ("ML-KEM-768 dk (2400)", 2400),
                    ("ML-KEM-1024 dk (3168)", 3168), ("FrodoKEM-976 sk (31,296)", 31296),
                    ("FrodoKEM-1344 sk (43,088)", 43088)]:
    print(f"  {label:44} {size:>7,} bytes -> {pages(size):3} page(s)")

print(f"\n5. Working sets against the 32 KB stack burn (BURN_BYTES = {BURN_BYTES:,})")
for label, size in [("FrodoKEM-976 n x nbar int16 matrix (S^T, B')", 976 * 8 * 2),
                    ("FrodoKEM-1344 n x nbar int16 matrix", 1344 * 8 * 2),
                    ("FrodoKEM-976 full A (976 x 976 int16)", 976 * 976 * 2),
                    ("FrodoKEM-976 one row of A (976 int16)", 976 * 2),
                    ("ML-KEM-768 A-hat (3 x 3 x 256 int16)", 3 * 3 * 256 * 2),
                    ("ML-KEM-768 one polynomial vector (3 x 256 int16)", 3 * 256 * 2)]:
    print(f"  {label:48} {size:>9,} bytes = {size / BURN_BYTES:6.2f} x BURN_BYTES")


def entropy(dist):
    return -sum(float(p) * math.log2(float(p)) for p in dist.values() if p > 0)


def cbd(eta):
    # FIPS 203 SamplePolyCBD: sum of eta bits minus sum of eta bits.
    d = {}
    for a in range(2 ** eta):
        for b in range(2 ** eta):
            v = bin(a).count("1") - bin(b).count("1")
            d[v] = d.get(v, 0) + Fraction(1, 4 ** eta)
    return d


def frodo(table):
    # Proposal section 7.5: t = r >> 1 (15 bits); e = #{z < d : t > T(z)}; sign = r & 1.
    d = {}
    prev = -1
    for k, tk in enumerate(table):
        mass = Fraction(tk - prev, 2 ** 15)
        prev = tk
        if k == 0:
            d[0] = d.get(0, 0) + mass
        else:
            d[k] = d.get(k, 0) + mass / 2
            d[-k] = d.get(-k, 0) + mass / 2
    assert prev == 2 ** 15 - 1, "the last table entry must be 2^15 - 1"
    return d


print("\n6. Entropy of small secret coefficients, and what memscan must match")
T976 = [5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767]  # Table A.4
T1344 = [9142, 23462, 30338, 32361, 32725, 32765, 32767]  # Table A.4
for label, dist in [("ML-KEM CBD eta=2 (ML-KEM-768/1024 s, e)", cbd(2)), ("ML-KEM CBD eta=3 (ML-KEM-512 s, e)", cbd(3)),
                    ("FrodoKEM-976 chi", frodo(T976)), ("FrodoKEM-1344 chi", frodo(T1344))]:
    assert sum(dist.values()) == 1
    h = entropy(dist)
    coeffs = math.ceil(64 / h)
    p0 = float(dist[0])
    print(f"  {label:44} H = {h:5.3f} bits/coeff; P(0) = {p0:.4f}; P(8-byte fragment = 0) = {p0 ** 4:.4f};"
          f" >= 64 bits needs {coeffs} coeffs = {2 * coeffs} bytes as int16")
p0 = float(cbd(2)[0])
print(f"  ML-KEM-768 s has 3 x 256 = 768 coefficients = 192 aligned 8-byte fragments;"
      f" expected all-zero fragments {192 * p0 ** 4:.2f}")

print("\n7. Hybrid KEM sizes (draft-irtf-cfrg-concrete-hybrid-kems-04) and per-recipient header cost")
# Group sizes, draft section 3.1: Nelem P-256 = 65, P-384 = 97, Curve25519 = 32.
# Published hybrid constants, draft sections 4.1-4.3: (Nek, Nct).
NELEM = {"P-256": 65, "P-384": 97, "X25519": 32}
MLKEM_EK_CT = {"ML-KEM-768": (1184, 1088), "ML-KEM-1024": (1568, 1568)}  # FIPS 203 Table 3
HYBRIDS = [("MLKEM768-P256", "ML-KEM-768", "P-256", 1249, 1153),
           ("MLKEM768-X25519 (= X-Wing)", "ML-KEM-768", "X25519", 1216, 1120),
           ("MLKEM1024-P384", "ML-KEM-1024", "P-384", 1665, 1665)]
for name, pq, group, nek, nct in HYBRIDS:
    ek, ct = MLKEM_EK_CT[pq]
    check(f"{name} Nek = ek + Nelem", ek + NELEM[group], nek)
    check(f"{name} Nct = ct + Nelem", ct + NELEM[group], nct)
# Per-recipient KEM ciphertext bytes in a file header (the wrapped file key
# and any stanza framing come on top and are not counted here).
print("  KEM ciphertext bytes per recipient stanza:")
for label, size in [("X-Wing (draft-11)", 1120), ("MLKEM1024-P384", 1665),
                    ("X-Wing + FrodoKEM-976 (three components)", 1120 + 15792),
                    ("X-Wing + FrodoKEM-1344 (three components)", 1120 + 21696)]:
    print(f"    {label:46} {size:>7,} bytes")

print(f"\n{'all sizes match the sources' if mismatches == 0 else f'{mismatches} MISMATCH(ES)'}")
sys.exit(1 if mismatches else 0)
