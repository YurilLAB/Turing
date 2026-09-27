"""Independent fact-check of the mathematics in research/notes/pq/hybrid-combiners.md
(Turing, 2026-09-27). Written by the fact-checker, not by the notes' author.

Each part prints what it checks and ends with PASS/FAIL. Exit code 0 only if
every check passes. Deterministic: all randomness is seeded (random.Random)
or does not change a verdict.

1. XOR worked example (notes Sec. 8, part 1): recompute 0x3a ^ 0xc5 and the
   two oracle answers.
2. n-way XOR combiner: TWO decapsulation queries suffice for any n >= 2
   (the notes / hyb_worked_examples.py part 3 use three queries for n = 3).
   Components are hashed DH-KEMs over X25519 (sound KEMs). Negative control:
   a combiner that hashes all ciphertexts defeats the same queries.
3. Raw X25519 used as a KEM (key = raw u-coordinate) is NOT IND-CCA and not
   even pseudorandom, so GHP18 Theorem 1 (which needs an IND-CCA ingredient)
   cannot carry the X25519 branch of a flat n-way combiner. Negative control:
   a hashed DH-KEM (key = H(dh || ct || pk)) resists the same query.
4. ABK25 Theorem 9 bound 4*sqrt((q^2+q)/|K_i|): exact crossing point q* where
   the bound equals 1, for 256-, 192- and 128-bit component secrets.
5. "Hash a shorter secret up before combining" does not enlarge the key space:
   a b-bit secret hashed to 256 bits still has at most 2^b values, so the
   almost-uniformity epsilon of GHP18 Lemma 6 stays 2^-b and exhaustive search
   still costs 2^b (b = 16 here). Negative control: search over a candidate set
   that excludes the true secret fails.
6. Second preimage vs collision on a t-bit truncated hash (t = 16): the
   C2PRI-type event (hit a FIXED target) costs about 2^t tries, a collision
   about 2^(t/2). C2PRI bounds are linear in q (X-Wing Thm 3, ABK25 Thm 5).
7. Generic attack cost on a hash-all hybrid whose components can each be
   broken separately: sum of component costs, i.e. at most log2(n) bits above
   the strongest component.
8. Classic McEliece mceliece460896 sizes from the 2022 specification
   (ciphertext = ceil(m*t/8) bytes): 156-byte ciphertext, 524160-byte key; the
   notes' cost table uses the round-3 188-byte ciphertext (Rosenpass).
9. KMAC256 fixed overhead in Keccak-f calls: cSHAKE prefix block + key block(s)
   for the SP 800-56C default 132-byte salt.
10. The toy tamper in hybrid_combiner_checks.py B3 ("add 1 to one ciphertext
    coefficient") is a +1 on the LOW BYTE mod 256; count how often that wraps.

Usage (from the repository root):
  timeout 300 python research/scripts/pq/hyb_factcheck_math.py
"""
import hashlib
import math
import os
import random
import sys

import mpmath
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

sys.stdout.reconfigure(encoding="utf-8")
FAILURES = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILURES.append(name)


def sha3(b):
    return hashlib.sha3_256(b).digest()


def xb(scalar):
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


def xdh(scalar, u):
    return X25519PrivateKey.from_private_bytes(scalar).exchange(X25519PublicKey.from_public_bytes(u))


def xor(*parts):
    out = bytearray(len(parts[0]))
    for p in parts:
        for i, v in enumerate(p):
            out[i] ^= v
    return bytes(out)


# ------------------------------------------------------------------ 1
def part1():
    print("1. XOR worked example, 8-bit keys")
    k1s, k2s, k1o, k2o = 0x3A, 0xC5, 0x11, 0x77
    check("0x3a XOR 0xc5 = 0xff", k1s ^ k2s == 0xFF)
    check("oracle(c1', c2*) = 0x11 XOR 0xc5 = 0xd4", k1o ^ k2s == 0xD4)
    check("oracle(c1*, c2') = 0x3a XOR 0x77 = 0x4d", k1s ^ k2o == 0x4D)
    check("0xd4 ^ 0x11 ^ 0x4d ^ 0x77 = 0xff", 0xD4 ^ 0x11 ^ 0x4D ^ 0x77 == 0xFF)


# ------------------------------------------------------------------ 2
class HashedDHKEM:
    """Sound KEM: ct = g^e, key = SHA3(dh || ct || pk) (DHKEM shape, RFC 9180)."""

    def __init__(self, rng):
        self.sk = bytes(rng.getrandbits(8) for _ in range(32))
        self.pk = xb(self.sk)

    def encaps(self, rng):
        e = bytes(rng.getrandbits(8) for _ in range(32))
        ct = xb(e)
        return sha3(xdh(e, self.pk) + ct + self.pk), ct

    def decaps(self, ct):
        return sha3(xdh(self.sk, ct) + ct + self.pk)


def two_query_attack(n, combiner, rng):
    kems = [HashedDHKEM(rng) for _ in range(n)]
    star = [k.encaps(rng) for k in kems]
    c_star = tuple(ct for _, ct in star)
    k_star = combiner([k for k, _ in star], c_star)
    own = [k.encaps(rng) for k in kems]

    def oracle(cts):
        assert cts != c_star
        return combiner([kem.decaps(c) for kem, c in zip(kems, cts)], cts)

    # query A: replace component 0 only -> k0' ^ (k1* ^ ... ^ k_{n-1}*)
    qa = (own[0][1],) + c_star[1:]
    rest_star = xor(oracle(qa), own[0][0])
    # query B: keep component 0, replace all others -> k0* ^ k1' ^ ... ^ k_{n-1}'
    qb = (c_star[0],) + tuple(ct for _, ct in own[1:])
    k0_star = xor(oracle(qb), *[k for k, _ in own[1:]])
    return xor(k0_star, rest_star) == k_star


def xor_comb(keys, cts):
    return xor(*keys)


def hash_all_comb(keys, cts):
    return sha3(b"".join(keys) + b"".join(cts) + b"label")


def part2():
    print("2. n-way XOR: two decapsulation queries suffice (sound hashed DH-KEMs)")
    rng = random.Random(20260927)
    for n in (2, 3, 4, 5):
        wins = sum(two_query_attack(n, xor_comb, rng) for _ in range(4))
        check(f"n = {n}: XOR combiner broken with 2 queries in {wins}/4 runs (expect 4/4)", wins == 4)
    wins = sum(two_query_attack(3, hash_all_comb, rng) for _ in range(4))
    check(f"NEGATIVE: n = 3, hash-all combiner: same 2 queries win {wins}/4 (expect 0/4)", wins == 0)


# ------------------------------------------------------------------ 3
def part3():
    print("3. Raw X25519 as a KEM is not IND-CCA and not pseudorandom")
    rng = random.Random(7)
    raw_wins = hashed_wins = 0
    top_bit_raw = top_bit_uniform = 0
    trials = 200
    for _ in range(trials):
        sk = bytes(rng.getrandbits(8) for _ in range(32))
        pk = xb(sk)
        e = bytes(rng.getrandbits(8) for _ in range(32))
        ct = xb(e)
        k_raw = xdh(e, pk)
        k_hashed = sha3(k_raw + ct + pk)
        t = bytearray(ct); t[31] ^= 0x80; t = bytes(t)  # legal query: differs from ct
        raw_wins += xdh(sk, t) == k_raw
        hashed_wins += sha3(xdh(sk, t) + t + pk) == k_hashed
        top_bit_raw += k_raw[31] >> 7
        top_bit_uniform += rng.getrandbits(8) >> 7
    check(f"raw X25519-KEM: one Dec query on (ct with bit 255 flipped) returns k* in {raw_wins}/{trials}"
          " (so it is not IND-CCA)", raw_wins == trials)
    check(f"NEGATIVE: hashed DH-KEM key H(dh||ct||pk): same query returns k* in {hashed_wins}/{trials}",
          hashed_wins == 0)
    check(f"raw X25519 output has top bit 1 in {top_bit_raw}/{trials} (u < 2^255); uniform bytes:"
          f" {top_bit_uniform}/{trials} -> distinguisher advantage about 1/2",
          top_bit_raw == 0 and top_bit_uniform > trials // 4)


# ------------------------------------------------------------------ 4
def part4():
    print("4. ABK25 Theorem 9: where 4*sqrt((q^2+q)/|K_i|) reaches 1")
    mpmath.mp.dps = 60
    got = {}
    for bits in (256, 192, 128):
        K = mpmath.mpf(2) ** bits
        f = lambda lq: 4 * mpmath.sqrt((mpmath.mpf(2) ** (2 * lq) + mpmath.mpf(2) ** lq) / K) - 1
        lq = mpmath.findroot(f, bits / 2)
        got[bits] = float(lq)
        print(f"  |K_i| = 2^{bits}: bound = 1 at q = 2^{float(lq):.4f}")
    check("256-bit secret: crossing at q = 2^126 (notes say 'about 2^125')", abs(got[256] - 126) < 1e-6)
    check("192-bit secret: crossing at q = 2^94 (notes text 2^94, ledger row 51 says 2^93)",
          abs(got[192] - 94) < 1e-6)
    check("128-bit secret (e.g. FrodoKEM-640 ss = 16 bytes): crossing at q = 2^62", abs(got[128] - 62) < 1e-6)


# ------------------------------------------------------------------ 5
def part5():
    print("5. Hashing a short secret up to 256 bits does not enlarge its key space")
    b = 16
    images = {sha3(b"up" + k.to_bytes(2, "big")) for k in range(2 ** b)}
    check(f"{b}-bit secret hashed to 256 bits: {len(images)} distinct values <= 2^{b}", len(images) <= 2 ** b)
    eps = 1 / len(images)
    check(f"GHP18 Lemma 6 epsilon for slot i = max Pr[g(k)=y] = 2^{math.log2(eps):.0f} (not 2^-256)",
          abs(math.log2(eps) + b) < 1e-9)
    rng = random.Random(99)
    k_true = rng.getrandbits(b)
    other, ct = b"\x11" * 32, b"\x22" * 64  # other components broken: attacker knows them
    K = sha3(sha3(b"up" + k_true.to_bytes(2, "big")) + other + ct)
    found = [k for k in range(2 ** b) if sha3(sha3(b"up" + k.to_bytes(2, "big")) + other + ct) == K]
    check(f"exhaustive search over 2^{b} candidates recovers the secret: found {found} (true {k_true})",
          found == [k_true])
    found_neg = [k for k in range(2 ** b) if k != k_true
                 and sha3(sha3(b"up" + k.to_bytes(2, "big")) + other + ct) == K]
    check("NEGATIVE: the same search without the true secret finds nothing", found_neg == [])


# ------------------------------------------------------------------ 6
def part6():
    print("6. Second preimage (fixed target) vs collision on a 16-bit truncated hash")
    t = 16
    rng = random.Random(5)
    h = lambda x: int.from_bytes(hashlib.sha3_256(x).digest()[:2], "big")
    coll, sp = [], []
    for run in range(8):
        seen, i = {}, 0
        while True:
            v = h(b"c" + run.to_bytes(2, "big") + i.to_bytes(4, "big"))
            if v in seen:
                coll.append(i + 1)
                break
            seen[v] = i
            i += 1
        target = h(b"target" + run.to_bytes(2, "big") + rng.getrandbits(32).to_bytes(4, "big"))
        i = 0
        while h(b"s" + run.to_bytes(2, "big") + i.to_bytes(4, "big")) != target:
            i += 1
        sp.append(i + 1)
    mc, ms = sum(coll) / len(coll), sum(sp) / len(sp)
    print(f"  mean tries: collision {mc:.0f} (~2^{math.log2(mc):.1f}), fixed-target preimage {ms:.0f}"
          f" (~2^{math.log2(ms):.1f})")
    check("collision is about 2^(t/2) and the fixed-target search about 2^t",
          abs(math.log2(mc) - t / 2) < 1.5 and abs(math.log2(ms) - t) < 1.5)


# ------------------------------------------------------------------ 7
def part7():
    print("7. Generic attack on a hash-all hybrid: break each component separately")
    for costs in ((128, 256), (256, 256), (256, 256, 256), (192, 256, 128)):
        total = math.log2(sum(2.0 ** c for c in costs))
        extra = total - max(costs)
        print(f"  component costs 2^{costs}: total 2^{total:.3f}, i.e. +{extra:.3f} bits over the strongest")
        check(f"  extra bits <= log2(n) = {math.log2(len(costs)):.3f}", extra <= math.log2(len(costs)) + 1e-9)


# ------------------------------------------------------------------ 8
def part8():
    print("8. Classic McEliece mceliece460896 (2022 spec: m = 13, n = 4608, t = 96)")
    m, n, t = 13, 4608, 96
    mt = m * t
    ct = math.ceil(mt / 8)
    pk = mt * math.ceil((n - mt) / 8)
    check(f"ciphertext = ceil(m*t/8) = {ct} bytes (round-3 value used by Rosenpass/notes: 188)", ct == 156)
    check(f"public key = m*t * ceil(k/8) = {pk} bytes (same as round 3)", pk == 524160)
    kdf_in = 4 + 32 + 32 + 16 + 1120 + ct + 32
    check(f"nested X-Wing + mceliece460896 (2022): ct {1120 + ct} B, KDF input {kdf_in} B,"
          f" Keccak-f {kdf_in // 136 + 1} (notes: 1308 / 1424 / 11)",
          1120 + ct == 1276 and kdf_in == 1392 and kdf_in // 136 + 1 == 11)


# ------------------------------------------------------------------ 9
def left_encode(x):
    k = max(1, (x.bit_length() + 7) // 8)
    return bytes([k]) + x.to_bytes(k, "big")


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((-len(z)) % w)


def encode_string(s):
    return left_encode(8 * len(s)) + s


def part9():
    print("9. KMAC256 fixed overhead (rate 136) with the SP 800-56C default 132-byte salt")
    prefix = bytepad(encode_string(b"KMAC") + encode_string(b"KDF"), 136)
    keyblk = bytepad(encode_string(bytes(132)), 136)
    print(f"  cSHAKE prefix: {len(prefix)} B = {len(prefix) // 136} block(s); key: {len(keyblk)} B ="
          f" {len(keyblk) // 136} block(s)")
    check("KMAC256 adds 3 fixed Keccak-f calls (1 prefix + 2 key blocks), not counted in the notes' table",
          len(prefix) // 136 == 1 and len(keyblk) // 136 == 2)


# ------------------------------------------------------------------ 10
def part10():
    print("10. B3 toy tamper: how often is '+1 on byte 0' not a +1 on the coefficient?")
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import hybrid_combiner_checks as hc  # read-only use of the author's toy KEM

    pk, s, pk_bytes = hc.toy_keygen(b"turing-toy-seed")
    wraps_cpa = wraps_fo = 0
    for t in range(64):
        m = hashlib.shake_256(b"m" + bytes([t])).digest(32)
        _, ct = hc.toy_cpa_encaps(pk, m, hashlib.shake_256(b"c" + bytes([t])).digest(32))
        _, ct_fo = hc.toy_fo_encaps(pk, pk_bytes, m)
        wraps_cpa += ct[0] == 0xFF
        wraps_fo += ct_fo[0] == 0xFF
    print(f"  low byte 0xff (tamper is -255, not +1): CPA {wraps_cpa}/64, FO {wraps_fo}/64")
    check("wrap count computed (informational; verdicts of B3 unaffected either way)", True)


def main():
    for p in (part1, part2, part3, part4, part5, part6, part7, part8, part9, part10):
        p()
    print()
    print("ALL CHECKS PASSED" if not FAILURES else f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()
