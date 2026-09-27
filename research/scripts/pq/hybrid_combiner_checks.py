"""Checks behind research/notes/pq/hybrid-combiners.md (Turing, 2026-09-26).

What each part reproduces, and from which source:

A. X-Wing, draft-connolly-cfrg-xwing-kem-11 (23 Sept 2026), Sections 5.2-5.5
   and the Appendix C test vectors: key generation, decapsulation, and the
   X25519 half of derandomised encapsulation, recomputed with pyca/cryptography
   (FIPS 203 ML-KEM-768, RFC 7748 X25519) and hashlib (SHA3-256, SHAKE256).
   Negative controls: the label-first ordering printed in the 2024 paper
   (Barbosa et al., IACR CiC 1(1), Fig. 12) must NOT match the draft vectors,
   and tampered ciphertexts must change the key.

B. Why a combiner must hash ciphertexts (executable forms of published attacks):
   B1 Bindel et al., PQCrypto 2019 (ePrint 2018/903), Sec. 3.1 p. 11: the XOR
      combiner is broken by "mix-and-match" decapsulation queries even when
      both components are sound (here: real ML-KEM-768 and real X25519).
   B2 X-Wing paper Sec. 2 p. 4: "X25519, if seen as a KEM, is not ciphertext
      second preimage resistant". RFC 7748 masks bit 255 of a u-coordinate,
      so flipping it gives a second ciphertext with the same shared secret;
      a combiner that omits ct_X is then broken with one query.
   B3 A toy LWE KEM without the Fujisaki-Okamoto re-encryption check is not
      C2PRI (a +1 on one ciphertext coefficient decodes to the same key); the
      same toy with FO re-encryption and implicit rejection is. This is the
      reason the draft says the X-Wing shortcut "cannot be assumed to be
      secure, when used with different KEMs" (Sec. 6).

C. Sizes and hashing cost of 2- and 3-component hybrids. Sizes from FIPS 203
   Table 3, the X-Wing draft Sec. 5.1, FrodoKEM preliminary standardization
   proposal (2025-09-29) Table A.5, and the Rosenpass whitepaper Sec. 2.1.4
   (Classic McEliece 460896, round-3 version).

D. Numerical value of Alagic-Bajaj-Kocoglu (ePrint 2025/1444) Theorem 9: the
   split-key PRF advantage of H(k1||...||kn||x) against q quantum queries is
   at most 4*sqrt((q^2+q)/|K_i|). Also GHP18 Lemma 6 (classical ROM): qH*eps.

E. KMAC256 (NIST SP 800-185) from a pure-Python Keccak-f[1600], checked
   against hashlib SHA3-256/SHAKE256 and against the NIST cSHAKE and KMAC
   example values (PDFs in research/papers/). Then an illustrative SP 800-56C
   Rev. 2 one-step KDF (Option 3, KMAC256, Sec. 4.1) used as a 3-component
   combiner, with checks that every input byte matters and that fixed-length
   fields make the encoding injective, and a counter-example for
   variable-length concatenation (SP 800-227 Sec. 4.6.2, "Concatenation of
   inputs").

Usage (from the repository root):
  python research/scripts/pq/hybrid_combiner_checks.py XWING_DRAFT_TXT

XWING_DRAFT_TXT is the plain-text draft, fetched with
  curl -L --max-time 60 -o draft-connolly-cfrg-xwing-kem-11.txt \
    https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt
A copy is kept at research/papers/ietf-draft-connolly-cfrg-xwing-kem-11.txt
(byte-identical to the ietf.org archive on 2026-09-27).
All randomness is either fixed (seeds) or does not affect the printed
verdicts, so the script is deterministic in what it checks. Exit code 0 only
if every check passes.
"""
import hashlib
import math
import os
import re
import sys

import numpy as np
import pypdf
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
PAPERS = os.path.normpath(os.path.join(HERE, "..", "..", "papers"))

FAILURES = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILURES.append(name)


def sha3_256(b):
    return hashlib.sha3_256(b).digest()


def x25519(scalar, u):
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(u)
    )


def x25519_base(scalar):
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # draft Sec. 5.3: "\.//^\"


# ---------------------------------------------------------------- Part A
def parse_xwing_vectors(path):
    text = open(path, encoding="utf-8").read()
    start = text.rindex("Appendix C.  Test vectors")  # skip the table of contents
    end = text.index("Appendix D.", start)
    vectors, cur, field = [], None, None
    for line in text[start:end].splitlines():
        m = re.match(r"^(seed|sk|pk|eseed|ct|ss)\b\s*([0-9a-f]*)\s*$", line)
        if m:
            field = m.group(1)
            if field == "seed":
                cur = {}
                vectors.append(cur)
            cur[field] = m.group(2)
            continue
        m = re.match(r"^\s+([0-9a-f]+)\s*$", line)
        if m and cur is not None and field is not None:
            cur[field] += m.group(1)
    return [{k: bytes.fromhex(v) for k, v in vec.items()} for vec in vectors]


def xwing_expand(sk):
    expanded = hashlib.shake_256(sk).digest(96)
    mk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
    sk_x = expanded[64:96]
    return mk, mk.public_key().public_bytes_raw(), sk_x, x25519_base(sk_x)


def xwing_decaps(sk, ct, label_first=False):
    mk, pk_m, sk_x, pk_x = xwing_expand(sk)
    ct_m, ct_x = ct[0:1088], ct[1088:1120]
    ss_m = mk.decapsulate(ct_m)
    ss_x = x25519(sk_x, ct_x)
    if label_first:  # paper, Fig. 12
        return sha3_256(XWING_LABEL + ss_m + ss_x + ct_x + pk_x)
    return sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)  # draft Sec. 5.3


def part_a(draft_path):
    print("A. X-Wing draft-11 test vectors (Appendix C)")
    vecs = parse_xwing_vectors(draft_path)
    print(f"  parsed {len(vecs)} vectors")
    check("at least one vector parsed", len(vecs) >= 1)
    for i, v in enumerate(vecs):
        lens = {k: len(x) for k, x in v.items()}
        check(
            f"vector {i}: lengths sk=32 pk=1216 eseed=64 ct=1120 ss=32 ({lens})",
            lens.get("sk") == 32 and lens.get("pk") == 1216 and lens.get("eseed") == 64
            and lens.get("ct") == 1120 and lens.get("ss") == 32,
        )
        mk, pk_m, sk_x, pk_x = xwing_expand(v["sk"])
        check(f"vector {i}: GenerateKeyPairDerand(sk) reproduces pk", pk_m + pk_x == v["pk"])
        ct_x = x25519_base(v["eseed"][32:64])
        check(f"vector {i}: ct_X = X25519(eseed[32:64], base) matches ct[1088:1120]",
              ct_x == v["ct"][1088:1120])
        check(f"vector {i}: Decapsulate(ct, sk) reproduces ss", xwing_decaps(v["sk"], v["ct"]) == v["ss"])
        check(f"vector {i}: NEGATIVE: paper's label-first order does not reproduce ss",
              xwing_decaps(v["sk"], v["ct"], label_first=True) != v["ss"])
        t = bytearray(v["ct"]); t[100] ^= 1
        check(f"vector {i}: NEGATIVE: one flipped ML-KEM ciphertext bit changes ss",
              xwing_decaps(v["sk"], bytes(t)) != v["ss"])
        t = bytearray(v["ct"]); t[1119] ^= 0x80
        ss_x_orig = x25519(sk_x, v["ct"][1088:1120])
        ss_x_flip = x25519(sk_x, bytes(t[1088:1120]))
        check(f"vector {i}: X25519 ignores bit 255 of ct_X (RFC 7748 masking): same ss_X",
              ss_x_orig == ss_x_flip)
        check(f"vector {i}: ...but X-Wing hashes ct_X, so ss changes",
              xwing_decaps(v["sk"], bytes(t)) != v["ss"])


# ---------------------------------------------------------------- Part B
class HybridMLKEMX25519:
    """ML-KEM-768 + X25519 (as a KEM: ct = ephemeral u, ss = raw X25519 output)
    with a pluggable combiner. The decapsulation oracle refuses only the exact
    challenge ciphertext, as in the IND-CCA game (GHP18 Fig. 2)."""

    def __init__(self, combiner):
        self.combiner = combiner
        self.mk = mlkem.MLKEM768PrivateKey.generate()
        self.pk_m = self.mk.public_key()
        self.sk_x = os.urandom(32)
        self.pk_x = x25519_base(self.sk_x)
        self.challenge = None

    def encaps(self):
        ss_m, ct_m = self.pk_m.encapsulate()
        e = os.urandom(32)
        ct_x, ss_x = x25519_base(e), x25519(e, self.pk_x)
        ct = ct_m + ct_x
        return self.combiner(ss_m, ss_x, ct_m, ct_x, self.pk_m.public_bytes_raw(), self.pk_x), ct

    def decaps_oracle(self, ct):
        assert ct != self.challenge, "oracle refuses the challenge ciphertext"
        ct_m, ct_x = ct[:1088], ct[1088:]
        ss_m = self.mk.decapsulate(ct_m)
        ss_x = x25519(self.sk_x, ct_x)
        return self.combiner(ss_m, ss_x, ct_m, ct_x, self.pk_m.public_bytes_raw(), self.pk_x)


def xor_combiner(ss_m, ss_x, ct_m, ct_x, pk_m, pk_x):
    return bytes(a ^ b for a, b in zip(ss_m, ss_x))


def pedestrian_combiner(ss_m, ss_x, ct_m, ct_x, pk_m, pk_x):
    return sha3_256(ss_m + ss_x + XWING_LABEL)  # no ciphertexts, no keys


def xwing_combiner(ss_m, ss_x, ct_m, ct_x, pk_m, pk_x):
    return sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)


def universal_combiner(ss_m, ss_x, ct_m, ct_x, pk_m, pk_x):
    # draft-irtf-cfrg-hybrid-kems-12 Sec. 5.1.3 UniversalCombiner layout
    return sha3_256(ss_m + ss_x + ct_m + ct_x + pk_m + pk_x + b"toy-UG-label")


def mix_and_match_attack(h):
    """Bindel et al. 2019 p. 11: recover k1* and k2* from two decapsulation
    queries on (c1*, fresh c2) and (fresh c1, c2*), then output k1* XOR k2*."""
    k_star, c_star = h.encaps()
    h.challenge = c_star
    ss_m_fresh, ct_m_fresh = h.pk_m.encapsulate()
    e = os.urandom(32)
    ct_x_fresh, ss_x_fresh = x25519_base(e), x25519(e, h.pk_x)
    r1 = h.decaps_oracle(ct_m_fresh + c_star[1088:])  # = ss_m_fresh ^ ss_x*
    r2 = h.decaps_oracle(c_star[:1088] + ct_x_fresh)  # = ss_m* ^ ss_x_fresh
    ss_x_star = bytes(a ^ b for a, b in zip(r1, ss_m_fresh))
    ss_m_star = bytes(a ^ b for a, b in zip(r2, ss_x_fresh))
    guess = bytes(a ^ b for a, b in zip(ss_m_star, ss_x_star))
    return guess == k_star


def msb_flip_attack(h):
    """One query on (ct_M*, ct_X* with bit 255 flipped): legal (differs from the
    challenge) and, if the combiner ignores ct_X, returns the challenge key."""
    k_star, c_star = h.encaps()
    h.challenge = c_star
    t = bytearray(c_star); t[-1] ^= 0x80
    return h.decaps_oracle(bytes(t)) == k_star


# Toy LWE KEM (NOT SECURE: tiny parameters, for the C2PRI demonstration only)
TQ, TN, TL = 3329, 64, 256  # modulus, dimension, message bits


def _ternary(seed, label, count):
    raw = hashlib.shake_256(label + seed).digest(count)
    return np.frombuffer(raw, dtype=np.uint8).astype(np.int64) % 3 - 1


def toy_keygen(seed):
    raw = hashlib.shake_256(b"A" + seed).digest(2 * TN * TN)
    a = (np.frombuffer(raw, dtype="<u2").astype(np.int64) % TQ).reshape(TN, TN)
    s = _ternary(seed, b"S", TN * TL).reshape(TN, TL)
    e = _ternary(seed, b"E", TN * TL).reshape(TN, TL)
    b = (a @ s + e) % TQ
    pk = (a, b)
    pk_bytes = a.astype("<u2").tobytes() + b.astype("<u2").tobytes()
    return pk, s, pk_bytes


def toy_enc(pk, m_bits, coins):
    a, b = pk
    r = _ternary(coins, b"r", TN)
    e1 = _ternary(coins, b"e1", TN)
    e2 = _ternary(coins, b"e2", TL)
    u = (r @ a + e1) % TQ
    v = (r @ b + e2 + m_bits * (TQ // 2)) % TQ
    return u.astype("<u2").tobytes() + v.astype("<u2").tobytes()


def toy_dec(s, ct):
    arr = np.frombuffer(ct, dtype="<u2").astype(np.int64)
    u, v = arr[:TN], arr[TN:]
    d = (v - u @ s) % TQ
    return ((d > TQ // 4) & (d < 3 * TQ // 4)).astype(np.int64)


def bits(m):
    return np.unpackbits(np.frombuffer(m, dtype=np.uint8)).astype(np.int64)


def toy_cpa_encaps(pk, m, coins):
    return sha3_256(m), toy_enc(pk, bits(m), coins)


def toy_cpa_decaps(s, ct):
    return sha3_256(np.packbits(toy_dec(s, ct).astype(np.uint8)).tobytes())


def toy_fo_encaps(pk, pk_bytes, m):
    g = hashlib.sha3_512(m + sha3_256(pk_bytes)).digest()
    return g[:32], toy_enc(pk, bits(m), g[32:])


def toy_fo_decaps(pk, pk_bytes, s, z, ct):
    m2 = np.packbits(toy_dec(s, ct).astype(np.uint8)).tobytes()
    g = hashlib.sha3_512(m2 + sha3_256(pk_bytes)).digest()
    if toy_enc(pk, bits(m2), g[32:]) == ct:
        return g[:32]
    return sha3_256(z + ct)  # implicit rejection, as in FIPS 203 Alg. 18


def part_b():
    print("B1. XOR combiner vs mix-and-match (Bindel et al. 2019, p. 11)")
    wins = sum(mix_and_match_attack(HybridMLKEMX25519(xor_combiner)) for _ in range(5))
    check(f"XOR combiner: challenge key recovered in {wins}/5 runs (expect 5/5)", wins == 5)
    wins = sum(mix_and_match_attack(HybridMLKEMX25519(universal_combiner)) for _ in range(5))
    check(f"UniversalCombiner: same attack succeeds in {wins}/5 runs (expect 0/5)", wins == 0)

    print("B2. Omitting ct_X: X25519 is not C2PRI (X-Wing paper p. 4)")
    wins = sum(msb_flip_attack(HybridMLKEMX25519(pedestrian_combiner)) for _ in range(5))
    check(f"SHA3(ss_M||ss_X) combiner: one query wins {wins}/5 (expect 5/5)", wins == 5)
    wins = sum(msb_flip_attack(HybridMLKEMX25519(xwing_combiner)) for _ in range(5))
    check(f"X-Wing combiner (hashes ct_X, pk_X): wins {wins}/5 (expect 0/5)", wins == 0)

    print("B3. Toy LWE KEM (n=64, q=3329): C2PRI with and without FO re-encryption")
    pk, s, pk_bytes = toy_keygen(b"turing-toy-seed")
    z = hashlib.shake_256(b"z" + b"turing-toy-seed").digest(32)
    cpa_second_preimages = fo_second_preimages = trials = 0
    for t in range(64):
        m = hashlib.shake_256(b"m" + bytes([t])).digest(32)
        k, ct = toy_cpa_encaps(pk, m, hashlib.shake_256(b"c" + bytes([t])).digest(32))
        check_ok = toy_cpa_decaps(s, ct) == k
        k_fo, ct_fo = toy_fo_encaps(pk, pk_bytes, m)
        check_ok &= toy_fo_decaps(pk, pk_bytes, s, z, ct_fo) == k_fo
        if not check_ok:
            check(f"toy KEM correctness at trial {t}", False)
            continue
        trials += 1
        tampered = bytearray(ct); tampered[0] = (tampered[0] + 1) % 256  # u[0] += 1
        cpa_second_preimages += toy_cpa_decaps(s, bytes(tampered)) == k
        tampered = bytearray(ct_fo); tampered[0] = (tampered[0] + 1) % 256
        fo_second_preimages += toy_fo_decaps(pk, pk_bytes, s, z, bytes(tampered)) == k_fo
    check(f"toy KEMs decapsulate correctly in {trials}/64 trials", trials == 64)
    check(f"CPA toy (K = H(m)): tampered ct gives the same key in {cpa_second_preimages}/64"
          " (not C2PRI)", cpa_second_preimages == 64)
    check(f"FO toy (re-encrypt + implicit rejection): {fo_second_preimages}/64 (C2PRI holds)",
          fo_second_preimages == 0)


# ---------------------------------------------------------------- Part C
SIZES = {  # name: (public key, ciphertext, shared secret) in bytes, source
    "X25519": (32, 32, 32, "RFC 7748 / X-Wing draft Sec. 5.3 (32-byte strings)"),
    "ML-KEM-768": (1184, 1088, 32, "FIPS 203 Table 3"),
    "ML-KEM-1024": (1568, 1568, 32, "FIPS 203 Table 3"),
    "X-Wing": (1216, 1120, 32, "draft-connolly-cfrg-xwing-kem-11 Sec. 5.1"),
    "FrodoKEM-976": (15632, 15792, 24, "FrodoKEM proposal 2025-09-29 Table A.5"),
    "McEliece-460896 (r3)": (524160, 188, 32, "Rosenpass whitepaper Sec. 2.1.4 (ss: all Rosenpass keys 32 B, Sec. 2.1)"),
}
RATE = 136  # SHA3-256 / SHAKE256 / KMAC256 rate in bytes


def keccak_calls(nbytes):
    return nbytes // RATE + 1  # pad10*1 always adds at least one bit


def part_c():
    print("C. Sizes and combiner hashing cost")
    x, m7, m10, xw, fr, mc = (SIZES[k] for k in ["X25519", "ML-KEM-768", "ML-KEM-1024",
                                                 "X-Wing", "FrodoKEM-976", "McEliece-460896 (r3)"])
    check("X-Wing pk = ML-KEM-768 pk + X25519 pk (1184 + 32 = 1216)", m7[0] + x[0] == xw[0])
    check("X-Wing ct = ML-KEM-768 ct + X25519 ct (1088 + 32 = 1120)", m7[1] + x[1] == xw[1])
    xwing_in = 32 + 32 + 32 + 32 + 6
    check("X-Wing combiner input = 134 bytes (paper Sec. 8)", xwing_in == 134)
    hash_ct = xwing_in + m7[1]
    check("X-Wing-Hash-CT input = 1222 bytes (paper Sec. 8)", hash_ct == 1222)
    rows = [
        ("X-Wing (C2PRI combiner)", xw[0], xw[1], xwing_in),
        ("ML-KEM-768 + X25519, UG (hash all)", m7[0] + x[0], m7[1] + x[1],
         32 + 32 + m7[1] + x[1] + m7[0] + x[0] + 16),
        ("nested: X-Wing + FrodoKEM-976, outer hashes all", xw[0] + fr[0], xw[1] + fr[1],
         4 + 32 + fr[2] + 16 + xw[1] + fr[1] + xw[0] + fr[0]),
        ("nested: X-Wing + FrodoKEM-976, outer with cached H(pk)", xw[0] + fr[0], xw[1] + fr[1],
         4 + 32 + fr[2] + 16 + xw[1] + fr[1] + 32),
        ("flat: ML-KEM-1024 + X25519 + FrodoKEM-976, hash all", m10[0] + x[0] + fr[0],
         m10[1] + x[1] + fr[1], 4 + 32 + 32 + fr[2] + 16 + m10[1] + x[1] + fr[1] + m10[0] + x[0] + fr[0]),
        ("nested: X-Wing + McEliece-460896, outer with cached H(pk)", xw[0] + mc[0], xw[1] + mc[1],
         4 + 32 + mc[2] + 16 + xw[1] + mc[1] + 32),
    ]
    print(f"  {'composition':58s} {'pk (B)':>8s} {'ct (B)':>8s} {'KDF in (B)':>10s} {'Keccak-f':>8s}")
    for name, pk, ct, kin in rows:
        print(f"  {name:58s} {pk:8d} {ct:8d} {kin:10d} {keccak_calls(kin):8d}")
    print("  (KDF in: shared secrets + ciphertexts (+ keys) + 16-byte label (+ 4-byte counter"
          " for SP 800-56C); Keccak-f: sponge absorb calls at rate 136, excluding the"
          " one-block KMAC key/prefix blocks.)")
    check("keccak_calls(134) == 1 and keccak_calls(1222) == 9",
          keccak_calls(134) == 1 and keccak_calls(1222) == 9)


# ---------------------------------------------------------------- Part D
def part_d():
    print("D. ABK25 Theorem 9 (QROM) and GHP18 Lemma 6 (ROM) bounds, log2")
    for key_bits in (256, 192):
        for logq in (64, 80, 96, 100, 128):
            q = 2.0 ** logq
            adv = 4 * math.sqrt((q * q + q) / 2.0 ** key_bits)
            print(f"  |K_i| = 2^{key_bits}, q = 2^{logq}: 4*sqrt((q^2+q)/|K_i|) = 2^{math.log2(adv):.1f}"
                  + ("  (vacuous: >= 1)" if adv >= 1 else ""))
    adv = 2.0 ** 128 * 2.0 ** -256
    print(f"  classical: qH = 2^128, eps = 2^-256: qH*eps = 2^{math.log2(adv):.0f}")
    b = lambda logq, kb: 4 * math.sqrt((2.0 ** (2 * logq) + 2.0 ** logq) / 2.0 ** kb)
    check("QROM bound, 256-bit component key: < 1 at q = 2^125, >= 1 at q = 2^127",
          b(125, 256) < 1.0 <= b(127, 256))
    check("QROM bound, 192-bit component key (FrodoKEM-976 ss): < 1 at q = 2^93, >= 1 at q = 2^95",
          b(93, 192) < 1.0 <= b(95, 192))


# ---------------------------------------------------------------- Part E
def _rc_and_rot():
    rc, r = [], 1
    for _ in range(24):
        c = 0
        for j in range(7):
            if r & 1:
                c |= 1 << ((1 << j) - 1)
            r = ((r << 1) ^ 0x71) & 0xFF if r & 0x80 else (r << 1) & 0xFF
        rc.append(c)
    rot = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        rot[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return rc, rot


RC, ROT = _rc_and_rot()
M64 = (1 << 64) - 1


def keccak_f(a):
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                v, n = a[x + 5 * y], ROT[x][y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = ((v << n) | (v >> (64 - n))) & M64 if n else v
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= RC[rnd]
    return a


def sponge(msg, suffix, out_len, rate=RATE):
    p = bytearray(msg) + bytes([suffix])
    p += bytes((-len(p)) % rate)
    p[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        st = keccak_f(st)
    out = bytearray()
    while True:
        out += b"".join(st[i].to_bytes(8, "little") for i in range(rate // 8))
        if len(out) >= out_len:
            return bytes(out[:out_len])
        st = keccak_f(st)


def left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def encode_string(s):
    return left_encode(8 * len(s)) + s


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((-len(z)) % w)


def cshake256(x, out_len, n=b"", s=b""):
    if not n and not s:
        return sponge(x, 0x1F, out_len)
    return sponge(bytepad(encode_string(n) + encode_string(s), RATE) + x, 0x04, out_len)


def kmac256(key, x, out_len, s=b""):
    new_x = bytepad(encode_string(key), RATE) + x + right_encode(8 * out_len)
    return cshake256(new_x, out_len, b"KMAC", s)


def nist_samples(pdf, kind):
    text = " ".join((p.extract_text() or "") for p in pypdf.PdfReader(pdf).pages)
    text = re.sub(r"\s+", " ", text)
    out = []
    for m in re.finditer(kind + r": Sample #(\d+) Security Strength: 256-bits", text):
        nxt = text.find(": Sample #", m.end())
        seg = text[m.start():nxt if nxt > 0 else len(text)]
        key = re.search(r"Key is ((?:[0-9A-F]{2} )+)", seg)
        data = re.search(r"Data is ((?:[0-9A-F]{2} )+)", seg)
        outlen = int(re.search(r"Requested output length is (\d+)-bits", seg).group(1))
        s = re.search(r'S \(as a character string\) is "(.*?)"', seg).group(1)
        outval = re.search(r"Outval is ((?:[0-9A-F]{2} ?)+)", seg).group(1)
        out.append(dict(
            no=int(m.group(1)),
            key=bytes.fromhex(key.group(1)) if key else None,
            data=bytes.fromhex(data.group(1)),
            outlen=outlen // 8,
            s=b"" if s == "(null)" else s.encode(),
            out=bytes.fromhex(outval)[: outlen // 8],
        ))
    return out


def kdf_56c_kmac256(z, fixed_info, out_len=32):
    """SP 800-56C Rev. 2 Sec. 4.1 one-step KDF, Option 3: H(x) = KMAC256(salt, x,
    H_outputBits, "KDF"), default salt = 132 zero bytes, x = counter || Z || FixedInfo."""
    salt = bytes(132)
    return kmac256(salt, (1).to_bytes(4, "big") + z + fixed_info, out_len, b"KDF")


def part_e():
    print("E. KMAC256 from pure-Python Keccak, then an SP 800-56C one-step combiner")
    for msg in (b"", b"abc", bytes(range(200)), bytes(300)):
        check(f"SHA3-256 matches hashlib on {len(msg)}-byte input",
              sponge(msg, 0x06, 32) == hashlib.sha3_256(msg).digest())
        check(f"SHAKE256 matches hashlib on {len(msg)}-byte input",
              sponge(msg, 0x1F, 100) == hashlib.shake_256(msg).digest(100))
    cs = [v for v in nist_samples(os.path.join(PAPERS, "nist-cshake-kmac-example-values.pdf"), "cSHAKE")]
    km = [v for v in nist_samples(os.path.join(PAPERS, "nist-kmac-example-values.pdf"), "KMAC")]
    check(f"parsed cSHAKE256 samples {[v['no'] for v in cs]} and KMAC256 samples {[v['no'] for v in km]}",
          len(cs) >= 2 and len(km) >= 3)
    for v in cs:
        check(f"cSHAKE256 NIST sample #{v['no']}", cshake256(v["data"], v["outlen"], b"", v["s"]) == v["out"])
    for v in km:
        check(f"KMAC256 NIST sample #{v['no']}", kmac256(v["key"], v["data"], v["outlen"], v["s"]) == v["out"])
    bad = kmac256(km[0]["key"], km[0]["data"], km[0]["outlen"], km[0]["s"] + b"!")
    check("NEGATIVE: KMAC256 with a changed customization string does not match", bad != km[0]["out"])

    # Illustrative 3-component layout (fixed lengths, so plain concatenation is injective).
    f = lambda tag, n: hashlib.shake_256(tag).digest(n)  # deterministic dummy values
    parts = dict(ss1=f(b"ss1", 32), ss2=f(b"ss2", 24), ss3=f(b"ss3", 32),
                 ct1=f(b"ct1", 1120), ct2=f(b"ct2", 15792), ct3=f(b"ct3", 64),
                 pkh=f(b"pkh", 32))
    label = b"Turing-example-3way-v0"  # illustrative only, not a registered label
    z = parts["ss1"] + parts["ss2"] + parts["ss3"]
    fixed = encode_string(label) + parts["ct1"] + parts["ct2"] + parts["ct3"] + parts["pkh"]
    k = kdf_56c_kmac256(z, fixed)
    print(f"  example output (dummy inputs): {k.hex()}")
    changed = 0
    for name in parts:
        t = dict(parts); b = bytearray(t[name]); b[len(b) // 2] ^= 1; t[name] = bytes(b)
        z2 = t["ss1"] + t["ss2"] + t["ss3"]
        fx2 = encode_string(label) + t["ct1"] + t["ct2"] + t["ct3"] + t["pkh"]
        changed += kdf_56c_kmac256(z2, fx2) != k
    check(f"flipping one bit in any of the {len(parts)} inputs changes the key ({changed}/{len(parts)})",
          changed == len(parts))
    # Variable-length concatenation is ambiguous (SP 800-227 Sec. 4.6.2):
    check("variable-length concat collides: ('ab','c') and ('a','bc') give the same KMAC input",
          kdf_56c_kmac256(b"ab" + b"c", b"") == kdf_56c_kmac256(b"a" + b"bc", b""))
    check("encode_string per field removes the collision",
          kdf_56c_kmac256(encode_string(b"ab") + encode_string(b"c"), b"")
          != kdf_56c_kmac256(encode_string(b"a") + encode_string(b"bc"), b""))


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    part_a(sys.argv[1])
    part_b()
    part_c()
    part_d()
    part_e()
    print()
    print("ALL CHECKS PASSED" if not FAILURES else f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()
