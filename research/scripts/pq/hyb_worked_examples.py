"""Worked examples and three-component combiner checks for
research/notes/pq/hybrid-combiners.md (Turing, 2026-09-27).

What each part reproduces, and from which source:

1. The "mix-and-match" attack on the XOR combiner, with small numbers a reader
   can follow by hand. Source: Bindel, Brendel, Fischlin, Goncalves, Stebila,
   PQCrypto 2019 (ePrint 2018/903), Sec. 3.1 p. 11; GHP18 (ePrint 2018/024)
   Lemma 2 p. 7. The toy "KEM" here is only a lookup of known keys; the point
   is the arithmetic of the attack.

2. Three-component hybrids ML-KEM-768 + X25519 + a toy lattice KEM that plays
   the role of a custom (unanalysed) component. Four combiners are compared:
     flat_all        KDF over all shared secrets, all ciphertexts and a hash of
                     all public keys (GHP18 Theorem 1 / ABK25 Theorem 8 with
                     n = 3; SP 800-227 eq. (14) with t = 3)
     flat_omit_toy   the same but WITHOUT the toy ciphertext (the X-Wing
                     shortcut applied to a component with no C2PRI proof)
     nested          X-Wing (draft-connolly-cfrg-xwing-kem-11 Sec. 5.3) as one
                     KEM, combined with the toy KEM by an outer GHP-style
                     combiner that hashes both ciphertexts
     nested_omit_toy the nested form without the toy ciphertext
   Attack: take the challenge ciphertext, add 1 to the first coefficient of
   the toy ciphertext, ask the decapsulation oracle (legal: the ciphertext
   differs from the challenge). If the answer equals the challenge key, the
   hybrid is broken. Expected (X-Wing paper Sec. 3 p. 4; ABK25 Theorem 8):
   broken exactly when the combiner omits the toy ciphertext AND the toy KEM is
   not C2PRI (no FO re-encryption check). The same toy with FO re-encryption
   and implicit rejection resists the attack even when its ciphertext is
   omitted, which is why ABK25 lets C2PRI ciphertexts be left out.
   The KDF is the SP 800-56C Rev. 2 one-step KDF with KMAC256 (Sec. 4.1,
   Option 3), taken from hybrid_combiner_checks.py where it is checked
   against the NIST KMAC256 sample values.

3. A three-way XOR combiner is broken by the three-query generalisation of
   mix-and-match even though all three components are sound (GHP18 Lemma 2
   covers any n).

Usage (from the repository root, needs pyca/cryptography >= 44 for ML-KEM):
  python research/scripts/pq/hyb_worked_examples.py
Exit code 0 only if every check passes. Verdicts are deterministic; ML-KEM
and X25519 draw fresh randomness, which does not change any verdict.
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import hybrid_combiner_checks as hc  # noqa: E402  (verified KMAC256, toy LWE KEM, X25519 helpers)
from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")
FAILURES = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILURES.append(name)


# ---------------------------------------------------------------- Part 1
def part1():
    print("1. XOR combiner, mix-and-match, by hand (8-bit keys)")
    k1_star, k2_star = 0x3A, 0xC5  # challenge component keys (unknown to the attacker)
    k_star = k1_star ^ k2_star
    k1_own, k2_own = 0x11, 0x77  # keys of the attacker's own fresh encapsulations
    print(f"  challenge key k* = k1* XOR k2* = {k1_star:#04x} XOR {k2_star:#04x} = {k_star:#04x}")
    ans_a = k1_own ^ k2_star  # oracle on (c1_own, c2*)
    ans_b = k1_star ^ k2_own  # oracle on (c1*, c2_own)
    print(f"  oracle(c1', c2*) = {k1_own:#04x} XOR k2* = {ans_a:#04x}  ->  k2* = {ans_a:#04x} XOR {k1_own:#04x} = {ans_a ^ k1_own:#04x}")
    print(f"  oracle(c1*, c2') = k1* XOR {k2_own:#04x} = {ans_b:#04x}  ->  k1* = {ans_b:#04x} XOR {k2_own:#04x} = {ans_b ^ k2_own:#04x}")
    guess = (ans_a ^ k1_own) ^ (ans_b ^ k2_own)
    print(f"  attacker's k = {guess:#04x}")
    check("two legal queries recover the challenge key", guess == k_star)


# ---------------------------------------------------------------- Part 2
LABEL = b"Turing-example-3way-v0"  # illustrative only; not a registered label
TOY_CT_LEN = 2 * (hc.TN + hc.TL)  # u (64 coeffs) + v (256 coeffs), 2 bytes each


def enc_fixed(*fields):
    return b"".join(fields)  # every field has a fixed length in this construction


def kdf(z, fixed_info):
    return hc.kdf_56c_kmac256(z, hc.encode_string(LABEL) + fixed_info)


class ToyKEM:
    """Toy LWE KEM from hybrid_combiner_checks.py (n=64, q=3329; NOT secure).
    fo=False: K = H(m), no re-encryption check (not C2PRI).
    fo=True : FO with re-encryption and implicit rejection (C2PRI)."""

    def __init__(self, fo, seed):
        self.fo = fo
        self.pk, self.s, self.pk_bytes = hc.toy_keygen(seed)
        self.z = hashlib.shake_256(b"z" + seed).digest(32)
        self.ctr = 0

    def encaps(self):
        self.ctr += 1
        m = hashlib.shake_256(b"m" + self.ctr.to_bytes(4, "big")).digest(32)
        if self.fo:
            return hc.toy_fo_encaps(self.pk, self.pk_bytes, m)
        coins = hashlib.shake_256(b"c" + self.ctr.to_bytes(4, "big")).digest(32)
        return hc.toy_cpa_encaps(self.pk, m, coins)

    def decaps(self, ct):
        if self.fo:
            return hc.toy_fo_decaps(self.pk, self.pk_bytes, self.s, self.z, ct)
        return hc.toy_cpa_decaps(self.s, ct)


class ThreeWay:
    def __init__(self, combiner, toy_fo):
        self.combiner = combiner
        self.mk = mlkem.MLKEM768PrivateKey.generate()
        self.ek_m = self.mk.public_key().public_bytes_raw()
        self.sk_x = os.urandom(32)
        self.ek_x = hc.x25519_base(self.sk_x)
        self.toy = ToyKEM(toy_fo, b"turing-3way-toy")
        self.ek_hash = hc.sha3_256(self.ek_m + self.ek_x + self.toy.pk_bytes)
        self.challenge = None

    def split(self, ct):
        return ct[:1088], ct[1088:1120], ct[1120:]

    def encaps(self):
        ss_m, ct_m = self.mk.public_key().encapsulate()
        e = os.urandom(32)
        ct_x, ss_x = hc.x25519_base(e), hc.x25519(e, self.ek_x)
        ss_t, ct_t = self.toy.encaps()
        ct = ct_m + ct_x + ct_t
        return self.combiner(self, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t), ct

    def decaps_oracle(self, ct):
        assert ct != self.challenge, "the oracle refuses the challenge ciphertext"
        ct_m, ct_x, ct_t = self.split(ct)
        ss_m = self.mk.decapsulate(ct_m)
        ss_x = hc.x25519(self.sk_x, ct_x)
        ss_t = self.toy.decaps(ct_t)
        return self.combiner(self, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t)


def flat_all(h, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t):
    return kdf(ss_m + ss_x + ss_t, enc_fixed(ct_m, ct_x, ct_t, h.ek_hash))


def flat_omit_toy(h, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t):
    return kdf(ss_m + ss_x + ss_t, enc_fixed(ct_m, ct_x, h.ek_hash))


def _xwing(h, ss_m, ss_x, ct_x):
    return hc.sha3_256(ss_m + ss_x + ct_x + h.ek_x + hc.XWING_LABEL)  # draft-11 Sec. 5.3


def nested(h, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t):
    return kdf(_xwing(h, ss_m, ss_x, ct_x) + ss_t, enc_fixed(ct_m + ct_x, ct_t, h.ek_hash))


def nested_omit_toy(h, ss_m, ss_x, ss_t, ct_m, ct_x, ct_t):
    return kdf(_xwing(h, ss_m, ss_x, ct_x) + ss_t, enc_fixed(ct_m + ct_x, h.ek_hash))


def toy_malleation_attack(h):
    k_star, c_star = h.encaps()
    h.challenge = c_star
    t = bytearray(c_star)
    t[1120] = (t[1120] + 1) % 256  # u[0] += 1 in the toy ciphertext (little-endian uint16)
    return h.decaps_oracle(bytes(t)) == k_star


def part2():
    print("2. Three-component hybrids: ML-KEM-768 + X25519 + toy lattice KEM")
    h = ThreeWay(flat_all, toy_fo=False)
    k, ct = h.encaps()
    check(f"hybrid ciphertext length = 1088 + 32 + {TOY_CT_LEN} = {len(ct)}", len(ct) == 1120 + TOY_CT_LEN)
    for name, comb in [("flat_all", flat_all), ("flat_omit_toy", flat_omit_toy),
                       ("nested", nested), ("nested_omit_toy", nested_omit_toy)]:
        h = ThreeWay(comb, toy_fo=False)
        k, ct = h.encaps()
        check(f"{name}: correctness (decaps == encaps key)", h.decaps_oracle(ct) == k)
    runs = 5
    expect = {  # (combiner, toy has FO) -> expected number of wins out of `runs`
        ("flat_all", False): 0, ("flat_omit_toy", False): runs,
        ("nested", False): 0, ("nested_omit_toy", False): runs,
        ("flat_all", True): 0, ("flat_omit_toy", True): 0,
        ("nested", True): 0, ("nested_omit_toy", True): 0,
    }
    combs = dict(flat_all=flat_all, flat_omit_toy=flat_omit_toy, nested=nested,
                 nested_omit_toy=nested_omit_toy)
    for (name, fo), want in expect.items():
        wins = sum(toy_malleation_attack(ThreeWay(combs[name], fo)) for _ in range(runs))
        kind = "FO toy (C2PRI)" if fo else "CPA toy (not C2PRI)"
        check(f"{name:16s} with {kind:20s}: one-query attack wins {wins}/{runs} (expect {want}/{runs})",
              wins == want)


# ---------------------------------------------------------------- Part 3
def part3():
    print("3. Three-way XOR combiner: three-query mix-and-match, all components sound")
    mk = mlkem.MLKEM768PrivateKey.generate()
    pk_m = mk.public_key()
    sk_x = os.urandom(32)
    pk_x = hc.x25519_base(sk_x)
    toy = ToyKEM(True, b"turing-xor-toy")

    def enc():
        ss_m, ct_m = pk_m.encapsulate()
        e = os.urandom(32)
        ct_x, ss_x = hc.x25519_base(e), hc.x25519(e, pk_x)
        ss_t, ct_t = toy.encaps()
        return (ss_m, ss_x, ss_t), (ct_m, ct_x, ct_t)

    def xor3(a, b, c):
        return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))

    def oracle(cts, challenge):
        assert cts != challenge
        return xor3(mk.decapsulate(cts[0]), hc.x25519(sk_x, cts[1]), toy.decaps(cts[2]))

    wins = 0
    for _ in range(3):
        ss_star, c_star = enc()
        k_star = xor3(*ss_star)
        own_ss, own_ct = enc()  # attacker's own encapsulations, keys known
        recovered = []
        for i in range(3):  # keep component i of the challenge, replace the others
            q = tuple(c_star[j] if j == i else own_ct[j] for j in range(3))
            ans = oracle(q, c_star)
            others = [own_ss[j] for j in range(3) if j != i]
            recovered.append(xor3(ans, *others))
        wins += xor3(*recovered) == k_star
    check(f"three-way XOR: challenge key recovered in {wins}/3 runs (expect 3/3)", wins == 3)


def main():
    part1()
    part2()
    part3()
    print()
    print("ALL CHECKS PASSED" if not FAILURES else f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()
