"""Raw X25519 used as a KEM is not C2PRI: the 2-torsion (inversion) second preimage.

Reproduces Theorem 1 of T. Kang, C. Lee, Y. Son, "On the Necessity of Public Contexts
in Hybrid KEMs: A Case Study of X-Wing", IACR ePrint 2026/140 (file
research/papers/2026-kang-lee-son-public-contexts-hybrid-kems-x-wing.pdf, p. 6):
for a ciphertext (ephemeral u-coordinate) c*, the value c' = (c*)^-1 mod p, with
p = 2^255 - 19, is the u-coordinate of P* + T where T = (0, 0) has order 2. RFC 7748
clamping makes the secret scalar a multiple of 8, so [sk]T = O and
X25519(sk, c') = X25519(sk, c*). A different ciphertext gives the same shared secret.

Also checks the other known trick (bit 255 of the u-coordinate is masked by RFC 7748,
Sec. 5), and shows that an X-Wing style combiner, which hashes ct_X and pk_X
(draft-connolly-cfrg-xwing-kem-11 Sec. 5.3), separates both second preimages.

Negative control: c* + 1 (an unrelated u-coordinate) gives a different secret.

Uses pyca/cryptography's X25519 (an independent, audited implementation).
Deterministic: private keys are derived from fixed seeds with SHA-256.

Usage (from the repository root):
  timeout 120 python research/scripts/pq/hyb_x25519_torsion.py
"""
import hashlib
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

P = 2**255 - 19
FAIL = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        FAIL.append(name)


def raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def u_of(b):
    return int.from_bytes(b, "little") & ((1 << 255) - 1)


def enc(u):
    return (u % P).to_bytes(32, "little")


def dh(sk, ct_bytes):
    return sk.exchange(X25519PublicKey.from_public_bytes(ct_bytes))


def xwing_like(ss_m, ss_x, ct_x, pk_x):
    # draft-connolly-cfrg-xwing-kem-11 Sec. 5.3 layout, label last.
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + bytes.fromhex("5c2e2f2f5e5c")).digest()


def main():
    trials = 50
    same_inv = same_bit = same_plus1 = 0
    xw_inv_diff = xw_bit_diff = 0
    for t in range(trials):
        sk = X25519PrivateKey.from_private_bytes(hashlib.sha256(b"recipient-%d" % t).digest())
        pk = raw(sk.public_key())
        eph = X25519PrivateKey.from_private_bytes(hashlib.sha256(b"ephemeral-%d" % t).digest())
        ct = raw(eph.public_key())
        k_star = dh(sk, ct)
        assert k_star == eph.exchange(sk.public_key())
        u = u_of(ct)
        ct_inv = enc(pow(u, P - 2, P))              # c' = c*^-1 mod p
        ct_bit = bytes(ct[:31]) + bytes([ct[31] ^ 0x80])  # flip bit 255
        ct_p1 = enc(u + 1)                            # negative control
        assert ct_inv != ct and ct_bit != ct and ct_p1 != ct
        k_inv = dh(sk, ct_inv)
        k_bit = dh(sk, ct_bit)
        k_p1 = dh(sk, ct_p1)
        same_inv += k_inv == k_star
        same_bit += k_bit == k_star
        same_plus1 += k_p1 == k_star
        ss_m = hashlib.sha256(b"stand-in ML-KEM secret %d" % t).digest()
        xw_star = xwing_like(ss_m, k_star, ct, pk)
        xw_inv_diff += xwing_like(ss_m, k_inv, ct_inv, pk) != xw_star
        xw_bit_diff += xwing_like(ss_m, k_bit, ct_bit, pk) != xw_star
    print(f"Raw X25519 as a KEM, {trials} key pairs:")
    print(f"  inversion c' = c*^-1 mod p gives the same secret: {same_inv}/{trials}")
    print(f"  bit-255 flip gives the same secret:               {same_bit}/{trials}")
    print(f"  NEGATIVE control c* + 1 gives the same secret:    {same_plus1}/{trials}")
    check("inversion second preimage works every time (Kang-Lee-Son Thm 1)", same_inv == trials)
    check("bit-255 second preimage works every time (RFC 7748 masking)", same_bit == trials)
    check("NEGATIVE: c* + 1 never gives the same secret", same_plus1 == 0)
    check("X-Wing-style combiner (hashes ct_X, pk_X) separates the inversion preimage", xw_inv_diff == trials)
    check("X-Wing-style combiner separates the bit-255 preimage", xw_bit_diff == trials)

    # The algebra behind the trick, on one explicit point: x(P + T) = 1/x(P) for T = (0, 0)
    # on y^2 = x^3 + A x^2 + x (A = 486662). Chord through P = (x1, y1) and T = (0, 0):
    # slope m = y1/x1, x3 = m^2 - A - x1 - 0.
    A = 486662
    x1 = 9  # base point u-coordinate
    rhs = (x1**3 + A * x1 * x1 + x1) % P
    y1 = pow(rhs, (P + 3) // 8, P)
    if (y1 * y1 - rhs) % P != 0:
        y1 = y1 * pow(2, (P - 1) // 4, P) % P
    check("found y for the base point (u = 9) on Curve25519", (y1 * y1 - rhs) % P == 0)
    m = y1 * pow(x1, P - 2, P) % P
    x3 = (m * m - A - x1) % P
    check("x(P + T) = x(P)^-1 mod p for the base point", x3 == pow(x1, P - 2, P))

    print("\nALL CHECKS PASSED" if not FAIL else f"\nFAILED: {FAIL}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
