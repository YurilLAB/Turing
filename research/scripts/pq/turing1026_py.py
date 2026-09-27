"""Turing-1026 in Python: a third independent implementation (docs/16, docs/17).

The turing crate has its own Keccak; the bombe reference (refkem1026.rs) uses
the Rust sha3 crate; this uses a third cSHAKE256, pycryptodome's, in a third
language, written from the specification in docs/17 section 1. Its only job is
to reproduce vectors/turing-1026-v1.txt from the 32-byte seeds, so a bug shared
between the two Rust implementations (a misread of the spec, say) would show up
here as a mismatch.

NumPy does the integer matrix products (A S, S' A, S' B, B' S) mod q; every
byte-level step -- cSHAKE256, the CBD(18) sampler, packing, encoding and
decoding -- is plain Python from the spec.

    pip install pycryptodome numpy
    python research/scripts/pq/turing1026_py.py [vectors/turing-1026-v1.txt]

Exit status 0 if every vector matches, 1 if any differs, 2 on a setup error.
"""
import hashlib
import os
import sys

import numpy as np
from Crypto.Hash import cSHAKE256

N, NBAR, MBAR, LOG_Q, ETA = 1026, 32, 8, 15, 18
Q = 1 << LOG_Q
SALT_BYTES = 64
MSG_BYTES = NBAR * MBAR // 8  # 32
PKE_BYTES = ((MBAR * N + MBAR * NBAR) * LOG_Q) // 8  # 15,870


def x(label, parts, outlen):
    """cSHAKE256 with function name N empty and customization S = label."""
    return cSHAKE256.new(data=b"".join(parts), custom=label.encode()).read(outlen)


def cbd_samples(buf, pos, count):
    """`count` CBD(18) samples from `buf` starting at byte `pos`: each is the
    popcount of the next 18 bits minus that of the following 18, bits taken
    least significant first within each byte. The next draw starts at the next
    whole byte, so return the updated position."""
    need = count * 2 * ETA
    bits = [(buf[pos + k // 8] >> (k % 8)) & 1 for k in range(need)]
    out = [sum(bits[i : i + ETA]) - sum(bits[i + ETA : i + 2 * ETA]) for i in range(0, need, 2 * ETA)]
    return out, pos + (need + 7) // 8


def noise_bytes(counts):
    return sum((c * 2 * ETA + 7) // 8 for c in counts)


def matrix(seed_a):
    """A (n x n): row i is cSHAKE256(seed_a || le16(i), "matrix"), two bytes
    per coefficient, little-endian, mod q."""
    a = np.empty((N, N), dtype=np.int64)
    for i in range(N):
        b = x("Turing-1026 v1 matrix", [seed_a, i.to_bytes(2, "little")], 2 * N)
        a[i] = [(b[2 * k] | (b[2 * k + 1] << 8)) % Q for k in range(N)]
    return a


def pack(values):
    """15-bit little-endian coefficients into a bit string, LSB first."""
    out = bytearray((len(values) * LOG_Q + 7) // 8)
    for i, v in enumerate(values):
        for k in range(LOG_Q):
            if (v >> k) & 1:
                out[(i * LOG_Q + k) // 8] |= 1 << ((i * LOG_Q + k) % 8)
    return bytes(out)


def unpack(data, count):
    return [sum(((data[(i * LOG_Q + k) // 8] >> ((i * LOG_Q + k) % 8)) & 1) << k for k in range(LOG_Q)) for i in range(count)]


def keygen(seed):
    derived = x("Turing-1026 v1 key generation", [seed], 96)
    seed_a, r, z = derived[:32], derived[32:64], derived[64:]
    buf = x("Turing-1026 v1 key noise", [r], noise_bytes([N * NBAR, N * NBAR]))
    s, pos = cbd_samples(buf, 0, N * NBAR)
    e, _ = cbd_samples(buf, pos, N * NBAR)
    s = np.array(s, dtype=np.int64).reshape(N, NBAR)
    e = np.array(e, dtype=np.int64).reshape(N, NBAR)
    a = matrix(seed_a)
    b = (a @ s + e) % Q
    pk = seed_a + pack(b.reshape(-1).tolist())
    h = x("Turing-1026 v1 public key", [pk], 32)
    return {"seed_a": seed_a, "z": z, "s": s, "b": b, "pk": pk, "h": h}


def encrypt(key, mu, coins):
    buf = x("Turing-1026 v1 encryption noise", [coins], noise_bytes([MBAR * N, MBAR * N, MBAR * NBAR]))
    sp, pos = cbd_samples(buf, 0, MBAR * N)
    ep, pos = cbd_samples(buf, pos, MBAR * N)
    epp, _ = cbd_samples(buf, pos, MBAR * NBAR)
    sp = np.array(sp, dtype=np.int64).reshape(MBAR, N)
    ep = np.array(ep, dtype=np.int64).reshape(MBAR, N)
    epp = np.array(epp, dtype=np.int64).reshape(MBAR, NBAR)
    a = matrix(key["seed_a"])
    bp = (sp @ a + ep) % Q
    encode = np.array([[(mu[i // 8] >> (i % 8)) & 1 for i in range(r * NBAR, r * NBAR + NBAR)] for r in range(MBAR)], dtype=np.int64)
    c = (sp @ key["b"] + epp + encode * (Q // 2)) % Q
    return pack(bp.reshape(-1).tolist()) + pack(c.reshape(-1).tolist())


def decrypt(key, body):
    bp = np.array(unpack(body[: (MBAR * N * LOG_Q) // 8], MBAR * N), dtype=np.int64).reshape(MBAR, N)
    c = np.array(unpack(body[(MBAR * N * LOG_Q) // 8 :], MBAR * NBAR), dtype=np.int64).reshape(MBAR, NBAR)
    d = (c - bp @ key["s"]) % Q
    mu = bytearray(MSG_BYTES)
    for r in range(MBAR):
        for j in range(NBAR):
            if Q // 4 <= d[r, j] < 3 * Q // 4:
                i = r * NBAR + j
                mu[i // 8] |= 1 << (i % 8)
    return bytes(mu)


def encapsulate(key, mu, salt):
    coins = x("Turing-1026 v1 coins", [key["h"], mu, salt], 96)
    body = encrypt(key, mu, coins[:64])
    ct = body + salt
    return ct, x("Turing-1026 v1 shared key", [ct, coins[64:]], 32)


def decapsulate(key, ct):
    body, salt = ct[:PKE_BYTES], ct[PKE_BYTES:]
    mu = decrypt(key, body)
    coins = x("Turing-1026 v1 coins", [key["h"], mu, salt], 96)
    again = encrypt(key, mu, coins[:64])
    if again == body:
        return x("Turing-1026 v1 shared key", [ct, coins[64:]], 32)
    return x("Turing-1026 v1 rejection key", [key["z"], key["h"], ct], 32)


def parse_vectors(text):
    vectors, cur = [], {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("COUNT"):
            cur = {"COUNT": line.split(" = ", 1)[1] if " = " in line else "?"}
            vectors.append(cur)
        elif " = " in line and vectors:
            k, v = line.split(" = ", 1)
            cur[k] = v
    return vectors


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "..", "vectors", "turing-1026-v1.txt")
    if not os.path.exists(path):
        print(f"vectors not found: {path}", file=sys.stderr)
        return 2
    vectors = parse_vectors(open(path, encoding="utf-8").read())
    if not vectors:
        print("no vectors parsed", file=sys.stderr)
        return 2
    ok = 0
    for v in vectors:
        seed = bytes.fromhex(v["SEED"])
        mu = bytes.fromhex(v["MESSAGE"])
        salt = bytes.fromhex(v["SALT"])
        key = keygen(seed)
        ct, shared = encapsulate(key, mu, salt)
        # The rejection key of the ciphertext with its first byte flipped, as
        # the vector file defines REJECTED_KEY.
        bad = bytearray(ct)
        bad[0] ^= 1
        rej = decapsulate(key, bytes(bad))
        got = {
            "PUBLIC_KEY_SHA3_256": hashlib.sha3_256(key["pk"]).hexdigest(),
            "CIPHERTEXT_SHA3_256": hashlib.sha3_256(ct).hexdigest(),
            "SHARED_KEY": shared.hex(),
            "REJECTED_KEY": rej.hex(),
        }
        # Decapsulation of the valid ciphertext returns the shared key.
        assert decapsulate(key, ct).hex() == shared.hex(), f"vector {v.get('COUNT')}: decapsulation mismatch"
        good = all(got[k] == v[k] for k in got)
        ok += good
        tag = "PASS" if good else "FAIL"
        print(f"  COUNT {v.get('COUNT', '?'):>2}  {tag}")
        if not good:
            for k in got:
                if got[k] != v[k]:
                    print(f"      {k}: got {got[k]}\n           want {v[k]}")
    print(f"-> {ok} of {len(vectors)} vectors reproduced")
    return 0 if ok == len(vectors) else 1


if __name__ == "__main__":
    sys.exit(main())
