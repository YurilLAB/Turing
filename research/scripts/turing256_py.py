"""Turing-256 v2 in Python: a third independent implementation (docs/15).

The turing crate is the constant-time implementation; the bombe reference
(refcipher256.rs) is the second, but it shares the committed S-box table and
matrices with the turing crate and gets cSHAKE256 from the same Rust sha3
crate. This one shares nothing: it has its own Keccak (checked against
hashlib's SHA3-256 and SHAKE256 and against NIST SP 800-185's cSHAKE256
sample #3), and it derives every constant from its public label as docs/05,
docs/06 and docs/15 describe -- the S-box's affine maps, Turing's
MixColumns, Turing-256's 32 x 32 MixState and its round constants -- instead
of reading them from the Rust files. Its job is to reproduce
vectors/turing-256-v2.txt, every round constant, round key and
reduced-round output included, so that a mistake in a committed constant or
a misreading of the specification shared by both Rust implementations would
show up here as a mismatch.

Three negative controls run first: ShiftRows rotating the wrong way, one
key-schedule warm-up round fewer and no round constants (version 1) must
each fail to reproduce the vectors.

    python research/scripts/turing256_py.py [vectors/turing-256-v2.txt]

Exit status 0 if every value matches, 1 if any differs, 2 on a setup error.
No dependencies beyond the standard library.
"""
import hashlib
import os
import sys

# --- Keccak-f[1600] and cSHAKE256, from FIPS 202 and SP 800-185 -------------

MASK = (1 << 64) - 1


def _rc_bit(t):
    """FIPS 202 Algorithm 5: bit t of the round-constant LFSR."""
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


ROUND_CONSTANTS = [sum(_rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)]

# Rotation offsets of lane (x, y) at index x + 5y (FIPS 202 Algorithm 2).
ROTATIONS = [0] * 25
_x, _y = 1, 0
for _t in range(24):
    ROTATIONS[_x + 5 * _y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def _rotl(v, n):
    return ((v << n) | (v >> (64 - n))) & MASK if n else v


def keccak_f(a):
    for rc in ROUND_CONSTANTS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], ROTATIONS[x + 5 * y])
        a = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


class Sponge:
    """Keccak[512] (rate 136 bytes) with a domain suffix: 0x06 SHA-3,
    0x1f SHAKE, 0x04 cSHAKE. Squeezes on demand."""

    RATE = 136

    def __init__(self, message, suffix):
        padded = bytearray(message) + bytes([suffix])
        padded += bytes(-len(padded) % self.RATE)
        padded[-1] |= 0x80
        self.a = [0] * 25
        for off in range(0, len(padded), self.RATE):
            block = padded[off : off + self.RATE]
            for i in range(self.RATE // 8):
                self.a[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
            self.a = keccak_f(self.a)
        self.out = b"".join(w.to_bytes(8, "little") for w in self.a)[: self.RATE]

    def read(self, n):
        got = bytearray()
        while len(got) < n:
            if not self.out:
                self.a = keccak_f(self.a)
                self.out = b"".join(w.to_bytes(8, "little") for w in self.a)[: self.RATE]
            take = min(n - len(got), len(self.out))
            got += self.out[:take]
            self.out = self.out[take:]
        return bytes(got)


def _left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def _encode_string(s):
    return _left_encode(8 * len(s)) + s


def cshake256(data, custom):
    """cSHAKE256(X = data, L, N = "", S = custom) as a reader (SP 800-185)."""
    prefix = _left_encode(Sponge.RATE) + _encode_string(b"") + _encode_string(custom.encode())
    prefix += bytes(-len(prefix) % Sponge.RATE)
    return Sponge(prefix + bytes(data), 0x04)


def check_keccak():
    for msg in [b"", b"abc", bytes(range(200)), b"\xa3" * 137]:
        if Sponge(msg, 0x06).read(32) != hashlib.sha3_256(msg).digest():
            return "SHA3-256 differs from hashlib"
        if Sponge(msg, 0x1F).read(300) != hashlib.shake_256(msg).digest(300):
            return "SHAKE256 differs from hashlib"
    # NIST SP 800-185 cSHAKE256 sample #3 (N = "", S = "Email Signature").
    sample = bytes.fromhex("d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1")
    if cshake256(bytes([0, 1, 2, 3]), "Email Signature").read(32) != sample:
        return "cSHAKE256 differs from NIST SP 800-185 sample #3"
    return None


# --- GF(2^8) with x^8 + x^4 + x^3 + x + 1 ----------------------------------


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return p


MUL = [[gmul(a, b) for b in range(256)] for a in range(256)]
INV = [0] + [next(b for b in range(1, 256) if MUL[a][b] == 1) for a in range(1, 256)]


def mat_vec(m, v):
    out = []
    for row in m:
        acc = 0
        for coef, x in zip(row, v):
            acc ^= MUL[coef][x]
        out.append(acc)
    return out


def mat_inv(m):
    """Gauss-Jordan over GF(2^8); None if singular."""
    n = len(m)
    aug = [list(row) + [int(i == j) for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        piv = next((r for r in range(col, n) if aug[r][col]), None)
        if piv is None:
            return None
        aug[col], aug[piv] = aug[piv], aug[col]
        f = INV[aug[col][col]]
        aug[col] = [MUL[f][v] for v in aug[col]]
        for r in range(n):
            if r != col and aug[r][col]:
                g = aug[r][col]
                aug[r] = [v ^ MUL[g][w] for v, w in zip(aug[r], aug[col])]
    return [row[n:] for row in aug]


# --- The constants, derived from their labels -------------------------------


def gf2_invertible(rows):
    rows = list(rows)
    for col in range(8):
        piv = next((r for r in range(col, 8) if rows[r] >> col & 1), None)
        if piv is None:
            return False
        rows[col], rows[piv] = rows[piv], rows[col]
        for r in range(8):
            if r != col and rows[r] >> col & 1:
                rows[r] ^= rows[col]
    return True


def affine(rows, const, x):
    """Output bit i is the parity of rows[i] & x, then XOR the constant."""
    return sum((bin(r & x).count("1") & 1) << i for i, r in enumerate(rows)) ^ const


def sbox_tables(counter=3):
    """docs/05: from cSHAKE256(X = counter as u32 big-endian, S = "Turing v1
    S-box"), draw A_in then A_out: 8 row bytes, redrawn while singular, then
    a constant byte. Counter 3 is the one Bombe's grading accepted."""
    stream = cshake256(counter.to_bytes(4, "big"), "Turing v1 S-box")
    maps = []
    for _ in range(2):
        while True:
            rows = stream.read(8)
            if gf2_invertible(rows):
                break
        maps.append((rows, stream.read(1)[0]))
    (in_rows, in_c), (out_rows, out_c) = maps
    s = [affine(out_rows, out_c, INV[affine(in_rows, in_c, x)]) for x in range(256)]
    inv_s = [0] * 256
    for x, y in enumerate(s):
        inv_s[y] = x
    return s, inv_s


def cauchy(label, n, counter=0):
    """docs/06, docs/15: M[i][j] = 1/(x_i + y_j) on the first 2n distinct
    bytes of cSHAKE256(X = counter as u32 big-endian, S = label)."""
    stream = cshake256(counter.to_bytes(4, "big"), label)
    points = []
    while len(points) < 2 * n:
        b = stream.read(1)[0]
        if b not in points:
            points.append(b)
    xs, ys = points[:n], points[n:]
    return [[INV[x ^ y] for y in ys] for x in xs]


# --- Turing-256 v2 (docs/15) -------------------------------------------------

ROUNDS = 24


def round_constants():
    """Round constants 1..24: consecutive 32-byte reads of cSHAKE256(X = "",
    S = "Turing-256 v2 round constants")."""
    stream = cshake256(b"", "Turing-256 v2 round constants")
    return [list(stream.read(32)) for _ in range(ROUNDS)]


class Turing256:
    def __init__(self, s, inv_s, cols, state, rc, shifts=(0, 1, 3, 4), warmup=9, per_pair=8):
        self.s, self.inv_s = s, inv_s
        self.cols, self.cols_inv = cols, mat_inv(cols)
        self.state, self.state_inv = state, mat_inv(state)
        self.rc = rc
        self.shifts, self.warmup, self.per_pair = shifts, warmup, per_pair

    def shift_rows(self, v, inverse=False):
        out = [0] * 32
        for c in range(8):
            for r, sh in enumerate(self.shifts):
                src = (c - sh) % 8 if inverse else (c + sh) % 8
                out[4 * c + r] = v[4 * src + r]
        return out

    def mix_columns(self, v, m):
        return [b for c in range(8) for b in mat_vec(m, v[4 * c : 4 * c + 4])]

    def round_keys(self, key, count=ROUNDS + 1):
        kp = cshake256(key, "Turing-256 v2 key").read(64)
        kl, kr = list(kp[:32]), list(kp[32:])
        l, r = kl, kr
        consts = cshake256(b"", "Turing-256 v2 key schedule constants")

        def feistel(l, r):
            c = consts.read(32)
            f = mat_vec(self.state, [self.s[a ^ b] for a, b in zip(l, c)])
            return [a ^ b for a, b in zip(r, f)], l

        for _ in range(self.warmup):
            l, r = feistel(l, r)
        out = []
        while len(out) < count:
            if out:
                for _ in range(self.per_pair):
                    l, r = feistel(l, r)
            out.append([a ^ b for a, b in zip(l, kl)])
            out.append([a ^ b for a, b in zip(r, kr)])
        return out[:count]

    def encrypt(self, rks, p, rounds=ROUNDS):
        v = [a ^ b for a, b in zip(p, rks[0])]
        for rnd in range(1, rounds + 1):
            v = [self.s[b] for b in v]
            if rnd < rounds:
                v = mat_vec(self.state, v) if rnd % 2 else self.mix_columns(self.shift_rows(v), self.cols)
            v = [a ^ b ^ c for a, b, c in zip(v, self.rc[rnd - 1], rks[rnd])]
        return v

    def decrypt(self, rks, c, rounds=ROUNDS):
        v = list(c)
        for rnd in range(rounds, 0, -1):
            v = [a ^ b ^ c for a, b, c in zip(v, self.rc[rnd - 1], rks[rnd])]
            if rnd < rounds:
                v = mat_vec(self.state_inv, v) if rnd % 2 else self.shift_rows(self.mix_columns(v, self.cols_inv), True)
            v = [self.inv_s[b] for b in v]
        return [a ^ b for a, b in zip(v, rks[0])]


# --- The vector file ---------------------------------------------------------


def parse(path):
    """The KEY/PLAINTEXT/CIPHERTEXT triples, the ROUND_CONSTANT[r] lines, and
    the ROUND_KEY[i] and AFTER_ROUND[r] lines, which belong to COUNT = 2."""
    triples, extra, cur = [], {}, {}
    with open(path) as fh:
        for line in fh:
            if " = " not in line or line.startswith("#"):
                continue
            name, value = (s.strip() for s in line.split(" = ", 1))
            if name in ("KEY", "PLAINTEXT"):
                cur[name] = bytes.fromhex(value)
            elif name == "CIPHERTEXT":
                triples.append((cur.pop("KEY"), cur.pop("PLAINTEXT"), bytes.fromhex(value)))
            elif name.startswith(("ROUND_CONSTANT[", "ROUND_KEY[", "AFTER_ROUND[")):
                extra[name] = bytes.fromhex(value)
    return triples, extra


def mismatches(cipher, triples, extra):
    """Every value of the file this cipher does not reproduce."""
    bad = []
    for i, (k, p, c) in enumerate(triples):
        rks = cipher.round_keys(k)
        got = bytes(cipher.encrypt(rks, p))
        if got != c:
            bad.append(f"COUNT = {i}: ciphertext {got.hex()}")
        elif bytes(cipher.decrypt(rks, c)) != p:
            bad.append(f"COUNT = {i}: decryption does not give the plaintext")
    if not extra:
        return bad
    k, p, _ = triples[2]
    rks = cipher.round_keys(k)
    for name, want in extra.items():
        idx = int(name[name.index("[") + 1 : -1])
        if name.startswith("ROUND_CONSTANT"):
            got = bytes(cipher.rc[idx - 1])
        elif name.startswith("ROUND_KEY"):
            got = bytes(rks[idx])
        else:
            got = bytes(cipher.encrypt(rks, p, idx))
        if got != want:
            bad.append(f"{name}: {got.hex()}")
    return bad


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "..", "vectors", "turing-256-v2.txt")
    err = check_keccak()
    if err:
        print(f"setup: {err}")
        return 2
    triples, extra = parse(path)
    if len(triples) != 8 or len(extra) != 3 * ROUNDS + 1:
        print(f"setup: expected 8 vectors and {3 * ROUNDS + 1} intermediate values, found {len(triples)} and {len(extra)}")
        return 2
    s, inv_s = sbox_tables()
    cols = cauchy("Turing v1 MixColumns", 4)
    state = cauchy("Turing-256 v1 MixState", 32)
    rc = round_constants()
    if mat_inv(cols) is None or mat_inv(state) is None:
        print("setup: a Cauchy matrix is singular")
        return 2

    # Negative controls: each planted mistake must be caught.
    for name, planted in [
        ("ShiftRows rotating right", Turing256(s, inv_s, cols, state, rc, shifts=(0, 7, 5, 4))),
        ("8 warm-up rounds", Turing256(s, inv_s, cols, state, rc, warmup=8)),
        ("no round constants", Turing256(s, inv_s, cols, state, [[0] * 32] * ROUNDS)),
    ]:
        if not mismatches(planted, triples[:1], {}):
            print(f"control failed: {name} reproduces vector 0")
            return 2
        print(f"control: {name} is caught")

    bad = mismatches(Turing256(s, inv_s, cols, state, rc), triples, extra)
    for line in bad:
        print("MISMATCH", line)
    checked = 2 * len(triples) + len(extra)
    print(f"{checked - len(bad)} of {checked} values reproduced (8 ciphertexts, 8 decryptions, {ROUNDS} round "
          f"constants, {ROUNDS + 1} round keys, {ROUNDS} reduced-round outputs)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
