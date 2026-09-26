"""Predict the 2-round boomerang return rate of Turing from S-box tables.

2 rounds: RK0, S, MixState, RK1, S, RK2. alpha on byte 0 in, delta on byte 0
out. Both pairs cross MixState with the same 16-byte difference M*(gamma,0..),
so the rate is sum over gamma of (DDT[alpha][gamma]/256)^2 (in, then back)
times BCT[M00*gamma][delta]/256 (the switch in the last S-box; the other 15
last-layer S-boxes see no lower difference, so they always switch).
"""
import math
import pathlib
import re

# The cipher's generated constants, relative to this script.
CRATE = pathlib.Path(__file__).resolve().parents[2] / "crates" / "turing" / "src"

src = open(CRATE / "sbox_constants.rs").read()
body = src[src.index("pub const TABLE: [u8; 256] = ["):]
body = body[: body.index("];")]
S = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", body)]
assert len(S) == 256 and sorted(S) == list(range(256))
inv = [0] * 256
for x, y in enumerate(S):
    inv[y] = x

lin = open(CRATE / "linear_constants.rs").read()
row0 = lin[lin.index("pub const MIX_STATE: [[u8; 16]; 16] = ["):]
M00 = int(re.findall(r"0x([0-9a-fA-F]{2})", row0)[0], 16)


def mul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return p


def ddt_row(a):
    row = [0] * 256
    for x in range(256):
        row[S[x] ^ S[x ^ a]] += 1
    return row


def bct(d_in, d_out):
    return sum(1 for x in range(256) if inv[S[x] ^ d_out] ^ inv[S[x ^ d_in] ^ d_out] == d_in)


alpha, delta = 0x01, 0x8A
row = ddt_row(alpha)
rate = sum((row[g] / 256) ** 2 * bct(mul(M00, g), delta) / 256 for g in range(1, 256) if row[g])
print(f"M00 = {M00:#04x}; BCT[alpha][delta] = {bct(alpha, delta)}")
print(f"predicted 2-round rate {rate:.3e} = 2^{math.log2(rate):.2f}")
print(f"measured 33 / 262144 = 2^{math.log2(33 / 262144):.2f}")
in_and_back = sum((row[g] / 256) ** 2 for g in range(256))
print(f"in and back through byte 0: 2^{math.log2(in_and_back):.2f}")
