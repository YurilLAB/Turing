"""Exact 2-round boomerang return rate for Turing (alpha, delta on byte 0).

x1 = first S-box input of pair 1 (uniform), u = last S-box input of pair 1
(uniform and independent of x1, because it mixes all 16 bytes).
gamma = S(x1) ^ S(x1 ^ alpha); the pairs differ by M*(gamma,0,..) after
MixState, so the last S-box inputs differ by beta0 = M00*gamma in byte 0.
Shifting ciphertexts by delta changes the last S-box inputs by
T(u) = S^-1(S(u) ^ delta) ^ u. The quartet returns iff
  (a) T(u) == T(u ^ beta0)  (both pairs shifted alike: the lower switch), and
  (b) the first S-box, whose outputs are both shifted by c = m0 * T(u)
      (m0 = MixState^-1[0][0]), still maps the pair to difference alpha.
Other bytes: the lower difference is zero in bytes 1..15 of the last layer,
and after (a) the returned pair differs only in byte 0 before round 1.
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
inv = [0] * 256
for x, y in enumerate(S):
    inv[y] = x

lin = open(CRATE / "linear_constants.rs").read()
first = lambda name: int(re.findall(r"0x([0-9a-fA-F]{2})", lin[lin.index(f"pub const {name}: [[u8; 16]; 16] = ["):])[0], 16)
M00, m0 = first("MIX_STATE"), first("MIX_STATE_INV")


def mul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return p


alpha, delta = 0x01, 0x8A
T = [inv[S[u] ^ delta] ^ u for u in range(256)]
hits = 0
for x1 in range(256):
    gamma = S[x1] ^ S[x1 ^ alpha]
    beta0 = mul(M00, gamma)
    for u in range(256):
        if T[u] != T[u ^ beta0]:
            continue
        c = mul(m0, T[u])
        if inv[S[x1] ^ c] ^ inv[S[x1 ^ alpha] ^ c] == alpha:
            hits += 1
rate = hits / 65536
print(f"M00 = {M00:#04x}, m0 = {m0:#04x}")
print(f"exact 2-round rate {hits}/65536 = 2^{math.log2(rate):.2f}; expected returns in 262144 quartets: {rate * 262144:.1f}")
print(f"measured 33 / 262144 = 2^{math.log2(33 / 262144):.2f}")
