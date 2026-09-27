"""Worked example: replacing a division by q = 3329 with a multiply and shift.

Reproduces, as a learner's example, why the KyberSlash1 fix in pq-crystals/kyber
(commit dda29cc, ref/poly.c poly_tomsg) gives the same message bits as the
division it replaced, and where the shortcut stops being exact.
The two code versions (also transcribed in research/scripts/pq/ct_bugclasses.c,
tomsg_div and tomsg_mul):
  before: t += ((int16_t)t >> 15) & q;  t = (((t << 1) + q/2) / q) & 1;
          (q/2 is integer division, 1664; t is a uint16 in [0, q))
  after:  t <<= 1; t += 1665; t *= 80635; t >>= 28; t &= 1;
          (t is a uint32 holding the coefficient, which may be negative, so
           the arithmetic wraps modulo 2^32)
Idea: 1/3329 ~= 80635 / 2^28, so (x * 80635) >> 28 ~= x / 3329. The fixed
code adds 1665 instead of 1664 to absorb the tiny error of the constant.
Usage: python sc_div_by_mul.py   (deterministic, under a second)
"""
from fractions import Fraction

Q = 3329
M, S = 80635, 28
MASK32 = (1 << 32) - 1


def bit_div(c):
    """Pre-fix: c is any int16 coefficient; map to [0, q) then round 2c/q."""
    t = c & 0xFFFF
    t = (t + ((Q if c < 0 else 0))) & 0xFFFF          # t += (t >> 15) & q
    return (((t << 1) + Q // 2) // Q) & 1


def bit_mul(c):
    """Fixed: uint32 arithmetic on the (possibly negative) coefficient."""
    t = c & MASK32
    t = (t << 1) & MASK32
    t = (t + 1665) & MASK32
    t = (t * M) & MASK32
    return (t >> S) & 1


def main():
    print(f"2^{S} / {Q} = {float(Fraction(2**S, Q)):.6f}; the code rounds this to M = {M}")
    print(f"(x*M) >> {S} therefore divides by 2^{S}/M = {2**S / M:.7f}, not exactly {Q}")
    centred = range(-(Q - 1) // 2, (Q - 1) // 2 + 1)
    canonical = range(0, Q)
    for name, rng in (("centred [-(q-1)/2, (q-1)/2]", centred), ("canonical [0, q)", canonical)):
        bad = sum(1 for c in rng if bit_div(c) != bit_mul(c))
        print(f"message-bit mismatches, coefficients {name}: {bad} of {len(rng)}")
    allbad = sum(1 for c in range(-32768, 32768) if bit_div(c) != bit_mul(c))
    print(f"message-bit mismatches over all 65,536 int16 values: {allbad} "
          f"(so callers must reduce coefficients first)")
    print("worked values (canonical c):")
    for c in (0, 832, 833, 1664, 2496, 2497, 3328):
        x = 2 * c + 1665
        print(f"   c = {c:4d}: 2c+1665 = {x:4d}; x*M = {x * M:>11,d}; >>28 = {(x * M) >> S}; "
              f"bit = {bit_mul(c)}; division code bit = {bit_div(c)}")
    # Negative control: a constant one larger is caught.
    def bit_bad(c):
        t = ((((c & MASK32) << 1) + 1665) * (M + 1)) & MASK32
        return (t >> S) & 1
    wrong = sum(1 for c in canonical if bit_bad(c) != bit_div(c))
    print(f"negative control: M+1 = {M + 1} gives {wrong} mismatches on [0, q)")
    assert wrong > 0
    assert all(bit_div(c) == bit_mul(c) for c in centred)
    assert all(bit_div(c) == bit_mul(c) for c in canonical)
    print("checks passed")


if __name__ == "__main__":
    main()
