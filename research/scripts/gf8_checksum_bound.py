"""The keyed checksum's fault bound in GF(2^8), where everything can be tried
(docs/13, keyschedule.rs `checksum`).

The checksum is sum_i H^(i+1) * k_i over N round keys. A fault that changes
the keys by E_i and the stored check by e, leaving the point H alone, passes
exactly when sum_i H^(i+1) * E_i = e: a non-zero polynomial in H of degree
at most N, so at most N points pass. With N = 4 in GF(2^8) (reduction
polynomial 0x11b, as in the S-box field), this script:

  1. samples random faults and counts, for each, the odd points H that pass
     (the cipher requires the point to be odd): never more than 4;
  2. checks that the bound is attained, by the fault E = (80, bd, bb, 55),
     e = 39, which passes at 11, 79, 87 and bf;
  3. checks that a fault which also moves H by d != 0 passes for exactly one
     k_0 out of 256, for every point: round key 0's term is d * k_0 and k_0
     appears nowhere else.

Before the review of 2026-09-27 (F2) docs/13 said "no fault tried passed at
more than 3", which was sample luck; this script is the check the page cites.

    python research/scripts/gf8_checksum_bound.py [SAMPLES]
"""
import random
import sys

N = 4


def mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def power(h, n):
    r = 1
    for _ in range(n):
        r = mul(r, h)
    return r


# POW[h][i] = h^(i+1), for the N weights.
POW = [[power(h, i + 1) for i in range(N)] for h in range(256)]


def checksum(keys, h):
    s = 0
    for i, k in enumerate(keys):
        s ^= mul(POW[h][i], k)
    return s


def passing_points(E, e):
    return [h for h in range(1, 256, 2) if checksum(E, h) == e]


def main():
    samples = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    rng = random.Random(20260928)
    worst, histogram = 0, {}
    for _ in range(samples):
        E = [rng.randrange(256) for _ in range(N)]
        if not any(E):
            continue
        e = rng.randrange(256)
        n = len(passing_points(E, e))
        histogram[n] = histogram.get(n, 0) + 1
        worst = max(worst, n)
    print(f"1. {samples} random faults with H untouched: passing odd points per fault {dict(sorted(histogram.items()))}; most {worst}")
    assert worst <= N, "a fault passed at more points than the degree allows"

    example = passing_points([0x80, 0xBD, 0xBB, 0x55], 0x39)
    print(f"2. E = (80, bd, bb, 55), e = 39 passes at {[f'{h:02x}' for h in example]}")
    assert example == [0x11, 0x79, 0x87, 0xBF], "the bound 4 is attained"

    moved = 0
    for _ in range(2_000):
        h = rng.randrange(1, 256, 2)
        d = rng.randrange(1, 256)
        keys = [0] + [rng.randrange(256) for _ in range(N - 1)]
        E = [rng.randrange(256) for _ in range(N)]
        e = rng.randrange(256)
        # The fault moves the keys by E, the check by e and the point to h + d.
        count = 0
        for k0 in range(256):
            keys[0] = k0
            faulted = [k ^ x for k, x in zip(keys, E)]
            if checksum(faulted, h ^ d) == checksum(keys, h) ^ e:
                count += 1
        assert count == 1, f"H moved: {count} values of k0 pass (h {h:02x}, d {d:02x})"
        moved += 1
    print(f"3. {moved} faults that also move H: each passes for exactly one k0 in 256")


if __name__ == "__main__":
    main()
