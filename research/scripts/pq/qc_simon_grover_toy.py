"""Toy quantum simulations for the notes research/notes/pq/quantum-crypto-and-quantum-attacks.md.

Reproduces, on tiny parameters, the mechanisms described in:

  * Grover (1996), arXiv quant-ph/9605043: about (pi/4)*sqrt(N/M) iterations
    find one of M marked items among N; Zalka (1999) shows this is optimal.
  * Kaplan, Leurent, Leverrier, Naya-Plasencia, CRYPTO 2016, arXiv 1602.05973:
      - Sec. 2.1: Simon's algorithm (each run gives a random y with y.s = 0);
      - Sec. 3.2: Kuwakado-Morii attack on Even-Mansour E(x) = P(x^k1)^k2 with
        f(x) = E(x) ^ P(x), which has period k1;
      - Sec. 6: slide attack with f(b,x) = P(E(x))^x (b=0), E(P(x))^x (b=1),
        period 1||k, for a cipher of r identical keyed rounds.
  * Roetteler, Steinwandt, Inf. Process. Lett. 115(1):40-44, 2015, arXiv
    1306.2301, Sec. 3: with a superposition of XOR-related keys, the paper's
    function f_s(x) = {E_x(m), E_{s^x}(m)} (an unordered pair, stored as
    (min, max)) has period s, whatever the key schedule is. The toy below
    uses the equivalent two-branch encoding f(b,x) = E_x(m) (b=0),
    E_{K^x}(m) (b=1), whose period is 1||K (the same device as KLLN's slide
    function); both need r > ceil(k/n) known blocks so the key is unique.
  * Jaques et al., EUROCRYPT 2020 (ePrint 2019/1146) Sec. 2.2 / 6.1: number of
    known plaintext blocks r needed so that the key is unique.

Simulation method. Simon's algorithm is simulated exactly, not by sampling a
classical shortcut: the output register is measured first (allowed by the
principle of deferred measurement), which collapses the input register to the
uniform superposition over the preimage set f^-1(y); the Walsh-Hadamard
transform of that state is computed with numpy and the measured y is drawn
from its squared amplitudes. Grover's algorithm is simulated as a full
statevector. Everything is seeded, so every run prints the same numbers.

Run:  python research/scripts/pq/qc_simon_grover_toy.py
"""
import math

import numpy as np

SEED = 20260926
rng = np.random.default_rng(SEED)


# ---------------------------------------------------------------- helpers
def wht(v):
    """Normalised Walsh-Hadamard transform of a length-2^m vector (= H^{(x)m})."""
    v = v.astype(float).copy()
    h = 1
    n = len(v)
    while h < n:
        v = v.reshape(-1, 2, h)
        a = v[:, 0, :].copy()
        b = v[:, 1, :].copy()
        v[:, 0, :] = a + b
        v[:, 1, :] = a - b
        v = v.reshape(n)
        h *= 2
    return v / math.sqrt(n)


def simon_sample(f_table, nbits):
    """One run of Simon's subroutine on f given as a table over 2^nbits inputs.

    Returns the measured y (an int), distributed exactly as in the quantum
    circuit H - O_f - measure output - H - measure input.
    """
    size = 1 << nbits
    x0 = int(rng.integers(size))              # Pr[output = y] = |f^-1(y)| / 2^n
    y_val = f_table[x0]
    state = (f_table == y_val).astype(float)  # uniform over the preimage set
    state /= np.linalg.norm(state)
    amp = wht(state)
    probs = amp ** 2
    probs /= probs.sum()
    return int(rng.choice(size, p=probs))


def gf2_nullspace(rows, nbits):
    """Basis of {s : s.u = 0 for all u in rows} over GF(2); rows are ints."""
    pivots = {}                               # pivot bit -> reduced row
    for r in rows:
        for bit in sorted(pivots, reverse=True):
            if (r >> bit) & 1:
                r ^= pivots[bit]
        if r:
            top = r.bit_length() - 1
            for bit in list(pivots):          # keep rows fully reduced
                if (pivots[bit] >> top) & 1:
                    pivots[bit] ^= r
            pivots[top] = r
    free = [b for b in range(nbits) if b not in pivots]
    basis = []
    for fb in free:
        s = 1 << fb
        for bit, row in pivots.items():
            # row has leading bit `bit`; s must satisfy row.s = 0
            if bin(row & s).count("1") % 2:
                s |= 1 << bit
        basis.append(s)
    return basis, len(pivots)


def run_simon(f_table, nbits, queries):
    ys = [simon_sample(f_table, nbits) for _ in range(queries)]
    basis, rank = gf2_nullspace(ys, nbits)
    return ys, basis, rank


def random_perm(nbits):
    return rng.permutation(1 << nbits)


def check_period(f_table, s, trials=64):
    size = len(f_table)
    xs = rng.integers(size, size=trials)
    return all(f_table[x] == f_table[x ^ s] for x in xs)


# ---------------------------------------------------------------- 1. Grover
def grover_demo():
    print("=== 1. Grover search (statevector) ===")
    nbits = 10
    size = 1 << nbits
    for marked_count in (1, 4):
        marked = rng.choice(size, size=marked_count, replace=False)
        oracle = np.ones(size)
        oracle[marked] = -1.0
        state = np.full(size, 1 / math.sqrt(size))
        k_opt = math.floor(math.pi / 4 * math.sqrt(size / marked_count))
        for _ in range(k_opt):
            state = oracle * state                      # phase oracle
            state = 2 * state.mean() - state            # inversion about the mean
        p = float(np.sum(state[marked] ** 2))
        print(f"N = 2^{nbits}, M = {marked_count}: {k_opt} iterations "
              f"(pi/4*sqrt(N/M) = {math.pi/4*math.sqrt(size/marked_count):.2f}); "
              f"success probability {p:.4f}; classical expected guesses about N/(2M) = {size/(2*marked_count):.0f}")
    # Over-rotation: running twice as long gets worse, a property of Grover.
    marked = [123]
    oracle = np.ones(size)
    oracle[marked] = -1.0
    state = np.full(size, 1 / math.sqrt(size))
    for _ in range(2 * math.floor(math.pi / 4 * math.sqrt(size))):
        state = oracle * state
        state = 2 * state.mean() - state
    print(f"N = 2^{nbits}, M = 1, twice the optimal iterations: success probability "
          f"{float(state[123]**2):.4f} (Grover must know roughly how many solutions exist)")


# ------------------------------------------------ 2. spurious keys, toy cipher
def toy_cipher_table(kbits, nbits):
    """A random keyed permutation family: E[k] is a permutation of 2^nbits."""
    return np.array([random_perm(nbits) for _ in range(1 << kbits)])


def spurious_demo():
    print("\n=== 2. How many known blocks make the key unique (toy, k = 12, n = 8) ===")
    kbits, nbits = 12, 8
    table = toy_cipher_table(kbits, nbits)
    key = int(rng.integers(1 << kbits))
    msgs = rng.choice(1 << nbits, size=3, replace=False)
    for r in (1, 2, 3):
        cands = np.ones(1 << kbits, dtype=bool)
        for m in msgs[:r]:
            cands &= table[:, m] == table[key, m]
        expected = ((1 << kbits) - 1) * 2.0 ** (-r * nbits)
        print(f"r = {r} block(s): {int(cands.sum())} key(s) consistent "
              f"(true key included: {bool(cands[key])}); expected spurious (2^k-1)*2^(-rn) = {expected:.3f}")
    print("For Turing (k = 256, n = 128): see qc_grover_costs.py (r = 3 gives expected spurious 2^-128).")


# ------------------------------------------------ 3. Even-Mansour (Kuwakado-Morii)
def even_mansour_demo():
    print("\n=== 3. Simon on Even-Mansour E(x) = P(x ^ k1) ^ k2, n = 8 (superposition queries, Q2) ===")
    nbits = 8
    size = 1 << nbits
    P = random_perm(nbits)
    k1, k2 = int(rng.integers(1, size)), int(rng.integers(size))
    xs = np.arange(size)
    E = P[xs ^ k1] ^ k2
    f = E ^ P[xs]                                  # f(x) = E(x) ^ P(x), period k1
    ys, basis, rank = run_simon(f, nbits, queries=3 * nbits)
    cand = [s for s in basis if check_period(f, s)]
    print(f"secret k1 = {k1:#04x}; {len(ys)} superposition queries; rank of the y's = {rank} (n - 1 = {nbits-1} expected)")
    print(f"null-space basis = {[hex(s) for s in basis]}; candidates passing a classical period check = {[hex(s) for s in cand]}")
    if cand:
        rec_k1 = cand[0]
        rec_k2 = int(E[0] ^ P[0 ^ rec_k1])
        print(f"recovered k1 = {rec_k1:#04x} (correct: {rec_k1 == k1}), k2 = E(0) ^ P(k1) = {rec_k2:#04x} (correct: {rec_k2 == k2})")
    all_y_orth = all(bin(y & k1).count("1") % 2 == 0 for y in ys)
    print(f"every measured y satisfies y.k1 = 0: {all_y_orth}")


# ------------------------------------------------ 4. Slide attack, and constants
def slide_demo():
    print("\n=== 4. Quantum slide attack (KLLN16 Sec. 6), n = 8, r = 12 rounds ===")
    nbits = 8
    size = 1 << nbits
    rounds = 12
    P = random_perm(nbits)
    xs = np.arange(size)

    def encrypt(x, keys):
        for k in keys:
            x = P[x ^ k]
        return x ^ keys[-1]

    k = int(rng.integers(1, size))
    same = [k] * rounds
    E = encrypt(xs, same)
    f = np.concatenate([P[E] ^ xs, encrypt(P[xs], same) ^ xs])  # index = b*2^n + x
    ys, basis, rank = run_simon(f, nbits + 1, queries=3 * (nbits + 1))
    cand = [s for s in basis if check_period(f, s)]
    print(f"identical round keys, no constants: secret k = {k:#04x}; rank = {rank} of {nbits+1}; "
          f"period candidates = {[hex(s) for s in cand]} (expected 1||k = {(1 << nbits) | k:#05x})")

    # Same cipher, but each round key XORed with a distinct round constant.
    consts = [int(c) for c in rng.integers(size, size=rounds)]
    keys = [k ^ c for c in consts]
    E2 = encrypt(xs, keys)
    f2 = np.concatenate([P[E2] ^ xs, encrypt(P[xs], keys) ^ xs])
    ys2, basis2, rank2 = run_simon(f2, nbits + 1, queries=3 * (nbits + 1))
    cand2 = [s for s in basis2 if s and check_period(f2, s)]
    print(f"distinct round constants: rank = {rank2} of {nbits+1}; nonzero period candidates = {cand2} "
          f"(none expected: the slide property P(E(x)) ^ k = E(P(x ^ k)) no longer holds)")


# ------------------------------------------------ 5. Quantum related-key attack
def related_key_demo():
    print("\n=== 5. Quantum related-key attack (Roetteler-Steinwandt), k = 10, n = 8 ===")
    kbits, nbits = 10, 8
    table = toy_cipher_table(kbits, nbits)          # E_K for every K: any key schedule
    # A 'whitened' key schedule: the cipher really uses W(K) for a random
    # bijection W (standing in for cSHAKE whitening). The attack never looks inside.
    W = rng.permutation(1 << kbits)
    # The paper's inequality (1) asks for r > ceil(k/n) blocks; ceil(10/8) = 2, so r = 3.
    msgs = rng.choice(1 << nbits, size=3, replace=False)
    secret = int(rng.integers(1, 1 << kbits))

    def enc_blocks(K):
        return tuple(int(table[W[K], m]) for m in msgs)

    # Encode the pair of ciphertext tuples as one integer label for f.
    labels = {}
    fvals = np.empty(2 << kbits, dtype=np.int64)
    for b in (0, 1):
        for x in range(1 << kbits):
            key = x if b == 0 else secret ^ x     # b = 1 uses the related-key oracle
            t = enc_blocks(key)
            fvals[(b << kbits) | x] = labels.setdefault(t, len(labels))
    ys, basis, rank = run_simon(fvals, kbits + 1, queries=3 * (kbits + 1))
    cand = [s for s in basis if check_period(fvals, s)]
    print(f"secret K = {secret:#05x}; rank = {rank} of {kbits+1}; candidates = {[hex(s) for s in cand]} "
          f"(expected 1||K = {(1 << kbits) | secret:#05x}); key whitening W did not matter")


if __name__ == "__main__":
    print(f"seed = {SEED}")
    grover_demo()
    spurious_demo()
    even_mansour_demo()
    slide_demo()
    related_key_demo()
