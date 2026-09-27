"""Grover arithmetic for Turing, for research/notes/pq/quantum-crypto-and-quantum-attacks.md.

Reproduces and extends:
  * NIST PQC Call for Proposals (Dec 2016), Sec. 4.A.5, p. 18, and the Call for
    Additional Signatures (Sept 2022), Sec. 4.B.3, p. 17: quantum gate counts
    for AES key search of the form 2^X / MAXDEPTH, MAXDEPTH in [2^40, 2^96].
    Check: evaluating NIST's formulas at MAXDEPTH = 2^40, 2^64, 2^96 must give
    the "[NIS16]" rows of Jaques et al. Table 13 (ePrint 2019/1146, p. 32):
    130.0/106.0/74.0, 193.0/169.0/137.0, 258.0/234.0/202.0.
  * Jaques et al. Sec. 2.2 and 6.1 (pp. 5-6, 26): expected number of spurious
    keys (2^k - 1) * 2^(-r n) for r known blocks; AES-256 needs r = 3.
  * Grover (1996): about (pi/4) sqrt(N) iterations; Zalka (1999): parallel
    Grover on S machines needs (pi/4) sqrt(N/S) iterations each.
  * Kaplan et al., ToSC 2016(1), arXiv 1510.05836, Sec. 4.2.1 eq. (4) and
    Sec. 8 (pp. 9, 19-20): a Q2 differential distinguisher of probability
    2^-h costs 2^(h/2+1) queries, and needs h < n; a Q2 linear distinguisher
    costs 1/epsilon (epsilon = correlation) against 1/epsilon^2 classically.
    Sec. 8 p. 20: with k >= 2n the data complexity is always below 2^(k/2),
    so classical breaks tend to give Q1 breaks (q1_translation below).
  * Banegas, Bernstein, SAC 2017, ePrint 2017/789, Sec. 1.5 p. 4: t-target
    preimage search on p mesh-connected processors costs roughly
    sqrt(N / (p t^(1/2))) steps (t instead of t^(1/2) if communication were
    free).

It also counts S-boxes in one Grover-oracle evaluation of Turing and of
AES-256, as a crude proxy for circuit size and depth. The Turing constants are
read from the source tree (crates/turing/src/structure.rs, keyschedule.rs),
so the numbers follow the working tree; version 1 (docs/09, 16 rounds) is
printed alongside. AES-256's key expansion follows FIPS 197 upd1 Algorithm 2
(p. 18): SubWord when i mod Nk = 0, or Nk > 6 and i mod Nk = 4.

These S-box counts are NOT quantum resource estimates: no quantum circuit for
Turing exists. They only show the order of magnitude of the difference.

Run:  python research/scripts/pq/qc_grover_costs.py
"""
import math
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[3]
log2 = math.log2


def read_const(path, name):
    text = (ROOT / path).read_text(encoding="utf-8")
    m = re.search(rf"pub const {name}: usize = ([0-9]+);", text)
    if not m:
        raise SystemExit(f"constant {name} not found in {path}")
    return int(m.group(1))


def nist_table():
    print("=== NIST gate-count formulas 2^X / MAXDEPTH (log2 of total quantum gates) ===")
    formulas = {
        "2016 call Sec. 4.A.5 p. 18 (circuits of Grassl et al.)": {"AES-128": 170, "AES-192": 233, "AES-256": 298},
        "2022 call Sec. 4.B.3 p. 17 (cites Jaques et al. EUROCRYPT 2020)": {"AES-128": 157, "AES-192": 221, "AES-256": 285},
        "Jaques et al. revised ePrint 2019/1146, Table 13 p. 32 'approximation'": {"AES-128": 159, "AES-192": 224, "AES-256": 288},
    }
    for src, table in formulas.items():
        print(f"-- {src}")
        for name, x in table.items():
            vals = ", ".join(f"MAXDEPTH=2^{d}: 2^{x - d:.1f}" for d in (40, 64, 96))
            print(f"   {name}: 2^{x}/MAXDEPTH -> {vals}")
    expected = {"AES-128": (130.0, 106.0, 74.0), "AES-192": (193.0, 169.0, 137.0), "AES-256": (258.0, 234.0, 202.0)}
    first = next(iter(formulas.values()))
    ok = all(tuple(float(first[k] - d) for d in (40, 64, 96)) == v for k, v in expected.items())
    print(f"check against Jaques et al. Table 13 [NIS16] rows: {'match' if ok else 'MISMATCH'}")
    drops = [first[k] - list(formulas.values())[1][k] for k in first]
    print(f"2016 -> 2022 reduction in bits: {drops} (Jaques et al. p. 31: 11-13 bits in the original version, "
          f"9-12 in the revision)")
    print("NIST footnote 5 (both calls): the estimates 'may understate the quantum security of AES for very large")
    print("values of MAXDEPTH'; Jaques et al. p. 31: this is the case for AES-128 at MAXDEPTH = 2^96 (no parallelisation)")


def spurious(k, n):
    print(f"\n=== Known blocks needed for a unique key, k = {k}, n = {n} ===")
    for r in (1, 2, 3):
        lam_log2 = log2(2.0 ** k - 1) - r * n if r * n < k + 60 else k - r * n
        lam = 2.0 ** lam_log2
        p_unique = math.exp(-lam) if lam < 700 else 0.0
        print(f"r = {r}: expected spurious keys ~ 2^{lam_log2:.2f}; Pr[no spurious] ~ exp(-lambda) = {p_unique:.6g}")
    print("r = 3 is the smallest r with a negligible chance of a spurious key (the AES-256 value in Jaques et al. Sec. 6.1)")


def grover_iterations(k):
    print(f"\n=== Grover iterations for a {k}-bit key ===")
    it = math.pi / 4 * 2.0 ** (k / 2)
    print(f"(pi/4) * 2^{k//2} = 2^{log2(it):.2f} sequential oracle calls")
    for s_log in (20, 40, 64):
        per = math.pi / 4 * 2.0 ** ((k - s_log) / 2)
        print(f"  split over 2^{s_log} machines (Zalka): 2^{log2(per):.2f} iterations each, "
              f"2^{log2(per) + s_log:.2f} oracle calls in total")
    print("  total work grows as sqrt(S): parallel Grover is less efficient than one long run")


def aes256_sboxes():
    nk, nr = 8, 14
    subwords = 0
    for i in range(nk, 4 * nr + 4):
        if i % nk == 0 or (nk > 6 and i % nk == 4):
            subwords += 1
    return nr * 16, subwords * 4, nr  # cipher S-boxes, key-expansion S-boxes, S-box layers


def turing_sboxes(rounds, warmup, per_pair):
    round_keys = rounds + 1
    pairs = math.ceil(round_keys / 2)
    feistel = warmup + (pairs - 1) * per_pair
    return rounds * 16, feistel * 16, feistel, round_keys


def oracle_proxy():
    print("\n=== S-box count of one Grover oracle call (proxy only, r = 3 known blocks) ===")
    rounds = read_const("crates/turing/src/structure.rs", "ROUNDS")
    warmup = read_const("crates/turing/src/keyschedule.rs", "WARMUP_ROUNDS")
    per_pair = read_const("crates/turing/src/keyschedule.rs", "ROUNDS_PER_PAIR")
    a_c, a_k, a_layers = aes256_sboxes()
    r = 3
    aes_g = a_k + r * a_c
    aes_d = a_layers  # key expansion runs alongside the rounds
    print(f"AES-256: cipher {a_c} S-boxes (14 rounds x 16), key expansion {a_k} "
          f"(13 SubWord x 4); oracle with r = 3: {aes_g} S-boxes, about {aes_d} S-box layers deep")
    for label, rr in (("Turing v1 (docs/09)", 16), (f"Turing working tree (structure.rs ROUNDS = {rounds})", rounds)):
        t_c, t_k, feistel, nkeys = turing_sboxes(rr, warmup, per_pair)
        g = t_k + r * t_c
        d = feistel + 1
        print(f"{label}: {nkeys} round keys, {feistel} Feistel rounds -> key schedule {t_k} S-boxes, "
              f"cipher {t_c}; oracle with r = 3: {g} S-boxes; about {d} S-box layers deep")
        print("   (no Keccak counted: an attacker can Grover-search the 256-bit whitened key K' = cSHAKE256(K)"
              " directly, since K' alone fixes every round key, so the cSHAKE layer adds nothing to key search)")
        ratio = (g / aes_g) * (d / aes_d)
        print(f"   ratio to AES-256: size x{g/aes_g:.2f}, depth x{d/aes_d:.2f}; "
              f"under a depth limit total gates scale with size x depth: x{ratio:.1f} = +{log2(ratio):.1f} bits")


def kaplan_bounds():
    print("\n=== Q2 differential/linear distinguishers from Turing's published bounds (Kaplan et al. eq. 4, Sec. 8) ===")
    n = 128
    # docs/09 table: minimum active S-boxes per window (v1), S-box max DP = 2^-6.
    trail = {1: 1, 2: 5, 3: 18, 4: 25, 5: 35}
    print("Probabilities below are UPPER bounds, so every cost below is a LOWER bound on a distinguisher's cost.")
    for w, a in trail.items():
        h = 6 * a
        if h < n:
            print(f"{w} rounds: every trail <= 2^-{h}; a single-trail distinguisher needs >= 2^{h/2 + 1:.0f} "
                  f"superposition queries (Q2) or >= 2^{h + 1} classical ones")
        else:
            print(f"{w} rounds: every trail <= 2^-{h} < 2^-{n}: fewer than one right pair per input difference, "
                  f"so no distinguisher from a single trail in either model")
    # docs/09 / docs/12: provable bounds that count all trails at once (independent round keys).
    for rounds, name, lg in ((3, "differential (MEDP)", 102.0), (3, "linear hull (MELP = correlation^2)", 99.6),
                             (5, "differential (MEDP)", 110.8), (5, "linear hull (MELP = correlation^2)", 105.9)):
        if "linear" in name:
            print(f"{rounds} rounds, {name} <= 2^-{lg}: classical >= 2^{lg:.1f} = 1/eps^2, "
                  f"Q2 >= 2^{lg/2:.2f} = 1/eps")
        else:
            print(f"{rounds} rounds, {name} <= 2^-{lg}: classical >= 2^{lg + 1:.1f}, Q2 >= 2^{lg/2 + 1:.1f}")
    print("Note: the 5-round all-trail bounds (2^-110.8, 2^-105.9) are above 2^-128, so they do not by themselves")
    print("exclude a usable 4- or 5-round differential or hull; docs/09 relies on its round margin for that gap,")
    print("and the gap is the same in the classical, Q1 and Q2 models.")
    print("Reading: quantum cost >= sqrt(classical cost); the h < n limit is the same in both models,")
    print("so the classical 'usable trails cover at most 3 rounds' step of docs/09 carries over; the key-guessing")
    print("terms of an attack shrink from 2^g to 2^(g/2), exactly as brute force shrinks from 2^256 to 2^128.")


def multi_target():
    print("\n=== Generic multi-target search (t keys encrypting one shared known block) ===")
    print("Banegas-Bernstein SAC 2017 (ePrint 2017/789) Sec. 1.5 p. 4: with p processors on a 2-D mesh a t-target")
    print("preimage costs roughly sqrt(N / (p t^(1/2))) steps; without communication cost t^(1/2) would be t.")
    k = 256
    for t_log in (0, 32, 64):
        for p_log in (0, 40):
            ideal = (k - p_log - t_log) / 2
            real = (k - p_log - t_log / 2) / 2
            print(f"t = 2^{t_log}, p = 2^{p_log}: classical 2^{k - t_log} trials in total; quantum time on p processors "
                  f"~ 2^{real:.1f} steps (mesh model), ~ 2^{ideal:.1f} (communication ignored)")
    print("Precondition: every target encrypts the SAME known block under its own key, so one function H(k) = E_k(m)")
    print("covers all targets. A per-file random value in the block-cipher input removes the shared m.")


def q1_translation():
    print("\n=== Why k = 2n makes the classical margin the quantum margin (Kaplan et al. ToSC 2016, Sec. 8) ===")
    print("Q1 last-rounds attack: T_Q1 = D + sqrt(key-guessing work) (constants and C_kout dropped).")
    print("For Turing n = 128, k = 256: classical data D <= 2^128 = 2^(k/2) always.")
    for d_log, w_log in ((100, 220), (120, 250), (127, 255)):
        t_c = max(d_log, w_log)
        t_q = max(d_log, w_log / 2)
        print(f"  D = 2^{d_log}, key guessing W = 2^{w_log}: classical ~2^{t_c} < 2^256 (a break); "
              f"Q1 ~2^{t_q:.1f} < 2^128 = Grover (also a break)")
    print("So every classical attack faster than 2^256 that needs fewer than about 2^127 blocks gives a Q1 attack")
    print("faster than Grover, if its key-guessing part quantises quadratically (the paper's point for k >= 2n).")


if __name__ == "__main__":
    nist_table()
    spurious(256, 128)
    grover_iterations(256)
    oracle_proxy()
    kaplan_bounds()
    multi_target()
    q1_translation()
