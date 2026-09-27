"""dfr.py - decryption-failure-rate (DFR) calculator for ML-KEM (FIPS 203) and FrodoKEM.

What it reproduces, and from where
----------------------------------
* ML-KEM: the "decapsulation failure rate" column of FIPS 203 Table 1 (section 3.2, PDF page 24,
  printed page 15): ML-KEM-512 2^-138.8, ML-KEM-768 2^-164.8, ML-KEM-1024 2^-174.8, with the
  parameters of FIPS 203 Table 2 (section 8, PDF page 48, printed page 39). FIPS 203 cites the
  pq-crystals "security-estimates" scripts (its reference [15]) for these numbers; the round-3
  Kyber specification (Table 1, PDF page 11) gives 2^-139 / 2^-164 / 2^-174.
  Cross-check against the script itself: dfr_run_pqcrystals.py dumps its law as JSON.
* FrodoKEM: the "failure rate" column of the FrodoKEM round-3 specification Table 2 (PDF page 24)
  and of the 2025 ISO preliminary standardization proposal Table A.9 (Annex D, PDF page 19):
  Frodo-640 2^-138.7, Frodo-976 2^-199.6, Frodo-1344 2^-252.5, using the error tables of
  round-3 Table 3 (PDF page 25) / 2025 Table A.3 (PDF page 15). The published figures use the
  symmetric rule |e| >= q/2^(B+1) (the submission's own failure_prob_pke.py folds x to
  min(x, q-x)); the exact decode interval of round-3 Lemma 2.18 is [-q/2^(B+1), q/2^(B+1)).
  Cross-check against the official code: dfr_run_frodo_script.py.
* Barbosa, Kannwischer, Lim, Schwabe, Strub, "Formally verified correctness bounds for
  lattice-based cryptography" (ACM CCS 2025, ePrint 2025/1562), Table 1 (PDF page 13): ML-KEM-768
  provable 2^-80, heur(cu,cv) 2^-164, heur(cu) 2^-158; ML-KEM-1024 2^-95, 2^-174, 2^-169; optimal
  split thresholds t_cu = 296 / 240 (section 5.5, PDF page 12). Sub-command `provable`.

Method (the same in spirit as both specifications)
--------------------------------------------------
Decryption computes "message + error" and rounds. The error is a sum of many products of small
random numbers. Its exact probability law is built by convolution: the law of a sum of
independent integers is the convolution of their laws, and the law of a product X*Y is
sum_{a*b=z} P(X=a)P(Y=b). One coefficient's law is exact; the failure rate of the whole
message is bounded with the union bound (number of coefficients x per-coefficient rate).
For ML-KEM one extra modelling step is needed: the rounding ("compression") errors of the
ciphertext are treated as independent of everything else, with the law of the rounding
error of a uniformly random element of Z_q. FrodoKEM needs no such step.

Arithmetic: float64 with direct (not FFT) convolution (numpy.convolve). All terms are
non-negative, so relative rounding error stays near 1e-12 even for values near 2^-260
(FFT convolution would destroy such tails). Tail sums use math.fsum. Entries below 2^-900
are trimmed; the dropped mass is below 2^-880 and cannot affect any printed digit.

Sub-commands (every one prints what it checks, and PASS/FAIL where there is a target)
------------------------------------------------------------------------------------
  python dfr.py validate [PQCRYSTALS_JSON]  reproduce FIPS 203 Table 1 and FrodoKEM Table 2,
                                          explain the 0.4-bit gap to the pq-crystals script,
                                          run negative controls and an exact-rational check
  python dfr.py simulate [TRIALS]           Monte-Carlo run of real toy schemes (random A,
                                          real compression) against the model's prediction
  python dfr.py weakkeys [SAMPLES [SEED]]   per-key DFR: how much worse the unluckiest keys are
  python dfr.py boost                       failure-boosting cost bracket (norm-based selection)
                                          for ML-KEM-768/1024 and three dimension-1024 variants
  python dfr.py provable                    reproduce the heuristic-free bound of Barbosa et al.
                                          (CCS 2025, Table 1) and apply it to dim-1024 variants
  python dfr.py sweep                       DFR trade-offs for ~1000-dimension designs
  python dfr.py all [PQCRYSTALS_JSON]       everything above

Deterministic: fixed seeds; no network; runs in a few minutes.
"""
from __future__ import annotations

import json
import math
import sys
from fractions import Fraction
from math import comb, fsum, log2

import numpy as np

TRIM = 2.0 ** -900


# --------------------------------------------------------------------------------------
# Probability laws on consecutive integers
# --------------------------------------------------------------------------------------
class Law:
    """P(X = lo + i) = p[i]."""

    def __init__(self, lo: int, p):
        self.lo = int(lo)
        self.p = np.asarray(p, dtype=np.float64)

    @staticmethod
    def from_dict(d: dict) -> "Law":
        lo, hi = min(d), max(d)
        p = np.zeros(hi - lo + 1)
        for k, v in d.items():
            p[k - lo] += float(v)
        return Law(lo, p)

    @property
    def hi(self) -> int:
        return self.lo + len(self.p) - 1

    def support(self) -> np.ndarray:
        return np.arange(self.lo, self.hi + 1)

    def trim(self, eps: float = TRIM) -> "Law":
        nz = np.nonzero(self.p > eps)[0]
        if len(nz) == 0:
            return Law(0, [1.0])
        return Law(self.lo + nz[0], self.p[nz[0]: nz[-1] + 1].copy())

    def conv(self, other: "Law") -> "Law":
        return Law(self.lo + other.lo, np.convolve(self.p, other.p)).trim()

    def power(self, n: int) -> "Law":
        """Law of the sum of n independent copies (binary powering)."""
        result = Law(0, [1.0])
        base = self
        while n:
            if n & 1:
                result = result.conv(base)
            n >>= 1
            if n:
                base = base.conv(base)
        return result

    def scale(self, c: int) -> "Law":
        """Law of c*X for an integer c != 0."""
        if c == 0:
            return Law(0, [1.0])
        xs = self.support() * c
        lo, hi = xs.min(), xs.max()
        p = np.zeros(hi - lo + 1)
        p[xs - lo] = self.p
        return Law(lo, p)

    def times(self, other: "Law") -> "Law":
        """Law of X*Y for independent X ~ self, Y ~ other."""
        d: dict = {}
        for a, pa in zip(self.support(), self.p):
            for b, pb in zip(other.support(), other.p):
                d[int(a * b)] = d.get(int(a * b), 0.0) + pa * pb
        return Law.from_dict(d)

    def total(self) -> float:
        return fsum(self.p)

    def mean(self) -> float:
        return float(np.dot(self.support(), self.p))

    def var(self) -> float:
        m = self.mean()
        return float(np.dot((self.support() - m) ** 2, self.p))

    def prob(self, pred) -> float:
        """fsum of P(X=x) over x with pred(x) true (pred takes a numpy int array)."""
        mask = pred(self.support())
        return fsum(sorted(self.p[mask]))  # ascending order: small tail terms first


def cbd(eta: int) -> Law:
    """Centred binomial law of FIPS 203 (Algorithm 8): x - y, x, y ~ Binomial(eta, 1/2)."""
    return Law(-eta, [comb(2 * eta, k) / 4.0 ** eta for k in range(2 * eta + 1)])


def cbd_exact(eta: int) -> dict:
    return {k - eta: Fraction(comb(2 * eta, k), 4 ** eta) for k in range(2 * eta + 1)}


def table_law(half_table, denom_bits: int = 16) -> Law:
    """Symmetric law from a FrodoKEM table of P(0), P(+-1), ... in multiples of 2^-16."""
    m = len(half_table) - 1
    p = [half_table[abs(i)] / 2.0 ** denom_bits for i in range(-m, m + 1)]
    return Law(-m, p)


# --------------------------------------------------------------------------------------
# ML-KEM (FIPS 203) error model
# --------------------------------------------------------------------------------------
def round_half_up(num: int, den: int) -> int:
    """FIPS 203 section 2.3: round to nearest, ties (y + 1/2) go up. num, den > 0 integers."""
    return (2 * num + den) // (2 * den)


def compress(x: int, d: int, q: int) -> int:
    return round_half_up((1 << d) * x, q) % (1 << d)  # FIPS 203 eq. (4.7)


def decompress(y: int, d: int, q: int) -> int:
    return round_half_up(q * y, 1 << d)  # FIPS 203 eq. (4.8)


def centred(a: int, q: int) -> int:
    a %= q
    return a - q if a > q // 2 else a


def compression_error_law(q: int, d: int, rounding: str = "fips") -> Law:
    """Law of Decompress_d(Compress_d(x)) - x for x uniform in Z_q.

    rounding="fips"   : exact integer arithmetic of FIPS 203 (ties round up).
    rounding="python3": what pq-crystals' proba_util.mod_switch does under Python 3
                        (round() rounds ties to even) - used only to match that script.
    """
    counts: dict = {}
    for x in range(q):
        if rounding == "fips":
            z = decompress(compress(x, d, q), d, q)
        else:
            y = int(round(1.0 * (1 << d) * x / q) % (1 << d))
            z = int(round(1.0 * q * y / (1 << d)) % q)
        e = centred(z - x, q)
        counts[e] = counts.get(e, 0) + 1
    return Law.from_dict({k: v / q for k, v in counts.items()})


class MLKEMParams:
    def __init__(self, name, k, eta1, eta2, du, dv, n=256, q=3329):
        self.name, self.k, self.eta1, self.eta2, self.du, self.dv = name, k, eta1, eta2, du, dv
        self.n, self.q = n, q

    def with_(self, **kw) -> "MLKEMParams":
        d = dict(name=self.name, k=self.k, eta1=self.eta1, eta2=self.eta2, du=self.du,
                 dv=self.dv, n=self.n, q=self.q)
        d.update(kw)
        return MLKEMParams(**d)


# FIPS 203 Table 2 (section 8, printed page 39)
MLKEM = [
    MLKEMParams("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4),
    MLKEMParams("ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4),
    MLKEMParams("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5),
]
FIPS203_TABLE1 = {"ML-KEM-512": -138.8, "ML-KEM-768": -164.8, "ML-KEM-1024": -174.8}


def mlkem_error_law(P: MLKEMParams, rounding: str = "fips", sign_dv: int = +1) -> Law:
    """Law of one coefficient of  e^T r + e2 + dv - s^T (e1 + du)  (see FIPS 203 Alg. 14/15).

    s, e, r ~ CBD(eta1); e1, e2 ~ CBD(eta2); du, dv = compression errors (independence
    heuristic). The term e^T r is a sum of k*n products (each key coefficient meets exactly one
    r coefficient in a given output coefficient, up to sign, and the laws are symmetric).
    """
    s = cbd(P.eta1)
    e1 = cbd(P.eta2)
    du = compression_error_law(P.q, P.du, rounding)
    dv = compression_error_law(P.q, P.dv, rounding)
    if sign_dv < 0:
        dv = dv.scale(-1)
    er = s.times(s).power(P.k * P.n)              # e^T r : e, r both CBD(eta1)
    su = s.times(e1.conv(du)).power(P.k * P.n)    # s^T (e1 + du)
    return er.conv(su).conv(e1.conv(dv))          # + e2 + dv


def mlkem_coeff_failure(law: Law, q: int) -> tuple[float, float]:
    """Exact per-coefficient failure probability for message bit 0 and bit 1.

    FIPS 203: mu = Decompress_1(bit) (0 or 1665); decryption returns Compress_1(mu + err mod q).
    """
    mu1 = decompress(1, 1, q)
    xs = law.support()

    def comp1(w):
        w = np.mod(w, q)
        return ((4 * w + q) // (2 * q)) % 2      # Compress_1 with ties up (never tie: q odd)

    fail0 = comp1(xs) != 0
    fail1 = comp1(xs + mu1) != 1
    p0 = fsum(sorted(law.p[fail0]))
    p1 = fsum(sorted(law.p[fail1]))
    return p0, p1


def symmetric_tail(law: Law, t: float) -> float:
    """P(|X| >= ceil(t)) summed like pq-crystals tail_probability (which stops at max-1)."""
    lo = int(math.ceil(t))
    xs = law.support()
    mask = (np.abs(xs) >= lo) & (np.abs(xs) < law.hi)
    return fsum(sorted(law.p[mask]))


def mlkem_dfr(P: MLKEMParams, rounding="fips"):
    law = mlkem_error_law(P, rounding)
    p0, p1 = mlkem_coeff_failure(law, P.q)
    avg = P.n * (p0 + p1) / 2.0      # union bound, uniformly random message
    worst = P.n * max(p0, p1)        # union bound, worst message (HHK-style max over m)
    return law, p0, p1, avg, worst


# --------------------------------------------------------------------------------------
# FrodoKEM error model
# --------------------------------------------------------------------------------------
class FrodoParams:
    def __init__(self, name, n, D, B, table, nbar=8):
        self.name, self.n, self.D, self.B, self.table, self.nbar = name, n, D, B, table, nbar
        self.q = 1 << D

    def with_(self, **kw) -> "FrodoParams":
        d = dict(name=self.name, n=self.n, D=self.D, B=self.B, table=self.table, nbar=self.nbar)
        d.update(kw)
        return FrodoParams(**d)


# FrodoKEM round-3 spec Table 1/3/4 (pages 24-25) = 2025 proposal Tables A.1 and A.3
FRODO = [
    FrodoParams("Frodo-640", 640, 15, 2,
                [9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1]),
    FrodoParams("Frodo-976", 976, 16, 3,
                [11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1]),
    FrodoParams("Frodo-1344", 1344, 16, 4, [18286, 14320, 6876, 2023, 364, 40, 2]),
]
FRODO_TABLE2 = {"Frodo-640": -138.7, "Frodo-976": -199.6, "Frodo-1344": -252.5}


def frodo_error_law(P: FrodoParams) -> Law:
    """Law of one entry of E''' = S'E + E'' - E'S: 2n products of two chi samples plus one chi
    (round-3 spec section 2.2.7, page 19)."""
    chi = table_law(P.table)
    return chi.times(chi).power(2 * P.n).conv(chi)


def frodo_dfr(P: FrodoParams):
    """Decode (2025 proposal section 7.3) is floor((C + 2^(D-B-1)) / 2^(D-B)) mod 2^B, so an
    entry decodes correctly iff err is in [-q/2^(B+1), q/2^(B+1)) - the rule of round-3
    section 2.2.7. The message value does not matter."""
    law = frodo_error_law(P)
    h = P.q >> (P.B + 1)
    p = law.prob(lambda x: (x < -h) | (x >= h))
    return law, p, P.nbar * P.nbar * p


# --------------------------------------------------------------------------------------
# helpers for printing
# --------------------------------------------------------------------------------------
def lg(x: float) -> float:
    return log2(x) if x > 0 else float("-inf")


def check(label: str, ok: bool) -> bool:
    print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
    return ok


# --------------------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------------------
def exact_small_check() -> bool:
    """Exactness of the machinery: build a small law two ways - by brute-force enumeration with
    exact fractions, and with Law.times/power/conv in float64 - and compare every entry."""
    print("\n[exact-check] 3 products CBD(2)*CBD(2) plus one CBD(2), by enumeration vs Law code")
    c = cbd_exact(2)
    exact: dict = {}
    vals = list(c.items())
    for a1, p1 in vals:
        for b1, q1 in vals:
            for a2, p2 in vals:
                for b2, q2 in vals:
                    for a3, p3 in vals:
                        for b3, q3 in vals:
                            for g, pg in vals:
                                z = a1 * b1 + a2 * b2 + a3 * b3 + g
                                exact[z] = exact.get(z, 0) + p1 * q1 * p2 * q2 * p3 * q3 * pg
    law = cbd(2).times(cbd(2)).power(3).conv(cbd(2))
    worst = 0.0
    for z, pz in exact.items():
        got = law.p[z - law.lo] if law.lo <= z <= law.hi else 0.0
        worst = max(worst, abs(got - float(pz)) / float(pz))
    print(f"    support {min(exact)}..{max(exact)}, exact total = {sum(exact.values())}, "
          f"max relative error of float law = {worst:.2e}")
    return check("float64 convolution equals exact enumeration to < 1e-12 relative", worst < 1e-12)


def validate(pqc_json: str | None) -> bool:
    ok = True
    print("=" * 88)
    print("VALIDATE 1: ML-KEM per FIPS 203 (exact FIPS rounding and exact per-bit decoding)")
    print("=" * 88)
    print("  model: e^T r + e2 + dv - s^T(e1 + du); union bound over n = 256 coefficients")
    results = {}
    for P in MLKEM:
        law, p0, p1, avg, worst = mlkem_dfr(P)
        t832 = law.prob(lambda x: np.abs(x) >= 832)      # |e| >= floor(q/4)
        t833 = law.prob(lambda x: np.abs(x) >= 833)      # |e| >= ceil(q/4)
        results[P.name] = dict(law=law, p0=p0, p1=p1, avg=avg, worst=worst,
                               t832=P.n * t832, t833=P.n * t833)
        print(f"\n  {P.name}: k={P.k} eta1={P.eta1} eta2={P.eta2} du={P.du} dv={P.dv}  "
              f"sd(error)={law.var() ** 0.5:.2f}  mass={law.total():.15f}")
        print(f"    per-coefficient failure: bit 0 = 2^{lg(p0):.3f}, bit 1 = 2^{lg(p1):.3f}")
        print(f"    DFR (random message, exact decoding)   = 2^{lg(avg):.3f}")
        print(f"    DFR (worst message = all ones)          = 2^{lg(worst):.3f}")
        print(f"    256 * P(|e| >= 833)  [ceil(q/4) rule]   = 2^{lg(P.n * t833):.3f}")
        print(f"    256 * P(|e| >= 832)  [floor(q/4) rule]  = 2^{lg(P.n * t832):.3f}   "
              f"FIPS 203 Table 1: 2^{FIPS203_TABLE1[P.name]}")
        ok &= check(f"floor(q/4) rule reproduces FIPS 203 Table 1 to 0.05 bit "
                    f"({lg(P.n * t832):.3f} vs {FIPS203_TABLE1[P.name]})",
                    abs(lg(P.n * t832) - FIPS203_TABLE1[P.name]) < 0.05)
        ok &= check("exact DFR <= published value (published figure is conservative)",
                    lg(worst) <= FIPS203_TABLE1[P.name] + 0.05)

    print("\n  Why the pq-crystals script (commit 75c2694) run under Python 3 prints a lower")
    print("  number: tail_probability(D, ps.q/4) starts at ceil(832.25) = 833 under Python 3,")
    print("  but ps.q/4 is integer division (= 832) under Python 2; and Python 3 round() rounds")
    print("  ties to even inside mod_switch, while Python 2 rounds them away from zero (= the")
    print("  FIPS 203 rule for these non-negative values). Reproducing the script's model:")
    for P in MLKEM:
        lawpy = mlkem_error_law(P, rounding="python3", sign_dv=-1)
        t_py3 = P.n * symmetric_tail(lawpy, P.q / 4)
        lawp2 = mlkem_error_law(P, rounding="fips", sign_dv=-1)
        t_py2 = P.n * symmetric_tail(lawp2, P.q // 4)
        print(f"    {P.name}: script model as Python 3 runs it -> 2^{lg(t_py3):.4f};  "
              f"as Python 2 would run it -> 2^{lg(t_py2):.4f}  (FIPS 203: "
              f"2^{FIPS203_TABLE1[P.name]})")
        results[P.name]["py3"] = t_py3
        results[P.name]["py2"] = t_py2
        ok &= check("Python-2 behaviour of the script reproduces FIPS 203 Table 1 to 0.05 bit",
                    abs(lg(t_py2) - FIPS203_TABLE1[P.name]) < 0.05)
    if pqc_json:
        print("\n  Comparison with the pq-crystals script's own output (dumped by "
              "run_pqcrystals_failure.py):")
        with open(pqc_json) as fh:
            ref = json.load(fh)
        for P in MLKEM:
            r = ref[P.name]
            lawpy = mlkem_error_law(P, rounding="python3", sign_dv=-1)
            maxrel = 0.0
            for k, v in r["law"].items():
                k = int(k)
                if v > 2.0 ** -300 and lawpy.lo <= k <= lawpy.hi:
                    maxrel = max(maxrel, abs(lawpy.p[k - lawpy.lo] - v) / v)
            print(f"    {P.name}: script prints 2^{r['log2']:.4f}; this code (same model) "
                  f"2^{lg(results[P.name]['py3']):.4f}; max relative difference over the "
                  f"law = {maxrel:.1e}")
            ok &= check("independent implementation matches the script's law to < 1e-9",
                        maxrel < 1e-9)
            ok &= check("and its failure number to 0.001 bit",
                        abs(r["log2"] - lg(results[P.name]["py3"])) < 1e-3)

    print("\n  Negative controls (a changed parameter must no longer match its table value):")
    ctrl = [
        (MLKEM[1].with_(eta1=3), "ML-KEM-768"),
        (MLKEM[1].with_(du=9), "ML-KEM-768"),
        (MLKEM[0].with_(eta1=2), "ML-KEM-512"),
        (MLKEM[2].with_(dv=4), "ML-KEM-1024"),
    ]
    for P, ref_name in ctrl:
        law = mlkem_error_law(P)
        v = lg(P.n * law.prob(lambda x: np.abs(x) >= 832))
        print(f"    {ref_name} with eta1={P.eta1} du={P.du} dv={P.dv}: 2^{v:.2f} "
              f"(table 2^{FIPS203_TABLE1[ref_name]})")
        ok &= check("no longer matches (differs by > 1 bit)",
                    abs(v - FIPS203_TABLE1[ref_name]) > 1.0)

    print("\n" + "=" * 88)
    print("VALIDATE 2: FrodoKEM (round-3 Table 2 / 2025 proposal Table A.9)")
    print("=" * 88)
    for P in FRODO:
        chi = table_law(P.table)
        law, p, dfr = frodo_dfr(P)
        h = P.q >> (P.B + 1)
        sym = P.nbar ** 2 * law.prob(lambda x: np.abs(x) >= h)
        print(f"\n  {P.name}: n={P.n} q=2^{P.D} B={P.B} chi mass={chi.total():.6f} "
              f"var(chi)={chi.var():.4f}  sd(error)={law.var() ** 0.5:.2f}  threshold {h}")
        print(f"    exact decode rule e not in [-{h}, {h}): per-entry 2^{lg(p):.3f}, "
              f"DFR = 64 x that = 2^{lg(dfr):.3f}")
        print(f"    symmetric rule |e| >= {h}:            DFR = 2^{lg(sym):.3f}   "
              f"published: 2^{FRODO_TABLE2[P.name]}")
        ok &= check(f"symmetric rule reproduces the published failure rate to 0.05 bit "
                    f"({lg(sym):.3f} vs {FRODO_TABLE2[P.name]})",
                    abs(lg(sym) - FRODO_TABLE2[P.name]) < 0.05)
        ok &= check("exact-rule DFR <= published value (published figure is conservative)",
                    lg(dfr) <= FRODO_TABLE2[P.name] + 0.05)
    print("\n  Negative controls (exact decode window; the symmetric rule differs by < 0.05 bit):")
    for P, ref_name in [(FRODO[1].with_(B=4), "Frodo-976"), (FRODO[0].with_(n=720), "Frodo-640"),
                        (FRODO[2].with_(table=FRODO[1].table), "Frodo-1344")]:
        _, _, dfr = frodo_dfr(P)
        print(f"    {ref_name} with n={P.n} B={P.B} table={'976' if P.table is FRODO[1].table else 'own'}:"
              f" 2^{lg(dfr):.2f} (table 2^{FRODO_TABLE2[ref_name]})")
        ok &= check("no longer matches (differs by > 1 bit)",
                    abs(lg(dfr) - FRODO_TABLE2[ref_name]) > 1.0)

    print("\n" + "=" * 88)
    print("VALIDATE 3: why exact convolution and not a Gaussian (erfc) estimate")
    print("=" * 88)
    print("  Gaussian tails use a continuity correction: P(|N| >= 832.5) for ML-KEM (between the")
    print("  floor rule 832 and exact decoding 833) and P(|N| >= h - 0.5) for FrodoKEM. Other")
    print("  conventions move the Gaussian value by at most about 0.2 bit; the gap is tens of bits.")
    for P in MLKEM:
        law = results[P.name]["law"]
        sd = law.var() ** 0.5
        g = P.n * math.erfc(832.5 / (sd * math.sqrt(2)))
        g832 = P.n * math.erfc(832.0 / (sd * math.sqrt(2)))
        print(f"  {P.name}: Gaussian with the same variance gives 2^{lg(g):.2f} (at 832: "
              f"2^{lg(g832):.2f}); exact (floor rule) 2^{lg(results[P.name]['t832']):.2f}")
    for P in FRODO:
        law = frodo_error_law(P)
        sd = law.var() ** 0.5
        h = P.q >> (P.B + 1)
        g = 64 * math.erfc((h - 0.5) / (sd * math.sqrt(2)))
        gh = 64 * math.erfc(h / (sd * math.sqrt(2)))
        _, _, dfr = frodo_dfr(P)
        print(f"  {P.name}: Gaussian with the same variance gives 2^{lg(g):.2f} (at h: "
              f"2^{lg(gh):.2f}); exact decode window 2^{lg(dfr):.2f}")
    ok &= exact_small_check()
    print("\nVALIDATE overall:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------------------
# simulate: toy versions of the real schemes (random A, real compression) vs the model
# --------------------------------------------------------------------------------------
def negacyclic_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    n = len(a)
    full = np.convolve(a.astype(np.int64), b.astype(np.int64))
    res = full[:n].copy()
    res[: n - 1] -= full[n:]
    return np.mod(res, q)


def sample_cbd(rng, eta, shape):
    return (rng.integers(0, 2, size=shape + (eta,)).sum(-1)
            - rng.integers(0, 2, size=shape + (eta,)).sum(-1))


def abs_counts(x: np.ndarray, vmax: int) -> dict:
    return {v: int(np.count_nonzero(np.abs(x) == v)) for v in range(1, vmax + 1)}


def simulate_mlkem_like(P: MLKEMParams, keys: int, per_key: int, seed: int):
    """Real K-PKE arithmetic (FIPS 203 Alg. 13-15 without NTT/bytes): uniform A, CBD secrets,
    Compress/Decompress exactly as FIPS 203. A fresh key every per_key encryptions.
    Returns (wrong bits, wrong messages, expected wrong bits from the per-key model)."""
    rng = np.random.default_rng(seed)
    q, n, k = P.q, P.n, P.k
    ctab = {d: np.array([compress(x, d, q) for x in range(q)]) for d in (P.du, P.dv, 1)}
    dtab = {d: np.array([decompress(y, d, q) for y in range(1 << d)]) for d in (P.du, P.dv, 1)}
    bit_err = msg_err = 0
    expected = 0.0
    counts = []
    for _ in range(keys):
        A = rng.integers(0, q, size=(k, k, n))
        s = sample_cbd(rng, P.eta1, (k, n))
        e = sample_cbd(rng, P.eta1, (k, n))
        t = [np.mod(sum(negacyclic_mul(A[i][j], s[j], q) for j in range(k)) + e[i], q)
             for i in range(k)]
        expected += per_key * mlkem_key_dfr(P, abs_counts(e, P.eta1), abs_counts(s, P.eta1))
        for _ in range(per_key):
            m = rng.integers(0, 2, size=n)
            r = sample_cbd(rng, P.eta1, (k, n))
            e1 = sample_cbd(rng, P.eta2, (k, n))
            e2 = sample_cbd(rng, P.eta2, (n,))
            u = [np.mod(sum(negacyclic_mul(A[j][i], r[j], q) for j in range(k)) + e1[i], q)
                 for i in range(k)]
            v = np.mod(sum(negacyclic_mul(t[i], r[i], q) for i in range(k)) + e2
                       + dtab[1][m], q)
            u2 = [dtab[P.du][ctab[P.du][ui]] for ui in u]
            v2 = dtab[P.dv][ctab[P.dv][v]]
            w = np.mod(v2 - sum(negacyclic_mul(s[i], u2[i], q) for i in range(k)), q)
            wrong = int(np.count_nonzero(ctab[1][w] != m))
            counts.append(wrong)
            bit_err += wrong
            msg_err += wrong > 0
    return bit_err, msg_err, expected, counts


def simulate_frodo_like(P: FrodoParams, keys: int, per_key: int, seed: int):
    """Real FrodoPKE arithmetic mod q (uniform A, table sampler, Encode/Decode of the 2025
    proposal section 7.3). A fresh key every per_key encryptions.
    Returns (wrong symbols, expected wrong symbols from the per-key/per-column model)."""
    rng = np.random.default_rng(seed)
    q, n, nb, B, D = P.q, P.n, P.nbar, P.B, P.D
    chi = table_law(P.table)
    vals, probs = chi.support(), chi.p / chi.p.sum()
    sym_err = 0
    expected = 0.0
    counts = []
    for _ in range(keys):
        A = rng.integers(0, q, size=(n, n), dtype=np.int64)
        S = rng.choice(vals, size=(n, nb), p=probs)
        E = rng.choice(vals, size=(n, nb), p=probs)
        Bm = np.mod(A @ S + E, q)
        m = len(P.table) - 1
        col = [frodo_column_failure(P, abs_counts(E[:, j], m), abs_counts(S[:, j], m))
               for j in range(nb)]
        expected += per_key * nb * sum(col)          # nb rows share each column's law
        for _ in range(per_key):
            mu = rng.integers(0, 1 << B, size=(nb, nb))
            S1 = rng.choice(vals, size=(nb, n), p=probs)
            E1 = rng.choice(vals, size=(nb, n), p=probs)
            E2 = rng.choice(vals, size=(nb, nb), p=probs)
            B1 = np.mod(S1 @ A + E1, q)
            V = np.mod(S1 @ Bm + E2 + (mu << (D - B)), q)
            M = np.mod(V - B1 @ S, q)
            mu2 = ((M + (1 << (D - B - 1))) >> (D - B)) % (1 << B)
            wrong = int(np.count_nonzero(mu2 != mu))
            counts.append(wrong)
            sym_err += wrong
    return sym_err, expected, counts


def within_3sigma(observed: int, expected: float, counts) -> tuple[bool, float]:
    """Total count vs its model mean. Failures inside one encryption are correlated (they share
    the same randomness), so the standard error uses the empirical variance of the
    per-encryption counts: SE = sqrt(N * var), never less than the Poisson sqrt(expected)."""
    c = np.asarray(counts, dtype=float)
    se = max(math.sqrt(len(c) * c.var(ddof=1)) if len(c) > 1 else 0.0,
             math.sqrt(max(expected, 1e-300)))
    z = (observed - expected) / se
    return abs(z) <= 3.0, z


def simulate(trials: int = 4000) -> bool:
    ok = True
    print("=" * 88)
    print("SIMULATE: real toy schemes vs the convolution model")
    print("=" * 88)
    print("  Test 1 (per-key model): the error law conditioned on each simulated key's own")
    print("  secret, summed over the keys actually used, must match the observed count.")
    print("  Test 2 (average model): the key-averaged DFR (what the standards publish) must")
    print("  match too, but only up to key-to-key variation (reported, not asserted).")
    print("\n  ML-KEM-like: n=256, q=3329, large eta so failures are frequent; real uniform A,")
    print("  real FIPS 203 Compress/Decompress. Tests the compression-independence heuristic.")
    toys = [MLKEMParams("toy-A", k=2, eta1=16, eta2=16, du=10, dv=4),
            MLKEMParams("toy-B", k=2, eta1=12, eta2=12, du=8, dv=3),
            MLKEMParams("toy-C", k=3, eta1=11, eta2=11, du=10, dv=4)]
    per_key = 40
    for i, P in enumerate(toys):
        law = mlkem_error_law(P)
        p0, p1 = mlkem_coeff_failure(law, P.q)
        keys = max(1, trials // per_key)
        bits, msgs, exp_key, cnts = simulate_mlkem_like(P, keys, per_key, seed=1000 + i)
        exp_avg = keys * per_key * P.n * (p0 + p1) / 2
        good, z = within_3sigma(bits, exp_key, cnts)
        _, z_avg = within_3sigma(bits, exp_avg, cnts)
        print(f"  {P.name} k={P.k} eta={P.eta1} du={P.du} dv={P.dv}, {keys} keys x {per_key}: "
              f"wrong bits {bits}; per-key model expects {exp_key:.1f} (z={z:+.2f}); "
              f"average model expects {exp_avg:.1f} (z={z_avg:+.2f}); wrong messages {msgs}")
        ok &= check("per-key model within 3 sigma of the observed count", good)
    print("\n  FrodoKEM-like: the real n=640 table and B=2 but small q so failures are frequent;")
    print("  real uniform A. The model has no heuristic step here, so this tests the code.")
    for i, D in enumerate((12, 13)):
        P = FRODO[0].with_(D=D, name=f"Frodo-640 q=2^{D}")
        _, p, _ = frodo_dfr(P)
        keys, pk = 20, max(1, trials // 40)
        errs, exp_key, cnts = simulate_frodo_like(P, keys, pk, seed=2000 + i)
        exp_avg = keys * pk * 64 * p
        good, z = within_3sigma(errs, exp_key, cnts)
        _, z_avg = within_3sigma(errs, exp_avg, cnts)
        print(f"  {P.name}, {keys} keys x {pk}: wrong symbols {errs}; per-key model expects "
              f"{exp_key:.1f} (z={z:+.2f}); average model expects {exp_avg:.1f} (z={z_avg:+.2f})")
        ok &= check("per-key model within 3 sigma of the observed count", good)
    print("\nSIMULATE overall:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------------------
# weak keys: the DFR of one fixed key, and how bad the unluckiest keys are
# --------------------------------------------------------------------------------------
def keyed_sum(counts: dict, partner: Law) -> Law:
    """Law of sum_i x_i * Y_i, where the fixed key has counts[|v|] coefficients of absolute
    value v and the Y_i ~ partner are independent and symmetric."""
    out = Law(0, [1.0])
    for v, c in sorted(counts.items()):
        if v == 0 or c == 0:
            continue
        out = out.conv(partner.power(int(c)).scale(int(v)))
    return out


def tilt(law: Law, lam: float) -> tuple[np.ndarray, float]:
    """Exponential tilt P_lam(x) ~ P(x) exp(lam x^2); returns (P_lam, KL(P_lam||P) in bits)."""
    x = law.support().astype(float)
    w = law.p * np.exp(lam * x * x)
    pl = w / w.sum()
    kl = float(np.sum(pl[pl > 0] * np.log2(pl[pl > 0] / law.p[pl > 0])))
    return pl, kl


def tilted_counts(law: Law, lam: float, N: int) -> tuple[dict, float]:
    pl, kl = tilt(law, lam)
    by_abs: dict = {}
    for x, p in zip(law.support(), pl):
        by_abs[abs(int(x))] = by_abs.get(abs(int(x)), 0.0) + p
    counts = {v: int(round(N * p)) for v, p in by_abs.items()}
    return counts, N * kl


def lam_for_bits(law: Law, N: int, bits: float) -> float:
    """Tilt such that a random key has this histogram with probability ~2^-bits (Sanov)."""
    lo, hi = 0.0, 5.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if N * tilt(law, mid)[1] < bits:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def mlkem_key_dfr(P: MLKEMParams, cnt_e: dict, cnt_s: dict) -> float:
    """Per-key DFR (union bound over 256 coefficients, random message), FIPS rounding."""
    r = cbd(P.eta1)
    e1u = cbd(P.eta2).conv(compression_error_law(P.q, P.du))
    tail = cbd(P.eta2).conv(compression_error_law(P.q, P.dv))
    law = keyed_sum(cnt_e, r).conv(keyed_sum(cnt_s, e1u)).conv(tail)
    p0, p1 = mlkem_coeff_failure(law, P.q)
    return P.n * (p0 + p1) / 2


def frodo_column_failure(P: FrodoParams, cnt_e: dict, cnt_s: dict) -> float:
    chi = table_law(P.table)
    law = keyed_sum(cnt_e, chi).conv(keyed_sum(cnt_s, chi)).conv(chi)
    h = P.q >> (P.B + 1)
    return law.prob(lambda x: (x < -h) | (x >= h))


def median_ci(sorted_vals: np.ndarray, conf: float = 0.95) -> tuple[float, float]:
    """Distribution-free confidence interval for the median from order statistics
    (binomial(n, 1/2) quantiles; normal approximation to pick the ranks)."""
    n = len(sorted_vals)
    zq = 1.959963984540054 if conf == 0.95 else 2.5758293035489
    lo = max(0, int(math.floor(n / 2 - zq * math.sqrt(n) / 2)) - 1)
    hi = min(n - 1, int(math.ceil(n / 2 + zq * math.sqrt(n) / 2)))
    return float(sorted_vals[lo]), float(sorted_vals[hi])


def weakkeys(samples: int = 200, seed: int = 7) -> bool:
    print("=" * 88)
    print("WEAK KEYS: DFR of a fixed key (the attacker faces one key, not the average)")
    print("=" * 88)
    print(f"  {samples} random keys per parameter set, numpy seed {seed}")
    rng = np.random.default_rng(seed)
    ok = True
    for P in (MLKEM[1], MLKEM[2]):
        N = P.k * P.n
        s_law = cbd(P.eta1)
        vals, probs = s_law.support(), s_law.p / s_law.p.sum()
        logs, dfrs = [], []
        for _ in range(samples):
            e = rng.choice(vals, size=N, p=probs)
            s = rng.choice(vals, size=N, p=probs)
            ce = {v: int(np.count_nonzero(np.abs(e) == v)) for v in range(1, P.eta1 + 1)}
            cs = {v: int(np.count_nonzero(np.abs(s) == v)) for v in range(1, P.eta1 + 1)}
            d = mlkem_key_dfr(P, ce, cs)
            dfrs.append(d)
            logs.append(lg(d))
        _, _, _, avg, _ = mlkem_dfr(P)
        logs = np.sort(np.array(logs))
        mlo, mhi = median_ci(logs)
        q1, q3 = np.percentile(logs, [25, 75])
        print(f"\n  {P.name}: {samples} random keys: log2 per-key DFR min {logs.min():.1f}, "
              f"quartiles {q1:.1f} / {np.median(logs):.1f} / {q3:.1f}, max {logs.max():.1f}; "
              f"sd {logs.std(ddof=1):.2f} bits; 95% CI of the median [{mlo:.1f}, {mhi:.1f}]")
        print(f"    mean of per-key DFRs 2^{lg(np.mean(dfrs)):.2f}; average-case DFR "
              f"2^{lg(avg):.2f} (the sample mean falls short because rare heavy keys dominate "
              f"the average)")
        ok &= check("mean of sampled per-key DFRs within 3 bits of the average-case DFR "
                    "(consistency of the two computations)", abs(lg(np.mean(dfrs)) - lg(avg)) < 3)
        # unlucky keys by Sanov tilt of the joint histogram of (s, e)
        for bits in (32, 64, 128):
            lam = lam_for_bits(s_law, 2 * N, bits)
            cnt, cost = tilted_counts(s_law, lam, N)
            d = mlkem_key_dfr(P, cnt, cnt)
            print(f"    key whose (s,e) histogram has probability ~2^-{bits} (tilt lam={lam:.4f},"
                  f" Sanov cost {2 * cost:.1f} bits): DFR 2^{lg(d):.1f}")
    for P in (FRODO[1],):
        chi = table_law(P.table)
        _, p_avg, dfr_avg = frodo_dfr(P)
        print(f"\n  {P.name}: average per-entry failure 2^{lg(p_avg):.1f}, DFR 2^{lg(dfr_avg):.1f}")
        for bits in (32, 64, 128):
            lam = lam_for_bits(chi, 2 * P.n, bits)
            cnt, cost = tilted_counts(chi, lam, P.n)
            pc = frodo_column_failure(P, cnt, cnt)
            print(f"    one heavy column (probability ~2^-{bits}): its entries fail with "
                  f"2^{lg(pc):.1f}; key DFR ~ 8 x that + rest = 2^{lg(8 * pc + 56 * p_avg):.1f}")
    print("\n  Reading: 'probability ~2^-b' is a large-deviation (Sanov) estimate that ignores")
    print("  polynomial factors; treat these rows as order-of-magnitude.")
    print("\nWEAKKEYS overall:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------------------
# failure boosting (simple, norm-based; D'Anvers et al. PKC 2019 section 3 idea)
# --------------------------------------------------------------------------------------
def tilted_law(law: Law, lam: float) -> tuple[Law, float]:
    """The exponentially tilted law P_lam(x) ~ P(x) exp(lam x^2) as a Law, and KL(P_lam||P) in bits."""
    pl, kl = tilt(law, lam)
    return Law(law.lo, pl), kl


def boost_iid_point(P: MLKEMParams, lam_r: float, lam_e: float) -> tuple[float, float]:
    """Conservative (attacker-favourable) point: the kept ciphertexts' r and e1 coefficients are
    i.i.d. from the tilted laws. alpha = 2^-(N KL_r + N KL_e) (Sanov, polynomial factors
    ignored); beta = exact union-bound DFR with r ~ tilt, e1 ~ tilt, key ~ CBD(eta1), e2 and the
    compression errors unselected. Returns (log2(1/alpha), log2 beta).
    At lam = 0 this is exactly the average-case DFR, so the curve starts at the right place."""
    N = P.k * P.n
    key = cbd(P.eta1)
    r_t, kl_r = tilted_law(cbd(P.eta1), lam_r)
    e_t, kl_e = tilted_law(cbd(P.eta2), lam_e)
    du = compression_error_law(P.q, P.du)
    tail = cbd(P.eta2).conv(compression_error_law(P.q, P.dv))
    law = key.times(r_t).power(N).conv(key.times(e_t.conv(du)).power(N)).conv(tail)
    p0, p1 = mlkem_coeff_failure(law, P.q)
    return N * (kl_r + kl_e), lg(P.n * (p0 + p1) / 2)


def boost_typical_point(P: MLKEMParams, bits_r: float, bits_e: float) -> tuple[float, float]:
    """Optimistic (defender-favourable) point: every kept ciphertext has exactly the typical
    histogram of the tilted law (no fluctuation above it). Returns (log2(1/alpha), log2 beta)."""
    N = P.k * P.n
    r_law, e1_law, key = cbd(P.eta1), cbd(P.eta2), cbd(P.eta1)
    lam_r = lam_for_bits(r_law, N, bits_r) if bits_r else 0.0
    lam_e = lam_for_bits(e1_law, N, bits_e) if bits_e else 0.0
    cnt_r, _ = tilted_counts(r_law, lam_r, N)
    pl_e1, _ = tilt(e1_law, lam_e)
    du = compression_error_law(P.q, P.du)
    tail = cbd(P.eta2).conv(compression_error_law(P.q, P.dv))
    law = keyed_sum(cnt_r, key)
    for v, p in zip(e1_law.support(), pl_e1):
        c = int(round(N * p))
        if c:
            law = law.conv(key.times(du.conv(Law(int(v), [1.0]))).power(c))
    law = law.conv(tail)
    p0, p1 = mlkem_coeff_failure(law, P.q)
    return bits_r + bits_e, lg(P.n * (p0 + p1) / 2)


BOOST_SETS = [
    MLKEM[1], MLKEM[2],
    MLKEMParams("dim-1024 q=3329 eta 2/2 no compression", k=4, eta1=2, eta2=2, du=12, dv=12),
    MLKEMParams("dim-1024 q=7681 eta 2/2 du 11 dv 5", k=4, eta1=2, eta2=2, du=11, dv=5, q=7681),
    MLKEMParams("dim-1024 q=7681 eta 3/3 du 11 dv 5", k=4, eta1=3, eta2=3, du=11, dv=5, q=7681),
]


def boost() -> bool:
    print("=" * 88)
    print("BOOST: how much can pre-selecting heavy ciphertexts raise the failure rate?")
    print("=" * 88)
    print("  Model (idea of D'Anvers et al. PKC 2019, section 3): the attacker keeps only")
    print("  ciphertexts whose randomness (r, e1) is unusually large; alpha = fraction kept,")
    print("  beta = failure rate of a kept ciphertext on a random key. Work for one failure:")
    print("  classical 1/(alpha beta); with Grover 1/(sqrt(alpha) beta); decryption queries")
    print("  1/beta. Two brackets: 'iid' lets the kept randomness fluctuate like the tilted law")
    print("  (attacker-favourable: cost is likely UNDER-estimated), 'typical' pins it to the tilted")
    print("  law's typical histogram (cost OVER-estimated). The truth should lie in between.")
    print("  Selection bits are split between r and e1 on a grid; polynomial factors, e2, the")
    print("  message and directional information after a first failure are ignored.")
    print("  This is an estimate for comparing parameter sets, not a security bound.")
    grid = [0, 8, 16, 24, 32, 48, 64, 96, 128, 160, 192, 256]
    for P in BOOST_SETS:
        N = P.k * P.n
        _, _, _, avg, _ = mlkem_dfr(P)
        print(f"\n  {P.name}: k={P.k} q={P.q} eta={P.eta1}/{P.eta2} du={P.du} dv={P.dv}; "
              f"average DFR 2^{lg(avg):.1f}")
        lam_r = {b: (lam_for_bits(cbd(P.eta1), N, b) if b else 0.0) for b in grid}
        lam_e = {b: (lam_for_bits(cbd(P.eta2), N, b) if b else 0.0) for b in grid}
        pts_iid, pts_typ = [], []
        for br in grid:
            for be in grid:
                if br + be > 320:
                    continue
                pts_iid.append(boost_iid_point(P, lam_r[br], lam_e[be]))
                pts_typ.append(boost_typical_point(P, br, be))
        for label, pts in (("iid (attacker-favourable)", pts_iid),
                           ("typical (defender-favourable)", pts_typ)):
            cl = min(pts, key=lambda t: t[0] - t[1])
            qu = min(pts, key=lambda t: t[0] / 2 - t[1])
            lim = [t for t in pts if -t[1] <= 64]
            print(f"    {label:30s} cheapest classical 2^{cl[0] - cl[1]:.1f} "
                  f"(alpha 2^-{cl[0]:.0f}, queries 2^{-cl[1]:.1f}); cheapest quantum "
                  f"2^{qu[0] / 2 - qu[1]:.1f} (alpha 2^-{qu[0]:.0f}, queries 2^{-qu[1]:.1f})")
            if lim:
                ql = min(lim, key=lambda t: t[0] / 2 - t[1])
                print(f"    {'':30s} with at most 2^64 queries: quantum 2^{ql[0] / 2 - ql[1]:.1f}")
            else:
                best = max(pts, key=lambda t: t[1])
                print(f"    {'':30s} no grid point reaches beta >= 2^-64 (largest beta 2^{best[1]:.1f} "
                      f"at alpha 2^-{best[0]:.0f})")
        # consistency check: the iid curve at alpha = 1 must equal the average-case DFR
        b0 = [t for t in pts_iid if t[0] == 0][0][1]
        print(f"    check: iid model at alpha = 1 gives 2^{b0:.2f} vs average DFR 2^{lg(avg):.2f}")
    print("\nBOOST: estimate only; no PASS/FAIL target.")
    return True


# --------------------------------------------------------------------------------------
# provable: heuristic-free bound of Barbosa, Kannwischer, Lim, Schwabe, Strub (ACM CCS 2025)
# --------------------------------------------------------------------------------------
BARBOSA_TABLE1 = {  # ePrint 2025/1562, Table 1 (PDF page 13): provable, heur(cu,cv), heur(cu)
    "ML-KEM-768": (-80, -164, -158), "ML-KEM-1024": (-95, -174, -169)}
BARBOSA_TCU = {"ML-KEM-768": 296, "ML-KEM-1024": 240}  # optimal t_cu, section 5.5, PDF page 12


def provable_bounds(P: MLKEMParams, strict: bool = True):
    """Three correctness bounds for an ML-KEM-like PKE, following Barbosa et al. section 3.2 and 5.5.

    Failure event of their game COR (Figure 3): ||n||_inf > floor(q/4) - 1, with
    n = <e,r> - <s,e1> - <s,cu> + e2 + cv.
      heur(cu,cv): cu and cv are rounding errors of uniform elements, independent of the rest
                   (the Kyber/FIPS 203 heuristic).
      heur(cu)   : cv replaced by its worst case t_max_cv; cu still from a uniform u.
      provable   : split the threshold: P(||n1|| > T - t_max_cv - t_cu) + P(||<s,cu>|| > t_cu),
                   n1 = <e,r> - <s,e1> + e2 (exact, no rounding), cu from a uniform u (justified
                   by an MLWE reduction, plus eps_LWE which is not counted here); minimised over t_cu.
    All three use the union bound over the n coefficients. strict=True uses ">" as in the paper's
    games; strict=False uses ">=" (one step more conservative), which is the reading that matches
    every number the paper prints (see dfr_barbosa_explore.py)."""
    T = P.q // 4 - 1
    s, e1 = cbd(P.eta1), cbd(P.eta2)
    n1 = s.times(s).power(P.k * P.n).conv(s.times(e1).power(P.k * P.n)).conv(e1)
    cu = compression_error_law(P.q, P.du)
    cv = compression_error_law(P.q, P.dv)
    tmax_cv = int(max(abs(cv.lo), abs(cv.hi)))
    n2 = s.times(cu).power(P.k * P.n)          # marginal law of <s, cu> (for the split bound)
    # <s,e1> and <s,cu> share the same s_j, so the joint term is s_j*(e1_j + cu_j), NOT the
    # convolution of n1 and n2 (that would treat the two uses of s_j as independent).
    joint = s.times(s).power(P.k * P.n).conv(s.times(e1.conv(cu)).power(P.k * P.n)).conv(e1)
    full = joint.conv(cv)

    def tail(law: Law, t: int) -> float:
        return law.prob((lambda x: np.abs(x) > t) if strict else (lambda x: np.abs(x) >= t))

    heur_cucv = P.n * tail(full, T)
    heur_cu = P.n * tail(joint, T - tmax_cv)
    best = None
    for tcu in range(0, T - tmax_cv + 1):
        p1 = P.n * tail(n1, T - tmax_cv - tcu)
        p2 = P.n * tail(n2, tcu)
        tot = p1 + p2
        if tot > 0 and (best is None or tot < best[0]):
            best = (tot, tcu, p1, p2)
    return dict(T=T, tmax_cv=tmax_cv, tmax_cu=int(max(abs(cu.lo), abs(cu.hi))),
                heur_cucv=heur_cucv, heur_cu=heur_cu, provable=best)


def matches_truncated(value_log2: float, printed: int) -> bool:
    """The paper prints integer exponents; a value v matches printed p if p - 1 < v <= p (the
    printed number is v truncated toward zero), allowing 0.05 bit of slack."""
    return printed - 1 - 0.05 < value_log2 <= printed + 0.05


def provable() -> bool:
    print("=" * 88)
    print("PROVABLE: heuristic-free correctness bound (Barbosa et al., ePrint 2025/1562, CCS 2025)")
    print("=" * 88)
    print("  Reproduces Table 1 (PDF page 13) for ML-KEM-768/1024: provable, heur(cu,cv), heur(cu),")
    print("  the optimal split thresholds t_cu = 296 / 240 and the partial probabilities 2^-81, 2^-82")
    print("  (768) and 2^-96, 2^-97 (1024) (section 5.5, PDF page 12). The paper prints integer")
    print("  exponents; a match means our value truncates toward zero to the printed integer.")
    ok = True
    for P in MLKEM[1:]:
        ref = BARBOSA_TABLE1[P.name]
        for strict in (False, True):
            r = provable_bounds(P, strict)
            tot, tcu, p1, p2 = r["provable"]
            conv = "'>' (paper's games)" if strict else "'>=' (one step conservative)"
            print(f"\n  {P.name}, threshold test {conv}: T = floor(q/4)-1 = {r['T']}, "
                  f"max|cv| = {r['tmax_cv']}, max|cu| = {r['tmax_cu']}")
            print(f"    heur(cu,cv) 2^{lg(r['heur_cucv']):.2f} (paper 2^{ref[1]}); heur(cu) "
                  f"2^{lg(r['heur_cu']):.2f} (paper 2^{ref[2]})")
            print(f"    provable 2^{lg(tot):.2f} at t_cu = {tcu} (parts 2^{lg(p1):.2f} + "
                  f"2^{lg(p2):.2f}); paper 2^{ref[0]} at t_cu = {BARBOSA_TCU[P.name]}")
            if not strict:
                ok &= check("heur(cu,cv) truncates to the paper's value",
                            matches_truncated(lg(r['heur_cucv']), ref[1]))
                ok &= check("heur(cu) truncates to the paper's value",
                            matches_truncated(lg(r['heur_cu']), ref[2]))
                ok &= check("provable truncates to the paper's value",
                            matches_truncated(lg(tot), ref[0]))
                ok &= check("optimal t_cu within 3 of the paper",
                            abs(tcu - BARBOSA_TCU[P.name]) <= 3)
    print("\n  Negative control: ML-KEM-768 with dv = 5 (smaller cv) must NOT match the paper's")
    r = provable_bounds(MLKEM[1].with_(dv=5), strict=False)
    print(f"    heur(cu) 2^{lg(r['heur_cu']):.2f}, provable 2^{lg(r['provable'][0]):.2f}")
    ok &= check("no longer matches the paper's ML-KEM-768 values",
                not matches_truncated(lg(r['heur_cu']), -158)
                and not matches_truncated(lg(r['provable'][0]), -80))
    print("\n  Dimension-1024 variants ('>=' test; what a provable bound costs; security NOT estimated):")
    for P in BOOST_SETS[2:]:
        r = provable_bounds(P, strict=False)
        tot, tcu, p1, p2 = r["provable"]
        print(f"    {P.name}: max|cu| {r['tmax_cu']}, max|cv| {r['tmax_cv']}; heur(cu,cv) "
              f"2^{lg(r['heur_cucv']):.1f}; heur(cu) 2^{lg(r['heur_cu']):.1f}; provable "
              f"2^{lg(tot):.1f} (t_cu = {tcu})")
    print("\nPROVABLE overall:", "PASS" if ok else "FAIL")
    return ok


# --------------------------------------------------------------------------------------
# sweep: trade-offs near 1000 dimensions
# --------------------------------------------------------------------------------------
def sweep() -> bool:
    print("=" * 88)
    print("SWEEP: DFR trade-offs near 1000 dimensions (DFR only - NOT security estimates)")
    print("=" * 88)
    print("\n  Module-LWE, n=256, k=4 (dimension 1024): effect of q, eta and compression")
    print("  (du = dv = 12 with q = 3329 means no compression: 2^12 > q, rounding error 0;")
    print("   columns 'vs 2^-192' / 'vs 2^-256' = log2 DFR + 192 / + 256, negative = below)")
    print("       q eta1 eta2 du dv   log2 DFR (exact decoding, random msg)  vs 2^-192  vs 2^-256")
    for q, eta1, eta2, du, dv in [(3329, 2, 2, 11, 5), (3329, 3, 2, 11, 5), (3329, 3, 3, 11, 5),
                                  (3329, 2, 2, 10, 4), (3329, 2, 2, 11, 4), (3329, 2, 2, 11, 6),
                                  (3329, 4, 4, 11, 5), (3329, 2, 2, 12, 12), (3329, 1, 1, 11, 5),
                                  (3329, 1, 1, 12, 12), (7681, 2, 2, 11, 5), (7681, 3, 3, 11, 5),
                                  (7681, 2, 2, 12, 6), (7681, 4, 4, 13, 13)]:
        P = MLKEMParams("x", k=4, eta1=eta1, eta2=eta2, du=du, dv=dv, q=q)
        _, _, _, avg, _ = mlkem_dfr(P)
        if avg > 0:
            print(f"    {q:5d} {eta1:4d} {eta2:4d} {du:2d} {dv:2d}   {lg(avg):8.1f}"
                  f"{'':30s}{lg(avg) + 192:8.1f}  {lg(avg) + 256:8.1f}")
        else:
            print(f"    {q:5d} {eta1:4d} {eta2:4d} {du:2d} {dv:2d}   below 2^-880 (trimmed)")
    print("\n  Plain LWE, n=976, nbar=8, Frodo-976 error table: effect of q and bits per entry B")
    print("    log2 q  B  log2 DFR")
    for D in (15, 16):
        for B in (2, 3, 4):
            P = FRODO[1].with_(D=D, B=B)
            _, _, dfr = frodo_dfr(P)
            print(f"    {D:6d} {B:2d} {lg(dfr):9.1f}")
    print("\n  Plain LWE, n=1024 (a '1000-dimension' point), q=2^16, B=3: effect of the error table")
    for name, table in [("Frodo-976 table (sigma 2.3)", FRODO[1].table),
                        ("Frodo-640 table (sigma 2.8)", FRODO[0].table),
                        ("Frodo-1344 table (sigma 1.4)", FRODO[2].table)]:
        P = FRODO[1].with_(n=1024, D=16, B=3, table=table)
        _, _, dfr = frodo_dfr(P)
        shown = f"{lg(dfr):8.1f}" if dfr > 0 else "  below 2^-880 (law trimmed at 2^-900)"
        print(f"    {name:30s} log2 DFR {shown}")
    print("\nSWEEP: informational; security of these variants is NOT estimated here.")
    return True


def main(argv) -> int:
    cmd = argv[1] if len(argv) > 1 else "validate"
    arg = argv[2] if len(argv) > 2 else None
    ok = True
    if cmd in ("validate", "all"):
        ok &= validate(arg)
    if cmd in ("simulate", "all"):
        ok &= simulate(int(arg) if (arg and cmd == "simulate") else 4000)
    if cmd in ("weakkeys", "all"):
        if cmd == "weakkeys" and arg:
            seed = int(argv[3]) if len(argv) > 3 else 7
            ok &= weakkeys(int(arg), seed)
        else:
            ok &= weakkeys()
    if cmd in ("boost", "all"):
        ok &= boost()
    if cmd in ("provable", "all"):
        ok &= provable()
    if cmd in ("sweep", "all"):
        ok &= sweep()
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
