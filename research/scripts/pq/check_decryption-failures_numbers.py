"""Independent fact-check of the numbers in research/notes/pq/decryption-failures.md.

Written by the fact-checker, from scratch; it does NOT import or read dfr.py.
Everything is deterministic (fixed seeds) and prints what it checks.

Method (same mathematics as the notes, independent code):
  * CBD(eta) laws are exact (binomial coefficients / 4^eta).
  * The ML-KEM compression rounding error cu (du bits) / cv (dv bits) is the law of
    Decompress_d(Compress_d(x)) - x for x uniform in Z_q, with FIPS 203 rounding
    (round half up) -- or Python-3 ties-to-even to emulate the pq-crystals script run
    under Python 3.
  * ML-KEM decryption error: err = sum_{kn} e_j r_j + sum_{kn} s_j (e1_j + cu_j) + e2 + cv.
  * FrodoKEM: err = sum_{2n} (chi x chi) + chi; 64 entries; decoding window half-width
    q / 2^(B+1).
  * Direct (not FFT) convolution in float64 via numpy.convolve; all terms are >= 0.

Usage:
  python check_decryption-failures_numbers.py main        (~1-3 min)
  python check_decryption-failures_numbers.py weakkeys    (~ few min)
  python check_decryption-failures_numbers.py pqcrystals SE_DIR   (runs the designers' script)
  python check_decryption-failures_numbers.py frodoofficial PSS_DIR
"""
import math
import sys
from fractions import Fraction

import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

TRIM = 1e-300


# ---------------------------------------------------------------- laws
class Law:
    """Discrete law on consecutive integers: p[i] = P(X = lo + i)."""

    def __init__(self, lo, p):
        p = np.asarray(p, dtype=np.float64)
        nz = np.nonzero(p > TRIM)[0]
        if len(nz) == 0:
            raise ValueError("empty law")
        self.lo = lo + int(nz[0])
        self.p = p[nz[0]:nz[-1] + 1].copy()

    @property
    def hi(self):
        return self.lo + len(self.p) - 1

    def conv(self, other):
        return Law(self.lo + other.lo, np.convolve(self.p, other.p))

    def power(self, n):
        result = Law(0, [1.0])
        base = self
        while n:
            if n & 1:
                result = result.conv(base)
            n >>= 1
            if n:
                base = base.conv(base)
        return result

    def prob_ge(self, t):  # P(X >= t)
        i = t - self.lo
        if i <= 0:
            return float(self.p.sum())
        if i >= len(self.p):
            return 0.0
        return float(self.p[i:][::-1].sum())

    def prob_le(self, t):  # P(X <= t)
        i = t - self.lo
        if i < 0:
            return 0.0
        if i >= len(self.p):
            return float(self.p.sum())
        return float(self.p[:i + 1].sum())

    def var(self):
        x = np.arange(self.lo, self.hi + 1, dtype=np.float64)
        m = float((x * self.p).sum())
        return float(((x - m) ** 2 * self.p).sum())

    def mean(self):
        x = np.arange(self.lo, self.hi + 1, dtype=np.float64)
        return float((x * self.p).sum())


def law_from_dict(d):
    lo, hi = min(d), max(d)
    p = np.zeros(hi - lo + 1)
    for k, v in d.items():
        p[k - lo] += float(v)
    return Law(lo, p)


def cbd_dict(eta):
    return {x: Fraction(math.comb(2 * eta, x + eta), 4 ** eta) for x in range(-eta, eta + 1)}


def cbd(eta):
    return law_from_dict(cbd_dict(eta))


def product_dict(a, b):
    out = {}
    for x, px in a.items():
        for y, py in b.items():
            out[x * y] = out.get(x * y, 0) + px * py
    return out


def product_law(A, B):
    """Law of X*Y for independent X ~ A, Y ~ B (Law objects)."""
    out = {}
    for i, px in enumerate(A.p):
        x = A.lo + i
        if px == 0:
            continue
        for j, py in enumerate(B.p):
            y = B.lo + j
            out[x * y] = out.get(x * y, 0.0) + px * py
    return law_from_dict(out)


def round_half_up(num, den):
    """round(num/den) with ties up, integers only (den > 0)."""
    return (2 * num + den) // (2 * den)


def round_half_even(num, den):
    q, r = divmod(num, den)
    if 2 * r > den:
        return q + 1
    if 2 * r < den:
        return q
    return q if q % 2 == 0 else q + 1


def centred(x, q):
    x %= q
    return x - q if x > q // 2 else x


def rounding_error_law(q, d, rounding="fips"):
    """Law of Decompress_d(Compress_d(x)) - x (centred), x uniform in Z_q."""
    if d is None:
        return Law(0, [1.0])
    rnd = round_half_up if rounding == "fips" else round_half_even
    two_d = 2 ** d
    cnt = {}
    for x in range(q):
        y = rnd(two_d * x, q) % two_d
        z = rnd(q * y, two_d)
        e = centred(z - x, q)
        cnt[e] = cnt.get(e, 0) + 1
    return law_from_dict({k: Fraction(v, q) for k, v in cnt.items()})


def log2(x):
    return math.log2(x) if x > 0 else float("-inf")


# ---------------------------------------------------------------- ML-KEM
def mlkem_error_law(k, eta1, eta2, du, dv, q=3329, n=256, rounding="fips"):
    s = cbd(eta1)
    e2 = cbd(eta2)
    cu = rounding_error_law(q, du, rounding)
    cv = rounding_error_law(q, dv, rounding)
    er = product_law(s, s)                     # e_j * r_j, both CBD(eta1)
    s_e1cu = product_law(s, e2.conv(cu))       # s_j * (e1_j + cu_j)
    total = er.power(k * n).conv(s_e1cu.power(k * n)).conv(e2).conv(cv)
    return total


def mlkem_rates(law, q=3329, n=256):
    """Return dict of log2 DFR under several decoding rules (union bound over n)."""
    t_floor = q // 4                                    # 832 (published rule)
    p_floor = law.prob_ge(t_floor) + law.prob_le(-t_floor)
    # exact decoding.  Compress_1(w) = round(2w/q) mod 2 (ties up).
    # bit 0: w = err; correct iff round(2w/q) mod 2 == 0
    one = round_half_up(q, 2)                           # Decompress_1(1)
    # find exact windows by scanning w in [0, q)
    ok0 = [(round_half_up(2 * w, q) % 2) == 0 for w in range(q)]
    ok1 = [(round_half_up(2 * w, q) % 2) == 1 for w in range(q)]

    def fail_prob(offset, okarr):
        # err range of law; w = (offset + err) mod q
        tot = 0.0
        for i, p in enumerate(law.p):
            err = law.lo + i
            if not okarr[(offset + err) % q]:
                tot += p
        return tot
    p0 = fail_prob(0, ok0)
    p1 = fail_prob(one, ok1)
    return {
        "floor_rule": log2(n * p_floor),
        "exact_random_m": log2(n * (p0 + p1) / 2),
        "exact_worst_m": log2(n * max(p0, p1)),
        "p0": p0, "p1": p1,
    }


def gaussian_tail_log2(var, t, n):
    """log2( n * P(|N(0,var)| >= t) ), via erfc in mpmath-free log form."""
    from scipy.special import log_ndtr
    lp = math.log(2.0) + log_ndtr(-t / math.sqrt(var))  # ln P(|N|>=t)
    return math.log2(n) + lp / math.log(2.0)


# ---------------------------------------------------------------- FrodoKEM
FRODO = {
    "Frodo-640": dict(n=640, logq=15, B=2,
                      tab=[9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1]),
    "Frodo-976": dict(n=976, logq=16, B=3,
                      tab=[11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1]),
    "Frodo-1344": dict(n=1344, logq=16, B=4,
                       tab=[18286, 14320, 6876, 2023, 364, 40, 2]),
}


def frodo_chi(tab):
    d = {0: Fraction(tab[0], 2 ** 16)}
    for i, v in enumerate(tab[1:], start=1):
        d[i] = Fraction(v, 2 ** 16)
        d[-i] = Fraction(v, 2 ** 16)
    assert sum(d.values()) == 1, "table does not sum to 2^16"
    return d


def frodo_error_law(n, tab):
    chi = law_from_dict(frodo_chi(tab))
    prod = product_law(chi, chi)
    return prod.power(2 * n).conv(chi), chi, prod


def frodo_rates(law, logq, B, entries=64):
    h = 2 ** logq // 2 ** (B + 1)
    p_sym = law.prob_ge(h) + law.prob_le(-h)
    p_exact = law.prob_ge(h) + law.prob_le(-h - 1)     # e not in [-h, h)
    return log2(entries * p_sym), log2(entries * p_exact)


# ---------------------------------------------------------------- checks
def show(label, got, want, tol):
    ok = abs(got - want) <= tol
    print(f"  {label:58s} got {got:10.4f}  notes {want:10.4f}  "
          f"{'OK' if ok else 'MISMATCH'} (tol {tol})")
    return ok


def main():
    allok = True
    print("=== A. ML-KEM DFR (FIPS 203 parameters, Table 2) ===")
    sets = {"ML-KEM-512": (2, 3, 2, 10, 4), "ML-KEM-768": (3, 2, 2, 10, 4),
            "ML-KEM-1024": (4, 2, 2, 11, 5)}
    notes = {"ML-KEM-512": (-138.775, -139.036, -138.943, -139.1358, -75.88),
             "ML-KEM-768": (-164.812, -165.123, -165.010, -165.2448, -81.18),
             "ML-KEM-1024": (-174.761, -175.074, -174.961, -175.1961, -145.63)}
    for name, (k, e1, e2, du, dv) in sets.items():
        law = mlkem_error_law(k, e1, e2, du, dv)
        r = mlkem_rates(law)
        nf, nr, nw, npy3, ngauss = notes[name]
        print(f"{name}: mean {law.mean():.3e} var {law.var():.3f} support {law.lo}..{law.hi}")
        allok &= show(f"{name} floor rule 256*P(|err|>=832)", r["floor_rule"], nf, 0.0015)
        allok &= show(f"{name} exact decoding, random m", r["exact_random_m"], nr, 0.0015)
        allok &= show(f"{name} exact decoding, worst m", r["exact_worst_m"], nw, 0.0015)
        print(f"    p0 (bit 0) = 2^{log2(r['p0']):.4f}, p1 (bit 1) = 2^{log2(r['p1']):.4f}")
        # Python-3 pq-crystals emulation: ties-to-even rounding and |err| >= 833
        law3 = mlkem_error_law(k, e1, e2, du, dv, rounding="even")
        py3 = log2(256 * (law3.prob_ge(833) + law3.prob_le(-833)))
        allok &= show(f"{name} Py3 emulation (ties-even, >=833)", py3, npy3, 0.0015)
        # Gaussian with same variance
        v = law.var()
        for t in (832, 832.5, 833):
            g = gaussian_tail_log2(v, t, 256)
            print(f"    Gaussian same variance, 256*P(|N|>={t}) = 2^{g:.2f}")
        g = gaussian_tail_log2(v, 832, 256)
        allok &= show(f"{name} Gaussian (t=832)", g, ngauss, 0.02)

    print("\n=== A2. ML-KEM negative controls ===")
    negs = [("ML-KEM-768 eta1=3", (3, 3, 2, 10, 4), -95.17),
            ("ML-KEM-768 du=9", (3, 2, 2, 9, 4), -87.35),
            ("ML-KEM-512 eta1=2", (2, 2, 2, 10, 4), -236.32),
            ("ML-KEM-1024 dv=4", (4, 2, 2, 11, 4), -153.80)]
    for label, (k, e1, e2, du, dv), want in negs:
        r = mlkem_rates(mlkem_error_law(k, e1, e2, du, dv))
        allok &= show(label + " floor rule", r["floor_rule"], want, 0.006)

    print("\n=== B. FrodoKEM DFR (64 entries, union bound) ===")
    fnotes = {"Frodo-640": (-138.7282, -138.7602, -148.80),
              "Frodo-976": (-199.5571, -199.6028, -213.19),
              "Frodo-1344": (-252.4924, -252.6053, -268.24)}
    for name, prm in FRODO.items():
        law, chi, _ = frodo_error_law(prm["n"], prm["tab"])
        sym, exact = frodo_rates(law, prm["logq"], prm["B"])
        ns, ne, ng = fnotes[name]
        print(f"{name}: chi var {chi.var():.4f}, err var {law.var():.2f}")
        allok &= show(f"{name} symmetric rule", sym, ns, 0.00015)
        allok &= show(f"{name} exact window [-h,h)", exact, ne, 0.00015)
        h = 2 ** prm["logq"] // 2 ** (prm["B"] + 1)
        g = gaussian_tail_log2(law.var(), h, 64)
        allok &= show(f"{name} Gaussian same variance (t=h)", g, ng, 0.02)

    print("\n=== B2. FrodoKEM negative controls ===")
    law976, _, _ = frodo_error_law(976, FRODO["Frodo-976"]["tab"])
    s, _ = frodo_rates(law976, 16, 4)
    allok &= show("Frodo-976 at B=4 (symmetric)", s, -50.21, 0.006)
    law720, _, _ = frodo_error_law(720, FRODO["Frodo-640"]["tab"])
    s, _ = frodo_rates(law720, 15, 2)
    allok &= show("Frodo-640 with n=720 (symmetric)", s, -124.70, 0.006)
    lawx, _, _ = frodo_error_law(1344, FRODO["Frodo-976"]["tab"])
    s, _ = frodo_rates(lawx, 16, 4)
    allok &= show("Frodo-1344 with Frodo-976 table (symmetric)", s, -35.86, 0.006)
    # official code with B+1 bits
    for name, want in (("Frodo-640", -34.15), ("Frodo-976", -50.18), ("Frodo-1344", -63.90)):
        prm = FRODO[name]
        law, _, _ = frodo_error_law(prm["n"], prm["tab"])
        s, _ = frodo_rates(law, prm["logq"], prm["B"] + 1)
        allok &= show(f"{name} with B+1 (symmetric)", s, want, 0.006)

    print("\n=== C. Worked example (CBD(2) toy) ===")
    c2 = cbd_dict(2)
    pr = product_dict(c2, c2)
    print("  CBD(2):", {k: str(v) for k, v in sorted(c2.items())})
    print("  product law:", {k: str(v) for k, v in sorted(pr.items())})
    want = {0: Fraction(39, 64), 1: Fraction(1, 8), -1: Fraction(1, 8), 2: Fraction(1, 16),
            -2: Fraction(1, 16), 4: Fraction(1, 128), -4: Fraction(1, 128)}
    ok = pr == want
    print(f"  product law equals notes' P(0)=39/64, P(+-1)=1/8, P(+-2)=1/16, P(+-4)=1/128: {ok}")
    allok &= ok
    # e = a1 b1 + ... + a4 b4 + c, exact fractions
    dist = {0: Fraction(1)}
    for _ in range(4):
        nd = {}
        for x, px in dist.items():
            for y, py in pr.items():
                nd[x + y] = nd.get(x + y, 0) + px * py
        dist = nd
    nd = {}
    for x, px in dist.items():
        for y, py in c2.items():
            nd[x + y] = nd.get(x + y, 0) + px * py
    dist = nd
    var = sum(px * x * x for x, px in dist.items())
    print(f"  support {min(dist)}..{max(dist)}, variance {var} (notes: -18..18, 5)")
    allok &= (min(dist), max(dist), var) == (-18, 18, 5)
    for t in (10,):
        p_ge = float(sum(p for x, p in dist.items() if abs(x) >= t))
        p_gt = float(sum(p for x, p in dist.items() if abs(x) > t))
        print(f"  P(|e|>={t}) = {p_ge:.4e}; P(|e|>{t}) = {p_gt:.4e} (notes 2.011e-4)")
        print(f"  8p = {8*p_ge:.4e}; 1-(1-p)^8 = {1-(1-p_ge)**8:.4e} (notes 1.608e-3 / 1.607e-3)")
        allok &= abs(p_ge - 2.011e-4) < 5e-8
    print("  Gaussian (var 5) optimism, bits, thresholds 8..12 (notes 1.5 to 5.6):")
    for t in range(8, 13):
        p_ex = float(sum(p for x, p in dist.items() if abs(x) >= t))
        g = 2 ** gaussian_tail_log2(5.0, t, 1)
        g2 = 2 ** gaussian_tail_log2(5.0, t - 0.5, 1)
        print(f"    t={t}: exact 2^{log2(p_ex):.2f}, Gauss(>=t) 2^{log2(g):.2f} "
              f"(diff {log2(p_ex)-log2(g):.2f}), Gauss(>=t-0.5) 2^{log2(g2):.2f} "
              f"(diff {log2(p_ex)-log2(g2):.2f})")

    print("\n=== D. FO bound-term table (section 5) ===")
    rows = [("ML-KEM-512", 128, -138.8), ("ML-KEM-768", 192, -164.8),
            ("ML-KEM-1024", 256, -174.8), ("Frodo-640", 128, -138.7),
            ("Frodo-976", 192, -199.6), ("Frodo-1344", 256, -252.5)]
    for name, lam, ld in rows:
        c = 2 + 128 + ld          # 4 q delta, q = 2^128
        qu = 3 + 2 * 64 + ld      # 8 q^2 delta, q = 2^64
        q1 = (-ld - 3) / 2        # 8 q^2 delta = 1
        print(f"  {name:12s} lambda+log2d {lam+ld:+6.1f}  classical 2^{c:6.1f}  quantum 2^{qu:6.1f}"
              f"  q* 2^{q1:.2f}")

    print("\n=== E. Sweep sample (section 7), exact decoding, random m ===")
    sweep = [((4, 2, 2, 11, 5), 3329, -175.1), ((4, 2, 2, 11, 6), 3329, -185.6),
             ((4, 2, 2, None, None), 3329, -231.0), ((4, 3, 2, 11, 5), 3329, -97.0),
             ((4, 1, 1, 11, 5), 3329, -589.4), ((4, 2, 2, 11, 5), 7681, -615.4),
             ((4, 3, 3, 11, 5), 7681, -328.4), ((4, 4, 4, None, None), 7681, -299.5)]
    for (k, e1, e2, du, dv), q, want in sweep:
        law = mlkem_error_law(k, e1, e2, du, dv, q=q)
        r = mlkem_rates(law, q=q)
        allok &= show(f"k=4 q={q} eta={e1}/{e2} du/dv={du}/{dv}", r["exact_random_m"], want, 0.06)
        print(f"      (floor rule {r['floor_rule']:.2f}, worst m {r['exact_worst_m']:.2f})")
    for n, tabname, B, want in ((976, "Frodo-976", 2, -703.0), (976, "Frodo-976", 3, -199.6),
                                (976, "Frodo-976", 4, -50.2), (1024, "Frodo-976", 3, -191.2),
                                (1024, "Frodo-640", 3, -89.3)):
        law, _, _ = frodo_error_law(n, FRODO[tabname]["tab"])
        s, e = frodo_rates(law, 16, B)
        allok &= show(f"plain LWE n={n} {tabname} table q=2^16 B={B} (exact window)", e, want, 0.06)
        print(f"      (symmetric rule {s:.2f})")

    print("\nRESULT:", "ALL MATCH" if allok else "SOME MISMATCH (see above)")


def weakkeys(nkeys=200, seed=20260927):
    """Per-key DFR (fixed s, e; heuristic compression noise) for ML-KEM-768/1024."""
    rng = np.random.default_rng(seed)
    for name, (k, eta1, eta2, du, dv) in (("ML-KEM-768", (3, 2, 2, 10, 4)),
                                          ("ML-KEM-1024", (4, 2, 2, 11, 5))):
        q, n = 3329, 256
        R = cbd(eta1)
        Y = cbd(eta2).conv(rounding_error_law(q, du))
        tailfix = cbd(eta2).conv(rounding_error_law(q, dv))
        scaled_R = {a: product_law(law_from_dict({a: 1.0}), R) for a in range(1, eta1 + 1)}
        scaled_Y = {a: product_law(law_from_dict({a: 1.0}), Y) for a in range(1, eta1 + 1)}
        vals_floor, vals_exact = [], []
        for _ in range(nkeys):
            s = rng.binomial(eta1, 0.5, k * n) - rng.binomial(eta1, 0.5, k * n)
            e = rng.binomial(eta1, 0.5, k * n) - rng.binomial(eta1, 0.5, k * n)
            law = tailfix
            for a in range(1, eta1 + 1):
                ce = int(np.sum(np.abs(e) == a))
                cs = int(np.sum(np.abs(s) == a))
                if ce:
                    law = law.conv(scaled_R[a].power(ce))
                if cs:
                    law = law.conv(scaled_Y[a].power(cs))
            r = mlkem_rates(law)
            vals_floor.append(r["floor_rule"])
            vals_exact.append(r["exact_random_m"])
        vf, ve = np.array(vals_floor), np.array(vals_exact)
        print(f"{name}: {nkeys} keys, seed {seed}")
        print(f"  floor rule: min 2^{vf.min():.1f} median 2^{np.median(vf):.1f} max 2^{vf.max():.1f}")
        print(f"  exact random m: min 2^{ve.min():.1f} median 2^{np.median(ve):.1f} "
              f"max 2^{ve.max():.1f}")
        mean_p = np.mean(2.0 ** vf)
        print(f"  mean over keys of floor-rule DFR: 2^{math.log2(mean_p):.2f}")
        print(f"  std of log2 per-key DFR (floor): {vf.std():.2f} bits; "
              f"quartiles 2^{np.percentile(vf, 25):.1f} .. 2^{np.percentile(vf, 75):.1f}")


def pqcrystals(se_dir):
    sys.path.insert(0, se_dir)
    import Kyber_failure as KF  # noqa
    from Kyber import KyberParameterSet  # noqa
    sets = {"light": KyberParameterSet(256, 2, 3, 3, 3329, 2**12, 2**10, 2**4, ke_ct=2),
            "recommended": KyberParameterSet(256, 3, 2, 2, 3329, 2**12, 2**10, 2**4),
            "paranoid": KyberParameterSet(256, 4, 2, 2, 3329, 2**12, 2**11, 2**5)}
    for name, ps in sets.items():
        F, p = KF.p2_cyclotomic_error_probability(ps)
        print(f"pq-crystals (Python {sys.version.split()[0]}) {name}: DFR = 2^{math.log2(p):.4f}")
        # same law with Python-2 threshold 832
        s = sum(F.get(i, 0) + F.get(-i, 0) for i in range(832, max(F.keys())))
        print(f"   same law, sum from 832: 2^{math.log2(256 * s):.4f}")


def frodoofficial(pss_dir):
    # numpy on Windows has no float128; the official code only needs a float type.
    if not hasattr(np, "float128"):
        np.float128 = np.longdouble
        print("(np.float128 missing on this platform; aliased to np.longdouble =", np.longdouble, ")")
    sys.path.insert(0, pss_dir)
    from failure_prob_pke import exact_failure_prob_pke  # noqa
    for name, prm in FRODO.items():
        d = {k: float(v) for k, v in frodo_chi(prm["tab"]).items()}
        q = 2 ** prm["logq"]
        dq = {x % q: p for x, p in d.items()}
        for B in (prm["B"], prm["B"] + 1):
            p = exact_failure_prob_pke(dq, q, prm["n"], B, 64 * prm["B"])
            print(f"official exact_failure_prob_pke {name} B={B} reclen={64*prm['B']}: "
                  f"2^{math.log2(p):.4f}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "main"
    if cmd == "main":
        main()
    elif cmd == "weakkeys":
        if len(sys.argv) > 3:
            weakkeys(int(sys.argv[2]), int(sys.argv[3]))
        else:
            weakkeys()
    elif cmd == "pqcrystals":
        pqcrystals(sys.argv[2])
    elif cmd == "frodoofficial":
        frodoofficial(sys.argv[2])
