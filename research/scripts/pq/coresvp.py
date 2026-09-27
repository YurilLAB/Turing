"""coresvp.py - core-SVP cost of the primal (uSVP) and dual lattice attacks on
LWE, Module-LWE and LWR, validated against published tables.

WHAT IT REPRODUCES
  The "core-SVP" methodology of
    [ADPS16] E. Alkim, L. Ducas, T. Poppelmann, P. Schwabe, "Post-quantum key
             exchange - a new hope", USENIX Security 2016, Sec. 6
             (research/papers/2016-alkim-ducas-poppelmann-schwabe-newhope.pdf, PDF p. 8-9),
  as used by the Kyber round-2 and round-3 specifications (Table 4 in both),
  the FrodoKEM round-3 specification (Table 10), the NewHope round-2
  specification (Table 12) and the Saber round-3 specification (Table 1).

  The published tables were produced by slightly different scripts. This file
  re-implements each one from its formulas (it does not import them) as a
  named "convention":

    newhope  GSA model, primal dimension d = n + m, dual length delta^d q^(n/d),
             epsilon = exp(-2 pi^2 tau^2); samples m <= 2n - 1.
             Source: scripts/PQsecurity.py of github.com/newhopecrypto/newhope.
    frodo    as newhope, but every SVP cost gets + log2(b) (b "vector
             operations" per sieve step, FrodoKEM round-3 spec Sec. 5.2.1
             footnote 7, PDF p. 41) and epsilon = 4 exp(-2 pi^2 tau^2).
             Source: pqsec.py of github.com/lwe-frodo/parameter-selection (MIT).
    kyber21  q-ary aware BKZ profile ("[q..q, GSA slope, 1..1]" shape) for the
             primal attack, with Kannan embedding d = n + m + 1; for the dual
             attack a randomised profile (no q-vectors). epsilon without the
             factor 4. Exhaustive search over b and m.
             Source: model_BKZ.py / MLWE_security.py of
             github.com/pq-crystals/security-estimates, commit 75c2694
             (2021-03-16; the repository has no licence file).
    kyber19  the same profiles WITHOUT the Kannan +1 (d = n + m) and with b and
             m searched on a step-5 grid (b = 50, 55, ...; m = max(5, b - n),
             +5, ..., < m_max), as in commit 71f89f3 (2019-03-21) of the same
             repository. This produced the Kyber round-2 Table 4.
    adps16   the formulas exactly as printed in ADPS16 Sec. 6.3-6.4 (PDF p. 9) and
             Kyber round-3 Sec. 5.1.2-5.1.3 (PDF p. 26): d = n + m + 1 for the
             primal attack, dual length delta^(d-1) q^(n/d),
             epsilon = 4 exp(-2 pi^2 tau^2).
             (Pass 1 of this script used epsilon WITHOUT the 4 here, contrary to
             the printed formula; corrected in pass 2, 2026-09-27.)

  THE EPSILON FACTOR. The dual attack's advantage is printed differently in
  the papers and in the scripts that produced their tables:
      ADPS16 p. 9 and Kyber r3 p. 26 print  eps = 4 exp(-2 pi^2 tau^2);
      FrodoKEM r3 p. 43 prints              eps = 2 exp(-2 pi^2 tau^2);
      NewHope PQsecurity.py and pq-crystals MLWE_security.py use eps = exp(...);
      Frodo parameter-selection pqsec.py (line 133) uses     eps = 4 exp(...).
  Each convention uses the factor of the SCRIPT that produced the published
  table (EPS_FACTOR below). Mode "eps" prints how much the factor matters.

  "core-SVP" = log2 of the cost of ONE call to an SVP oracle in dimension b
  (the BKZ block size), taken as 2^(c*b) with
      c = log2(sqrt(3/2))  ~ 0.2925  classical sieve [BDGL16]
      c = log2(sqrt(13/9)) ~ 0.2653  quantum sieve [Laarhoven 2016 thesis, Sec. 14.2.10]
      c = log2(sqrt(4/3))  ~ 0.2075  "plausible" floor = size of the sieve list
  The number of BKZ tours, the SVP calls per tour, memory and every
  polynomial factor are ignored. That is why the number is a conservative
  (attacker-favourable) proxy, not a runtime.

  In addition, gates_nn() re-implements the gate-count cost model that the
  lattice-estimator (github.com/malb/lattice-estimator, commit 53da598,
  2026-08-19, LGPLv3+) uses by default (RC.MATZOV, file estimator/reduction.py):
      cost(b, d) = d^3 + C (d - b) * C * 2^(a (b - d4f(b)) + b0),
      C = 1 / (1 - 2^-a),  d4f(b) = b ln(4/3) / ln(b / (2 pi e))  [Ducas 2018]
  with (a, b0) fitted by the estimator's authors to the AGPS20 sieve costs
  (MATZOV variant: a = 0.29613500308205365, b0 = 20.387885985467914).
  It turns a (b, d) pair from our primal search into a gate-count estimate.

WHAT IT CHECKS (run with no arguments)
  1. Published core-SVP numbers of Kyber512/768/1024 (round-3 Table 4 primal;
     the pq-crystals script output for dual and "plausible"), FrodoKEM
     640/976/1344 (round-3 Table 10), NewHope512/1024 (round-2 Table 12) and
     the USENIX 2016 rows (ADPS16 Table 1 = NewHope round-2 Table 12 top).
  2. Kyber round-2 Table 4 (eta = 2 everywhere) with the kyber19 convention,
     and the "112" statement of the round-3 changelog.
  3. LWR through its rounding error, against Saber round-3 Table 1 (within
     1 bit; Saber p. 11 says its estimators agree "up to small rounding
     differences").
  4. The gate-count model against the estimator's own doctest and README
     outputs, and the Kyber round-3 Sec. 5.2.1 arithmetic G = 2^151.5.
  5. Negative controls: perturb q, sigma or n and show the check FAILS.
  6. Monotonicity: cost rises with n and sigma, falls with q.
  Other modes: "table" prints the ~1000-dimension options for Turing;
  "example" prints a worked example of the primal success condition.

USAGE
  python coresvp.py            # validation + negative controls (about 2 minutes)
  python coresvp.py table      # ~1000-dimension parameter tables (a few minutes)
  python coresvp.py example    # worked Kyber512 example
  Deterministic; numpy only. Exit code 0 iff every check passes.
"""
import math
import sys

import numpy as np

LN2 = math.log(2.0)
C_CLASSICAL = math.log2(math.sqrt(3.0 / 2.0))   # 0.29248 [BDGL16]
C_QUANTUM = math.log2(math.sqrt(13.0 / 9.0))    # 0.26526 [Laa16 thesis]
C_PLAUSIBLE = math.log2(math.sqrt(4.0 / 3.0))   # 0.20752 list size
C_QRW_CL21 = 0.2570                             # [Chailloux-Loyer 2021]
C_QRW_BCSS23 = 0.2563                           # [Bonnetain et al. 2023]
NVEC = math.log2(math.sqrt(4.0 / 3.0))          # log2 of vectors per sieve / b

# lattice-estimator nearest-neighbour fits (estimator/reduction.py, commit 53da598)
NN_MATZOV_CLASSICAL = (0.29613500308205365, 20.387885985467914)   # RC.MATZOV default
NN_KYBER_CLASSICAL = (0.2988026130564745, 26.011121212891872)     # RC.Kyber (AGPS20 fit)

CONVENTIONS = ("newhope", "frodo", "kyber21", "kyber19", "adps16")
# Multiplicative factor in the dual advantage eps = F * exp(-2 pi^2 tau^2), per convention
# (see "THE EPSILON FACTOR" in the module docstring).
EPS_FACTOR = {"newhope": 1.0, "kyber21": 1.0, "kyber19": 1.0, "frodo": 4.0, "adps16": 4.0}


def delta_bkz(b):
    """Root Hermite factor of BKZ-b (Chen 2013 thesis; Kyber spec eq. (9) text):
    delta = ((pi b)^(1/b) * b / (2 pi e))^(1/(2(b-1)))."""
    return ((math.pi * b) ** (1.0 / b) * b / (2.0 * math.pi * math.e)) ** (1.0 / (2.0 * b - 2.0))


def svp_cost(b, c, conv):
    """log2 core-SVP cost of one SVP call in dimension b for sieve constant c."""
    extra = math.log2(b) if conv == "frodo" else 0.0
    return c * b + extra


def d4f(b):
    """Dimensions for free [Ducas 2018, EC]: b ln(4/3) / ln(b / (2 pi e))."""
    return max(b * math.log(4.0 / 3.0) / math.log(b / (2.0 * math.pi * math.e)), 0.0)


def gates_nn(b, d, nn=NN_MATZOV_CLASSICAL):
    """log2 gate count of progressive BKZ-b on a d-dimensional lattice in the
    lattice-estimator's Kyber/MATZOV cost model (see module docstring)."""
    a, b0 = nn
    C = 1.0 / (1.0 - 2.0 ** (-a))
    svp_calls = C * max(d - b, 1)
    gate = C * 2.0 ** (a * (b - d4f(b)) + b0)
    return math.log2(d ** 3 + svp_calls * gate)


# --------------------------------------------------------------------------
# Primal attack (unique-SVP via BKZ)
# --------------------------------------------------------------------------
def _primal_ok_gsa(n, q, se, ss, b, m, kannan):
    """GSA success test, vectorised over the numpy array m.

    Lattice {x : (A | I_m | -b) x = 0 mod q}, dimension d = n + m (+1),
    volume q^m (times nu^n after scaling the secret by nu = se/ss so that all
    target coordinates have standard deviation se, as in Bai-Galbraith).
    Success iff  se*sqrt(b) <= delta^(2b-d-1) * Vol^(1/d)     [ADPS16 eq. (1)].
    """
    d = n + m + kannan
    ld = math.log(delta_bkz(b))
    log_vol = m * math.log(q) + n * math.log(se / ss)
    rhs = (2 * b - d - 1) * ld + log_vol / d
    return math.log(se) + 0.5 * math.log(b) < rhs


def _primal_ok_qary(n1, q, s, b, m):
    """q-ary aware profile test (pq-crystals model_BKZ.construct_BKZ_shape),
    vectorised over m: nq = m q-vectors and n1 unit vectors (n1 = n + 1 with
    Kannan embedding in kyber21, n1 = n in kyber19).

    The profile (natural logs) is: log q for the first a vectors, then a GSA
    line of slope -2 ln(delta) that is shifted so the total volume is m*log q,
    then zeros. Success iff s*sqrt(b) < exp(profile[d - b]).
    """
    nq = m.astype(np.int64)
    d = nq + n1
    lq = math.log(q)
    sp = 2.0 * math.log(delta_bkz(b))       # minus the GSA slope
    B = int(math.floor(lq / sp))            # length of the sloped segment
    glv = nq * lq                           # goal log-volume

    def prefix(k):                          # sum of the first k entries of the long list
        k1 = np.minimum(k, nq)
        t = np.clip(k - nq, 0, B)
        return k1 * lq + t * lq - sp * t * (t + 1) / 2.0

    def window(x):
        return prefix(x + d) - prefix(x)

    lo = np.zeros_like(nq)
    hi = np.full_like(nq, B)
    while np.any(lo < hi):                  # smallest x with window(x) <= glv
        mid = (lo + hi) // 2
        good = window(mid) <= glv
        hi = np.where(good & (lo < hi), mid, hi)
        lo = np.where(~good & (lo < hi), mid + 1, lo)
    x = lo
    a = np.maximum(0, nq - x)
    bp = np.minimum(B, d - a)
    diff = glv - window(x)
    idx = d - b                             # 0-based index of b*_{d-b}
    k = x + idx
    val = np.where(k < nq, lq, np.where(k < nq + B, lq - (k - nq + 1) * sp, 0.0))
    val = val + np.where((idx >= a) & (idx < a + bp), diff / np.maximum(bp, 1), 0.0)
    return s * math.sqrt(b) < np.exp(val)


def _grid(conv, n, b, m_max):
    """Sample counts m tried at block size b, per convention."""
    if conv == "kyber19":
        return np.arange(max(5, b - n), m_max, 5, dtype=np.int64)
    lo = max(1, b - n + (1 if conv == "kyber21" else 0))
    return np.arange(lo, m_max + 1, dtype=np.int64)


def _b_range(conv, n, m_max):
    if conv == "kyber19":
        return range(50, n + m_max, 5)
    return range(50, n + m_max + 2)


def primal(n, q, se, ss, m_max, conv):
    """Smallest block size b for which some m in the convention's grid succeeds.

    Returns (b, m, d) with m the smallest successful sample count at that b,
    or None. The cost for a sieve constant c is svp_cost(b, c, conv).
    """
    for b in _b_range(conv, n, m_max):
        m = _grid(conv, n, b, m_max)
        if m.size == 0:
            if b - n > m_max:
                break
            continue
        if conv in ("kyber21", "kyber19"):
            if abs(se - ss) > 1e-12:
                raise ValueError("q-ary profile model needs sigma_s == sigma_e")
            n1 = n + 1 if conv == "kyber21" else n
            ok = _primal_ok_qary(n1, q, se, b, m)
            d_extra = 1 if conv == "kyber21" else 0
        else:
            d_extra = 1 if conv == "adps16" else 0
            ok = _primal_ok_gsa(n, q, se, ss, b, m.astype(float), d_extra)
        if np.any(ok):
            mm = int(m[np.argmax(ok)])
            return b, mm, n + mm + d_extra
    return None


# --------------------------------------------------------------------------
# Dual attack (short dual vector used as a distinguisher)
# --------------------------------------------------------------------------
def _dual_log_len(n, q, se, ss, b, m, conv):
    """Natural log of the dual vector length, vectorised over m.

    Dual lattice {(x, y) in Z^m x Z^n : A^T x = y mod q}: dimension d = n + m,
    volume q^n. Scaling y by ss/se multiplies the volume by (ss/se)^n; the
    inner product then has standard deviation se * length.
    """
    d = n + m
    ld = math.log(delta_bkz(b))
    lvol = n * (math.log(q) + math.log(ss / se))
    if conv in ("kyber21", "kyber19"):
        # randomised profile: GSA line ending at 1, no q-vectors (model_BKZ.py)
        sp = 2.0 * ld
        bb = math.floor((-1.0 + math.sqrt(1.0 + 8.0 * lvol / sp)) / 2.0)
        bb = np.minimum(bb, d)
        return bb * sp + (lvol - sp * bb * (bb + 1) / 2.0) / bb
    expo = d - 1 if conv == "adps16" else d
    return expo * ld + lvol / d


def dual(n, q, se, ss, m_max, c, conv, eps_factor=None):
    """Minimum over (b, m) of  c*b + max(0, -2 log2(eps) - 0.2075 b).

    eps = F exp(-2 pi^2 tau^2) with tau = length * se / q  [ADPS16 Sec. 6.4],
    F = EPS_FACTOR[conv] unless eps_factor is given: the advantage of one dual
    vector; 1/eps^2 vectors are needed and one sieve call is assumed to give
    2^(0.2075 b) of them, all as short as the shortest (attacker-favourable).
    Returns (cost, b, m).
    """
    f = EPS_FACTOR[conv] if eps_factor is None else eps_factor
    best = (float("inf"), None, None)
    for b in _b_range(conv, n, m_max):
        base = svp_cost(b, c, conv)
        if base > best[0]:
            break
        m = _grid(conv, n, b, m_max)
        if m.size == 0:
            if b - n > m_max:
                break
            continue
        tau = np.exp(_dual_log_len(n, q, se, ss, b, m.astype(float), conv)) * se / q
        log2_eps = math.log2(f) - 2.0 * math.pi ** 2 * tau ** 2 / LN2
        rep = np.maximum(0.0, -2.0 * log2_eps - NVEC * b)
        cost = base + rep
        i = int(np.argmin(cost))            # first minimum = smallest m
        if cost[i] < best[0]:
            best = (float(cost[i]), b, int(m[i]))
    return best


def estimate(n, q, se, ss=None, m_max=None, conv="kyber21", consts=None, do_dual=True):
    """Primal and dual core-SVP costs for LWE(n, q) with error std se, secret std ss.

    Module-LWE of rank k over degree-256 rings is passed as n = 256k (the
    attacks do not use the module structure). LWR is passed with se = the
    standard deviation of the rounding error.
    """
    ss = se if ss is None else ss
    m_max = n if m_max is None else m_max
    consts = consts or {"C": C_CLASSICAL, "Q": C_QUANTUM, "P": C_PLAUSIBLE}
    out = {"primal": {}, "dual": {}}
    p = primal(n, q, se, ss, m_max, conv)
    if p is not None:
        b, m, d = p
        out["primal"] = {"b": b, "m": m, "d": d}
        for k, c in consts.items():
            out["primal"][k] = svp_cost(b, c, conv)
    if do_dual:
        for k, c in consts.items():
            cost, b, m = dual(n, q, se, ss, m_max, c, conv)
            out["dual"][k] = cost
            out["dual"]["b_" + k] = b
            out["dual"]["m_" + k] = m
    return out


# --------------------------------------------------------------------------
# Error distributions
# --------------------------------------------------------------------------
def sd_binomial(eta):
    """Centered binomial B_eta (Kyber): variance eta/2."""
    return math.sqrt(eta / 2.0)


def sd_rounding(q, p):
    """LWR rounding error when p | q: uniform on q/p consecutive integers,
    variance ((q/p)^2 - 1)/12 (independence heuristic, Kyber spec footnote 4)."""
    r = q // p
    return math.sqrt((r * r - 1) / 12.0)


# --------------------------------------------------------------------------
# Validation against published tables
# --------------------------------------------------------------------------
# Each row: name, conv, n, q, se, ss, m_max, published values, rounding.
# published: dict attack -> (b or None, C, Q, P or None); rounding "floor" or "1dp".
PUBLISHED = [
    # Kyber round-3 spec v3.02 Table 4 (PDF p. 21): primal b, classical, quantum.
    # Plausible and all dual values: output of pq-crystals Kyber.py (commit
    # 75c2694), re-run 2026-09-27 (scratch attack-cost/kyber_rerun*.log).
    ("Kyber512", "kyber21", 512, 3329, sd_binomial(3), None, 768,
     {"primal": (406, 118, 107, 84), "dual": (403, 117, 106, 83)}, "floor"),
    ("Kyber768", "kyber21", 768, 3329, sd_binomial(2), None, 1024,
     {"primal": (626, 183, 166, 129), "dual": (620, 181, 164, 128)}, "floor"),
    ("Kyber1024", "kyber21", 1024, 3329, sd_binomial(2), None, 1280,
     {"primal": (878, 256, 232, 182), "dual": (868, 253, 230, 180)}, "floor"),
    # FrodoKEM round-3 spec Table 10 (PDF p. 43): C, Q, P to one decimal.
    # The spec does not print the sample bound; m_max = n + 8 (n from the
    # public matrix plus nbar = 8 from the ciphertext) reproduces every entry
    # (acs_frodo_msamp.py). The lattice-estimator's schemes.py uses n + 16,
    # which moves Frodo-640 dual classical from 149.6 to 149.5.
    ("Frodo-640", "frodo", 640, 2 ** 15, 2.8, None, 640 + 8,
     {"primal": (None, 150.8, 137.6, 109.6), "dual": (None, 149.6, 136.5, 108.7)}, "1dp"),
    ("Frodo-976", "frodo", 976, 2 ** 16, 2.3, None, 976 + 8,
     {"primal": (None, 216.0, 196.7, 156.0), "dual": (None, 214.5, 195.4, 154.9)}, "1dp"),
    ("Frodo-1344", "frodo", 1344, 2 ** 16, 1.4, None, 1344 + 8,
     {"primal": (None, 281.6, 256.3, 202.6), "dual": (None, 279.8, 254.7, 201.4)}, "1dp"),
    # NewHope round-2 spec Table 12 (PDF p. 34): m, b, C, Q, P (floor).
    ("NewHope512", "newhope", 512, 12289, 2.0, None, 2 * 512 - 1,
     {"primal": (384, 112, 101, 79), "dual": (383, 112, 101, 79)}, "floor"),
    ("NewHope1024", "newhope", 1024, 12289, 2.0, None, 2 * 1024 - 1,
     {"primal": (886, 259, 235, 183), "dual": (881, 257, 233, 182)}, "floor"),
    # ADPS16 Table 1 (USENIX 2016, PDF p. 9), repeated in NewHope round-2 Table 12.
    ("NewHope-USENIX", "newhope", 1024, 12289, math.sqrt(8), None, 2 * 1024 - 1,
     {"primal": (967, 282, 256, 200), "dual": (962, 281, 255, 199)}, "floor"),
    ("JarJar-USENIX", "newhope", 512, 12289, math.sqrt(12), None, 2 * 512 - 1,
     {"primal": (449, 131, 119, 93), "dual": (448, 131, 118, 92)}, "floor"),
    ("BCNS", "newhope", 1024, 2 ** 32 - 1, 3.192, None, 2 * 1024 - 1,
     {"primal": (296, 86, 78, 61), "dual": (296, 86, 78, 61)}, "floor"),
]

# Kyber round-2 spec Table 4 (research/papers/2019-avanzi-et-al-kyber-round2-
# specification.pdf, PDF p. 25): (b, m, classical, quantum); eta = 2 in all sets.
KYBER_R2 = [
    ("Kyber512-r2", 512, 768, {"primal": (385, 410, 112, 102), "dual": (380, 455, 111, 100)}),
    ("Kyber768-r2", 768, 1024, {"primal": (625, 655, 182, 165), "dual": (620, 650, 181, 164)}),
    ("Kyber1024-r2", 1024, 1280, {"primal": (880, 795, 257, 233), "dual": (870, 795, 254, 230)}),
]


def _fmt(x, rounding):
    return math.floor(x + 1e-9) if rounding == "floor" else round(x, 1)


def check_row(row, override=None, quiet=False):
    """Compute one published row; return True if every number matches.

    Match rule: floor-rounded rows must agree exactly; 1-decimal rows must agree
    within 0.05 (same one-decimal value). Block sizes must agree exactly when published.
    """
    name, conv, n, q, se, ss, m_max, pub, rounding = row
    if override:
        n = override.get("n", n)
        q = override.get("q", q)
        se = override.get("se", se)
    est = estimate(n, q, se, ss, m_max, conv)
    ok_all = True
    for att in ("primal", "dual"):
        pb, pc, pq_, pp = pub[att]
        r = est[att]
        if not r:
            ok_all = False
            continue
        got = [_fmt(r["C"], rounding), _fmt(r["Q"], rounding), _fmt(r["P"], rounding)]
        want = [pc, pq_, pp]
        tol = 0 if rounding == "floor" else 0.05
        ok = all(abs(g - w) <= tol + 1e-9 for g, w in zip(got, want))
        b_got = r["b"] if att == "primal" else r["b_Q"]
        m_got = r["m"] if att == "primal" else r["m_Q"]
        if pb is not None:
            ok = ok and (b_got == pb)
        ok_all = ok_all and ok
        if not quiet:
            print(f"  {name:15s} {att:6s} conv={conv:8s} b={b_got:4d} m={m_got:5d} "
                  f"C/Q/P computed={got} published={want} (b pub={pb}) "
                  f"{'PASS' if ok else 'FAIL'}")
    return ok_all


def validate():
    checks = {}
    print("== 1. Published core-SVP tables ==")
    results = [check_row(r) for r in PUBLISHED]
    print(f"  -> {sum(results)}/{len(results)} parameter sets reproduced\n")
    checks["1 published tables"] = all(results)

    print("== 2. Kyber round-2 Table 4 (eta = 2) with the 2019 script's conventions ==")
    ok2 = True
    for name, n, m_max, pub in KYBER_R2:
        e = estimate(n, 3329, 1.0, None, m_max, "kyber19",
                     {"C": C_CLASSICAL, "Q": C_QUANTUM})
        for att in ("primal", "dual"):
            r = e[att]
            b = r["b"] if att == "primal" else r["b_Q"]
            m = r["m"] if att == "primal" else r["m_Q"]
            got = (b, m, math.floor(r["C"]), math.floor(r["Q"]))
            ok = got == pub[att]
            ok2 = ok2 and ok
            print(f"  {name:13s} {att:6s} (b, m, C, Q) computed={got} published={pub[att]} "
                  f"{'PASS' if ok else 'FAIL'}")
    k21 = estimate(512, 3329, 1.0, None, 768, "kyber21", {"C": C_CLASSICAL}, do_dual=False)
    print(f"  The round-3 changelog (PDF p. 13) and p. 22 say Kyber512 'without the LWR"
          f" assumption' has 112 bits: that is the round-2 number above (kyber19).")
    print(f"  The fixed 2021 script model (kyber21, Kannan +1, exhaustive search) gives "
          f"{math.floor(k21['primal']['C'])} for the same eta = 2 instance "
          f"(b = {k21['primal']['b']}): the 1-bit gap is the script fix, not an error here.\n")
    checks["2 Kyber round-2 table"] = ok2

    print("== 3. LWR via rounding error: Saber round-3 spec Table 1 (PDF p. 11) ==")
    se = sd_rounding(2 ** 13, 2 ** 10)
    print(f"  rounding error std for q=2^13, p=2^10: {se:.4f} (variance {se * se:.4f})")
    ok3 = True
    for name, k, mu, pc, pq_ in (("LightSaber", 2, 10, 118, 107),
                                  ("Saber", 3, 8, 189, 172),
                                  ("FireSaber", 4, 6, 260, 236)):
        ss = math.sqrt(mu / 4.0)            # Saber secret: binomial, variance mu/4
        m_max = 256 * k                     # public-key samples (l*n rounded products)
        e = estimate(256 * k, 2 ** 13, se, ss, m_max, "newhope", do_dual=False)
        got = (math.floor(e["primal"]["C"]), math.floor(e["primal"]["Q"]))
        dif = (got[0] - pc, got[1] - pq_)
        ok = max(abs(dif[0]), abs(dif[1])) <= 1
        ok3 = ok3 and ok
        print(f"  {name:10s} m_max={m_max:5d} primal b={e['primal']['b']} C/Q={got} "
              f"published=({pc}, {pq_}) diff={dif} {'PASS (<= 1 bit)' if ok else 'FAIL'}")
    print()
    checks["3 Saber LWR within 1 bit"] = ok3

    print("== 4. Gate-count model vs lattice-estimator outputs and Kyber Sec. 5.2.1 ==")
    ok4 = True
    v = gates_nn(500, 1024, NN_KYBER_CLASSICAL)
    ok = abs(v - 176.55419197058822) < 1e-6
    ok4 = ok4 and ok
    print(f"  RC.Kyber(500, 1024): computed 2^{v:.10f}, estimator doctest 2^176.5541919706 "
          f"{'PASS' if ok else 'FAIL'}")
    v = d4f(500)
    ok = math.floor(v * 1000) == 42597      # doctest prints the prefix "42.597..."
    ok4 = ok4 and ok
    print(f"  d4f(500): computed {v:.6f}, estimator doctest prefix 42.597... "
          f"{'PASS' if ok else 'FAIL'}")
    v = gates_nn(406, 998, NN_MATZOV_CLASSICAL)
    ok = abs(v - 143.8) < 0.05
    ok4 = ok4 and ok
    print(f"  MATZOV model at Kyber512 usvp (b=406, d=998): 2^{v:.2f}, estimator README "
          f"'rop: ~2^143.8' {'PASS' if ok else 'FAIL'}")
    C = 1.0 / (1.0 - 2.0 ** -0.292)
    G = math.log2(1025 - 413) + 2 * math.log2(C) + 137.4
    ok = abs(C - 5.46) < 0.005 and abs(G - 151.5) < 0.1
    ok4 = ok4 and ok
    print(f"  Kyber spec p. 27-28: C = 1/(1-2^-0.292) = {C:.3f} (spec 5.46); "
          f"G = (1025-413) C^2 2^137.4 = 2^{G:.2f} (spec 2^151.5) {'PASS' if ok else 'FAIL'}")
    v = d4f(413)
    ok = abs(v - 37.3) < 0.05
    ok4 = ok4 and ok
    print(f"  Kyber spec p. 28: d4f(413) = {v:.2f} (spec 37.3) {'PASS' if ok else 'FAIL'}\n")
    checks["4 gate model"] = ok4

    print("== 5. Negative controls (each perturbed check must FAIL) ==")
    base = PUBLISHED[0]                     # Kyber512
    fro = PUBLISHED[3]                      # Frodo-640
    neg = [
        (base, {"q": 3329 * 2}, "Kyber512 with q doubled"),
        (base, {"q": 3329 - 200}, "Kyber512 with q - 200"),
        (base, {"se": sd_binomial(2)}, "Kyber512 with eta 3 -> 2"),
        (base, {"se": sd_binomial(3) * 1.05}, "Kyber512 with sigma +5%"),
        (base, {"n": 496}, "Kyber512 with n = 496"),
        (fro, {"q": 2 ** 16}, "Frodo-640 with q = 2^16"),
        (fro, {"se": 2.6}, "Frodo-640 with sigma 2.8 -> 2.6"),
        (fro, {"n": 632}, "Frodo-640 with n = 632"),
    ]
    all_failed = True
    for row, ov, label in neg:
        ok = check_row(row, override=ov, quiet=True)
        e = estimate(ov.get("n", row[2]), ov.get("q", row[3]), ov.get("se", row[4]),
                     None, row[6], row[1])
        print(f"  {label:32s} primal C={e['primal']['C']:.1f} dual C={e['dual']['C']:.1f} "
              f"-> check {'PASSED (bad control!)' if ok else 'FAILED as expected'}")
        all_failed = all_failed and not ok
    print(f"  -> all negative controls failed: {all_failed}\n")
    checks["5 negative controls"] = all_failed

    print("== 6. Monotonicity (primal core-SVP classical, newhope conv, m_max = n + 8) ==")
    mono = True
    prev = -1.0
    row = []
    for n in range(560, 1121, 40):
        c = estimate(n, 2 ** 15, 2.8, None, n + 8, "newhope", do_dual=False)["primal"]["C"]
        mono = mono and c > prev
        prev = c
        row.append(f"{n}:{c:.1f}")
    print("  in n (q=2^15, sigma=2.8): " + " ".join(row))
    prev = -1.0
    row = []
    for s in (1.0, 1.4, 2.0, 2.8, 4.0, 5.6, 8.0):
        c = estimate(1024, 2 ** 15, s, None, 1032, "newhope", do_dual=False)["primal"]["C"]
        mono = mono and c > prev
        prev = c
        row.append(f"{s}:{c:.1f}")
    print("  in sigma (n=1024, q=2^15): " + " ".join(row))
    prev = 1e9
    row = []
    for lq in (12, 13, 14, 15, 16, 18, 20):
        c = estimate(1024, 2 ** lq, 2.8, None, 1032, "newhope", do_dual=False)["primal"]["C"]
        mono = mono and c < prev
        prev = c
        row.append(f"2^{lq}:{c:.1f}")
    print("  in q (n=1024, sigma=2.8): " + " ".join(row))
    print(f"  -> rises with n and sigma, falls with q: {mono}\n")
    checks["6 monotonicity"] = mono

    print("SUMMARY:")
    for k, v in checks.items():
        print(f"  {k:28s} {'PASS' if v else 'FAIL'}")
    return all(checks.values())


# --------------------------------------------------------------------------
# Worked example and ~1000-dimension tables
# --------------------------------------------------------------------------
def example():
    """Kyber512 primal attack at the optimal m: success flips between b = 405 and 406."""
    n, q, s = 512, 3329, sd_binomial(3)
    print("Worked example: Kyber512 as LWE(n=512, q=3329, sigma=sqrt(3/2))")
    for b in (100, 300, 405, 406, 878):
        d = delta_bkz(b)
        print(f"  b={b}: delta={d:.6f}, log2 core-SVP classical={C_CLASSICAL * b:.1f}, "
              f"quantum={C_QUANTUM * b:.1f}, d4f={d4f(b):.1f}")
    m = np.arange(1, 769, dtype=np.int64)
    for b in (405, 406):
        ok = _primal_ok_qary(n + 1, q, s, b, m)
        print(f"  b={b}: q-ary profile success for some m <= 768? {bool(np.any(ok))}"
              f" (first m = {int(m[np.argmax(ok)]) if np.any(ok) else '-'})")
    # plain GSA view at m = 486 (the optimum reported by the Kyber script)
    for b in (405, 406, 410):
        dd = n + 486 + 1
        lhs = s * math.sqrt(b)
        rhs = delta_bkz(b) ** (2 * b - dd - 1) * q ** (486 / dd)
        print(f"  plain GSA, m=486, d={dd}, b={b}: sigma*sqrt(b)={lhs:.3f}  "
              f"delta^(2b-d-1) q^(m/d)={rhs:.3f}  success={lhs <= rhs}")


def _sigma_for_target(n, q, m_max, target, conv="newhope"):
    """Smallest sigma (to 0.005) whose primal classical core-SVP reaches target bits.

    A primal search that finds no block size up to n + m_max counts as
    'above every target' (infinite cost). Returns None if even sigma = 0.05
    already reaches the target (the search interval is [0.05, 16])."""
    def cost(s):
        p = estimate(n, q, s, None, m_max, conv, {"C": C_CLASSICAL}, do_dual=False)["primal"]
        return p.get("C", float("inf"))

    lo, hi = 0.05, 16.0
    if cost(lo) >= target:
        return None
    while hi - lo > 0.005:
        mid = (lo + hi) / 2
        if cost(mid) >= target:
            hi = mid
        else:
            lo = mid
    return hi


def table():
    consts = {"C": C_CLASSICAL, "Q": C_QUANTUM, "P": C_PLAUSIBLE}
    print("T0. Reference sets: primal core-SVP vs gate-count estimates.")
    print("    'MATZOV model' = gates_nn() at our primal (b, d) (lattice-estimator default model);")
    print("    'published refined' = Kyber round-3 Table 4 log2(gates) (PDF p. 21) and FrodoKEM")
    print("    2025 proposal Table A.8 (PDF p. 18), both from the Kyber team's leaky-LWE method.")
    ref = (("Kyber512", 512, 3329, sd_binomial(3), 768, "kyber21", 151.5),
           ("Kyber768", 768, 3329, sd_binomial(2), 1024, "kyber21", 215.1),
           ("Kyber1024", 1024, 3329, sd_binomial(2), 1280, "kyber21", 287.3),
           ("Frodo-640", 640, 2 ** 15, 2.8, 648, "newhope", 175.1),
           ("Frodo-976", 976, 2 ** 16, 2.3, 984, "newhope", 240.0),
           ("Frodo-1344", 1344, 2 ** 16, 1.4, 1352, "newhope", 305.4))
    print(f"{'set':>11} | {'b':>4} {'d':>5} | {'coreC':>6} | {'MATZOV':>7} | {'published':>9} | "
          f"{'MATZOV-core':>11} {'pub-core':>8}")
    for name, n, q, s, mm, conv, pub in ref:
        b, m, d = primal(n, q, s, s, mm, conv)
        core = C_CLASSICAL * b
        g = gates_nn(b, d)
        print(f"{name:>11} | {b:4d} {d:5d} | {core:6.1f} | {g:7.1f} | {pub:9.1f} | "
              f"{g - core:11.1f} {pub - core:8.1f}")
    print()
    print("T1. Plain LWE, secret and error std sigma, m_max = n + 8 samples (FrodoKEM-like, nbar = 8).")
    print("    Core-SVP in log2 (newhope convention: GSA, no log2(b) factor; add ~log2(b) ~ 9.5 for")
    print("    the Frodo convention). 'gates' = lattice-estimator MATZOV cost model at the primal (b, d).")
    print(f"{'n':>5} {'log2q':>5} {'sigma':>5} | {'b':>4} {'C':>6} {'Q':>6} {'P':>6} | "
          f"{'dualC':>6} {'dualQ':>6} | {'b(q-ary)':>8} | {'gates':>6}")
    for n in (976, 1024):
        for lq in (13, 14, 15, 16):
            for sigma in (1.0, 1.4, 2.0, 2.8, 4.0, 8.0):
                q = 2 ** lq
                g = estimate(n, q, sigma, None, n + 8, "newhope", consts)
                k = primal(n, q, sigma, sigma, n + 8, "kyber21")
                kb = k[0] if k else -1
                gp = g["primal"]
                print(f"{n:5d} {lq:5d} {sigma:5.1f} | {gp['b']:4d} {gp['C']:6.1f} {gp['Q']:6.1f} "
                      f"{gp['P']:6.1f} | {g['dual']['C']:6.1f} {g['dual']['Q']:6.1f} | {kb:8d} | "
                      f"{gates_nn(gp['b'], gp['d']):6.1f}")
    print()
    print("T2. Smallest sigma (secret = error std) for a primal classical core-SVP target, plain LWE,")
    print("    m_max = n + 8, newhope convention.")
    print(f"{'n':>5} {'log2q':>5} | {'>=128':>6} {'>=192':>6} {'>=256':>6}")
    for n in (976, 1000, 1024):
        for lq in (13, 14, 15, 16):
            vals = [_sigma_for_target(n, 2 ** lq, n + 8, t) for t in (128, 192, 256)]
            print(f"{n:5d} {lq:5d} | " + " ".join(f"{v:6.3f}" if v else "   n/a" for v in vals))
    print("    (sigma below ~0.5 is outside the regime these formulas were validated on: the")
    print("    secret is then nearly ternary/sparse and hybrid and combinatorial attacks apply.)")
    print()
    print("T2b. Secret std differs from error std (plain LWE n = 1024, q = 2^15, m_max = 1032),")
    print("     newhope convention with Bai-Galbraith rescaling of the secret.")
    print(f"{'sigma_s':>8} {'sigma_e':>8} | {'b':>5} {'C':>6} {'Q':>6} | {'dualC':>6}")
    for ss, se in ((2.8, 2.8), (math.sqrt(2.0 / 3.0), 2.8), (0.5, 2.8), (1.0, 2.8), (2.8, 1.0)):
        e = estimate(1024, 2 ** 15, se, ss, 1032, "newhope",
                     {"C": C_CLASSICAL, "Q": C_QUANTUM})
        print(f"{ss:8.3f} {se:8.3f} | {e['primal']['b']:5d} {e['primal']['C']:6.1f} "
              f"{e['primal']['Q']:6.1f} | {e['dual']['C']:6.1f}")
    print()
    print("T3. Module-LWE rank k = 4 over degree 256 (n = 1024), m_max = 1280, kyber21 convention,")
    print("    centered binomial eta for secret and error.")
    print(f"{'q':>6} {'eta':>4} {'sigma':>6} | {'b':>5} {'C':>6} {'Q':>6} | {'dual b':>6} "
          f"{'dualC':>6} {'dualQ':>6} | {'gates':>6}")
    for q in (3329, 7681, 12289, 2 ** 13, 2 ** 15):
        for eta in (1, 2, 3, 4, 6):
            s = sd_binomial(eta)
            e = estimate(1024, q, s, None, 1280, "kyber21", consts)
            print(f"{q:6d} {eta:4d} {s:6.3f} | {e['primal']['b']:5d} {e['primal']['C']:6.1f} "
                  f"{e['primal']['Q']:6.1f} | {e['dual']['b_C']:6d} {e['dual']['C']:6.1f} "
                  f"{e['dual']['Q']:6.1f} | {gates_nn(e['primal']['b'], e['primal']['d']):6.1f}")
    print()
    print("T4. Module-LWR rank 4 (n = 1024), q = 2^13, rounding to p, secret binomial var mu/4,")
    print("    m_max = 1024 (public-key samples), newhope convention with secret scaling.")
    print(f"{'p':>6} {'mu':>4} {'se(round)':>9} | {'b':>5} {'C':>6} {'Q':>6}")
    for lp in (9, 10, 11):
        for mu in (4, 6, 8):
            se = sd_rounding(2 ** 13, 2 ** lp)
            e = estimate(1024, 2 ** 13, se, math.sqrt(mu / 4.0), 1024, "newhope", do_dual=False)
            print(f"{2 ** lp:6d} {mu:4d} {se:9.4f} | {e['primal']['b']:5d} {e['primal']['C']:6.1f} "
                  f"{e['primal']['Q']:6.1f}")
    print()
    print("T5. Sensitivity of the quantum figure to the sieve constant, Kyber1024 primal b = 878:")
    for label, c in (("Laarhoven 2016, 0.2653", C_QUANTUM), ("Chailloux-Loyer 2021, 0.2570", C_QRW_CL21),
                     ("Bonnetain et al. 2023, 0.2563", C_QRW_BCSS23), ("plausible floor, 0.2075", C_PLAUSIBLE)):
        print(f"  {label:32s} -> {c * 878:6.1f}")


def eps_sensitivity():
    """How much the dual-attack epsilon factor (1, 2 or 4) and the printed-vs-script
    conventions move the published numbers. Informational; no pass/fail."""
    consts = {"C": C_CLASSICAL, "Q": C_QUANTUM, "P": C_PLAUSIBLE}
    print("E1. Dual core-SVP (classical) for eps = F exp(-2 pi^2 tau^2), F = 1, 2, 4.")
    rows = (("Kyber512", 512, 3329, sd_binomial(3), 768, "kyber21"),
            ("Kyber1024", 1024, 3329, sd_binomial(2), 1280, "kyber21"),
            ("NewHope1024", 1024, 12289, 2.0, 2047, "newhope"),
            ("Frodo-640", 640, 2 ** 15, 2.8, 648, "frodo"),
            ("Frodo-976", 976, 2 ** 16, 2.3, 984, "frodo"),
            ("Frodo-1344", 1344, 2 ** 16, 1.4, 1352, "frodo"),
            ("LWE n1024 q2^16 s2.8", 1024, 2 ** 16, 2.8, 1032, "newhope"))
    print(f"{'set':>21} {'conv':>8} | {'F=1':>7} {'F=2':>7} {'F=4':>7} | {'F=4 - F=1':>9}")
    for name, n, q, s, mm, conv in rows:
        v = [dual(n, q, s, s, mm, C_CLASSICAL, conv, f)[0] for f in (1.0, 2.0, 4.0)]
        print(f"{name:>21} {conv:>8} | {v[0]:7.2f} {v[1]:7.2f} {v[2]:7.2f} | {v[2] - v[0]:9.2f}")
    print()
    print("E2. FrodoKEM Table 10 dual rows with the factor PRINTED in the spec (F = 2, PDF p. 43)")
    print("    versus the factor in pqsec.py (F = 4), frodo convention otherwise.")
    for name, n, q, s, pub in (("Frodo-640", 640, 2 ** 15, 2.8, (149.6, 136.5, 108.7)),
                               ("Frodo-976", 976, 2 ** 16, 2.3, (214.5, 195.4, 154.9)),
                               ("Frodo-1344", 1344, 2 ** 16, 1.4, (279.8, 254.7, 201.4))):
        for f in (2.0, 4.0):
            got = tuple(round(dual(n, q, s, s, n + 8, c, "frodo", f)[0], 1)
                        for c in (C_CLASSICAL, C_QUANTUM, C_PLAUSIBLE))
            print(f"  {name:10s} F={f:.0f}: C/Q/P = {got}  published {pub}  "
                  f"{'match' if got == pub else 'differs'}")
    print()
    print("E3. Formulas exactly as printed (adps16 convention: Kannan d+1, dual length")
    print("    delta^(d-1) q^(n/d), eps = 4 exp) versus the published tables.")
    for name, n, q, s, mm, pub in (
            ("NewHope1024", 1024, 12289, 2.0, 2047, "primal 259/235/183, dual 257/233/182"),
            ("NewHope-USENIX", 1024, 12289, math.sqrt(8), 2047, "primal 282/256/200, dual 281/255/199"),
            ("Kyber512", 512, 3329, sd_binomial(3), 768, "primal 118/107/84, dual 117/106/83"),
            ("Kyber1024", 1024, 3329, sd_binomial(2), 1280, "primal 256/232/182, dual 253/230/180")):
        e = estimate(n, q, s, None, mm, "adps16", consts)
        p, d = e["primal"], e["dual"]
        print(f"  {name:14s} adps16: primal b={p['b']} {math.floor(p['C'])}/{math.floor(p['Q'])}/"
              f"{math.floor(p['P'])}, dual {math.floor(d['C'])}/{math.floor(d['Q'])}/"
              f"{math.floor(d['P'])}   published: {pub}")


def main(argv):
    mode = argv[1] if len(argv) > 1 else "validate"
    if mode == "eps":
        eps_sensitivity()
        return 0
    if mode == "validate":
        ok = validate()
        print("OVERALL:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if mode == "table":
        table()
        return 0
    if mode == "example":
        example()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
