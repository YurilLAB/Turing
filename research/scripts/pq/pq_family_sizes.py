"""Recompute key and ciphertext sizes of post-quantum KEM families from their parameters.

Reproduces, from first principles, the size tables quoted in
research/notes/pq/pq-families-for-diversity.md and checks them against the primary sources:

  FrodoKEM   -- FrodoKEM Preliminary Standardization Proposal, revision 2025-09-29,
                Section 8 (size formulas), Tables A.1-A.6 (parameters, error tables, sizes).
  Classic McEliece -- cryptosystem specification 2022-10-23, Section 7 (m, n, t);
                NIST IR 8545 Table 8 (sizes); NIST IR 8413 Table 6 (round-3 sizes).
  HQC        -- HQC specification 2025-08-22, Section 4.1-4.2 (Tables 5 and 6).
  BIKE       -- BIKE round-4 specification 2022-10-10, Tables 4 and 5 (sizes in bits);
                NIST IR 8545 Table 6 (sizes in bytes).
  NTRU       -- NTRU round-3 specification 2020-09-30, Section 1.5 (derived constants);
                NIST IR 8413 Table 6 (includes the June-2021 level-5 sets).
  NTRU Prime -- NTRU Prime round-3 specification 2020-10-07, Sections 3.1-3.15 (Encode,
                parameters), Table 1 (sizes); NIST IR 8413 Table 7.
  ML-KEM     -- FIPS 203, Section 8, Tables 2 and 3.
  NTRU+      -- KpqC final specification 2026-01-30, Table 7 (pk, ct).
  SMAUG-T    -- KpqC final specification 2026-02-04, Tables 1 and 3 (pk, ct).

It also checks that each FrodoKEM error table (Table A.3, probabilities in units of 2^-16)
is consistent with its sampling table T_chi (Table A.4) under the inversion sampler of
Section 7.5, and computes the standard deviation of each table for comparison with the sigma
column of Table A.3.

Run:  python pq_family_sizes.py
Deterministic; no network access; exits non-zero if any check fails.
"""
import math
import sys

FAILS = []


def check(label, got, want):
    ok = got == want
    print(f"  [{'ok' if ok else 'MISMATCH'}] {label}: computed {got}, source {want}")
    if not ok:
        FAILS.append(label)


# ----------------------------------------------------------------------------------------
# FrodoKEM (proposal 2025-09-29)
# ----------------------------------------------------------------------------------------
FRODO = {
    # name: (D, n, nbar, B, len_sec, len_SE, len_salt)  -- Tables A.1 and A.2
    "FrodoKEM-640": (15, 640, 8, 2, 128, 256, 256),
    "FrodoKEM-976": (16, 976, 8, 3, 192, 384, 384),
    "FrodoKEM-1344": (16, 1344, 8, 4, 256, 512, 512),
    "eFrodoKEM-640": (15, 640, 8, 2, 128, 128, 0),
    "eFrodoKEM-976": (16, 976, 8, 3, 192, 192, 0),
    "eFrodoKEM-1344": (16, 1344, 8, 4, 256, 256, 0),
}
FRODO_SIZES = {  # Tables A.5 and A.6: (sk, pk, ct, ss) bytes
    "FrodoKEM-640": (19888, 9616, 9752, 16),
    "FrodoKEM-976": (31296, 15632, 15792, 24),
    "FrodoKEM-1344": (43088, 21520, 21696, 32),
    "eFrodoKEM-640": (19888, 9616, 9720, 16),
    "eFrodoKEM-976": (31296, 15632, 15744, 24),
    "eFrodoKEM-1344": (43088, 21520, 21632, 32),
}
LEN_A = 128

# Table A.3: sigma, then probabilities of 0, +-1, +-2, ... in units of 2^-16.
FRODO_CHI = {
    "640": (2.8, [9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1]),
    "976": (2.3, [11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1]),
    "1344": (1.4, [18286, 14320, 6876, 2023, 364, 40, 2]),
}
# Table A.4: T_chi(0..d)
FRODO_T = {
    "640": [4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767],
    "976": [5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767],
    "1344": [9142, 23462, 30338, 32361, 32725, 32765, 32767],
}


def frodo():
    print("FrodoKEM (proposal rev. 2025-09-29): sizes from Section 8 formulas")
    for name, (D, n, nbar, B, lsec, lse, lsalt) in FRODO.items():
        pk_bits = LEN_A + D * n * nbar
        sk_bits = 2 * lsec + LEN_A + D * n * nbar + 16 * n * nbar
        ct_bits = D * n * nbar + D * nbar * nbar + lsalt
        got = (sk_bits // 8, pk_bits // 8, ct_bits // 8, lsec // 8)
        check(f"{name} (sk, pk, ct, ss)", got, FRODO_SIZES[name])
        # message capacity: B bits per entry of the nbar x nbar matrix must equal len_sec
        check(f"{name} message bits B*nbar^2 = len_sec", B * nbar * nbar, lsec)
    print("FrodoKEM error tables: Table A.3 probabilities vs Table A.4 sampler thresholds")
    for lvl, (sigma, probs) in FRODO_CHI.items():
        T = FRODO_T[lvl]
        total = probs[0] + 2 * sum(probs[1:])
        check(f"chi-{lvl} probabilities sum to 2^16", total, 65536)
        # Sampler (Sec 7.5): t uniform in [0, 2^15); |e| = #{i < d : t > T(i)}; sign from r0.
        # Pr[|e| = 0] = (T(0)+1)/2^15 ; Pr[e = +k] = Pr[e = -k] = (T(k)-T(k-1))/2^16.
        derived = [2 * (T[0] + 1)] + [T[k] - T[k - 1] for k in range(1, len(T))]
        check(f"chi-{lvl} Table A.4 reproduces Table A.3", derived, probs)
        var = sum(2 * p * k * k for k, p in enumerate(probs) if k > 0) / 65536
        print(f"      chi-{lvl}: sd of the table = {math.sqrt(var):.4f} (Table A.3 sigma column = {sigma})")


# ----------------------------------------------------------------------------------------
# Classic McEliece (spec 2022-10-23, Section 7)
# ----------------------------------------------------------------------------------------
MCE = {"mceliece348864": (12, 3488, 64), "mceliece460896": (13, 4608, 96),
       "mceliece6688128": (13, 6688, 128), "mceliece6960119": (13, 6960, 119),
       "mceliece8192128": (13, 8192, 128)}
MCE_IR8545 = {  # NIST IR 8545 Table 8: (pk, sk, ct)
    "mceliece348864": (261120, 6492, 96), "mceliece460896": (524160, 13608, 156),
    "mceliece6688128": (1044992, 13932, 208), "mceliece6960119": (1047319, 13948, 194),
    "mceliece8192128": (1357824, 14120, 208)}
MCE_IR8413_PK = {"mceliece6688128": 104992}  # as printed in NIST IR 8413 Table 6 (typo check)


def mceliece():
    print("Classic McEliece: pk = mt*ceil(k/8) (spec 6.2: mt rows of k bits, each row padded to bytes),"
          " ct = ceil(mt/8), sk = 40 + 2t + (2m-1)2^(m-1)/8 + ceil(n/8), with k = n - mt")
    for name, (m, n, t) in MCE.items():
        k = n - m * t
        pk = m * t * math.ceil(k / 8)
        ct = math.ceil(m * t / 8)
        # private key (spec 6.2): delta(32) || c(8) || g (t coeffs, 2 bytes) || alpha as
        # Benes control bits ((2m-1)2^(m-1) bits) || s (n bits)
        sk = 32 + 8 + 2 * t + ((2 * m - 1) * (1 << (m - 1))) // 8 + math.ceil(n / 8)
        check(f"{name} (pk, sk, ct)", (pk, sk, ct), MCE_IR8545[name])
        print(f"      {name}: code length n={n}, dimension k={k}, rate k/n={k / n:.3f}, errors t={t};"
              f" round-3 ct with 32-byte confirmation = {ct + 32}")
    for name, printed in MCE_IR8413_PK.items():
        m, n, t = MCE[name]
        true_pk = m * t * math.ceil((n - m * t) / 8)
        print(f"      NIST IR 8413 Table 6 prints {name} pk as {printed}; formula gives {true_pk}"
              f" -> {'typo in IR 8413' if printed != true_pk else 'consistent'}")


# ----------------------------------------------------------------------------------------
# HQC (spec 2025-08-22, Section 4)
# ----------------------------------------------------------------------------------------
HQC = {"HQC-1": (46, 384, 17669, 128), "HQC-3": (56, 640, 35851, 192), "HQC-5": (90, 640, 57637, 256)}
HQC_T6 = {"HQC-1": (2241, 2321, 4433), "HQC-3": (4514, 4602, 8978), "HQC-5": (7237, 7333, 14421)}


def is_prime(x):
    if x < 2:
        return False
    i = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += 1
    return True


def order_of_2_is_full(n):
    """True if 2 generates (Z/nZ)*, i.e. x^n - 1 = (x - 1)(x^(n-1) + ... + 1) over F2 (HQC 6.3)."""
    phi = n - 1
    fac, x, d = set(), phi, 2
    while d * d <= x:
        while x % d == 0:
            fac.add(d)
            x //= d
        d += 1
    if x > 1:
        fac.add(x)
    return all(pow(2, phi // f, n) != 1 for f in fac)


def hqc():
    print("HQC: ek = 32 + ceil(n/8); dk = ek + 32 + ceil(k/8) + 32; c = ceil(n/8) + ceil(n1*n2/8) + 16")
    for name, (n1, n2, n, k) in HQC.items():
        ek = 32 + math.ceil(n / 8)
        dk = ek + 32 + math.ceil(k / 8) + 32
        c = math.ceil(n / 8) + math.ceil(n1 * n2 / 8) + 16
        check(f"{name} (ek, dk, c)", (ek, dk, c), HQC_T6[name])
        smallest = next(p for p in range(n1 * n2 + 1, n + 1) if is_prime(p) and order_of_2_is_full(p))
        check(f"{name} n = smallest primitive prime > n1*n2 = {n1 * n2}", smallest, n)


# ----------------------------------------------------------------------------------------
# BIKE (round-4 spec, Table 5 gives bits)
# ----------------------------------------------------------------------------------------
BIKE = {"BIKE-L1": 12323, "BIKE-L3": 24659, "BIKE-L5": 40973}
BIKE_IR8545 = {"BIKE-L1": (1541, 1573), "BIKE-L3": (3083, 3115), "BIKE-L5": (5122, 5154)}


def bike():
    print("BIKE: pk = r bits, ct = r + 256 bits (spec Table 5); bytes = ceil(bits/8)")
    for name, r in BIKE.items():
        got = (math.ceil(r / 8), math.ceil((r + 256) / 8))
        check(f"{name} (pk, ct) bytes vs NIST IR 8545 Table 6", got, BIKE_IR8545[name])
        check(f"{name} r prime and 2 primitive mod r", is_prime(r) and order_of_2_is_full(r), True)


# ----------------------------------------------------------------------------------------
# NTRU (round-3 spec derived constants; level-5 sets from NIST IR 8413 Table 6)
# ----------------------------------------------------------------------------------------
NTRU = {"ntruhps2048677": (677, 2048), "ntruhrss701": (701, 8192), "ntruhps4096821": (821, 4096),
        "ntruhps40961229": (1229, 4096), "ntruhrss1373": (1373, None)}
NTRU_T6 = {"ntruhps2048677": (930, 1234, 930), "ntruhrss701": (1138, 1450, 1138),
           "ntruhps4096821": (1230, 1590, 1230), "ntruhps40961229": (1842, 2366, 1842),
           "ntruhrss1373": (2401, 2983, 2401)}


def ntru():
    print("NTRU: pk = ct = ceil((n-1)log2 q/8); sk = 2*ceil((n-1)/5) + ceil((n-1)log2 q/8) + 32")
    for name, (n, q) in NTRU.items():
        if q is None:  # ntru-hrss: q = 2^ceil(7/2 + log2 n)  (spec 1.3.3)
            q = 2 ** math.ceil(3.5 + math.log2(n))
        logq = int(math.log2(q))
        packed = math.ceil((n - 1) * logq / 8)
        s3 = math.ceil((n - 1) / 5)
        got = (packed, 2 * s3 + packed + 32, packed)
        check(f"{name} (q={q}) (pk, sk, ct)", got, NTRU_T6[name])


# ----------------------------------------------------------------------------------------
# NTRU Prime (round-3 spec)
# ----------------------------------------------------------------------------------------
def encode_len(M):
    """Length in bytes of Encode(R, M) (spec Figure 1); depends only on M."""
    limit = 16384
    if len(M) == 0:
        return 0
    if len(M) == 1:
        m, out = M[0], 0
        while m > 1:
            out += 1
            m = (m + 255) // 256
        return out
    out, M2 = 0, []
    for i in range(0, len(M) - 1, 2):
        m = M[i] * M[i + 1]
        while m >= limit:
            out += 1
            m = (m + 255) // 256
        M2.append(m)
    if len(M) & 1:
        M2.append(M[-1])
    return out + encode_len(M2)


NTRUP = {653: 4621, 761: 4591, 857: 5167, 953: 6343, 1013: 7177, 1277: 7879}
NTRUP_T1 = {  # spec Table 1: (sk, pk, ct) for sntrup then ntrulpr
    ("sntrup", 653): (1518, 994, 897), ("ntrulpr", 653): (1125, 897, 1025),
    ("sntrup", 761): (1763, 1158, 1039), ("ntrulpr", 761): (1294, 1039, 1167),
    ("sntrup", 857): (1999, 1322, 1184), ("ntrulpr", 857): (1463, 1184, 1312),
    ("sntrup", 953): (2254, 1505, 1349), ("ntrulpr", 953): (1652, 1349, 1477),
    ("sntrup", 1013): (2417, 1623, 1455), ("ntrulpr", 1013): (1773, 1455, 1583),
    ("sntrup", 1277): (3059, 2067, 1847), ("ntrulpr", 1277): (2231, 1847, 1975)}
NTRUP_IR8413_SK = {("sntrup", 653): 15158}  # as printed in NIST IR 8413 Table 7 (typo check)


def ntruprime():
    print("NTRU Prime: sizes from the spec's Encode (Figure 1) and encodings (Sections 3.1-3.3)")
    for p, q in NTRUP.items():
        small = math.ceil(p / 4)
        field = encode_len([q] * p)
        rounded = encode_len([(q - 1) // 3 + 1] * p)
        s_pk, s_ct = field, rounded + 32
        s_sk = 2 * small + s_pk + small + 32  # f, 1/g, pk, rho, cached Hash4(pk)
        check(f"sntrup{p} (sk, pk, ct)", (s_sk, s_pk, s_ct), NTRUP_T1[("sntrup", p)])
        l_pk = 32 + rounded
        l_ct = rounded + 128 + 32
        l_sk = small + l_pk + 32 + 32  # a, pk, rho, cached Hash4(pk)
        check(f"ntrulpr{p} (sk, pk, ct)", (l_sk, l_pk, l_ct), NTRUP_T1[("ntrulpr", p)])
    for key, printed in NTRUP_IR8413_SK.items():
        print(f"      NIST IR 8413 Table 7 prints {key[0]}{key[1]} secret key as {printed};"
              f" spec Table 1 gives {NTRUP_T1[key][0]} -> typo in IR 8413")


# ----------------------------------------------------------------------------------------
# ML-KEM (FIPS 203 Tables 2 and 3)
# ----------------------------------------------------------------------------------------
MLKEM = {"ML-KEM-512": (2, 10, 4), "ML-KEM-768": (3, 10, 4), "ML-KEM-1024": (4, 11, 5)}
MLKEM_T3 = {"ML-KEM-512": (800, 1632, 768), "ML-KEM-768": (1184, 2400, 1088), "ML-KEM-1024": (1568, 3168, 1568)}


def mlkem():
    print("ML-KEM: ek = 384k+32, dk = 768k+96, ct = 32(du*k + dv)")
    for name, (k, du, dv) in MLKEM.items():
        check(f"{name} (ek, dk, ct)", (384 * k + 32, 768 * k + 96, 32 * (du * k + dv)), MLKEM_T3[name])


# ----------------------------------------------------------------------------------------
# KpqC KEMs (added 2026-09-27): NTRU+ final spec 2026-01-30 Table 7; SMAUG-T final spec
# 2026-02-04 Tables 1 and 3. The packing formulas below are my own derivation (plain bit
# packing of every coefficient), checked against the spec tables; they are not quoted from
# the specifications.
# ----------------------------------------------------------------------------------------
NTRUPLUS = {"NTRU+768": 768, "NTRU+864": 864, "NTRU+1152": 1152}
NTRUPLUS_T7 = {"NTRU+768": (1152, 1152), "NTRU+864": (1296, 1296), "NTRU+1152": (1728, 1728)}
SMAUG = {  # name: (k, n, q, p, p') from spec Table 3
    "SMAUG-T128": (2, 256, 1024, 256, 32), "SMAUG-T192": (3, 256, 2048, 512, 16),
    "SMAUG-T256": (4, 256, 2048, 512, 128)}
SMAUG_T3 = {"SMAUG-T128": (672, 672), "SMAUG-T192": (1088, 992), "SMAUG-T256": (1440, 1376)}


def kpqc():
    print("NTRU+: q = 3457 < 2^12, so pk = ct = 12 n / 8 bytes (derivation)")
    for name, n in NTRUPLUS.items():
        check(f"{name} (pk, ct)", (12 * n // 8, 12 * n // 8), NTRUPLUS_T7[name])
    print("SMAUG-T: pk = 32-byte seed + k n log2(q) / 8; ct = k n log2(p) / 8 + n log2(p') / 8 (derivation)")
    for name, (k, n, q, p, pp) in SMAUG.items():
        lq, lp, lpp = (int(math.log2(x)) for x in (q, p, pp))
        check(f"{name} (pk, ct)", (32 + k * n * lq // 8, k * n * lp // 8 + n * lpp // 8), SMAUG_T3[name])


def dimension_table():
    print("What 'about 1000 dimensions' means per family (secret dimension, not attack-lattice dimension)")
    rows = [
        ("FrodoKEM-976", "plain LWE", "n = 976", 976),
        ("ML-KEM-1024", "Module-LWE", "k*n = 4*256", 4 * 256),
        ("FireSaber", "Module-LWR", "l*n = 4*256", 4 * 256),
        ("NewHope1024 (withdrawn)", "Ring-LWE", "n = 1024", 1024),
        ("sntrup1013 / ntrulpr1013", "NTRU / Ring-LWR (prime-degree field)", "p = 1013", 1013),
        ("ntruhps40961229", "NTRU (cyclotomic x^n - 1)", "n = 1229", 1229),
        ("NTRU+1152 (KpqC)", "NTRU (x^n - x^(n/2) + 1)", "n = 1152", 1152),
        ("SMAUG-T256 (KpqC)", "Module-LWE + Module-LWR", "k*n = 4*256", 4 * 256),
    ]
    for name, family, how, d in rows:
        print(f"      {name:28s} {family:40s} {how:14s} -> {d}")


if __name__ == "__main__":
    if "--negative-control" in sys.argv:
        # Planted error: replace two source values with plausible wrong ones (the NIST round-3
        # FrodoKEM-640 ciphertext size without the salt, and the IR 8413 McEliece typo).
        # The run must report MISMATCH and exit 1; if it passes, the checker is not checking.
        FRODO_SIZES["FrodoKEM-640"] = (19888, 9616, 9720, 16)
        MCE_IR8545["mceliece6688128"] = (104992, 13932, 208)
        print("NEGATIVE CONTROL: two planted wrong source values; expect 2 MISMATCH lines and exit 1")
    frodo()
    mceliece()
    hqc()
    bike()
    ntru()
    ntruprime()
    mlkem()
    kpqc()
    dimension_table()
    print()
    if FAILS:
        print("FAILED checks:", FAILS)
        sys.exit(1)
    print("All checks passed.")
