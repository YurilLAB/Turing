"""Comparison numbers for post-quantum KEM families as Turing candidates.

Reproduces the comparison table and the derived ratios in
research/notes/pq/pq-families-for-diversity.md (Sections 2.7, 5.1 and 7).

Inputs (all transcribed from primary sources; see the notes' claim ledger):
  sizes   -- FIPS 203 Table 3 (ML-KEM); FrodoKEM proposal 2025-09-29 Tables A.5/A.6;
             NTRU Prime round-3 spec Table 1; NIST IR 8413 Table 6 (NTRU);
             HQC spec 2025-08-22 Table 6; NIST IR 8545 Tables 6 and 8 (BIKE, Classic McEliece).
             (pq_family_sizes.py recomputes all of these from the scheme parameters.)
  speed   -- eBACS/SUPERCOP median cycles, machine "amd64; Raptor Cove (b06a2-40);
             2024 Intel Core 5 210H, P cores; freshwrap,big", supercop-20260627
             (https://bench.cr.yp.to/results-kem/amd64-freshwrap,big.html, saved 2026-09-26,
             extracted with ebacs_kem_extract.py);
             FrodoKEM CiC 2025 paper Table 10 (Kyber and FrodoKEM, i7-8700 / i3-8109U);
             HQC spec 2025-08-22 Tables 7 and 8 (reference vs AVX2).

What it computes and checks:
  1. public key + ciphertext bytes per family, and the ratio to ML-KEM-768;
  2. total cycles (keygen + encaps + decaps) and encaps + decaps, ratio to ML-KEM-768;
  3. FrodoKEM-976-AES / Kyber768 ratios from the CiC paper's own Table 10;
  4. HQC reference / optimized ratios;
  5. bytes a recipient-side file header would carry for candidate hybrid layers
     (one ciphertext per recipient; public keys transmitted once);
  6. the spread of FrodoKEM security estimates across cost models: FrodoKEM proposal
     2025-09-29 Table A.7 versus the CiC 2025 paper's Tables 6 (core-SVP) and 7 (C-2D-Sieve);
  7. a planted-error negative control (--negative-control) that must fail.

Deterministic, no network. Run:  python fam_compare.py   (exits 1 if a check fails)
"""
import sys

FAILS = []


def check(label, cond):
    print(f"  [{'ok' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILS.append(label)


# name: (family, assumption, "dimension" description, dim, pk, ct, level claimed)
SIZES = {
    "ML-KEM-768": ("lattice", "Module-LWE", "k*n = 3*256", 768, 1184, 1088, "3"),
    "ML-KEM-1024": ("lattice", "Module-LWE", "k*n = 4*256", 1024, 1568, 1568, "5"),
    "FrodoKEM-976": ("lattice", "plain LWE", "n = 976", 976, 15632, 15792, "3"),
    "FrodoKEM-1344": ("lattice", "plain LWE", "n = 1344", 1344, 21520, 21696, "5"),
    "eFrodoKEM-976": ("lattice", "plain LWE", "n = 976", 976, 15632, 15744, "3"),
    "sntrup1013": ("lattice", "NTRU (x^p-x-1)", "p = 1013", 1013, 1623, 1455, "4 (IR 8413)"),
    "sntrup1277": ("lattice", "NTRU (x^p-x-1)", "p = 1277", 1277, 2067, 1847, "5 (IR 8413)"),
    "ntrulpr1013": ("lattice", "Ring-LWR (x^p-x-1)", "p = 1013", 1013, 1455, 1583, "4 (IR 8413)"),
    "ntruhps40961229": ("lattice", "NTRU (x^n-1)", "n = 1229", 1229, 1842, 1842, "5"),
    "HQC-3": ("code", "QCSD (Hamming)", "n = 35,851", 35851, 4514, 8978, "3"),
    "HQC-5": ("code", "QCSD (Hamming)", "n = 57,637", 57637, 7237, 14421, "5"),
    "BIKE-L3": ("code", "QCSD + QCCF (MDPC)", "2r = 49,318", 49318, 3083, 3115, "3"),
    "mceliece460896": ("code", "Goppa / syndrome decoding", "n = 4608", 4608, 524160, 156, "3 (NIST: >= 2)"),
    "mceliece6688128": ("code", "Goppa / syndrome decoding", "n = 6688", 6688, 1044992, 208, "5"),
}

# eBACS medians, supercop-20260627, amd64 Raptor Cove freshwrap,big: (keygen, encaps, decaps)
EBACS = {
    "ML-KEM-768": (33532, 32523, 34174),
    "ML-KEM-1024": (47930, 47432, 49592),
    "FrodoKEM-976": (1755889, 2337295, 2233020),      # frodokem976aes (T: flag)
    "FrodoKEM-1344": (3180018, 3950169, 3797699),     # frodokem1344aes (T: flag)
    "sntrup1013": (1253407, 46811, 62564),
    "sntrup1277": (1961552, 59730, 78908),
    "ntrulpr1013": (39750, 67126, 80016),
    # HQC: the round-4 builds (hqc192round4, hqc256round4; T: flag). eBACS's plain "hqc192"/"hqc256"
    # are the "2020.04 version" (about 2-4x slower: 654166/945962/1299266 and 1068618/1547563/2100537).
    # Neither is the 2025-08-22 specification (see fam_ebacs_versions.py).
    "HQC-3": (159282, 397628, 645720),                # hqc192round4 (T: flag)
    "HQC-5": (323747, 767333, 1263532),               # hqc256round4 (T: flag)
    "BIKE-L3": (1223722, 205199, 4350881),            # bikel3 (C:T: flags)
    "mceliece460896": (149639212, 56309, 274128),     # large IQR ('?') on keygen
    "mceliece6688128": (369472702, 93703, 270169),    # large IQR ('?') on keygen
}

# FrodoKEM CiC 2025 Table 10 (thousands of cycles): (pk, ct, KG, E, D)
CIC_T10 = {"Kyber768": (1184, 1088, 39, 53, 42), "FrodoKEM-976-AES": (15632, 15792, 2043, 2125, 2042)}
# HQC spec Tables 7 and 8 (thousands of cycles): reference, optimized
HQC_REF = {"HQC-1": (4557, 9116, 13918), "HQC-3": (13783, 27571, 41669), "HQC-5": (33123, 66261, 100213)}
HQC_OPT = {"HQC-1": (76, 150, 353), "HQC-3": (181, 355, 732), "HQC-5": (363, 720, 1435)}


def main(negative=False):
    if negative:
        print("NEGATIVE CONTROL: planting FrodoKEM-976 ct = 15744 in the salted row; expect FAIL")
        SIZES["FrodoKEM-976"] = SIZES["FrodoKEM-976"][:5] + (15744, "3")
    ref = SIZES["ML-KEM-768"]
    ref_bytes = ref[4] + ref[5]
    print("1. Public key + ciphertext (bytes), ratio to ML-KEM-768")
    print(f"   {'scheme':18s} {'assumption':26s} {'dimension':14s} {'pk':>10s} {'ct':>7s} {'pk+ct':>10s} {'x768':>7s}")
    for name, (fam, assumption, how, dim, pk, ct, lvl) in SIZES.items():
        tot = pk + ct
        print(f"   {name:18s} {assumption:26s} {how:14s} {pk:>10,} {ct:>7,} {tot:>10,} {tot / ref_bytes:>7.1f}")
    check("salted FrodoKEM-976 ct exceeds eFrodoKEM-976 ct by the 384-bit salt (48 bytes)",
          SIZES["FrodoKEM-976"][5] - SIZES["eFrodoKEM-976"][5] == 384 // 8)
    check("ML-KEM-768 pk+ct = 2272", ref_bytes == 2272)

    print("\n2. eBACS medians (cycles), supercop-20260627, Intel Core 5 210H P-core; ratio to ML-KEM-768")
    rk = EBACS["ML-KEM-768"]
    rt, rs = sum(rk), rk[1] + rk[2]
    print(f"   {'scheme':18s} {'keygen':>12s} {'encaps':>10s} {'decaps':>10s} {'total x768':>11s} {'enc+dec x768':>13s}")
    for name, (kg, en, de) in EBACS.items():
        print(f"   {name:18s} {kg:>12,} {en:>10,} {de:>10,} {(kg + en + de) / rt:>11.1f} {(en + de) / rs:>13.1f}")
    check("FrodoKEM-976 enc+dec is 40-80x ML-KEM-768 on this machine",
          40 <= (EBACS["FrodoKEM-976"][1] + EBACS["FrodoKEM-976"][2]) / rs <= 80)
    check("Classic McEliece keygen is > 1000x ML-KEM-768 keygen",
          EBACS["mceliece460896"][0] / rk[0] > 1000)

    print("\n3. FrodoKEM CiC 2025 Table 10: FrodoKEM-976-AES vs Kyber768")
    k, f = CIC_T10["Kyber768"], CIC_T10["FrodoKEM-976-AES"]
    for i, lab in enumerate(("KeyGen", "Encaps", "Decaps")):
        print(f"   {lab}: {f[2 + i]} / {k[2 + i]} = {f[2 + i] / k[2 + i]:.1f}x")
    print(f"   pk+ct: {f[0] + f[1]:,} / {k[0] + k[1]:,} = {(f[0] + f[1]) / (k[0] + k[1]):.1f}x")
    check("CiC Table 10 ratios lie between 38x and 53x", all(38 <= f[2 + i] / k[2 + i] <= 53 for i in range(3)))

    print("\n4. HQC reference / AVX2-optimized cycle ratio (HQC spec Tables 7, 8)")
    for name in HQC_REF:
        r = [a / b for a, b in zip(HQC_REF[name], HQC_OPT[name])]
        print(f"   {name}: KeyGen {r[0]:.0f}x, Encaps {r[1]:.0f}x, Decaps {r[2]:.0f}x")
    allr = [a / b for n in HQC_REF for a, b in zip(HQC_REF[n], HQC_OPT[n])]
    check("all HQC ref/opt ratios lie in [35, 95] (note: ref and opt built with different gcc)", all(35 <= x <= 95 for x in allr))

    print("\n5. Per-recipient ciphertext bytes for candidate hybrid KEM layers (X25519 share = 32 bytes)")
    combos = {
        "X-Wing (X25519 + ML-KEM-768)": 32 + 1088,
        "X25519 + ML-KEM-1024": 32 + 1568,
        "X25519 + ML-KEM-768 + FrodoKEM-976": 32 + 1088 + 15792,
        "X25519 + ML-KEM-1024 + FrodoKEM-1344": 32 + 1568 + 21696,
        "X25519 + ML-KEM-768 + HQC-3": 32 + 1088 + 8978,
        "X25519 + ML-KEM-768 + mceliece6688128": 32 + 1088 + 208,
    }
    for k2, v in combos.items():
        print(f"   {k2:42s} {v:>7,} bytes")
    check("X-Wing ciphertext = 1120 bytes", combos["X-Wing (X25519 + ML-KEM-768)"] == 1120)

    print("\n6. FrodoKEM estimates under different cost models (log2 cost)")
    # Proposal 2025-09-29 Table A.7: (primal C, primal Q, dual C, dual Q)
    a7 = {"640": (150.8, 137.6, 149.6, 136.5), "976": (216.0, 196.7, 214.5, 195.4),
          "1344": (281.6, 256.3, 279.8, 254.7)}
    # CiC 2025 Table 6 (core-SVP): primal uSVP C-LSF, primal uSVP Q-RW, min over attacks C-LSF, Q-RW
    t6 = {"640": (138.5, 123.0, min(138.5, 139.5, 145.7, 144.4), min(123.0, 124.0, 129.3, 128.3)),
          "976": (199.8, 177.0, min(199.8, 200.8, 207.9, 205.4), min(177.0, 178.0, 184.1, 183.3)),
          "1344": (261.8, 231.6, min(261.8, 262.8, 270.9, 254.8), min(231.6, 232.6, 239.6, 227.6))}
    # CiC 2025 Table 7 (beyond core-SVP), C-2D-Sieve rows, all attacks and BKZ/PBKZ
    t7 = {"640": (163.6, 158.6, 164.4, 163.0, 159.1, 163.8),
          "976": (231.6, 225.4, 228.9, 231.0, 225.8, 228.4),
          "1344": (300.1, 292.3, 282.4, 299.5, 292.8, 281.8)}
    drops, rises = [], []
    for lvl in a7:
        d_c = a7[lvl][0] - t6[lvl][0]
        d_q = a7[lvl][1] - t6[lvl][1]
        d_min_c = min(a7[lvl][0], a7[lvl][2]) - t6[lvl][2]
        d_min_q = min(a7[lvl][1], a7[lvl][3]) - t6[lvl][3]
        up = min(t7[lvl]) - t6[lvl][2]
        up_max = max(t7[lvl]) - t6[lvl][2]
        drops += [d_c, d_q, d_min_c, d_min_q]
        rises += [up, up_max]
        print(f"   Frodo-{lvl}: proposal A.7 -> CiC T6 primal: classical -{d_c:.1f}, quantum -{d_q:.1f};"
              f" cheapest attack: classical -{d_min_c:.1f}, quantum -{d_min_q:.1f};"
              f" C-2D-Sieve above cheapest core-SVP classical: +{up:.1f} to +{up_max:.1f}")
    print(f"   range of drops: {min(drops):.1f} to {max(drops):.1f} bits; range of rises: {min(rises):.1f} to {max(rises):.1f} bits")
    check("refreshed core-SVP estimates are 10-30 bits below the proposal's Table A.7", 10 <= min(drops) and max(drops) <= 30)
    check("memory-aware C-2D-Sieve estimates are 10-50 bits above the cheapest core-SVP classical", 10 <= min(rises) and max(rises) <= 50)
    # CiC 2025 Table 7, C-LSF-Sieve rows (BKZ uSVP, BDD, dual-sieve-FFT; PBKZ uSVP, BDD, dual-sieve-FFT).
    # draft-longa-cfrg-frodokem-security-considerations-00 Sec. 5.2 quotes "149.8 bits",
    # "212.6 bits" and "266.8 bits" as the beyond-core-SVP estimates; they should be these minima.
    t7_lsf = {"640": (154.7, 149.8, 155.5, 154.3, 150.5, 155.1),
              "976": (218.6, 212.6, 217.6, 218.2, 213.1, 217.2),
              "1344": (282.9, 275.4, 267.2, 282.4, 276.0, 266.8)}
    quoted = {"640": 149.8, "976": 212.6, "1344": 266.8}
    for lvl in t7_lsf:
        print(f"   Frodo-{lvl}: min of CiC Table 7 C-LSF-Sieve rows = {min(t7_lsf[lvl])} (draft quotes {quoted[lvl]})")
    check("security-considerations draft figures = minima of CiC Table 7 C-LSF-Sieve rows",
          all(min(t7_lsf[l]) == quoted[l] for l in quoted))

    print()
    if FAILS:
        print("FAILED:", FAILS)
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main(negative="--negative-control" in sys.argv)
