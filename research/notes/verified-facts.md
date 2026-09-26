# Verified facts

Every number and claim below was checked against the primary source (the
file in `../papers/`, or the named page), not a search summary. Bombe
reproduces the ones marked **(reproduced)**.

## Cipher analysis

| Fact | Source | Used in |
|---|---|---|
| 2-round AES MEDP = 53/2^34 ≈ 1.656 × 2^-29 exactly; MELP = 109,953,193/2^54 ≈ 1.638 × 2^-28; for T ≥ 4: (53/2^34)^4 ≈ 1.881 × 2^-114 and (109,953,193/2^54)^4 ≈ 1.802 × 2^-110. Earlier bounds: MEDP in [53, 79]/2^34, MELP ≤ 192,773,764/2^54. "5-LIST(1) has size 56", "5-LIST(2) about 2^24" **(53/2^34, 79/2^34 and 192,773,764/2^54 reproduced)** | 2005-keliher-sui (abstract, sections 1, 4) | docs/12 |
| Park et al. Theorem 1: 2-round MEDP ≤ max over i, u of Σ_j DP_Si(u, j)^β_d (rows and columns); Theorem 2 the same for linear hulls with β_l. AES: Σ_j DP(1, j)^5 ≈ 1.23 × 2^-28; 4 rounds: 1.144 × 2^-111 (diff.), 1.075 × 2^-106 (lin.). AES S-box row: one 2^-6, 126 of 2^-7, 129 zeros | 2003-park-sung-lee-lim (decode with `scripts/decode_glyph_pdf.py`) | docs/12 |
| BCLR Proposition 1: an invariant for Add_ki∘L and Add_kj∘L has k_i + k_j as a linear structure, and LS(g) is L-invariant. Theorem 1: max dim W_L(c1..ct) = sum of the degrees of the t largest invariant factors. Midori-64/Mantis layer: min. polynomial (X+1)^6, 16 invariant factors: eight (X+1)^6, eight (X+1)^2; Midori's constants only touch the LSB of each cell, so dim W_L(D) ≤ 16. Invariant attacks broke PRINTcipher, Midori-64, iSCREAM, SCREAM, NORX v2.0, Simpira v1, Haraka v.0 **(Midori profile reproduced)** | 2017-beierle-canteaut-leander-rotella (sections 3.1, 4.1, 4.2) | docs/11 |
| Midori ShuffleCell: new (s0..s15) = (s0, s10, s5, s15, s14, s4, s11, s1, s9, s3, s12, s6, s7, s13, s2, s8); InvShuffleCell (s0, s7, s14, s9, s5, s2, s11, s12, s15, s8, s1, s6, s10, s13, s4, s3); MixColumn M = [[0,1,1,1],[1,0,1,1],[1,1,0,1],[1,1,1,0]], involutive; state column-major | 2015-banik-et-al-midori (section 3) | docs/11 |
| AES S-box polynomial: 05·x^254 + 09·x^253 + F9·x^251 + 25·x^247 + F4·x^239 + x^223 + B5·x^191 + 8F·x^127 + 63 (9 terms) **(reproduced)** | 2003-rosenthal, eq. (2.3) | docs/11 |
| Rivain-Prouff Algorithm 2: x^254 via x^2, x^3, x^12, x^15, x^240, x^252, x^254; "at least 4" non-square multiplications needed; the affine map is straightforward to mask. Turing's `gf::inv8` is exactly this chain | 2010-rivain-prouff (section 3.1) | docs/11 |
| Cube attack: Trivium with 767 of 1152 initialisation rounds broken with 2^45 bit operations | 2009-dinur-shamir (abstract, section on Trivium) | docs/11 |
| Todo: the division property generalises the integral property (EUROCRYPT 2015); first cryptanalysis of full MISTY1 (CRYPTO 2015) | 2015-todo-* (abstracts) | docs/11 |
| Plundervolt: software undervolting of Intel CPUs corrupts SGX enclave computations; full keys extracted from RSA-CRT and AES-NI | 2020-murdock-et-al (abstract) | docs/11 |
| PLATYPUS: unprivileged RAPL energy readings leak AES-NI keys from SGX and the Linux kernel | 2021-lipp-et-al (abstract) | docs/11 |
| Breaking Bad: compiler optimisations break constant-time implementations; trace analysis over 44,604 targets (ASIA CCS 2025) | 2025-schneider-et-al (abstract) | docs/11 |
| Persistent fault analysis targets S-box tables in memory (TCHES 2018(3), 150-172) | 2018-zhang-et-al | docs/11 |
| Wang-Peyrin: boomerang switch over multiple rounds, the Boomerang Difference Table (ToSC 2019(1), 142-169) | tosc.iacr.org article 7400 (not local) | docs/11 |
| Anubis's diffusion matrix has first row (1, 2, 4, 6) over GF(2^8)/0x11d: in the Linux kernel's `crypto/anubis.c`, S[0] = 0xba and T0[0] = 0xba69d2bb = 0xba × (1, 2, 4, 6) | Linux kernel source, `crypto/anubis.c` | docs/12 (control) |
| NIST SP 800-22 spectral test examples 2.6.4/2.6.8 do not match the definition; the corrected test and NIST's reference results do | 2004-kim-umeno-hasegawa, nist-sp800-22r1a | docs/10 |
| AES-128 key expansion: key 2b7e1516 28aed2a6 abf71588 09cf4f3c gives w4 = a0fafe17 and last round key d014f9a8 c9ee2589 e13f0cc8 b6630ca6 **(reproduced)** | nist-fips-197-upd1-aes, Appendix A.1 | docs/12 |

## Computed here (with the check that validates each)

| Result | Check |
|---|---|
| Turing's best minimal 2-round differential (ShiftRows+MixColumns window): 57/2^35 = 2^-29.17, pattern 2 in / 3 out | Same code gives AES's 53/2^34; pruned search = brute force on small ranges |
| Park bounds for Turing: B = 5 identical to AES; B = 17: MEDP ≤ (2^34 + 126·2^17)/2^136 ≈ 2^-102.00, MELP ≤ 2^-99.63 | AES values reproduced |
| Linear layers: MixState and ShiftRows+MixColumns have one invariant factor (degree 128); AES MC∘SR has 16 of degree 8 | Midori published profile reproduced |
| Byte-permutation symmetries: AES round 4, Turing SR+MC 4, MixState 1, both layers 1 | AES column rotation found |
| Scaling symmetries S^-1(βS(x)⊕b) affine: x^-1 255, AES 1, Turing 1 | control caught |
| Reflection distance of T L^-1 T vs L: Turing ≥ 124 of 128 | Hadamard involution scores 0 |
| Key-schedule linear relations: AES-128 1,088 (rank 449), Turing 0 of 2,432 bits | FIPS-197 expansion test |
| 2-round boomerang (alpha 0x01, delta 0x8a): exactly 8/65536 = 2^-13.00; 33 of 262,144 measured | `scripts/boomerang_exact.py`, `boomerang::two_round_rate` |
| 2-round differential-linear: max predicted |corr| 0.01782 (byte 1, mask 0xae); measured 0.01770 there | `difflinear::predict_two_rounds` |
| Cube testers: 16 random bits span more than 7 bytes with probability 99.65% (10.7 bytes on average) | exact count by inclusion-exclusion |
| Square attack: 4 rounds with 2^32 texts, 2 sets, 867 s (and again under a second key) | division-property prediction |
