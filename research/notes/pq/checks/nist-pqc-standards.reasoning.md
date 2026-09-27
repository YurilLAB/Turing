# Fact-check audit (lens: mathematics and reasoning): nist-pqc-standards.md

Independent check of `research/notes/pq/nist-pqc-standards.md` (89 667 bytes, mtime
2026-09-27 07:05). Lens: derivations, formulas, worked examples, the author's scripts,
security arguments and conclusions. Started 2026-09-27. This file is the audit trail
kept up to date as the check went. My own script:
`research/scripts/pq/check_nist-pqc-standards_reasoning.py`.

A sibling check with the "sources" lens is in `nist-pqc-standards.sources.md`; I do not repeat
its pure quote checks unless the reasoning depends on them.

## Method

1. Read the notes end to end, list every derivation, formula, worked example, computed number,
   security argument and conclusion.
2. Recompute each number with my own script (independent code, not the author's), with a
   negative control for each check.
3. Run the author's scripts with a timeout, read them, and check that what they print supports
   what the notes say they show.
4. Go to the primary PDFs for any number that a conclusion rests on.
5. Hunt for overclaims and confusions: rank x degree vs dimension, classical vs quantum,
   core-SVP vs gates, per-ciphertext vs per-key failure, category definitions, MAXDEPTH.

## Row-by-row check record

| # | claim checked | OK / WRONG / UNVERIFIABLE | evidence |
|---|---|---|---|
| S1 | Author script `nist_pqc_check.py` runs and reproduces what the notes say it does | OK (with caveats S2, S3) | `timeout 300 python research/scripts/pq/nist_pqc_check.py` -> "ALL CHECKS PASSED", exit 0 (run 2026-09-27) |
| S1n | Author negative control catches its four planted errors | OK | `--negative-control` -> 4 FAIL lines, "NEGATIVE CONTROL OK" |
| S2 | Script section 10 "check" (dimension near 1000 in categories 3 and 5) | WRONG (tautology) | line 249-250: `check(..., True, ...)`: prints PASS unconditionally; it tests nothing. The printed table is informative, the PASS is not |
| S3 | Script section 8 grid at MAXDEPTH = 2^96 (AES-128: 2^61 in 2022 call, 2^74 in 2016 call) | WRONG (formula outside its range) | 2022 call footnote 5 (nist-pqc-call-additional-signatures-2022.pdf PDF p. 17-18): estimates "may understate the quantum security of AES for very large values of MAXDEPTH"; JNRV 2020 (2020-jaques-et-al-grover-oracles-aes-lowmc.pdf, Sec. 6 "Implications for post-quantum security categories"): unrestricted AES-128 Grover G-cost "1.69 * 2^83 gates", and "for MAXDEPTH = 2^96, key search on AES-128 does not require any parallelization". So the true figure at 2^96 is about 2^83.8, not 2^61 |
| S4 | `samplentt_bound.py`: 2^-261.24 at L = 280, E[T] = 157.741, MC mean 157.750 | OK | `timeout 300 python research/scripts/pq/samplentt_bound.py`; model P(T > L) = P(Bin(2L, 3329/4096) <= 255) is right for Alg. 7 |
| N1 | Size formulas `|ek| = 384k+32`, `|dk| = 768k+96`, `|c| = 32(du*k+dv)` and Table 3 | OK | recomputed by hand and by author script; to be re-derived bit-by-bit in my script |
| N2 | Worked example ML-KEM-768: 1152 + 32 = 1184; 960 + 128 = 1088 | OK | arithmetic |
| N3 | 2022 quantum figures 13/12/13 bits below 2016; 2^(157-64) = 2^93 | OK | 170-157, 233-221, 298-285; JNRV Sec. 6 gives "roughly 2^10" over 1.69*2^83 at 2^64, i.e. about 2^93.8, consistent |
| N4 | Kyber r3 Table 4 numbers (999/1419/1885; 406/626/878; 1025/1467/1918; 413/637/894; 151.5/215.1/287.3; 93.8/138.5/189.7) | OK | 2021-avanzi-et-al-kyber-round3-specification.pdf Table 4 (text extraction), all match |
| N5 | "margins are 8.5 / 8.1 / 15.3 bits" and "the attack figures carry over" | WRONG (reasoning: outdated estimate presented as current) | Arithmetic is right, but IR 8413 Sec. 4.1 (quoted by the notes themselves in 6.3) says dual-attack improvements "suggest that all three KYBER parameter sets fall slightly below the security targets ... when the cost of memory access ... is not explicitly taken into account". NIST's own FAQ on Kyber512 (nist-kyber512-faq.pdf, Dec 2023, p. 2-3, already in research/papers/): best estimate "about 2^147 (or 2^145 ...)", uncertainty window "2^135 to 2^158"; MATZOV claimed 2^137; estimator gives 2^142.2 before hidden overheads. So the category-1 margin under NIST's current view is about 2-4 bits, with an uncertainty window that reaches below 2^143, not 8.5 bits |

| M1 | My script `check_nist-pqc-standards_reasoning.py` (independent methods, 5 negative controls) | OK, all PASS | `timeout 300 python research/scripts/pq/check_nist-pqc-standards_reasoning.py` exit 0 (2026-09-27) |
| N6 | ML-KEM sizes derived bit by bit from layouts of Alg. 13/14/16 | OK | my script section 1 |
| N7 | dk offsets in the hash check `H(dk[384k:768k+32]) == dk[768k+32:768k+64]` | OK | my script section 2; FIPS 203 Alg. 18 lines 1-4 (PDF p. 43) |
| N8 | Modulus check worked example (3328 passes, 3329 fails) | OK, and stronger: exhaustive, rejects exactly 3329..4095 | my script section 3; negative control: without mod q in ByteDecode12 the check is vacuous |
| N9 | SampleNTT 2^-261.24, E[T] = 157.7 | OK | my script section 4 (lgamma log-sum and negative-binomial mean, both independent of the author's code): -261.240, E[T] = 157.741; negative control L = 250 gives -172.98; FIPS 203 App. B Table 4 (PDF p. 55) "280 / 2^-261" |
| N10 | CBD eta = 2 has std dev 1 | OK | my script section 5 (variance exactly 1) |
| N11 | ML-DSA zeta = 1753 is a 512-th root of unity; beta = tau*eta; sizes | OK | my script section 8 (order exactly 512; sizes from component bits) |
| N12 | FIPS 204 errata: loop limit 814 -> 821 | OK (COMPUTED consistency) | FIPS 204 App. C Table 3 title "for a 2^-256 or less probability of failure"; ceil(256 / -log2(1 - 1/5.1)) = 814 and ceil(256 / -log2(1 - 1/5.14)) = 821, my script section 8 |
| N13 | SLH-DSA table h' and m columns | OK | my script section 9, m = ceil(ka/8) + ceil((h - h/d)/8) + ceil(h/(8d)) |
| N14 | SP 800-227 RS/RM list (Sec. 1.3) and the notes' remark that "RS6 ... pertain to key confirmation" is off | OK | SP 800-227 PDF p. 10-11: RS6 is the ephemeral-key rule, RS9 is "The key-confirmation key shall only be used for key confirmation", while the sentence lists RS6, RS7, RS8, RS10, RS11. The notes' diagnosis is right |
| N15 | SP 800-227 4.3 strength of truncated key = min(strength of K, length, KDM strength) | OK | SP 800-227 PDF p. 27 |
| N16 | SP 800-227 4.6.2: combiner (14) approved for t > 1 if one secret is from 56A/56B or an approved KEM; SP 800-133 methods need every key approved; concatenation should go through a KDF | OK | SP 800-227 PDF p. 38 |
| N17 | SP 800-227 4.6.3: KDF(K1, K2) "does not preserve IND-CCA security, regardless of the properties of the KDF"; KeyCombineCCA_H preserves IND-CCA "if H is modeled as a random oracle" provided at least one ingredient is IND-CCA | OK | SP 800-227 PDF p. 39 |
| N18 | IR 8547 Tables 1, 2, 5; Sec. 4.1.3 symmetric statements; Table 5 "ML-DSA-768/1024" misprint | OK | nist-ir-8547-pqc-transition.pdf PDF p. 19-22 |
| N19 | IR 8413 App. B RAM-model text | OK | IR 8413 App. B (pdfgrep "considered safe") |
| N20 | FIPS 203 Table 1 failure rate definition (average over d, z, m; hash/XOF heuristic) | OK | FIPS 203 Sec. 3.2 PDF p. 23-24: "taken over uniformly random seeds d, z ... and m" |

| N21 | Primal attack dimension d = n + m + 1 is larger than the secret dimension (notes 6.4) | OK | Kyber r3 Table 4: d = 999 for n = 512 (so m = 486 samples); 1885 for n = 1024 |
| N22 | "It does not add assumption diversity: both are LWE" (FrodoKEM + ML-KEM) | WRONG (overstated) | the notes' own BSI quote: FrodoKEM "unlike ML-KEM, is based on unstructured grids" and so "more conservative"; a structure-exploiting attack on module lattices would not transfer to plain LWE. What is true: no diversity against generic lattice-reduction or quantum-LWE advances, and not the non-lattice diversity IR 8545 2.2.1 aims at |
| N23 | FrodoKEM row of "What this means" table (and C: "FrodoKEM-976 / -1344 ... near 1000 dimensions") | INCOMPLETE | 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf Sec. 9.6: eFrodoKEM "exclusively intended for applications that guarantee that only a small number of ciphertexts (e.g., 2^8) are produced per public key"; a static file-encryption key needs salted FrodoKEM, not eFrodoKEM. Also 1344 is not "near 1000" |
| N24 | ANSSI CatKDF/CasKDF "reach IND-CCA2 if the underlying KEMs do" | OK as a paraphrase, but a reasoning trap | ANSSI FAQ (scratch anssi_faq_live.txt line 106): "en supposant que les KEM sous-jacents le sont" = assuming the underlying KEMs are IND-CCA2. That is not the SP 800-227 4.6.3 property (IND-CCA if at least one component is), which is the one a hedge needs |
| N25 | Classic McEliece "suits ... file encryption" attributed to IR 8545 | WRONG attribution (minor) | IR 8545 p. 16 [9]: "Responses noted that Classic McEliece may provide better performance ..." i.e. public-comment responses reported by NIST, not NIST's own assessment |
| N26 | Sec. 1.1 "hides one message bit in each of the 256 coefficients of the 'constant term'" | UNCLEAR for a learner | "constant term" of a polynomial means the X^0 coefficient; the message is in all 256 coefficients of the polynomial v (Alg. 14: v = NTT^-1(t_hat^T o y_hat) + e2 + mu) |
| N27 | KF 12 / Sec. 6.3 present IR 8413 (2022) "fall slightly below" as NIST's current view of Kyber | OUTDATED (minor) | nist-kyber512-faq.pdf (Dec 2023) p. 2: the MATZOV dual-sieve result "was brought into question by Ducas and Pulles"; NIST best estimate 2^147 for Kyber512, above 2^143 |

| N28 | Sec. 6.4 "(the ratio q/sigma fixes how much lattice reduction is needed)" | WRONG (oversimplified) | Lindner-Peikert 2011 Sec. 5 (2011-lindner-peikert-better-key-sizes-lwe.pdf): required root-Hermite factor delta = 2^(lg^2(beta) / (4 n lg q)), beta ~ q/s; so n and lg q enter as well as q/s. My script section 11: same n = 1000 and same q/sigma = 2^13 give lg delta 0.00264 (q = 2^16) vs 0.00352 (q = 2^12). The same heuristic lines up with the categories (ML-KEM-768 0.00381 vs FrodoKEM-976 0.00351, both cat. 3; ML-KEM-1024 0.00286 vs FrodoKEM-1344 0.00280, both cat. 5), a better teaching example than "q/sigma" |
| M2 | Re-run of my script after adding section 11 | OK | exit 0, all PASS |
| N29 | "What this means" table A, FrodoKEM row: "the 2025-09-29 FrodoKEM proposal is the public text" of ISO/IEC 18033-2 Amd 2 | OVERCLAIM (minor) | the notes' own Open question 1 says it is unknown whether the ISO text is identical to the 2025-09-29 proposal; the proposal calls itself "Preliminary Standardization Proposal". Say "closest public text; identity unverified" |
| N30 | Errata row 1 (zeta table value 1 at i = 0) does not change behaviour | OK | FIPS 203 Alg. 9 line 2 "i <- 1", Alg. 10 line 2 "i <- 127" counting down; the text says the values for i = 1..127 are used (PDF p. 35-36). Index 0 is never read |
| N31 | X-Wing's combiner omits the ML-KEM ciphertext and key (notes 4.5) | OK | 2024-barbosa-et-al-x-wing-hybrid-kem.pdf Fig. 12: s = label || k1 || k2 || c2 || pk2; k = SHA3-256(s) |
| N32 | KF 14: KEM-DEM strength is the weaker of KEM and Turing cipher; F: product cannot be FIPS-approved | OK (reasoning) | standard KEM-DEM composition (advantage adds); SP 800-227 Sec. 4.2 bullet "security of the symmetric-key algorithms used is appropriate for the security provided by the KEM" (PDF p. 27) |
| N33 | Sec. 4.4 inference: AEAD tag check on the file plays the key-confirmation role | OK (reasoning) | SP 800-227 PDF p. 28: "successful use of the shared secret key for authenticated encryption can act as key confirmation"; with implicit rejection a tampered c gives J(z||c) and the tag fails, which is the needed signal |
| N34 | C: ML-KEM-768 meets every authority read except CNSA 2.0; ML-KEM-1024 meets all | OK | CNSA FAQ lists only ML-KEM-1024; ANSSI "level-5 ... or level-3"; BSI Table 2.7 768/1024; ECCG "ML-KEM-1024 or ML-KEM-768"; NCSC all sets acceptable |

## Issues found

(filled in as discovered; see also the row table)

1. MAJOR. Notes 6.4: "Against the 2022-call classical thresholds (2^143 / 2^207 / 2^272) the
   margins are 8.5 / 8.1 / 15.3 bits ... so the attack figures carry over". The arithmetic is
   right but the figures are the 2021 round-3 spec's own estimates, which NIST later revised.
   NIST Kyber512 FAQ (Dec 2023): best estimate "about 2^147 (or 2^145 ...)", window
   "2^135 to 2^158"; i.e. about +4 (or +2) bits for ML-KEM-512, with a window reaching -8 bits.
   The notes even quote IR 8413 saying all three sets "fall slightly below" in the RAM model,
   which contradicts a positive 8.5-bit margin. "The parameters carry over" is true; "the attack
   figures carry over" is not. Ledger rows 26-27 should say "round-3 spec estimates, superseded".
2. MINOR. Author script section 8 / ledger row 55 ("and the full grid"): the grid value at
   MAXDEPTH 2^96 (AES-128: 2^61 in the 2022 formula, 2^74 in 2016) is outside the range where
   G/MAXDEPTH holds. The 2022 call's footnote 5 says the estimates "may understate the quantum
   security of AES for very large values of MAXDEPTH"; JNRV 2020 Sec. 6: unrestricted AES-128
   Grover costs 1.69 * 2^83 gates and "for MAXDEPTH = 2^96, key search on AES-128 does not
   require any parallelization". Using 2^61 as a category-1 quantum bar would set the bar about
   23 bits too low. My script section 6.
3. MINOR. Author script section 10 has a hard-coded `check(..., True, ...)`: it prints PASS for
   "an LWE dimension near 1000 appears in category 3 and category 5" without testing anything.
4. MINOR. N22 (FrodoKEM diversity overstated), N23 (eFrodoKEM caveat missing), N24 (CatKDF
   property as worded by ANSSI), N25 (attribution), N26 (wording), N27 (IR 8413 superseded by
   the NIST FAQ), N28 (q/sigma alone), N29 (FrodoKEM "public text").

## Confirmed highlights

- ML-KEM parameters and sizes: Table 3 re-derived bit by bit from the byte layouts; the three
  closed formulas and the ML-KEM-768 worked example are right.
- The modulus check rejects exactly the 12-bit values 3329..4095; its power comes only from the
  mod-q reduction in ByteDecode12 (negative control). The dk hash-check offsets are right.
- SampleNTT: P(> 280 iterations) = 2^-261.24 and E[T] = 157.741, reproduced by an independent
  method; FIPS 203 App. B Table 4 says 280 / 2^-261.
- Category gate counts, the 13/12/13-bit drop from 2016 to 2022, and 2^93 at MAXDEPTH 2^64
  (consistent with JNRV's own 2^93.8).
- Kyber round-3 Table 4 values are transcribed correctly.
- FIPS 204 errata loop limit 821 (was 814) is exactly what a 2^-256 target gives from
  5.14 (was 5.1) expected repetitions.
- SP 800-227: the RS/RM table, the key-confirmation numbering anomaly, the truncated-key
  strength rule, the approved combiners, and the IND-CCA statements (KDF(K1,K2) fails;
  KeyCombineCCA_H preserves IND-CCA in the ROM if at least one component is IND-CCA).
- The central conclusion: a "twist" inside ML-KEM ends conformance and all its analysis; a
  twist can only sit around unmodified components. No overclaim of provable security found.

## Status

DONE 2026-09-27. Claims checked: about 50 (34 recorded rows, several covering more than one
number). Issues: 1 major, 10 minor (listed above and in the structured return).
