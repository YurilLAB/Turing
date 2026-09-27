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

## Issues found

(filled in as discovered; see also the row table)

## Confirmed highlights

(filled in as discovered)

## Status

IN PROGRESS
