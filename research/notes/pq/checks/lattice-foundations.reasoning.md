# Fact-check audit (lens: mathematics and reasoning): lattice-foundations.md

Independent check of `research/notes/pq/lattice-foundations.md` (82 978 bytes, 385 lines,
mtime 2026-09-27 07:14). Lens: derivations, formulas, worked examples, the author's scripts,
security arguments and conclusions. Started 2026-09-27. This file is the audit trail
kept up to date as the check went. My own script:
`research/scripts/pq/check_lattice-foundations_reasoning.py`.

A sibling check with the "sources" lens is in `lattice-foundations.sources.md`; I do not repeat
its pure quote checks unless the reasoning depends on them.

## Method

1. Read the notes end to end; list every derivation, formula, worked example, computed number,
   security argument and conclusion.
2. Recompute each number with my own script (independent code), with a negative control.
3. Run the author's scripts (toy_lwe.py, lattice_basics.py, lf_*.py) with a timeout, read them,
   and check that their output supports what the notes say.
4. Go to the primary PDFs for any number a conclusion rests on.
5. Hunt for overclaims and confusions: reductions read as concrete guarantees, rank x degree vs
   dimension, classical vs quantum, core-SVP vs gates, per-ciphertext vs per-key failure.

## Row-by-row check record

| # | claim checked | OK / WRONG / UNVERIFIABLE | evidence |
|---|---|---|---|
| 1 | All six author scripts run and end "all checks passed" | OK | ran each with `timeout 300/400 python research/scripts/pq/<name>.py`; outputs in scratch pq/lfcheck/*.out; all exit=0 |
| 2 | 2-D example: bad = U x good, U = [[7,3],[9,4]], det U = 1, both |det| = 32 | OK | hand: 7(5,1)+3(-2,6) = (29,25); 9(5,1)+4(-2,6) = (37,33); lattice_basics.py Part A |
| 3 | GS lengths 5.099/6.276 (good), 38.288/0.836 (bad), products 32 | OK | lattice_basics.py Part A output; hand: mu = -4/26, b2* = (-1.231, 6.154) |
| 4 | Babai: (19,-9) = 3(5,1) - 2(-2,6) is a lattice point; good basis decodes (20.2,-9.9) to it | OK | hand + lattice_basics.py Part B |
| 5 | GH ratio 1.017 at m = 12 | OK (uses the exact-ball GH, not the sqrt(n/2 pi e) form) | lattice_basics.py Part C prints "GH(exact ball)" |
| 6 | Primal toy: d = 3n+1 = 121 (n = 40) 3/3, 145 (n = 48) 0/3; gap ~7 | OK | lattice_basics.py Part E; hand GH at d = 121: 2.66 x 97^(80/121) = 54.8, target sqrt(61) = 7.8 |
| 7 | "97^3 = 912,673" | OK | toy_lwe.py Part A |
| 8 | Regev/LP toy table values (3.262e-12, 5.446e-07, 5.542e-05, 2.970e-03, 0.1536, 492/3000) | OK as printed | toy_lwe.py Parts B-D output |
| 9 | Regev toy: "exact failure" vs "measured" in the same row | WRONG (per-key vs key-averaged confusion) | toy_lwe.py lines 202-209: one fixed key per eta, 20000 encryptions, compared with a failure probability averaged over keys (regev_noise_dist lines 182-186) |
| 10 | LP worst-case noise 17/130/258/1155 = 2 n eta^2 + eta | OK | hand |
| 11 | FrodoKEM quote: quantum reductions need std >= c sqrt(n), c > 1/(2 pi), n = LWE secret dimension | OK (quote exact) | FrodoKEM r3 spec Sec. 1.2.2 p.6 (pdfgrep "c√n"); p.? Sec. 5.1: "originally stated as c = sqrt(2/pi)" |
| 12 | Applying sqrt(n)/(2 pi) to ML-KEM (n = k*256), NewHope, Saber | WRONG (plain-LWE threshold misapplied to ring/module) | LS15 Thm 4.7 p.16: "alpha q > 2 sqrt(d) omega(sqrt(log n))", d = rank, n = ring degree; FrodoKEM text says "n is the dimension of the LWE secret" |
| 13 | PRS17 covers q = 3329 for ML-KEM "in theory" | WRONG (overclaim) | PRS17 p.2: results "appear to be sufficiently general to adapt to 'module' lattices" (not proved); LS15 Thm 4.7 p.16: decision M-LWE needs q prime, q = 1 mod nu |
| 14 | Kyber r3: attacker has m = (k+1)n LWE samples | OK (quote); notes' paraphrase "per key" imprecise | Kyber r3 spec Sec. 5.1.1 p.25; Thm 1 uses Adv^mlwe_{k+1,k,eta} (the ciphertext's secret r); key s has kn samples |
| 15 | Peikert 2009 classical reduction for q >= 2^n | OK | Peikert 2009 PDF p.2, pdfspans.py: '2' + superscript 'n' |

## Issues found

(filled in as discovered; full text in the structured return)

- I1 (minor): Regev toy compares one key's measured rate with the key-averaged exact failure probability (row 9).
- I2 (minor): sqrt(n)/(2 pi) threshold applied to ring/module schemes (row 12).
- I3 (minor): PRS17 "covers" ML-KEM's modulus (row 13).
- I4 (minor): "(k+1)n samples per key" (row 14).

## Confirmed highlights

(filled in as discovered)

## Status

IN PROGRESS
