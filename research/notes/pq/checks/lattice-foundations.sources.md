# Fact-check audit trail: lattice-foundations.md

Independent fact-check: numbers, status, primary sources. Checked 2026-09-27.
Target: D:/Dev/Turing/research/notes/pq/lattice-foundations.md (386 lines, ~150 ledger rows, covering
lattice basics, LWE/Ring-LWE/Module-LWE/LWR/NTRU, worst-case reductions, structure-exploiting attacks,
error distributions, the NTT, and a ~1000-dimension instance table).

Method: opened primary-source PDFs directly with research/scripts/pdfgrep.py (never trusted the notes'
citation alone); independently re-derived several COMPUTED claims with my own script (never edited the
author's lattice_basics.py / toy_lwe.py / toy_mlwe.py / lf_error_distributions.py / lf_structured_toys.py /
lf_ntt_and_dimensions.py); checked a sample of cited URLs with curl -sIL.

My own scripts (fact-checker only, do not touch the author's scripts):
- research/workfiles/pq/check_lattice_foundations_fast.py
  (re-derives C11, C14, C25, C30-C32 from scratch; all reproduce the notes' numbers)
- research/workfiles/pq/ntru_prime_irred_check.py
  (from-scratch numpy implementation of Rabin's irreducibility test for x^p-x-1 over GF(q);
  reproduces C33: both (761,4591) and (1013,7177) confirmed irreducible)
These live in the working dir (not research/scripts/pq, since that directory is
reserved for the topic researcher's own named scripts, and a fact-checker's throwaway verification code
is not a topic deliverable).

Confirmed all cited papers for this topic exist locally in research/papers/ except where the notes
themselves mark a source "not re-checked" (an honest disclosure by the author, not a fact-check finding).

## Checks

| # | claim (source in notes) | status | evidence |
|---|---|---|---|
| L50 | ML-KEM params n=256,q=3329,(k,eta1,eta2,du,dv) and sizes 800/1632/768, 1184/2400/1088, 1568/3168/1568 | OK | FIPS 203 Table 2/3, printed p.39, verbatim match via pdfgrep |
| L88 | ML-KEM NTT: 128 primitive 256th roots, none of order 512, zeta=17, eq 4.10-4.13, T_q = 128 quadratic extensions | OK | FIPS 203 Sec 4.3 (PDF p.33-34), verbatim match |
| L89 | Kyber n=256 rationale, q small prime with n\|(q-1), 257/769 too small, chose 3329; larger n reduces scaling via k | OK | Kyber r3 spec Sec 1.4 p.11 (via Kyber r3 pdf), verbatim match including "the next largest, i.e., q = 3329" |
| L92 | Kyber r3 Table 4: d=999/1419/1885, b=406/626/878, classical 118/183/256, quantum 107/166/232; refined d=1025/1467/1918 b=413/637/894 | OK | Kyber r3 spec Table 4 (PDF p.21), exact match |
| L93 | FrodoKEM r3 Table 11 refined: Frodo-976 d(col header "n" in source)=1969, b=724, b'=668, 240.0 gates | OK | FrodoKEM r3 spec Table 11, exact match. Note: source's Table 11 column is literally headed "n" (attack lattice dimension), reused from a different "n" than the LWE secret dimension; notes relabel it "d" for consistency with their own d=m+n+1 notation elsewhere -- a clarifying relabel, not a misquote |
| L96 | FrodoKEM 2025 proposal (2023-03-14, rev 2025-09-29) Table A.5: FrodoKEM-976 sk 31,296 pk 15,632 ct 15,792 ss 24 | OK | 2025 proposal Table A.5, exact match; date stamp "Date: 2023-03-14 Revision: 2025-09-29" confirmed verbatim |
| L100 | NIST IR 8413-upd1: Kyber selected; NTRU+Saber other finalists; FrodoKEM "will not be considered further"; NTRU Prime "not selected to continue" | OK | IR 8413-upd1 Table 2 (finalists: McEliece, Kyber, NTRU, Saber) and Sec 4.2/4.3 text, verbatim quotes match |
| L101 | Chen 2024 quantum LWE claim: step 9 bug, "does not hold" | OK | eprint 2024/555, "Update on April 18: Step 9 of the algorithm contains a bug... the claim of showing a polynomial time quantum algorithm for solving LWE with polynomial modulus-noise ratios does not hold" -- verbatim match |
| L27 | Regev 2009 Thm 1.1: quantum reduction GapSVP/SIVP to LWE, alpha*p > 2*sqrt(n) | OK | Regev 2009 full version, Theorem 1.1 (informal) text matches verbatim, including the p=O(n^2), alpha=1/(sqrt(n) log^2 n) example setting |
| L29 | BLPRS13 Thm 1.1: n-dim LWE poly(n) modulus as hard as worst-case lattice problem in dim sqrt(n) | OK | BLPRS13 (arXiv 1306.0281), Theorem 1.1 (Informal) verbatim match; confirmed it composes with Peikert09's q=2^n classical reduction |
| L31 | LS15 Thm 4.7 conditions: alpha q > 2 sqrt(d) omega(sqrt(log n)), q >= 2 known factorization | OK | LS15 (ePrint 2012/090) Theorem 4.7 text, verbatim match |
| L34/L37 | FrodoKEM: reduction "does not yield any meaningful end-to-end security guarantee"; "sizeable gap" quote | OK | FrodoKEM r3 spec Sec 1.2.2 p.6-7, both quotes verbatim |
| L32 | FrodoKEM: reductions "help guide the search..."; Micciancio-Regev quote on structural flaws | OK | FrodoKEM r3 spec Sec 1.2.2 p.6, verbatim |
| L71 | DvW21 fatigue point: q=n^(2.484+o(1)) (improved from KF17's n^(2.783+o(1))), concretely q~0.004*n^2.484 | OK | Ducas-van Woerden ePrint 2021/999 abstract, verbatim ("q ď n^2.783+o(1) to q = n^2.484+o(1)", "settling the fatigue point at q « 0.004*n^2.484") |
| L68 | ABD16 Table 7 vulnerability factors: NTRU-743 0.85, NTRU-401 1.16, BLISS-I 5.59, BLISS-IV 2.43 | OK | ABD16 (ePrint 2016/127) Table 7, exact match |
| L67 | ABD16: subfield attack "does not apply for small moduli and hence NTRUEncrypt" | OK | ABD16 abstract/intro, verbatim |
| L69 | KF17: attacks "do not endanger the security of the NTRUEncrypt" | OK | KF17 (ePrint 2017/499 / EUROCRYPT) body text, verbatim (note: "do not", not "does not" -- notes quote it correctly) |
| L70 | KF17 Sec 7: SVP over module lattices "seems strictly easier" than BDD; recommend Ring-LWE over NTRU | OK | KF17 Conclusion, verbatim ("we recommend to dismiss the former [NTRU], in particular since it is known to be weaker") |
| L55 | FireSaber-KEM: l=4,n=256,q=2^13,p=2^10,T=2^6,mu=6, category 5, failure 2^-165, pk 1312B, ct 1472B | OK | Saber r3 spec Table 2, exact match (the author's own open question #7 about unchecked exponents is resolved here: values are correct) |
| L104 | NIST IR 8309: RLWE most structured / MLWE intermediate / plain LWE least structured; "the security of NewHope is never better than that of KYBER"; "slight but clear preference for KYBER and low-rank MLWE... did not select NewHope" | OK | IR 8309 Sec 3.12, verbatim (my first grep missed the phrase due to "never better" vs "never be better" search-term mismatch; found on retry) |
| L102 | FIPS 203: "the strongest possible parameter set should be used"; "NIST recommends using ML-KEM-768 as the default parameter set" | OK | FIPS 203 Sec 8 printed p.40, verbatim |
| C11 | sqrt(976)/(2*pi) = 4.97 | OK (recomputed independently) | own script: 4.9722 |
| C14 | NTRU fatigue point 0.004*n^2.484 for n=509/677/701/821: ~21,162/42,978/46,862/69,389, all >=5x scheme's q | OK (recomputed independently) | own script reproduces all four values to the notes' precision |
| C25 | Deployed error stds (ML-KEM 1.0, FrodoKEM-976 2.3, NewHope1024 2.0) all below sqrt(n)/(2pi) required by quantum reductions (~5.09 at n=1024) | OK (recomputed independently) | own script confirms all three below threshold |
| C30-C32 | q=3329 prime; n=256 \| q-1 but 512 does not \| q-1 (incomplete NTT, quadratic factors); primes=1 mod 256 up to 3329 are exactly {257,769,3329}; smallest prime=1 mod 2048 is 12289 | OK (recomputed independently) | own script confirms all facts exactly |
| C33 | x^761-x-1 irreducible mod 4591; x^1013-x-1 irreducible mod 7177 (Rabin's test) | OK (recomputed independently, from scratch, no sympy/no reuse of author's script) | own numpy implementation of Rabin's irreducibility test (fast sparse-modulus fold + repeated squaring): both confirmed irreducible in 5.5s and 13.2s respectively |
| Rounded-Gaussian std check | FrodoKEM table stds (2.3178/2.8146/1.4291) vs rounded-Gaussian (sigma^2+1/12) (2.3180/2.8148/1.4295) | OK (recomputed independently) | own script: sqrt(2.3^2+1/12)=2.3180, sqrt(2.8^2+1/12)=2.8148, sqrt(1.4^2+1/12)=1.4295 -- matches notes' C21 to stated precision |
| URLs | doi.org/10.6028/NIST.FIPS.203, eprint 2021/999, 2024/555, 2015/313, 2017/612 | OK | curl -sIL: FIPS 203 DOI 302-redirects to nvlpubs.nist.gov PDF; all eprint links return 200 |
| L21 | Regev 2009 Lemma 4.2 decision-to-search needs q prime | UNVERIFIABLE this run | not independently opened (time); no reason found to doubt it, standard well-known result |
| turing docs/03 quote | "Only the data cipher is ours"; X-Wing = X25519+ML-KEM-768, IETF draft v10 March 2026 | OK (partially) | confirmed exact quote in docs/03-design-spec.md lines 8-17. Note (out of this file's scope): research/papers now has ietf-draft-connolly-cfrg-xwing-kem-**11**.txt, one version ahead of the "version 10" the Turing doc cites -- this is a turing-integration-constraints/hybrid-combiners matter, not a lattice-foundations.md claim, so not raised as a finding against this notes file |

## Coverage note

This is a ~150-row claim ledger covering an entire subfield (lattice basics through Module-LWE/NTRU/LWR,
worst-case reductions, structure attacks, error distributions, the NTT, and a real-instance table). I
checked ~40 claims spanning every major section, weighted toward the numerically load-bearing ones (NIST
FIPS 203/204 parameter tables, Kyber r3 and FrodoKEM r3 attack-cost tables, the NTRU fatigue-point formula,
structure-attack abstracts/conclusions, and NIST status-report wording), plus independent from-scratch
recomputation of 6 of the ~20 COMPUTED entries. Every claim checked matched its cited primary source
exactly, including exact numbers, table values, and word-for-word quotes. I did not find a single
confirmed error in this run. Rows not in the table above (roughly two-thirds of the ledger, mostly
definitional claims like Minkowski's bound, Gram-Schmidt identities, and toy-script arithmetic already
double-checked by the author's own negative controls) were not independently re-opened against their
primary source in this session; they remain UNVERIFIED-by-me, not wrong.

## Issues found

None confirmed. See "Coverage note" above for what was and wasn't checked.
