# How lattice security is estimated, with a validated estimator for ~1000-dimension parameters

This file explains how the security of lattice problems (LWE, Module-LWE, LWR) is turned into a number of
"bits", which attacks that number covers, and how far it can be trusted. It re-implements the
published estimation method as `research/scripts/pq/coresvp.py`, shows that the script reproduces the
published numbers of Kyber (rounds 2 and 3), FrodoKEM, NewHope and Saber exactly (or within the one bit
the Saber authors themselves allow), and then uses it to tabulate ~1000-dimension options for Turing.
It ends with the status of quantum algorithms for lattices, including Yilei Chen's 2024 claim.
Everything was checked on 2026-09-27. Background maths (what a lattice, LWE, Module-LWE and LWR are) is in
the sibling note `lattice-foundations.md`; decryption-failure probability is in `decryption-failures.md`;
the standards' status is in `nist-pqc-standards.md`.

**Revision log.** Pass 1 (2026-09-27 morning) wrote this note and `coresvp.py`. Pass 2 (2026-09-27
afternoon, in progress) re-ran every script with a timeout and re-read the cited tables in the PDFs
(Kyber r3 Table 4 and pp. 26-28, FrodoKEM r3 Table 10, Saber r3 Table 1, ADPS16 p. 9: all match). Pass 2
findings so far: the printed dual-attack advantage formula differs between papers and scripts (Sec. 6.3,
new item "epsilon factor"); the `adps16` convention in `coresvp.py` did not use the printed factor 4 and
is being corrected.

## Key findings

1. **Security of LWE-type schemes is an estimate, not a proof.** Designers estimate the cost of the best
   known attacks (primal and dual lattice reduction) under heuristic models of the BKZ algorithm. The
   common yardstick is "core-SVP": log2 of the cost of ONE call to an SVP solver in the BKZ block size b,
   taken as 2^(0.292 b) classically, 2^(0.265 b) quantumly and 2^(0.2075 b) as a "plausible" floor. It
   deliberately ignores the ~2^11.7 to 2^12.4 SVP calls a real attack makes, all polynomial factors and
   all memory cost, so it is a conservative (attacker-favourable) proxy, not a runtime (Sec. 3).
2. **Our script reproduces the published numbers.** `coresvp.py` reproduces every published core-SVP
   number of Kyber512/768/1024 (round 3, primal and dual, classical/quantum/plausible), Kyber round 2,
   FrodoKEM-640/976/1344, NewHope512/1024 and the USENIX-2016 rows exactly, and Saber (via the LWR
   rounding error) within 1 bit. It also reproduces the lattice-estimator's default gate-count model to
   1e-10 bits against the estimator's own test value. All 8 negative controls (perturbed q, sigma, n)
   fail as they should, and cost rises with n and sigma and falls with q (Sec. 6).
3. **Refined gate counts sit well above core-SVP, and the refined models disagree by ~8-14 bits.** The
   Kyber team's refined estimate is 151.5 / 215.1 / 287.3 log2(gates) for Kyber512/768/1024 against
   core-SVP 118 / 183 / 256, i.e. about 31-33 bits higher; FrodoKEM's is 175.1 / 240.0 / 305.4. The
   lattice-estimator's default (MATZOV) model gives 143.8 for Kyber512, 19-25 bits above core-SVP. The
   Kyber team itself puts its estimate within a factor 2^-16 to 2^14 (Sec. 3.3).
4. **The dual attack is contested, but a corrected version now exists.** MATZOV (2022) claimed dual
   attacks bring Kyber to 137.5 / 193.5 / 257.8 gates, below NIST's 143 / 207 / 272. Ducas-Pulles (CRYPTO
   2023) showed the independence heuristic behind this is wrong in some regimes. Carrier-Meyer-Hilfiger-
   Shen-Tillich (CRYPTO 2025, ePrint 2022/1750) then gave a variant (polar-code decoding instead of modulus
   switching) analysed "without using the flawed independence assumptions", backed by experiments, and
   found Kyber-512/768/1024 at 139.5 / 195.1 / 259.7 in the same RAM gate model, "3.5/11.9/12.3 bits below"
   the NIST figures (their Table 5.1, PDF p. 27). They ignore memory cost and do not compare with primal
   attacks. Fully provable dual attacks (Pouly-Shen 2024 and the 2025-2026 follow-ups) remain far more
   expensive: the newest, ePrint 2026/2166, gives 210 / 300 / 410 bits for ML-KEM-512/768/1024. NIST's
   Kyber512 FAQ (Dec. 2023) put the best RAM-model gate estimate at about 2^147 and its best guess with
   memory cost at about 2^160 (range 2^140 to 2^180). A careful design takes the minimum over primal and
   dual and keeps a margin that absorbs a ~12-bit dual gain (Sec. 4.3).
5. **Quantum speed-ups for lattice attacks are small.** The best quantum sieve exponent went 0.2653
   (Laarhoven 2016) -> 0.2570 (Chailloux-Loyer 2021) -> 0.2563 (Bonnetain et al. 2023), all in a QRAM
   model. Concrete studies find "a small quantum speedup" needing optimistic assumptions (AGPS20) or
   "little to no quantum speedup" at dimension 400 (Doriguello et al. 2025). Quantum core-SVP is 0.907x the
   classical figure (Sec. 2, 8).
6. **No confirmed polynomial-time quantum algorithm for LWE (2026-09-27).** Chen's April 2024 claim was
   withdrawn by the author on 2024-04-18 ("Step 9 of the algorithm contains a bug, which I don't know how
   to fix"). A 2025 "fix" by Zhang (arXiv 2509.12341, v8 2026-05-14) works only "in our access model",
   with part of the answer given "as explicit side information"; Apon (ePrint 2025/1945) rebuts it. Two
   2026 claims exist: Simon's polynomial-time DCP algorithm (ePrint 2026/1591, August 2026), which
   Gupte-Ragavan-Zhandry prove "cannot possibly work" (ePrint 2026/1693), and Luo's arXiv series claiming a
   quantum break of ML-KEM (2605.17412), unreviewed and unconfirmed (Sec. 8).
7. **BKW and Arora-Ge are not a threat to a KEM with Gaussian-like errors.** They need exponentially
   many samples or tiny bounded errors. A KEM gives the attacker about n + 8 (FrodoKEM-style) or (k+1)n
   (Kyber-style) samples. The estimator prices coded-BKW on Kyber512 at 2^178.8 operations and 2^166.8
   samples (Sec. 4.5-4.6).
8. **Small or sparse secrets open extra attacks** (hybrid lattice/meet-in-the-middle, May 2021's S^0.25
   ternary MITM, Albrecht 2017's small-secret dual). The core-SVP formulas do not model them. With a
   secret of std 0.816 (uniform ternary) instead of 2.8, primal core-SVP at n = 1024, q = 2^15 already drops
   from 249.2 to 214.1 before any hybrid attack (Sec. 4.4, T2b).
9. **"About 1000 dimensions" already exists in the standards.** ML-KEM-1024 is Module-LWE of rank 4 over
   degree 256, a 1024-dimensional LWE instance (core-SVP 256 classical); FrodoKEM-976 is plain LWE in
   dimension 976 (216.0 classical, FrodoKEM convention). A Turing lattice layer at ~1000 dimensions sits
   between these two known points (Sec. 7).
10. **At n ~ 1000 the security depends almost only on sigma^2/q.** With m ~ n samples the primal attack
    succeeds when sigma is below about delta^(...) * sqrt(q), so doubling q and multiplying sigma by
    sqrt(2) leaves the cost unchanged: at n = 1024, (q, sigma) = (2^13, 1.0), (2^14, 1.4), (2^15, 2.0),
    (2^16, 2.8) all give 229.0-229.6 bits classical core-SVP (T1, COMPUTED).
11. **Plain LWE at n ~ 1000 is strong.** At n = 1024, q = 2^16: sigma = 1.0 gives 182.2, 2.0 gives 212.0,
    2.8 gives 229.0, 4.0 gives 249.8 bits classical core-SVP. Classical core-SVP >= 256 needs sigma >= 4.42 at
    q = 2^16 or sigma >= 1.56 at q = 2^13 (T2). Larger sigma or smaller q raise decryption-failure risk,
    which is the sibling topic's job.
12. **The reference tool is the lattice-estimator** (github.com/malb/lattice-estimator, LGPLv3+, a
    SageMath module; default cost model MATZOV). It covers primal uSVP, primal BDD, hybrid, dual,
    dual-hybrid, coded-BKW and Arora-Gröbner. SageMath is not installed here, so pass 2 wrote a small
    numeric stand-in (`acs_sage_shim`) and ran the unmodified estimator through it: all 10 reference
    outputs the estimator's authors publish are reproduced to 0.05 bits with identical block sizes, and
    both negative controls fail (Sec. 5.1). The Arora-Gröbner estimate and the slow primal-hybrid runs
    are not covered. A final Turing parameter set should still be re-run under real SageMath once.
13. **The pq-crystals estimation scripts have no licence file** (github.com/pq-crystals/security-estimates,
    commit 75c2694); they may be read and run but not copied into Turing. `coresvp.py` re-implements their
    formulas. The FrodoKEM parameter scripts are MIT.
14. **Risk flag for a "twist".** Every estimate above assumes the attacker faces standard LWE/MLWE with
    independent Gaussian-like secret and error. Any new structure (unusual rings, sparse or correlated
    secrets, reused randomness, extra hints, homemade error samplers) moves the problem outside what the
    estimators model, and "harder to break" can then only be claimed after new cryptanalysis. The
    literature-backed ways to add margin are larger n, larger sigma/sqrt(q) (within the decryption-failure
    budget), and combining independent assumptions (hybrid KEMs; see `hybrid-combiners.md`).

## 1. Lattice reduction, BKZ and the root Hermite factor

**What an attack must do.** In LWE the attacker sees A (random, m x n, mod q) and b = A s + e mod q with
short s and e. The vector (s, e) is unusually short, so it is a very short vector in a lattice built from
A and b. Finding very short lattice vectors is what lattice-reduction algorithms do.

**BKZ.** The standard algorithm is BKZ with block size b (Schnorr-Euchner; BKZ 2.0 by Chen-Nguyen 2011).
It repeatedly solves the shortest vector problem (SVP) exactly in projected sub-lattices of dimension b.
Larger b gives a better basis but costs exponentially more.

**Root Hermite factor.** The quality of the output is summarised by delta: the first basis vector has
length about delta^d * Vol(L)^(1/d) in a d-dimensional lattice. For BKZ-b, Chen's 2013 thesis gives the
limit (Albrecht-Player-Scott 2015, eq. (1), PDF p. 9):

    delta(b) = (v_b^(-1/b))^(1/(b-1)) ~ ( (b / (2 pi e)) * (pi b)^(1/b) )^(1/(2(b-1)))

where v_b is the volume of the unit ball in dimension b. The approximation is the one used by Kyber
(round-3 spec, PDF p. 26), FrodoKEM (PDF p. 42) and NewHope. `acs_rhf.py` shows the exact and approximate
forms agree to within 1e-4 of (delta - 1) for b >= 50 (COMPUTED). Worked values: delta(100) = 1.009259,
delta(406) = 1.003941, delta(878) = 1.002254, delta(1000) = 1.002043. Plain LLL reaches about 1.0219 in
practice (APS15, PDF p. 8, citing Gama-Nguyen 2008).

**Geometric Series Assumption (GSA).** After BKZ-b the Gram-Schmidt lengths ||b*_i|| are assumed to fall
geometrically: ||b*_i|| = delta^(d - 2i - 1) * Vol(L)^(1/d) (Kyber spec PDF p. 26). The Kyber team notes the
GSA "misses a 'tail' phenomenon" and has "several inaccuracies" (PDF p. 28); for small q it can also
predict ||b*_0|| > q, which is impossible because the lattice contains q-vectors. The pq-crystals scripts
therefore use a "q-ary aware" profile: log q for the first vectors, a GSA slope, then 1s. `coresvp.py`
implements both.

**Worked example (Kyber512, acs_rhf.py).** Kyber512 as plain LWE: n = 512, q = 3329, sigma = sqrt(3/2),
m = 486 samples, d = n + m + 1 = 999. The primal attack wins when the secret's projection onto the last b
coordinates, about sigma * sqrt(b), is shorter than the predicted ||b*_(d-b)||:

| b | ||b*_(d-b)|| (GSA) | sigma * sqrt(b) | success |
|---|---|---|---|
| 400 | 23.354 | 24.495 | no |
| 405 | 24.459 | 24.648 | no |
| 406 | 24.683 | 24.678 | yes |
| 420 | 27.964 | 25.100 | yes |

So b = 406 and classical core-SVP = 0.2925 * 406 = 118.7, floored to 118, matching Kyber round-3 Table 4.

## 2. The cost of an SVP call: sieving exponents

Two families of SVP algorithms exist. **Enumeration** uses little memory but super-exponential time.
**Sieving** uses exponential time and exponential memory. Since about 2019 sieving is faster in practice
from about dimension 80 (Kyber spec PDF p. 25, 27: "a cross-over around dimension 80"), and the SVP
records are held by sieves. Estimates therefore use sieving.

| exponent c in 2^(c b + o(b)) | model | source |
|---|---|---|
| 0.415 = log2(4/3)... (list-based basic sieve) | classical | Kyber spec PDF p. 26 |
| 0.292 = log2 sqrt(3/2) | classical, BDGL16 locality-sensitive filtering | BDGL16 abstract, PDF p. 1 |
| 0.2653 = log2 sqrt(13/9) | quantum (Grover inside the sieve, QRAM) | Laarhoven thesis Sec. 14.2.10, PDF p. 198 |
| 0.2570 | quantum random walks, QRAM 2^(0.0767 d) | Chailloux-Loyer 2021, Thm. 1, PDF p. 3 |
| 0.2563 | reusable quantum walks | Bonnetain-Chailloux-Schrottenloher-Shen 2023, Prop. 4, PDF p. 27 |
| 0.2846 | quantum 3-tuple sieve, only with memory limited to 2^(0.1887 d) | Engelberts et al., arXiv 2510.08473, PDF p. 1 |
| 0.2075 = log2 sqrt(4/3) | "plausible" floor: the size of the sieve's list | FrodoKEM spec PDF p. 41 |

Notes for the learner:

- 0.292 is believed close to optimal for this kind of sieve: the FrodoKEM authors write that 2^(0.292b+o(b))
  "may be reasonable to assume ... is optimal" because its near-neighbour technique meets known lower
  bounds (FrodoKEM round-3 spec, PDF p. 41).
- **Dimensions for free** (Ducas 2018): SVP in dimension b can be solved by sieving in dimension
  b - d4f(b) with d4f(b) = b ln(4/3) / ln(b / (2 pi e)) (Ducas 2018, PDF p. 2; Kyber spec PDF p. 28:
  d4f(413) = 37.3). This is a sub-exponential gain that core-SVP ignores; it is why the Kyber team calls
  the sign of the o(b) term "a priori unclear" (PDF p. 27).
- Practical sieves were far slower than 2^(0.292b) when core-SVP was introduced: an implementation fit
  of about 2^(0.405b+11) cycles for b = 60..80 gives a 2^20 margin at b = 80 (FrodoKEM spec PDF p. 41).
- Quantum: the ratio 0.2653/0.2925 = 0.907, so quantum core-SVP is about 91% of classical. Changing the
  quantum constant to the best-known 0.2563 lowers Kyber1024's quantum figure from 232.9 to 225.0 (T5).
  But AGPS20 (PDF p. 1) finds only "a small quantum speedup in dimensions of cryptanalytic interest"
  needing "several optimistic physical and algorithmic assumptions", and Doriguello et al. (arXiv
  2410.13759, PDF p. 1) estimate ~10^13 physical qubits and ~10^31 years at dimension 400, "roughly the
  same" as one 6 GHz classical core. The Kyber and FrodoKEM teams therefore treat a refined quantum gate
  count as "essentially irrelevant" (Kyber spec PDF p. 28; FrodoKEM 2025 proposal PDF p. 18).
- Hhan (arXiv 2609.02764v1, 2026-09-02) claims exact SVP in 2^(n/2+o(n)) time and space. It is
  unreviewed and discloses heavy AI assistance; even if correct it is slower than 2^(0.292 n) heuristic
  sieving, so it does not change attack estimates.

## 3. Core-SVP methodology and why it is conservative

### 3.1 Definition

Introduced by Alkim-Ducas-Pöppelmann-Schwabe (NewHope, USENIX Security 2016, Sec. 6, PDF p. 8-9):

1. Model the attack as BKZ-b followed by a success test (primal or dual, Sec. 4).
2. Find the smallest b (optimising over the number of samples m) for which the test succeeds.
3. Report c * b with c = 0.292 (classical), 0.265 (quantum), 0.2075 (plausible).

It counts one SVP call and nothing else. What it leaves out:

- the number of SVP calls: progressive BKZ needs about C (d - b) calls with C = 1/(1 - 2^-0.292) = 5.46,
  about 3340 = 2^11.7 for Kyber512 (Kyber spec PDF p. 28; `acs_rhf.py` gives 2^11.7 / 2^12.1 / 2^12.4 for
  Kyber512 / 768 / 1024);
- polynomial factors inside each sieve (FrodoKEM adds a factor b "vector operations" for plain LWE, PDF
  p. 41 footnote 7; Kyber and NewHope drop it);
- memory: sieves need about 2^(0.2075 b) vectors; access to such memory is assumed free (RAM model).

### 3.2 Security categories

NIST defines categories 1 / 3 / 5 by key search on AES-128 / 192 / 256: 2^143 / 2^207 / 2^272 classical
gates (2016 call for proposals, PDF p. 18). The quantum figures were 2^170 / 2^233 / 2^298 divided by
MAXDEPTH in 2016 and 2^157 / 2^221 / 2^285 divided by MAXDEPTH in the 2022 call for additional signatures (PDF p. 17).
FIPS 203 assigns ML-KEM-512 / 768 / 1024 to categories 1 / 3 / 5 (PDF p. 23). There is no official
core-SVP threshold per category; teams argue from core-SVP to gates. Kyber claims category 1 from core-SVP
118 plus a refined count of 151.5 gates (a "2^8 factor margin" over 2^143, PDF p. 27). Saber states its
core-SVP figures sit 2^25 / 2^18 / 2^12 below the AES gate counts and that labelling LightSaber category 1
"relies on the assumption that this factor 2^25 can be accounted for" (Saber spec PDF p. 12).

### 3.3 How far refined estimates sit above core-SVP (T0, COMPUTED from published and our numbers)

| set | primal b | core-SVP C | lattice-estimator MATZOV model (our b, d) | published refined gates | refined - core |
|---|---|---|---|---|---|
| Kyber512 | 406 | 118.7 | 143.8 | 151.5 | 32.8 |
| Kyber768 | 626 | 183.1 | 205.5 | 215.1 | 32.0 |
| Kyber1024 | 878 | 256.8 | 276.2 | 287.3 | 30.5 |
| Frodo-640 | 485 | 141.9 | 166.2 | 175.1 | 33.2 |
| Frodo-976 | 706 | 206.5 | 228.4 | 240.0 | 33.5 |
| Frodo-1344 | 929 | 271.7 | 291.2 | 305.4 | 33.7 |

"Published refined" is Kyber round-3 Table 4 (PDF p. 21) and FrodoKEM 2025 proposal Table A.8 (PDF p. 18),
both by the Kyber team's method (leaky-LWE-estimator simulation, AGPS20 sieve gate counts). The core-SVP
column here has no FrodoKEM log2(b) term. Memory in the refined model: Kyber 93.8 / 138.5 / 189.7 bits,
FrodoKEM 110.4 / 155.8 / 202.1 bits.

The Kyber team lists eight "known unknowns" (Q1-Q8, spec PDF p. 29-31) that could move its gate count,
from idealised angles in the sieve analysis (2^-3 to 2^-1) and routing/congestion costs (2^2 to 2^8) to
refined BKZ strategies (2^-8 to 2^-2) and module-BKZ (2^-4 to 2^0), summarised as "somewhere between
2^-16 and 2^14" (PDF p. 30-31). NIST's round-3 report accepts this: in the very worst case "some of the
parameter sets may fall below their targeted security level in the gate-count model, although even in this
case, it is likely the submitted parameter sets will still meet their targeted security levels in any cost
model which realistically models the cost of memory access" (NIST IR 8413-upd1, PDF p. 37).

### 3.4 Why core-SVP is conservative, and where it is not

Conservative: it drops ~2^12 SVP calls, the sieve's polynomial overheads and all memory cost, and uses
asymptotic exponents; the gap to refined gate counts is 30-34 bits (Sec. 3.3). NewHope's round-2 spec
shows the same gap with the older lwe-estimator: NewHope1024 has core-SVP 259 but 289 (primal uSVP) in the
estimator with 2^(0.292b+16.4) per sieve and the SVP-call count (NewHope round-2 Table 13, PDF p. 35).

Not conservative: (a) dimensions for free and progressive sieving are sub-exponential gains the formula
does not subtract; (b) the GSA's tail errors, and (c) the dual attack's "many short vectors" assumption is
optimistic for the attacker in core-SVP but the MATZOV-style improvements are not in the simple formula at
all. The practical rule used by every team is to keep a margin of tens of bits between the core-SVP figure
and the category's gate threshold, and to argue the margin from refined models.

### 3.5 Memory cost and hidden overheads (pass 2)

Every number above is in the RAM model: reading any bit of a 2^90-bit memory costs one operation. Sieves
need about 2^(0.2075 b) stored vectors (Kyber512: 93.8 bits of memory in the Kyber team's refined
model), so this matters. Three primary sources quantify it.

- **NIST, "FAQ on Kyber512" (December 2023).** In the RAM gate-count model: the spec's 2^151 is "still
  generally acknowledged to be the best attack"; Q1-Q8 together give a range from 2^135 to 2^165; the
  estimator gives 2^142.2 (bdd, commit 564470e); adding the hidden BDGL overheads of Ducas 2022 (a factor
  about 2^5, or 2^3 with 2^10 times more memory) gives "about 2^147 (or 2^145 if we consider memories in
  excess of 2^105 bits feasible for a category 1 attacker)"; NIST's estimate of the largest memory a
  category-1 attacker could build is 2^96.5 bits (PDF p. 2-3). Core-SVP's 2^118 "should not be interpreted
  as concrete gate counts" (PDF p. 3). If memory access costs grow like the square root, cube root or fourth
  root of the memory size, the sieve exponent becomes 0.349, 0.3294 or 0.3198 instead of 0.292, and "naively
  ignoring the o(sieving dimension) term" gains 21, 14 or 10 bits; NIST treats the cube root as its best
  guess (PDF p. 3-4). NIST's best guess for the realistic cost of attacking Kyber512 is "about 2^160 bit
  operations/gates, with a plausible range of uncertainty being something like 2^140 to 2^180" (PDF p. 5).
- **Ducas, "Estimating the hidden overheads in the BDGL lattice sieving algorithm"** (PQCrypto 2022, ePrint
  2022/922): the real BDGL algorithm costs "about 2^6" more gates than the idealised model at sieving
  dimension ~380; part of this can be traded for memory "at a costly rate" (PDF p. 1).
- **Jaques, "Memory adds no cost to lattice sieving for computers in 3 or more spatial dimensions"**
  (ePrint 2024/080; IACR Communications in Cryptology 2024 per Carrier et al.'s reference list). In a model
  where processors, memory and wires come in fixed proportions, sieving can still reach 2^(0.2925 d + o(d))
  asymptotically in three spatial dimensions (2^(0.3113 d + o(d)) in two) (PDF p. 1). Concretely, with a
  routing constant of 2^-12.8, the Kyber512 primal attack rises to 2^158.7 (sieve dimension 375: 2^145.7),
  +7.2 bits over the spec's 2^151.5; Kyber768 to 229.9 (+14.8), Kyber1024 to 310.2 (+22.9) (Table 1, PDF
  p. 17). He notes MATZOV's gains and memory costs "nearly cancel out for Kyber-512" (PDF p. 17) and adds a
  disclaimer that better algorithms may change this (PDF p. 3).

Lesson for Turing: core-SVP is the right number to COMPARE designs (NIST FAQ PDF p. 3: it is "believed to
be mostly monotonically related to the real security level"), but it is not a cost. Realistic costs sit
25-45 bits higher for Kyber512 (118 core-SVP vs ~147 RAM gates vs ~160 with memory), and the memory
premium grows with the parameter size (Jaques: +7 to +23 bits from Kyber512 to Kyber1024). A ~1000-dimension
Turing layer with core-SVP >= 256 would sit far above any of these thresholds in every model read here.

## 4. The attacks

### 4.1 Primal attack (unique-SVP)

Build the lattice {x in Z^(m+n+1) : (A | I_m | -b) x = 0 mod q} of dimension d = m + n + 1 and volume q^m;
(s, e, 1) is an unusually short vector in it (Kannan embedding). Success condition (ADPS16 eq. (1), PDF
p. 9; Kyber eq. (9), PDF p. 26; FrodoKEM eq. (7), PDF p. 42):

    sigma * sqrt(b) <= delta(b)^(2b - d - 1) * q^(m/d)

The attacker chooses m (up to the samples available) to minimise b. This "2016 estimate" replaced the
older Gama-Nguyen-based condition. Albrecht-Göpfert-Virdia-Wunderer (ASIACRYPT 2017) ran lattice-reduction
experiments "exhibiting a behaviour in line with" it and found BKZ sometimes does slightly better (PDF
p. 1). Dachman-Soled-Ducas-Gong-Rossi (CRYPTO 2020) and Postlethwaite-Virdia (PKC 2021) replaced the
single threshold by a probabilistic simulation of progressive BKZ; that is how Kyber's refined estimate
gets b = 413 for median success (Kyber spec PDF p. 28).

When sigma_s differs from sigma_e (e.g. a small secret), the secret coordinates are rescaled by
sigma_e / sigma_s before reduction (Bai-Galbraith); `coresvp.py` does this in its GSA conventions.

### 4.2 Primal BDD

Instead of embedding, reduce the lattice with BKZ-b and then decode the target with one larger SVP call
in dimension eta > b (a "final big sieve"). The lattice-estimator prices Kyber512 at 2^140.2 this way
(b 389, eta 422), below its usvp estimate 2^143.8 (estimator README and docs/schemes/nist-pqc-round-3.rst,
commit 53da598). The Kyber team lists the same idea as Q7 (PDF p. 30). In core-SVP terms it trades a
smaller b for one sieve in dimension eta; it is part of why core-SVP is only a proxy.

### 4.3 Dual attack, dual-hybrid, and the dispute

**Basic dual attack.** Find a short vector (x, y) with A^T x = y mod q; then <x, b> - <y, s> = <x, e> is
small (Gaussian of std length * sigma) for LWE and uniform otherwise. One vector of length l gives a
distinguishing advantage eps ~ exp(-2 pi^2 tau^2), tau = l sigma / q (ADPS16 Sec. 6.4, PDF p. 9; FrodoKEM
uses eps = 2 delta' with the factor 4 variant, PDF p. 42-43). About 1/eps^2 vectors are needed; core-SVP
assumes one sieve gives 2^(0.2075 b) of them, all as short as the shortest (Kyber spec PDF p. 26). In
core-SVP the dual comes out 1-2 bits cheaper than the primal for Kyber, FrodoKEM and our ~1000-dim tables.
The Kyber team argues this is an artefact: most sieve vectors are sqrt(4/3) longer and the assumption
conflicts with dimensions for free, so the dual is "in fact significantly more expensive" (PDF p. 28).

**Dual-hybrid / FFT dual (Guo-Johansson ASIACRYPT 2021; MATZOV 2022).** Guess or enumerate some secret
coordinates, reduce a smaller lattice, and score all guesses at once with an FFT after modulus switching.
MATZOV also cut the estimated sieve gate cost (~430 gates per codeword instead of ~3,500,000 at rank 400;
about 6 bits at rank 400; PDF p. 3). Result: Kyber512 / 768 / 1024 at 137.5 / 193.5 / 257.8 gates;
LightSaber / Saber / FireSaber 138.4 / 202.7 / 264.9 (MATZOV PDF p. 4). NIST: "all three KYBER parameter
sets fall slightly below the security targets for their claimed security levels when the cost of memory
access for the attacker is not explicitly taken into account" (NIST IR 8413-upd1, PDF p. 38). The
lattice-estimator's default model follows MATZOV and gives Kyber512 dual_hybrid 2^139.7, its cheapest
attack (README); in core-SVP ("rough") mode it gives dual_hybrid 2^115.5 against usvp 2^118.6.

**The critique.** Ducas-Pulles (CRYPTO 2023) showed that the statistical "independence heuristic" behind
these attacks contradicts unconditional theorems in some regimes and well-tested heuristics in the regime
the NIST-scheme estimates use, observed a "waterfall-floor" phenomenon, and concluded the success
probability is "presumably significantly overestimated" (PDF p. 1). Their follow-up (ePrint 2023/1850)
gives an experimentally accurate score-distribution model as "a first step towards fixing the analysis".
Pouly-Shen (EUROCRYPT 2024, ePrint 2023/1508) proved a simplified dual attack correct without statistical
assumptions; its costs "are not competitive with the state of the art" because it lacks modulus switching
(PDF p. 23; note their published Table 1 had wrong numbers, fixed in the ePrint version, PDF p. 1). Qu-Xu
(ePrint 2025/859, ASIACRYPT 2025) add provable modulus switching. Carrier et al. (ePrint 2023/1852) give a
duality-formula analysis in the code-based setting.

**Where the dispute stands on 2026-09-27 (pass 2).** Three lines of work now exist.

1. *Heuristic dual attacks with a corrected analysis.* Carrier, Meyer-Hilfiger, Shen, Tillich, "Assessing
   the impact of a variant of MATZOV's dual attack on Kyber" (CRYPTO 2025, pp. 444-476; ePrint 2022/1750).
   They replace modulus switching by decoding with polar codes over Z_q ("lossy source coding"), analyse
   the score through a duality formula instead of the independence assumption, and use "a new simple
   heuristic that is backed up by experimental evidence" (PDF p. 5; experiments in Fig. 4.1, PDF p. 25).
   Their Table 5.1 (PDF p. 27), log2 cost in three models (C0 = core-SVP, CC = AGPS20 "list_decoding-
   classical" RAM gate count, CN = query model):

   | | NIST | MATZOV C0 / CC / CN (as recomputed in [AS22]) | Carrier et al. C0 / CC / CN |
   |---|---|---|---|
   | Kyber-512 | 143 | 115.4 / 139.2 / 134.4 | 121.8 / 139.5 / 134.5 |
   | Kyber-768 | 207 | 173.7 / 196.1 / 190.6 | 173.0 / 195.1 / 189.8 |
   | Kyber-1024 | 272 | 241.8 / 262.4 / 256.1 | 239.0 / 259.7 / 254.6 |

   Caveats they state (PDF p. 25-26): the CC model ignores memory access cost "and thus may significantly
   underestimate the true cost"; it inherits the idealised BDGL analysis, which Ducas (PQCrypto 2022)
   estimates underestimates the nearest-neighbour cost "by a factor of about 2^6" at sieving dimension 380;
   and "we do not compare our results with the state-of-the-art primal attacks". Read against the primal
   numbers in the same kind of RAM model (estimator: usvp 143.8, bdd 140.2 for Kyber512; Kyber team 151.5),
   the dual attack is now a credible competitor of the primal attack, not a clear winner. In core-SVP terms
   (C0) their Kyber512 dual is 121.8, above the primal 118.
2. *Provable dual attacks.* Pouly-Shen (EUROCRYPT 2024), Qu-Xu (ASIACRYPT 2025) and a run of 2026 preprints:
   Li-Wang-Wang, ePrint 2026/2166 (MATZOV-style FFT dual attack with a proof of correctness): 210 / 300 / 410
   bits for ML-KEM-512/768/1024, 28 / 47 / 68 bits below Pouly-Shen (PDF p. 1); Li-Wang-Wang, ePrint
   2026/2186 (general dual lattice, m ~ n samples): 216 / 317 / 426 bits (PDF p. 1); Wang-Wang-Zheng-Zhao,
   ePrint 2026/1326 (LaMS): 22 / 31 / 41 bits below a corrected Qu-Xu attack (PDF p. 1); Qu-Tian-Wang-Xu,
   ePrint 2026/2117: 26.1-43.7 bits below the original provable framework (PDF p. 1); Ling-Yan-Zhao, ePrint
   2026/979: a quantum rejection sampler cuts Pouly-Shen by 9 / 4 / 13 bits (PDF p. 1). All of these are
   preprints and all stay far above the heuristic and primal estimates. They show the dual attack CAN be
   made rigorous; they do not threaten ML-KEM.
3. *Better score models.* Ducas-Pulles, "Accurate score prediction for dual-sieve attacks" (Journal of
   Cryptology 39(1), 2026, per the reference list of ePrint 2026/1400); Li-Zheng, ePrint 2026/1048
   (covariance-based variance prediction; says the correct-guess variance was underestimated); Li-Zheng,
   ePrint 2026/1400 (modulus switching plus lossy source coding: "modest" improvement, decoding and FFT
   costs down 1-6 and 2-7 bits).

**The dual-hybrid gains more as the dimension grows (COMPUTED from published numbers,
`python acs_dual_vs_primal.py`).** Primal core-SVP = our unrounded Kyber Table 4 values; primal RAM gates =
the estimator's bdd attack (MATZOV cost model, commit 53da598); dual = the three published dual-hybrid rows.

| set (LWE dim.) | primal C0 | best dual C0 | C0 gap | primal RAM gates | best dual CC | CC gap | best dual CC minus NIST |
|---|---|---|---|---|---|---|---|
| Kyber512 (512) | 118.7 | 115.4 (MATZOV) | 3.3 | 140.2 | 137.1 (Ogilvie) | 3.1 | -5.9 |
| Kyber768 (768) | 183.1 | 170.2 (Ogilvie) | 12.9 | 201.0 | 192.7 (Ogilvie) | 8.3 | -14.3 |
| Kyber1024 (1024) | 256.8 | 234.8 (Ogilvie) | 22.0 | 270.7 | 257.2 (Ogilvie) | 13.5 | -14.8 |

At dimension 1024 with Kyber's narrow secret (sigma = 1), the best published dual-hybrid is 22 bits below the
primal core-SVP figure in the same core-SVP model, and 13.5 bits below the primal attack in the RAM gate
model. The simple dual attack of Sec. 4.3's first paragraph (no guessing) does not show this: in
`coresvp.py` the dual is only 1-3 bits below the primal. Consequence for this note's ~1000-dimension tables
(Sec. 7): their "dual C" column is NOT the best dual attack; for secrets as narrow as Kyber's, subtract up to
~22 bits from the core-SVP figure until the lattice-estimator's dual_hybrid has been run on the candidate
(Sec. 5.1 runs it). Caveats: the dual-hybrid numbers rest on the Carrier et al. heuristic (not proven),
ignore memory, and guess secret coordinates, so a wider secret should shrink the gain; the Kyber768/1024
secrets (eta = 2, sigma = 1) are narrower than FrodoKEM's (sigma 2.3-2.8).

NIST's own summary (FAQ on Kyber512, December 2023, PDF p. 2): MATZOV "claimed to reduce the gate count to
2^137 but the main result was brought into question by Ducas and Pulles"; "about 6 out of the 14 bits"
of MATZOV's gain come from sieving tweaks that "don't depend on the correctness of the main result"; the
estimator (commit 564470e, CN11 simulator, MATZOV cost) gives 2^142.2 for the primal bdd attack. The FAQ
predates the CRYPTO 2025 paper; no later NIST statement on it was checked here (see
`nist-pqc-standards.md`). Status: the ~12-bit dual gain in the RAM gate model for Kyber-768/1024 is now
backed by a heuristic analysis that avoids the known flaw; it is not proven, not compared with primal
attacks by its authors, and ignores memory (Open question 2).

### 4.4 Hybrid (lattice + meet-in-the-middle) and small or sparse secrets

Howgrave-Graham's hybrid attack (CRYPTO 2007, cited in NIST IR 8413 ref. [167]) guesses part of a small
secret with a meet-in-the-middle search and reduces the rest. Wunderer (ePrint 2016/733) shows earlier
analyses set probabilities "equal to 1, which ... are in fact as small as 2^-80", so hybrid estimates were
unreliable in both directions (PDF p. 1). May (CRYPTO 2021) meets ternary keys in about S^0.25 for key
space size S, about S^0.3 concretely for NTRU / NTRU Prime, without breaking their claims (PDF p. 1).
Albrecht (EUROCRYPT 2017) cut the dual attack on sparse small-secret LWE in HElib / SEAL from the promised
80 bits to 62 / 68 bits (PDF p. 1). Cheon-Hhan-Hong-Son (ePrint 2019/1114) combine dual and MITM for sparse
ternary secrets. Lesson: these attacks matter when the secret is ternary, binary or sparse. For secrets with
std >= 1 (Kyber's eta >= 2, FrodoKEM's sigma >= 1.4) the published analyses do not find them better than the
primal attack. Our core-SVP script does not model them.

**Pass-2 additions: ring structure and sparse secrets.**

- *MLWE is concretely a little weaker than "equivalent" LWE.* Ogilvie, "On the Concrete Hardness Gap Between
  MLWE and LWE" (ePrint 2026/279), merged with Hou-Jiang (ePrint 2026/366) into the CRYPTO 2026 paper "Careful
  with the Ring! Concrete Hardness Gaps Between LWE and MLWE" (DOI 10.1007/978-3-032-35377-1_15, as stated on
  PDF p. 1 of 2026/366). In power-of-two cyclotomic rings, multiplying by x^i acts as a signed permutation of
  coefficients and keeps the secret and error distributions, so one expensive lattice preprocessing serves
  many rotated copies of the secret in a hybrid attack (2026/279 PDF p. 1-2). For Kyber/ML-KEM this gives
  "a consistent ~2-3 bit gap": with the Carrier et al. coded dual attack as the base, Kyber512/768/1024 go to
  118.8 / 170.2 / 234.8 (C0), 137.1 / 192.7 / 257.2 (CC), 132.2 / 186.9 / 252.4 (CN) (Table 2, PDF p. 30; gaps
  in Table 3, PDF p. 31). For sparse-secret RLWE as used in FHE the gap reaches "up to 15 bits" (PDF p. 1);
  Hou-Jiang report that 12 of 16 recent FHE parameter sets fall below 128-bit security under their enhanced
  hybrid (2026/366 PDF p. 1).
- *Sparse and small secrets are attacked in practice.* Wenger et al., "Benchmarking Attacks on Learning with
  Errors" (IEEE S&P 2025; arXiv 2408.00882v2): with Kyber-like parameters (module rank 2) and sparse binomial
  secrets, SALSA and Cool & Cruel recover Hamming weight 9-11 secrets in 28-36 hours, and a dual hybrid
  meet-in-the-middle solves decision-LWE up to Hamming weight 4 in under an hour, while uSVP recovered nothing in
  1100 hours (abstract). Pulles-Vie (ePrint 2025/1990) implement a GPU primal hybrid (Guess + Verify) that beats
  Cool & Cruel on almost all of those benchmark instances (PDF p. 1). Karenin-Kirshanova-May-Nowakowski
  (ASIACRYPT 2025, ePrint 2025/1910) make lattice hybrid attacks practical with a batch-CVP slicer (title and
  venue only; not read further). Bassotto et al. (arXiv 2510.02162) recover sparse secrets in toy Kyber
  settings (n, k) = (128, 3) and (256, 2) with a machine-learning hybrid (abstract). None of these targets
  full-weight Kyber or FrodoKEM secrets; all of them show that a sparse or very small secret is a real
  weakness, not a theoretical one.

### 4.5 BKW

BKW (Blum-Kalai-Wasserman) cancels coordinates by adding and subtracting samples; it needs exponentially
many samples. Albrecht et al. (2012, ePrint 2012/636) found BKW beats their lattice-reduction estimates
from n ~ 250 (against the SIS/dual approach), but only with "an unbounded number of LWE samples" (PDF p. 1).
Kirchner-Fouque (CRYPTO 2015) used 2^28 samples for n = 128 with binary secret (PDF p. 1). The
lattice-estimator prices coded-BKW on Kyber512 at rop 2^178.8 with m ~ 2^166.8 samples (README). A KEM
public key gives about n (FrodoKEM) or (k+1)n (Kyber) samples, so the Kyber and FrodoKEM teams "rule out"
BKW (Kyber spec PDF p. 25; FrodoKEM spec PDF p. 41).

### 4.6 Arora-Ge and Gröbner bases

Arora-Ge (2011) linearise the polynomial that vanishes on every possible error value; this gives "a
slightly subexponential algorithm" for LWE with "noise rate below sqrt(n)" (PDF p. 1), but it needs a
number of samples that grows with the error range. The estimator's doctests show the effect on
n = 64, q = 7681: discrete Gaussian sigma = 3 with 2^50 samples costs 2^307.1 (m used 2^46.8), but errors
uniform on 7 values cost only 2^60.6 with 2^30.3 samples (estimator/gb.py, commit 53da598). Lesson: never
use very narrow, hard-bounded errors together with many samples. With ~n samples and Gaussian-like errors,
this attack is irrelevant (Kyber spec PDF p. 25: "linearization attacks" ruled out).

### 4.7 Algebraic (ring/module) attacks

Known attacks on Kyber-type Module-LWE "do not make use of the structure" (Kyber spec PDF p. 25). Quantum
algorithms for Ideal-SVP exist for principal/ideal lattices; Ducas et al. note obstacles for Ring-LWE and
suggest Module-LWE creates more (Kyber spec PDF p. 31). The Albrecht-Deo reduction from MLWE to RLWE
suggests larger module rank helps (same page). Module-BKZ could exploit ring symmetries; the Kyber team
bounds the gain at 2^-4 to 2^0 (Q8, PDF p. 30). Plain LWE (FrodoKEM) avoids this whole question at a cost
in key size. Overstretched NTRU is a separate case (Kirchner-Fouque 2017, Albrecht-Bai-Ducas 2016; see
`pq-families-for-diversity.md`).

## 5. Tools

**lattice-estimator** (github.com/malb/lattice-estimator, clone at commit 53da598, 2026-08-19, in the
scratch dir). Successor of Albrecht-Player-Scott's lwe-estimator ("On the concrete hardness of Learning
with Errors", JMC 2015; ePrint 2015/046). A SageMath module (`estimator/conf.py` imports `sage.all`),
licensed LGPLv3+ (README). It estimates LWE, NTRU and SIS against: primal uSVP, primal BDD, BDD hybrid and
MITM hybrid, dual, dual-hybrid, coded-BKW and Arora-Gröbner (README "Status"; module files). Defaults:
`red_cost_model = RC.MATZOV`, `red_shape_model = GSA`, `max_beta = 1754` (conf.py). `LWE.estimate.rough`
uses core-SVP (RC.ADPS16, 0.292 b) for usvp and dual_hybrid only (lwe.py). The README warns estimates
change between versions and asks users to cite the commit. Its `schemes.py` encodes Kyber, Saber,
FrodoKEM (with m = n + 16), NTRU, Falcon, Dilithium and HE parameters.

**pq-crystals/security-estimates** (github.com/pq-crystals/security-estimates; README is one line, no
licence file; commits 71f89f3 of 2019-03-21 and 75c2694 of 2021-03-16). Python 3 scripts `Kyber.py`,
`MLWE_security.py`, `model_BKZ.py` (core-SVP with a q-ary BKZ profile), `Kyber_failure.py`,
`proba_util.py`, `Dilithium.py`, `MSIS_security.py`. Re-run here on 2026-09-27 (scratch
`attack-cost/kyber_rerun2.log`): output equals the published Table 4 and the dual rows below. The 2019
version (grid step 5 in b and m, no Kannan +1) reproduces round-2 Table 4 exactly (`se-2019b/run.log`).
Commit 75c2694 "Fixed missing Kannan-embedding dimension" and set the m step to 1.

**NewHope PQsecurity.py** (newhopecrypto/newhope scripts, Python 2) and **lwe-frodo/parameter-selection**
(MIT, commit e09cf4b, 2016-10-05, `pqsec.py`): same method with small convention differences (next
section).

**leaky-LWE-estimator** (Dachman-Soled-Ducas-Gong-Rossi, CRYPTO 2020): a Sage toolkit that simulates
progressive BKZ with hints; its NIST-round3 branch produced the refined Kyber and FrodoKEM gate counts
(Kyber spec PDF p. 28 footnote 9; FrodoKEM 2025 proposal PDF p. 18).

### 5.1 Running the lattice-estimator without SageMath (pass 2)

SageMath is not installed and installing it (a multi-GB download) was outside this task. Instead,
`research/scripts/pq/acs_sage_shim/sage/all.py` provides the ~35 SageMath names the estimator imports
(RR, ZZ, log, binomial, find_root, RealDistribution, ...), built on mpmath and scipy. Two details mattered
and were found by the validation itself: (1) Sage's `RealField(p)` for p > 53 must really compute at p bits,
because `prob.amplify` evaluates log(1 - 4 eps^2) with eps ~ 2^-40, which is 0 at 53 bits (the plain-dual
estimate crashed until this was fixed); (2) Sage integers divide without float overflow (the coded-BKW
sample count q^b / 2 exceeded 2^1024 in Python floats). The estimator code itself is unmodified (clone at
commit 53da598 in the scratch dir; LGPL code is not copied into this repository).

**Validation** (`python acs_estimator_run.py validate`, 2026-09-27, log `attack-cost/estimator_validate.run2.log`):
all 10 reference outputs the estimator's authors publish (README.rst, docs/schemes/nist-pqc-round-3.rst)
are reproduced to 0.05 bits with identical beta, eta and d:

| check | published (SageMath) | shim |
|---|---|---|
| Kyber512 primal_usvp | 2^143.8, beta 406, d 998 | 143.77, 406, 998 |
| Kyber512 primal_bdd | 2^140.2, beta 389, eta 422, d 1005 | 140.20, 389, 422, 1005 |
| Kyber512 dual | 2^149.9, beta 424, d 1024 | 149.88, 424, 1024 |
| Kyber512 dual_hybrid | 2^139.7, beta 387 | 139.66, 387 |
| Kyber512 coded_bkw | 2^178.8 | 178.76 |
| Kyber512 rough usvp / dual_hybrid | 2^118.6 (406) / 2^115.5 (395) | 118.55 (406) / 115.51 (395) |
| Kyber768 primal_bdd | 2^201.0, 606, 640, 1420 | 200.96, 606, 640, 1420 |
| Kyber1024 primal_bdd | 2^270.7, 855, 889, 1867 | 270.72, 855, 889, 1867 |
| LightSaber primal_bdd | 2^139.9, 388, 421, 1021 | 139.94, 388, 421, 1021 |

Negative controls fail as they must: Kyber512 with n = 500 gives usvp 140.45 (beta 394) and bdd 136.98;
perturbing the shim's pi by 1 % moves Kyber512 usvp to d = 990 and 143.72. What is NOT validated: the
Arora-Groebner estimate (needs PowerSeriesRing; not provided), NTRU and SIS estimates (not exercised),
and code paths no reference output touches.

## 6. Our estimator: coresvp.py and its validation

`research/scripts/pq/coresvp.py` (numpy only, deterministic, ~10 s for validation, ~70 s for tables).
`python coresvp.py` validates and exits 0 only if every check passes; `python coresvp.py table` prints
the Turing tables; `python coresvp.py example` prints a worked example. Output logs of the 2026-09-27 run
are in the scratch dir `attack-cost/coresvp_validate.log` and `coresvp_table.log`.

### 6.1 Conventions (each published table used a slightly different script)

| convention | primal model | dual length | eps | SVP cost | reproduces |
|---|---|---|---|---|---|
| newhope | GSA, d = n + m | delta^d q^(n/d) | exp(-2 pi^2 tau^2) | c b | NewHope r2 Table 12, ADPS16 Table 1 |
| frodo | as newhope | as newhope | 4 exp(...) | c b + log2 b | FrodoKEM r3 Table 10 |
| kyber21 | q-ary profile, Kannan d = n + m + 1 | randomised profile | exp(...) | c b | Kyber r3 Table 4 |
| kyber19 | q-ary profile, d = n + m, step-5 grid | randomised profile | exp(...) | c b | Kyber r2 Table 4 |
| adps16 | GSA, d = n + m + 1 | delta^(d-1) q^(n/d) | exp(...) | c b | formulas as printed |

### 6.2 Published versus computed (all COMPUTED by `python coresvp.py`; published values VERIFIED)

| set | source | attack | published b | computed b | published C / Q / P | computed C / Q / P |
|---|---|---|---|---|---|---|
| Kyber512 | r3 Table 4 p. 21 (+ script) | primal | 406 | 406 | 118 / 107 / 84 | 118 / 107 / 84 |
| Kyber512 | pq-crystals script | dual | 403 | 403 | 117 / 106 / 83 | 117 / 106 / 83 |
| Kyber768 | r3 Table 4 | primal | 626 | 626 | 183 / 166 / 129 | 183 / 166 / 129 |
| Kyber768 | script | dual | 620 | 620 | 181 / 164 / 128 | 181 / 164 / 128 |
| Kyber1024 | r3 Table 4 | primal | 878 | 878 | 256 / 232 / 182 | 256 / 232 / 182 |
| Kyber1024 | script | dual | 868 | 868 | 253 / 230 / 180 | 253 / 230 / 180 |
| Frodo-640 | r3 Table 10 p. 43 | primal | - | 485 | 150.8 / 137.6 / 109.6 | 150.8 / 137.6 / 109.6 |
| Frodo-640 | r3 Table 10 | dual | - | 481 | 149.6 / 136.5 / 108.7 | 149.6 / 136.5 / 108.7 |
| Frodo-976 | r3 Table 10 | primal | - | 706 | 216.0 / 196.7 / 156.0 | 216.0 / 196.7 / 156.0 |
| Frodo-976 | r3 Table 10 | dual | - | 701 | 214.5 / 195.4 / 154.9 | 214.5 / 195.4 / 154.9 |
| Frodo-1344 | r3 Table 10 | primal | - | 929 | 281.6 / 256.3 / 202.6 | 281.6 / 256.3 / 202.6 |
| Frodo-1344 | r3 Table 10 | dual | - | 923 | 279.8 / 254.7 / 201.4 | 279.8 / 254.7 / 201.4 |
| NewHope512 | r2 Table 12 p. 34 | primal / dual | 384 / 383 | 384 / 383 | 112/101/79 both | 112/101/79 both |
| NewHope1024 | r2 Table 12 | primal / dual | 886 / 881 | 886 / 881 | 259/235/183, 257/233/182 | same |
| NewHope-USENIX | ADPS16 Table 1 p. 9 | primal / dual | 967 / 962 | 967 / 962 | 282/256/200, 281/255/199 | same |
| JarJar-USENIX | ADPS16 Table 1 | primal / dual | 449 / 448 | 449 / 448 | 131/119/93, 131/118/92 | same |
| BCNS | NewHope r2 Table 12 | primal / dual | 296 / 296 | 296 / 296 | 86/78/61 both | same |
| Kyber512 r2 (eta 2) | r2 Table 4 p. 25 | primal / dual | 385 / 380 (m 410 / 455) | same, same m | 112/102, 111/100 | same |
| Kyber768 r2 | r2 Table 4 | primal / dual | 625 / 620 (m 655 / 650) | same | 182/165, 181/164 | same |
| Kyber1024 r2 | r2 Table 4 | primal / dual | 880 / 870 (m 795 / 795) | same | 257/233, 254/230 | same |
| LightSaber (LWR) | Saber r3 Table 1 p. 11 | primal | - | 404 | 118 / 107 | 118 / 107 |
| Saber (LWR) | Saber r3 Table 1 | primal | - | 648 | 189 / 172 | 189 / 171 |
| FireSaber (LWR) | Saber r3 Table 1 | primal | - | 890 | 260 / 236 | 260 / 236 |

Gate-model checks: `gates_nn(500, 1024)` with the estimator's RC.Kyber fit = 176.5541919706, equal to the
estimator doctest 176.55419197058822; d4f(500) = 42.597718 (doctest "42.597..."); the MATZOV model at
Kyber512's (b 406, d 998) = 143.77 (README "2^143.8"); Kyber's G = (1025 - 413) C^2 2^137.4 = 2^151.55 with
C = 5.458 (spec 2^151.5, C = 5.46); d4f(413) = 37.30 (spec 37.3).

### 6.3 Residual mismatches, explained

- **Kyber "112 without LWR".** The round-3 changelog and Sec. 1.5 say Kyber512 has "112 bits of core-SVP
  hardness" if the rounding noise is not counted (PDF p. 13, p. 22). That is the round-2 number for the same
  eta = 2 instance, computed by the 2019 script (grid step 5, no Kannan +1). The fixed 2021 model gives b =
  382, 111 bits. The 1-bit difference is the script fix, not a new attack.
- **FrodoKEM sample count.** The spec only says the attacker has "msamp ~ n" samples (PDF p. 41).
  m_max = n + 8 (n from the public matrix plus nbar = 8 from the ciphertext) reproduces every Table 10
  entry; the estimator's m = n + 16 moves one entry (Frodo-640 dual classical) by 0.1
  (`acs_frodo_msamp.py`, COMPUTED).
- **Saber quantum 171 vs 172.** The Saber team says its three estimators agreed "up to small rounding
  differences" (PDF p. 11); ours sits 1 bit low on one entry. The check tolerates 1 bit for LWR only.
- **Dual "published" values for Kyber** come from re-running the pq-crystals script (Table 4 prints the
  primal only).
- **NewHope Table 12 label.** The extracted text of the NewHope512 row label reads "n = 1024"; the b values
  (384) fit n = 512, which we use. Likely a typo in the spec; it does not affect the numbers.
- **The epsilon factor (pass 2).** The dual attack's one-vector advantage is printed as
  eps = 4 exp(-2 pi^2 tau^2) in ADPS16 (PDF p. 9) and the Kyber r3 spec (PDF p. 26), and as eps = 2 delta with
  delta = exp(-2 pi^2 tau^2) in the FrodoKEM r3 spec (PDF p. 43). The scripts that produced the tables differ:
  NewHope's `PQsecurity.py` (line 52) and pq-crystals `MLWE_security.py` (line 37) use eps = exp(...) with no
  factor; the MIT `pqsec.py` of FrodoKEM (line 133) uses log2 eps = 2 + ..., i.e. eps = 4 exp(...). Each
  published table matches its script, not its printed formula: with the printed F = 2, FrodoKEM's dual rows
  come out 0.2-0.3 bits higher (149.9 / 214.8 / 280.1 classical vs published 149.6 / 214.5 / 279.8). Across
  Kyber, NewHope, FrodoKEM and a Turing-like row, going from F = 1 to F = 4 lowers the dual cost by only
  0.6-0.9 bits (`python coresvp.py eps`, E1-E2). Using every formula exactly as printed (Kannan +1, dual
  length delta^(d-1) q^(n/d), F = 4; the `adps16` convention) moves the published values by at most 1 bit
  (E3: Kyber1024 primal 255 vs 256, dual 252 vs 253; NewHope-USENIX dual 280 vs 281). Lesson for Turing: a
  core-SVP figure is only defined to about +-1 bit unless the script is named, so a design should publish
  its script and never rely on a 1-bit margin. Pass 1 of `coresvp.py` wrongly used F = 1 in the `adps16`
  convention (which claims to follow the printed formulas); pass 2 corrected it. No validated number
  depended on it.
- **Independent re-run of the pq-crystals script (pass 2).** `Kyber.py` at commit 75c2694 was re-run
  (8 min 40 s) and its output is identical to pass 1 (`attack-cost/kyber_rerun3.log`); its sample counts
  (primal m = 486 / 650 / 860, dual m = 512 / 650 / 838) equal the m values `coresvp.py` reports.

### 6.4 Negative controls and monotonicity (COMPUTED)

Each perturbed check must fail, and does: Kyber512 with q doubled (primal C 107.0), q - 200 (119.9),
eta 3 -> 2 (111.7), sigma + 5% (120.5), n = 496 (114.4); Frodo-640 with q = 2^16 (138.1), sigma 2.6 (148.1),
n = 632 (148.4). Monotonicity (newhope convention, m_max = n + 8): at q = 2^15, sigma = 2.8, cost rises from
120.5 (n = 560) to 276.7 (n = 1120) in every step; at n = 1024, q = 2^15 it rises with sigma from 196.0
(sigma 1.0) to 330.5 (sigma 8.0); at n = 1024, sigma = 2.8 it falls with q from 329.9 (2^12) to 169.6 (2^20).

### 6.5 What the script does NOT do

It does not model BDD with a final large sieve, hybrid/MITM attacks, BKW, Arora-Ge, MATZOV-style
dual-hybrid, probabilistic BKZ simulation, or module/ring structure. It uses one cost model per
convention. It is a validated core-SVP calculator plus the estimator's gate model, not a replacement for
the lattice-estimator.

## 7. ~1000-dimension options for Turing (COMPUTED, `python coresvp.py table`)

All numbers are log2 classical (C) or quantum (Q) core-SVP in the newhope convention (no log2 b), primal
unless marked. For the FrodoKEM convention add log2(b) ~ 9.5. "Gates" is the lattice-estimator MATZOV
model at our primal (b, d). Secret and error share sigma unless stated.

**T1 extract: plain LWE, m_max = n + 8 (FrodoKEM-like with nbar = 8).**

| n | log2 q | sigma | b | C | Q | dual C | gates |
|---|---|---|---|---|---|---|---|
| 976 | 16 | 1.0 | 587 | 171.7 | 155.7 | 171.1 | 195.2 |
| 976 | 16 | 2.0 | 684 | 200.1 | 181.4 | 199.2 | 222.3 |
| 976 | 16 | 2.8 | 740 | 216.4 | 196.3 | 215.4 | 237.9 |
| 976 | 13 | 2.8 | 967 | 282.8 | 256.5 | 281.4 | 301.2 |
| 1024 | 16 | 1.0 | 623 | 182.2 | 165.3 | 181.6 | 205.3 |
| 1024 | 16 | 1.4 | 670 | 196.0 | 177.7 | 195.1 | 218.5 |
| 1024 | 16 | 2.0 | 725 | 212.0 | 192.3 | 211.2 | 233.8 |
| 1024 | 16 | 2.8 | 783 | 229.0 | 207.7 | 228.1 | 250.0 |
| 1024 | 16 | 4.0 | 854 | 249.8 | 226.5 | 248.6 | 269.8 |
| 1024 | 16 | 8.0 | 1024 | 299.5 | 271.6 | 297.7 | 317.2 |
| 1024 | 15 | 2.8 | 852 | 249.2 | 226.0 | 248.0 | 269.2 |
| 1024 | 14 | 2.8 | 931 | 272.3 | 247.0 | 270.8 | 291.2 |
| 1024 | 13 | 1.0 | 783 | 229.0 | 207.7 | 227.8 | 249.8 |
| 1024 | 13 | 2.8 | 1022 | 298.9 | 271.1 | 297.2 | 316.6 |

How to read it:

- **The sigma^2/q rule.** (q, sigma) = (2^13, 1.0), (2^14, 1.4), (2^15, 2.0), (2^16, 2.8) all give 229.0-229.6
  at n = 1024 (full table). Reason: with m ~ n, q^(m/d) ~ sqrt(q) in the primal condition, so what matters is
  sigma / sqrt(q). Halving q is worth the same as multiplying sigma by sqrt(2).
- **Per step of n.** Near n = 1000 each +40 in n adds about 11.4 bits (q = 2^15, sigma = 2.8, Sec. 6.4).
- **Dual vs primal.** Dual core-SVP is 0.6-3 bits below primal everywhere (full T1); the refined dual
  story is Sec. 4.3.
- **q-ary profile.** The kyber21 q-ary model gives b 0-3 larger than GSA here: for q >= 2^13 and n ~ 1000
  the q-vectors hardly matter.

**T2: smallest sigma for a primal classical core-SVP target (plain LWE, m_max = n + 8).**

| n | log2 q | >= 128 | >= 192 | >= 256 |
|---|---|---|---|---|
| 976 | 13 | 0.108 | 0.619 | 1.939 |
| 976 | 16 | 0.249 | 1.670 | 5.502 |
| 1000 | 13 | 0.097 | 0.548 | 1.740 |
| 1000 | 16 | 0.210 | 1.460 | 4.933 |
| 1024 | 13 | 0.085 | 0.486 | 1.561 |
| 1024 | 14 | 0.105 | 0.661 | 2.207 |
| 1024 | 15 | 0.140 | 0.914 | 3.126 |
| 1024 | 16 | 0.182 | 1.281 | 4.423 |

Sigma below ~0.5 is outside the regime these formulas were validated on (the secret becomes nearly
ternary/sparse; Sec. 4.4 attacks apply). So at n ~ 1000, plain LWE is "too big" for category 1 and fits
categories 3-5; this matches FrodoKEM, which uses n = 976 for level 3 and n = 1344 for level 5.

**T2b: secret narrower than error (n = 1024, q = 2^15, sigma_e = 2.8, m_max = 1032).**

| sigma_s | b | C | Q | dual C |
|---|---|---|---|---|
| 2.8 | 852 | 249.2 | 226.0 | 248.0 |
| 1.0 | 751 | 219.7 | 199.2 | 218.8 |
| 0.816 (uniform ternary) | 732 | 214.1 | 194.2 | 213.2 |
| 0.5 | 685 | 200.3 | 181.7 | 199.5 |

A narrow secret costs 30-50 bits here even before the hybrid and MITM attacks the script does not model.

**T3: Module-LWE, rank 4, degree 256 (dimension 1024), m_max = 1280, kyber21 convention.**

| q | eta (sigma) | b | C | Q | dual C | gates |
|---|---|---|---|---|---|---|
| 3329 | 1 (0.707) | 806 | 235.7 | 213.8 | 231.6 | 256.1 |
| 3329 | 2 (1.000) = ML-KEM-1024 | 878 | 256.8 | 232.9 | 253.9 | 276.2 |
| 3329 | 3 (1.225) | 925 | 270.5 | 245.4 | 267.9 | 289.4 |
| 3329 | 4 (1.414) | 961 | 281.1 | 254.9 | 278.7 | 299.4 |
| 3329 | 6 (1.732) | 1015 | 296.9 | 269.2 | 294.5 | 314.6 |
| 7681 | 2 | 792 | 231.6 | 210.1 | 229.6 | 252.3 |
| 12289 | 2 | 750 | 219.4 | 198.9 | 217.3 | 240.6 |
| 8192 | 2 | 786 | 229.9 | 208.5 | 227.8 | 250.7 |
| 32768 | 2 | 672 | 196.5 | 178.3 | 195.1 | 219.0 |

Raising eta from 2 to 3 at q = 3329 adds 13.7 bits; ML-KEM-1024's parameters are the row eta = 2.
Decryption failure and ciphertext size decide how far eta can go (sibling topics).

**T4: Module-LWR rank 4 (n = 1024), q = 2^13, rounding to p, binomial secret variance mu/4, m_max = 1024.**

| p | mu | rounding std | b | C | Q |
|---|---|---|---|---|---|
| 2^9 | 8 | 4.6098 | 995 | 291.0 | 263.9 |
| 2^10 | 6 (FireSaber) | 2.2913 | 890 | 260.3 | 236.1 |
| 2^10 | 8 | 2.2913 | 908 | 265.6 | 240.9 |
| 2^11 | 8 | 1.1180 | 830 | 242.8 | 220.2 |

LWR is estimated by treating the rounding error (uniform on q/p values, variance ((q/p)^2 - 1)/12) as LWE
noise. Kyber makes the same move for its ciphertext rounding error, stating "the heuristic assumption that
e' is independent of s and e" (Kyber r3 spec PDF p. 22, footnote 4), and the lattice-estimator models
Saber's rounding error as noise of std 2.29 (docs/schemes/nist-pqc-round-3.rst). It is a heuristic, not a
reduction.

**T5: quantum constant sensitivity at Kyber1024's b = 878.** 0.2653 -> 232.9; 0.2570 -> 225.6;
0.2563 -> 225.0; 0.2075 -> 182.2.

## 8. Quantum algorithms for lattices: Chen 2024 and after

- **Chen, "Quantum Algorithms for Lattice Problems"** (ePrint 2024/555; received 2024-04-10, revised
  2024-04-19). Claimed a polynomial-time quantum algorithm for LWE with certain polynomial modulus-noise
  ratios, hence GapSVP/SIVP within ~n^4.5 factors (PDF p. 1). The author's own update on page 1, dated
  April 18, says "Step 9 of the algorithm contains a bug, which I don't know how to fix", points to
  Sec. 3.5.9 (page 37), and states that the polynomial-time claim no longer holds. The bug was found by
  Hongxun Wu and, independently, Thomas Vidick. Whether the claimed regime would have covered ML-KEM or
  FrodoKEM parameters was not checked here; the claim is withdrawn in any case.
- **Zhang, "Exact Coset Sampling for Quantum Lattice Algorithms"** (arXiv 2509.12341; v1 2025-09-15, v8
  2026-05-14, "Preprint - Work in Progress"). The current version replaces Chen's Steps 8-9 "in the access
  model stated below", obtaining a residue "as explicit side information in our access model", under
  "Additional Conditions AC1-AC4 and the spectral concentration property AC5" (PDF p. 1). It does not claim
  an unconditional algorithm.
- **Apon, "So about that Quantum Lattice Thing"** (ePrint 2025/1945, 2025-10-28): argues that the first
  version of Zhang's algorithm needed the answer in advance ("foreknowledge of the answer") and that the
  later version misreads quantum mechanics, and concludes these issues refute Zhang's claims (PDF p. 1).
- **Quantum sieving** (Sec. 2): best exponent 0.2563 (2023); a memory-limited 3-tuple improvement to 0.2846
  (2026); concrete resource studies find little or no advantage at cryptographic sizes.
- **Simon, "A Polynomial-Time Quantum Algorithm for the Dihedral Coset Problem"** (ePrint 2026/1591,
  "Preliminary Draft" dated August 11, 2026; received 2026-08-03, four revisions to 2026-08-17; author at
  AWS). Claims a polynomial-time quantum algorithm for DCP which, through Regev's 2004 reduction as improved
  by Brakerski-Kirshanova-Stehle-Wen, would solve LWE with alpha = sqrt(n) polylog(n) (PDF p. 1). The
  ePrint page notes that the proof of Lemma 3 in the first draft "had an error" and "has been substantially
  updated", and that ePrint 2026/1693 "claims the algorithm cannot work", which the author is "in the
  process of evaluating" (landing page, read 2026-09-27).
  - Gupte-Ragavan-Zhandry, "The ePrint:2026/1591 Quantum Algorithm Does Not Solve DCP" (ePrint 2026/1693,
    received 2026-08-15, revised 2026-09-01): "we formally show" the algorithm does not extract the least
    significant bit of the secret with non-negligible advantage; "our result is not merely about Simon's
    analysis ... the algorithm cannot possibly work", because it can be simulated, up to error
    poly(n) 2^(-n/3), from only the most significant third of the classical Fourier labels; Lean 4 code is
    released (PDF p. 1).
  - Guo-Yang (ePrint 2026/1714; arXiv 2608.16598), completing Simon's lemma proofs, find one hypothesis
    that "the rule the algorithm gives for choosing that partition does not supply", so the lemmas "do not
    by itself establish the correctness of the algorithm" (PDF p. 1).
  Status: claim contested by a formal no-go result; not withdrawn as of the landing page read on
  2026-09-27.
- **Luo, "Module Lattice Security" Parts I-IV** (arXiv 2604.15858, 2604.22900, 2605.17404, 2605.17412;
  April-June 2026, single author). Part IV (v2, 2026-05-25) claims a polynomial-time quantum attack on
  ML-KEM through a tower decomposition of the principal ideal problem, with approximation factor
  "gamma <= 21 < q/2 = 1664.5 for ML-KEM-1024" and O(n^3 log^2 n) gates (arXiv abstract). The load-bearing
  step is Part III's claim to reduce the Cramer-Ducas-Peikert-Regev (CDPR) factor for ML-KEM "from
  exp(O~(sqrt n)) to a sub-polynomial value", while Part II's abstract still states a Hermite factor
  exp(O~(sqrt n)) "matches the ideal case". Background (VERIFIED): the CDPR 2016 attack recovers short
  generators of principal ideals in cyclotomic rings, and the Kyber team notes that quantum Ideal-SVP
  algorithms face obstacles for Ring-LWE and more for Module-LWE (Kyber r3 spec PDF p. 31). Status: an
  unreviewed preprint series with no independent confirmation and no primary-source rebuttal found in the
  searches of 2026-09-27; only secondary (blog) commentary, which this note does not use. Not evaluated
  here. Treat as UNVERIFIED and watch (Open question 7).

Conclusion: as of 2026-09-27 the best quantum attacks on LWE that anyone has confirmed are
quantum-accelerated sieves inside BKZ, worth less than a 10% reduction in the exponent on paper and less
in concrete estimates. Two 2026 claims of polynomial-time quantum attacks exist: one (Simon) faces a
formal no-go proof; the other (Luo) is unconfirmed. Neither changes any estimate in this note, but a
design that wants robustness against a surprise break of lattices should combine a lattice KEM with a
non-lattice component (`hybrid-combiners.md`, `pq-families-for-diversity.md`).

## What this means for Turing

1. **Adopt a stated methodology before choosing parameters.** Recommended: report, for every candidate,
   (a) classical and quantum core-SVP for primal and simple dual (`coresvp.py`, kyber21 convention for
   Module-LWE, newhope/frodo convention for plain LWE), (b) the lattice-estimator's attacks at a pinned
   commit, including `dual_hybrid` and the primal hybrids, in both the core-SVP ("rough", RC.ADPS16) and the
   default (RC.MATZOV) models (`acs_estimator_run.py`, validated in Sec. 5.1; confirm once under real
   SageMath), and (c) the minimum over all attacks. Evidence: this is what Kyber, FrodoKEM and Saber did
   (Sec. 3, 5); the estimator README asks users to state the commit; pass 2 showed that (a) alone misses the
   cheapest attack whenever the secret is narrow (Sec. 7, T6).
2. **Target margins, not thresholds.** The published refined gate counts sit 30-34 bits above core-SVP but
   the Kyber team's own uncertainty is 2^-16 to 2^14 (NIST FAQ: 2^135 to 2^165 for Kyber512), and the best
   published dual-hybrid is 22 bits (core-SVP model) or 13.5 bits (RAM gates) below the primal attack on
   Kyber1024 (Sec. 4.3). A Turing lattice layer meant to be "harder to break" than ML-KEM-768 should reach
   ML-KEM-1024 / FrodoKEM-976 levels AFTER taking the minimum over all attacks, rather than aim at a category
   boundary with the primal figure alone.
2a. **A literature-backed lever: keep the secret wide.** The dual-hybrid and primal-hybrid attacks guess
   secret coordinates, so they profit from narrow secrets. In the estimator runs of pass 2 (T6), at n ~ 1000
   the dual-hybrid beats the primal attack by 6-14 bits (core-SVP model) when the secret's standard deviation
   is 1.4 or less (ternary, eta = 2, eta = 3, sigma 1.0, sigma 1.4), and loses to it by 4-5 bits when the secret
   has sigma 2.3-2.8 (FrodoKEM-style). Wide secrets also avoid the sparse/ternary attacks of Sec. 4.4. The
   price is decryption-failure margin and ciphertext size (sibling topics `decryption-failures.md`,
   `turing-integration-constraints.md`). This is a design choice with published support, not a new idea:
   FrodoKEM already uses sigma = 2.3-2.8 secrets.
3. **Two literature-backed ~1000-dimension baselines exist.** (i) Module-LWE rank 4, q = 3329, eta = 2:
   exactly ML-KEM-1024 (256 / 232 core-SVP, refined 287.3 gates). (ii) Plain LWE n = 976, q = 2^16,
   sigma = 2.3: exactly FrodoKEM-976 (216.0 / 196.7, refined 240.0 gates). Using them unmodified keeps every
   estimate in this note valid. Any Turing-specific variant can be positioned against these two with
   `coresvp.py table` (T1, T3).
4. **What "harder" can honestly mean.** Within standard LWE the levers are n (about +11 bits per +40 in
   n near 1000), sigma^2/q (T1 rule), and module rank. Each costs size, speed or decryption-failure
   margin. These gains are estimate-backed. Combining assumptions (lattice + X25519 in X-Wing, or MLWE +
   plain LWE) gives robustness against a break of one family; that is the hybrid-combiners topic.
5. **What adds risk.** (a) Narrow, ternary or sparse secrets (T2b, T6; Sec. 4.4: dual/primal hybrids, and
   practical GPU and machine-learning attacks on sparse secrets; 12 of 16 recent FHE parameter sets fall
   below their target under a 2026 ring-aware hybrid). (b) Hard-bounded tiny errors with many samples
   (Arora-Ge, Sec. 4.6). (c) New algebraic structure (other rings, structured matrices) outside what the
   estimators model (Sec. 4.7); even the standard power-of-two cyclotomic ring costs ML-KEM a measured 2-3
   bits against hybrids (Ogilvie 2026), and up to 15 bits for sparse-secret RLWE. (d) LWR-style
   deterministic noise relies on a heuristic (Sec. 7 T4); Kyber leaned on it for only 6 bits (Kyber spec
   PDF p. 13). (e) Homemade parameters without an estimator run. (f) Relying on a 1-bit margin: core-SVP
   itself moves by up to 1 bit between published scripts (Sec. 6.3, epsilon factor). Each of these would
   need its own cryptanalysis before Turing could claim a benefit.
6. **Testing hook.** `coresvp.py` and `acs_estimator_run.py validate` exit non-zero if any published number
   stops reproducing, so both can run in CI as regression tests of the estimation code (see
   `testing-ci-cd.md`); their negative controls show the checks are not vacuous. The estimator run needs the
   LGPL clone at a pinned commit, fetched at CI time rather than vendored.
7. **Quantum.** No confirmed polynomial-time quantum attack on LWE exists as of 2026-09-27; two 2026 claims
   (Simon: refuted by a formal no-go; Luo: unconfirmed) are listed in Sec. 8. The quantum core-SVP figure
   (0.265 b, or 0.2563 b for the best known exponent) is the right quantum number to report, with the note
   that concrete studies find it optimistic for the attacker. Robustness against a surprise lattice break
   comes from combining with a non-lattice KEM, not from parameter choice.
8. **Realistic cost vs comparison number.** Quote core-SVP to compare candidates (NIST: "mostly
   monotonically related" to real security) and say explicitly that realistic costs are higher: for
   Kyber512, 118 core-SVP vs ~147 RAM gates vs NIST's ~160 best guess with memory (Sec. 3.5).

## Sources

| file in research/papers/ or "online" | full reference | URL | used for |
|---|---|---|---|
| 2016-alkim-ducas-poppelmann-schwabe-newhope.pdf | E. Alkim, L. Ducas, T. Pöppelmann, P. Schwabe, Post-quantum key exchange - a new hope, USENIX Security 2016 | https://eprint.iacr.org/2015/1092 | core-SVP method, eq. (1), dual, Table 1 |
| 2021-avanzi-et-al-kyber-round3-specification.pdf | R. Avanzi et al., CRYSTALS-Kyber Algorithm Specifications and Supporting Documentation v3.02, 2021-08-04 | https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf | Table 4, Sec. 5.1-5.3 |
| 2019-avanzi-et-al-kyber-round2-specification.pdf | CRYSTALS-Kyber round-2 specification, 2019 | https://pq-crystals.org/kyber/ | round-2 Table 4 |
| 2021-alkim-et-al-frodokem-round3-specification-20210604.pdf | E. Alkim et al., FrodoKEM round-3 specification, 2021-06-04 | https://frodokem.org/files/FrodoKEM-specification-20210604.pdf | Sec. 5.2, Table 10 |
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | FrodoKEM Preliminary Standardization Proposal, revision 2025-09-29 | https://frodokem.org/ (site; local copy used) | Tables A.7, A.8 |
| 2019-alkim-et-al-newhope-round2-specification.pdf | E. Alkim et al., NewHope round-2 specification | https://newhopecrypto.org/ | Tables 12, 13 |
| 2020-danvers-et-al-saber-round3-specification.pdf | J.-P. D'Anvers et al., Saber round-3 specification | https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf | Tables 1-2, p. 12 |
| 2016-becker-ducas-gama-laarhoven-nearest-neighbor-lattice-sieving.pdf | A. Becker, L. Ducas, N. Gama, T. Laarhoven, New directions in nearest neighbor searching with applications to lattice sieving, SODA 2016 | https://eprint.iacr.org/2015/1128 | 0.292 |
| 2016-laarhoven-phd-search-problems-in-cryptography.pdf | T. Laarhoven, Search problems in cryptography, PhD thesis, Eindhoven University of Technology, 2016 (ISBN 978-90-386-4021-1) | local copy | 0.2653, Sec. 14.2.10 |
| 2021-chailloux-loyer-lattice-sieving-quantum-random-walks.pdf | A. Chailloux, J. Loyer, Lattice sieving via quantum random walks, ASIACRYPT 2021 | https://arxiv.org/abs/2105.05608 | 0.2570 |
| 2023-bonnetain-chailloux-schrottenloher-shen-reusable-quantum-walks.pdf | X. Bonnetain, A. Chailloux, A. Schrottenloher, Y. Shen, Finding many collisions via reusable quantum walks, EUROCRYPT 2023 | https://eprint.iacr.org/2022/676 | 0.2563 |
| 2025-improved-quantum-algorithm-3-tuple-lattice-sieving-arxiv-2510-08473.pdf | L. Engelberts, Y. Chen, A. S. Gilani, M.-I. van Hoof, S. Jeffery, R. de Wolf, An improved quantum algorithm for 3-tuple lattice sieving (version dated 2026-07-08) | https://arxiv.org/abs/2510.08473 | 0.2846 memory-limited |
| 2024-practicality-quantum-sieving-svp-arxiv-2410-13759.pdf | J. F. Doriguello, G. Giapitzakis, A. Luongo, A. Morolia, On the practicality of quantum sieving algorithms for the shortest vector problem (2025-02-19) | https://arxiv.org/abs/2410.13759 | concrete quantum cost |
| 2020-albrecht-gheorghiu-postlethwaite-schanck-quantum-speedups-lattice-sieves.pdf | M. Albrecht, V. Gheorghiu, E. Postlethwaite, J. Schanck, Estimating quantum speedups for lattice sieves, ASIACRYPT 2020 | https://eprint.iacr.org/2019/1161 | small quantum speedup |
| 2018-ducas-shortest-vector-sieving-dimensions-for-free.pdf | L. Ducas, Shortest vector from lattice sieving: a few dimensions for free, EUROCRYPT 2018 | https://eprint.iacr.org/2017/999 | d4f formula |
| 2015-albrecht-player-scott-concrete-hardness-lwe.pdf | M. Albrecht, R. Player, S. Scott, On the concrete hardness of Learning with Errors, JMC 2015 | https://eprint.iacr.org/2015/046 | delta(b) eq. (1), LLL 1.0219 (p. 8) |
| 2011-chen-nguyen-bkz-2-0.pdf | Y. Chen, P. Q. Nguyen, BKZ 2.0: better lattice security estimates, ASIACRYPT 2011 | local copy | BKZ background |
| 2017-albrecht-gopfert-virdia-wunderer-revisiting-usvp-cost.pdf | M. Albrecht, F. Göpfert, F. Virdia, T. Wunderer, Revisiting the expected cost of solving uSVP, ASIACRYPT 2017 | https://eprint.iacr.org/2017/815 | 2016 estimate validated |
| 2021-postlethwaite-virdia-success-probability-usvp-bkz.pdf | E. Postlethwaite, F. Virdia, On the success probability of solving unique SVP via BKZ, PKC 2021 | https://eprint.iacr.org/2020/1308 | probabilistic uSVP |
| 2020-dachman-soled-ducas-gong-rossi-lwe-side-information.pdf | D. Dachman-Soled, L. Ducas, H. Gong, M. Rossi, LWE with side information, CRYPTO 2020 | https://eprint.iacr.org/2020/292 | leaky-LWE-estimator |
| 2022-matzov-report-security-lwe-improved-dual-attack.pdf | MATZOV, Report on the security of LWE: improved dual lattice attack, 2022 | https://doi.org/10.5281/zenodo.6412487 | dual gate counts |
| 2023-ducas-pulles-does-dual-sieve-attack-work.pdf | L. Ducas, L. Pulles, Does the dual-sieve attack on LWE even work?, CRYPTO 2023 | https://eprint.iacr.org/2023/302 | critique |
| 2023-ducas-pulles-accurate-score-prediction-dual-sieve.pdf | L. Ducas, L. Pulles, Accurate score prediction for dual-sieve attacks, ePrint 2023/1850 | https://eprint.iacr.org/2023/1850 | follow-up |
| 2023-pouly-shen-provable-dual-attacks-lwe.pdf | A. Pouly, Y. Shen, Provable dual attacks on LWE, EUROCRYPT 2024 (ePrint 2023/1508) | https://eprint.iacr.org/2023/1508 | provable dual |
| 2025-qu-xu-provable-dual-attack-modulus-switching.pdf | H. Qu, G. Xu, On the provable dual attack for LWE by modulus switching, ePrint 2025/859 (ASIACRYPT 2025) | https://eprint.iacr.org/2025/859 | provable dual + mod switching |
| 2023-carrier-et-al-sparse-lpn-to-lpn-dual-attack-3.pdf | K. Carrier, T. Debris-Alazard, C. Meyer-Hilfiger, J.-P. Tillich, Reduction from sparse LPN to LPN, dual attack 3.0, ePrint 2023/1852 | https://eprint.iacr.org/2023/1852 | dual analysis (codes) |
| 2016-wunderer-revisiting-hybrid-attack.pdf | T. Wunderer, Revisiting the hybrid attack, ePrint 2016/733 | https://eprint.iacr.org/2016/733 | hybrid attack |
| 2021-may-how-to-meet-ternary-lwe-keys.pdf | A. May, How to meet ternary LWE keys, CRYPTO 2021 | https://eprint.iacr.org/2021/216 | ternary MITM |
| 2017-albrecht-dual-attacks-small-secret-lwe-helib-seal.pdf | M. Albrecht, On dual lattice attacks against small-secret LWE ..., EUROCRYPT 2017 | https://eprint.iacr.org/2017/047 | small secrets |
| 2012-albrecht-et-al-complexity-bkw-lwe.pdf | M. Albrecht, C. Cid, J.-C. Faugère, R. Fitzpatrick, L. Perret, On the complexity of the BKW algorithm on LWE | https://eprint.iacr.org/2012/636 | BKW samples |
| 2015-kirchner-fouque-improved-bkw-lwe.pdf | P. Kirchner, P.-A. Fouque, An improved BKW algorithm for LWE ..., CRYPTO 2015 | https://eprint.iacr.org/2015/552 | BKW |
| 2011-arora-ge-new-algorithms-learning-with-errors.pdf | S. Arora, R. Ge, New algorithms for learning in presence of errors, ICALP 2011 | local copy | Arora-Ge |
| 2024-chen-quantum-algorithms-lattice-problems.pdf | Y. Chen, Quantum algorithms for lattice problems, ePrint 2024/555 (revised 2024-04-19) | https://eprint.iacr.org/2024/555 | withdrawn claim |
| 2025-exact-coset-sampling-quantum-lattice-algorithms-arxiv-2509-12341.pdf | Y. Zhang, Exact coset sampling for quantum lattice algorithms, arXiv 2509.12341 (v8 2026-05-14) | https://arxiv.org/abs/2509.12341 | claimed fix |
| 2025-so-about-that-quantum-lattice-thing-eprint-2025-1945.pdf | D. Apon, So about that quantum lattice thing: rebuttal ..., ePrint 2025/1945 | https://eprint.iacr.org/2025/1945 | rebuttal |
| 2026-shortest-vector-q-ary-coset-difference-tree-arxiv-2609-02764.pdf | M. Hhan, Finding a shortest vector and more in 2^(n/2+o(n)) time ..., arXiv 2609.02764v1 | https://arxiv.org/abs/2609.02764 | new SVP claim (no impact) |
| nist-pqc-call-for-proposals-2016.pdf | NIST, Submission requirements and evaluation criteria for the PQC standardization process, 2016 | https://csrc.nist.gov/ | categories, gate counts |
| nist-pqc-call-additional-signatures-2022.pdf | NIST, Call for additional digital signature schemes, 2022 | https://csrc.nist.gov/ | revised quantum gate counts |
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, ML-KEM, 2024 | https://doi.org/10.6028/NIST.FIPS.203 | categories |
| nist-ir-8413-pqc-round3-report.pdf | NIST IR 8413-upd1, Status report on the third round | https://doi.org/10.6028/NIST.IR.8413-upd1 | NIST view of Kyber estimates |
| online (scratch clone) | malb/lattice-estimator, commit 53da598 (2026-08-19), LGPLv3+ | https://github.com/malb/lattice-estimator | reference tool, gate model |
| online (scratch clone) | pq-crystals/security-estimates, commits 71f89f3 (2019-03-21), 75c2694 (2021-03-16), no licence | https://github.com/pq-crystals/security-estimates | reference scripts, re-run |
| online (scratch clone) | lwe-frodo/parameter-selection, commit e09cf4b (2016-10-05), MIT | https://github.com/lwe-frodo/parameter-selection | Frodo convention |
| online | ePrint 2024/555 landing page (history) and arXiv 2509.12341 abstract page (version list), read 2026-09-27 | as above | dates, versions |
| 2025-carrier-meyer-hilfiger-shen-tillich-variant-matzov-dual-attack-kyber.pdf | K. Carrier, C. Meyer-Hilfiger, Y. Shen, J.-P. Tillich, Assessing the impact of a variant of MATZOV's dual attack on Kyber, CRYPTO 2025, pp. 444-476 (ePrint 2022/1750) | https://eprint.iacr.org/2022/1750 | dual attack without the independence assumption; Table 5.1 |
| 2026-ogilvie-concrete-hardness-gaps-lwe-mlwe.pdf | T. Ogilvie, On the concrete hardness gap between MLWE and LWE, ePrint 2026/279 (merged into CRYPTO 2026 "Careful with the Ring!") | https://eprint.iacr.org/2026/279 | MLWE-LWE gap, Tables 2-3 |
| 2026-hou-jiang-careful-with-the-ring-hybrid-decoding-module-ring-lwe.pdf | J. Hou, H. Jiang, Careful with the Ring: enhanced hybrid decoding attacks against Module/Ring-LWE, ePrint 2026/366 (full version (b) of the CRYPTO 2026 paper) | https://eprint.iacr.org/2026/366 | ring-structured hybrids, sparse secrets |
| 2026-li-wang-wang-provable-matzov-fft-dual-attack-ml-kem.pdf | J. Li, L.-P. Wang, H. Wang, A provable correctness analysis of the MATZOV-style FFT dual attack on ML-KEM, ePrint 2026/2166 | https://eprint.iacr.org/2026/2166 | provable dual 210/300/410 |
| 2026-li-wang-wang-provable-fft-dual-attack-general-dual-lattice.pdf | J. Li, L.-P. Wang, H. Wang, Provable FFT-accelerated dual attack on LWE using the general dual lattice, ePrint 2026/2186 | https://eprint.iacr.org/2026/2186 | provable dual 216/317/426 |
| 2026-wang-et-al-lams-layered-modulus-switching-provable-dual.pdf | R.-J. Wang, Z.-X. Wang, Q.-X. Zheng, X. Zhao, LaMS: a p-adic layered modulus switching for provable dual attacks on LWE, ePrint 2026/1326 | https://eprint.iacr.org/2026/1326 | provable dual |
| 2026-qu-et-al-provable-dual-attack-lattice-projection.pdf | H. Qu, C. Tian, G. Wang, G. Xu, Provable dual attack on LWE via lattice projection, ePrint 2026/2117 | https://eprint.iacr.org/2026/2117 | provable dual |
| 2026-li-zheng-covariance-score-distribution-dual-attack.pdf | Y. Li, Q. Zheng, Unified dual attack analyses: covariance-based score distribution prediction for LWE, ePrint 2026/1048 | https://eprint.iacr.org/2026/1048 | score models |
| 2026-li-zheng-modulus-switching-lossy-source-coding-dual.pdf | Y. Li, Q. Zheng, What happens when integrating modulus switching and lossy source coding, ePrint 2026/1400 | https://eprint.iacr.org/2026/1400 | dual variant; reference list (Ducas-Pulles JoC 2026) |
| 2026-bi-et-al-improved-hybrid-dual-sparse-secrets-fhe.pdf | L. Bi, Y. Liu, X. Lu, J. Luo, K. Wang, An improved hybrid dual attack on LWE with sparse secrets and its application to FHE, ePrint 2026/1060 | https://eprint.iacr.org/2026/1060 | sparse secrets |
| 2026-ling-yan-zhao-dual-attack-quantum-rejection-sampling.pdf | C. Ling, H. Yan, N. Zhao, Improved dual attack and trapdoor sampling via quantum rejection sampling, ePrint 2026/979 | https://eprint.iacr.org/2026/979 | quantum provable dual |
| 2022-ducas-hidden-overheads-bdgl-sieving.pdf | L. Ducas, Estimating the hidden overheads in the BDGL lattice sieving algorithm, PQCrypto 2022 (ePrint 2022/922) | https://eprint.iacr.org/2022/922 | 2^6 overhead |
| 2024-jaques-memory-adds-no-cost-lattice-sieving.pdf | S. Jaques, Memory adds no cost to lattice sieving for computers in 3 or more spatial dimensions, ePrint 2024/080 (IACR CiC 2024) | https://eprint.iacr.org/2024/080 | memory-cost estimates |
| nist-kyber512-faq.pdf | NIST, FAQ on Kyber512, December 2023 | https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/faq/Kyber-512-FAQ.pdf | NIST's gate and memory estimates |
| 2025-zhao-ding-yang-sieving-streamed-memory-access-slides.pdf | Z. Zhao, J. Ding, B.-Y. Yang, Sieving with streamed memory access (NIST 6th PQC conference slides, 2025) | https://csrc.nist.gov/ | downloaded, not used for numbers |
| 2026-simon-polynomial-time-quantum-dihedral-coset-problem.pdf | D. R. Simon, A polynomial-time quantum algorithm for the dihedral coset problem [preliminary draft, 2026-08-11], ePrint 2026/1591 | https://eprint.iacr.org/2026/1591 | 2026 quantum claim |
| 2026-gupte-ragavan-zhandry-eprint-2026-1591-does-not-solve-dcp.pdf | A. Gupte, S. Ragavan, M. Zhandry, The ePrint:2026/1591 quantum algorithm does not solve DCP, ePrint 2026/1693 | https://eprint.iacr.org/2026/1693 | no-go result |
| 2026-guo-yang-rigorous-lemmas-simon-dcp.pdf | Y. Guo, S. Yang, Rigorous statements and proofs of the lemmas in Simon's algorithm for the DCP, ePrint 2026/1714 | https://eprint.iacr.org/2026/1714 | missing hypothesis |
| 2026-luo-module-lattice-security-part-iv-arxiv-2605-17412.pdf | M.-X. Luo, Module lattice security (Part IV): probabilistic polynomial quantum attack on Module-LWE over 2-power cyclotomics, arXiv 2605.17412v2 | https://arxiv.org/abs/2605.17412 | unconfirmed claim |
| online (arXiv API) | M.-X. Luo, Module lattice security Parts I-III, arXiv 2604.15858, 2604.22900, 2605.17404 (abstracts) | https://arxiv.org/abs/2604.15858 | claim context |
| 2024-wenger-et-al-benchmarking-attacks-lwe-arxiv-2408-00882.pdf | E. Wenger et al., Benchmarking attacks on learning with errors, IEEE S&P 2025 (arXiv 2408.00882v2) | https://arxiv.org/abs/2408.00882 | sparse-secret attacks in practice |
| 2025-pulles-vie-gpu-primal-hybrid-sparse-lwe.pdf | L. N. Pulles, P. Vie, Accelerating the primal hybrid attack against sparse LWE using GPUs, ePrint 2025/1990 | https://eprint.iacr.org/2025/1990 | hybrid in practice |
| online (arXiv API) | C. Bassotto, E. Franch, M. Krcek, S. Picek, NoMod: a non-modular attack on Module Learning With Errors, arXiv 2510.02162 | https://arxiv.org/abs/2510.02162 | ML-based sparse-secret attack |
| online | TU Darmstadt SVP Challenge hall of fame, read 2026-09-27 | https://www.latticechallenge.org/svp-challenge/ | practical record (dimension 210) |
| online (scratch clone) | FrodoKEM parameter-selection pqsec.py, NewHope PQsecurity.py, pq-crystals MLWE_security.py (dual epsilon lines) | see above | epsilon factor |

## Claim ledger

Status: VERIFIED = read in the primary source; COMPUTED = derived here (script + command);
UNVERIFIED = not settled. "coresvp" = `python research/scripts/pq/coresvp.py` (validate),
"table" = `python research/scripts/pq/coresvp.py table`, both run 2026-09-27.

| # | claim | status | source |
|---|---|---|---|
| 1 | Kyber512/768/1024 core-SVP primal: d 999/1419/1885, b 406/626/878, classical 118/183/256, quantum 107/166/232 | VERIFIED | Kyber r3 spec Table 4, PDF p. 21 |
| 2 | Kyber refined: d 1025/1467/1918, b 413/637/894, b' 375/586/829, log2 gates 151.5/215.1/287.3, memory 93.8/138.5/189.7 bits | VERIFIED | Kyber r3 Table 4, PDF p. 21 |
| 3 | Kyber512 gate estimate is a 2^8 margin over 2^143; known unknowns up to 2^16 either way | VERIFIED | Kyber r3 PDF p. 27 |
| 4 | Kyber Q1-Q8 summary: between 2^-16 and 2^14 | VERIFIED | Kyber r3 PDF p. 30-31 |
| 5 | C = 1/(1 - 2^-0.292) = 5.46; C (n - b) ~ 3340; d4f(413) = 37.3; G = (1025 - 413) C^2 2^137.4 = 2^151.5 | VERIFIED | Kyber r3 PDF p. 27-28 |
| 6 | Our recomputation: C = 5.458, G = 2^151.55, d4f(413) = 37.30; SVP calls 2^11.7/12.1/12.4 | COMPUTED | coresvp (check 4); `python acs_rhf.py` |
| 7 | Primal success condition sigma sqrt(b) <= delta^(2b-d-1) q^(m/d), delta formula | VERIFIED | ADPS16 PDF p. 9 eq. (1); Kyber r3 PDF p. 26 eq. (9); FrodoKEM r3 PDF p. 42 eq. (7) |
| 8 | Dual: eps = 4 exp(-2 pi^2 tau^2), tau = l sigma / q, R = max(1, 1/(2^(0.2075 b) eps^2)) | VERIFIED | Kyber r3 PDF p. 26; ADPS16 PDF p. 9 |
| 9 | pq-crystals script uses eps without the factor 4 | VERIFIED | MLWE_security.py LWE_dual_cost (commit 75c2694) |
| 10 | Kyber dual core-SVP (script): b 403/620/868, m 512/650/838, C 117/181/253, Q 106/164/230, P 83/128/180; primal P 84/129/182 | VERIFIED (re-run) | Kyber.py re-run 2026-09-27, scratch attack-cost/kyber_rerun2.log |
| 11 | Kyber round-2 Table 4: primal (b, m, C, Q) 385/410/112/102, 625/655/182/165, 880/795/257/233; dual 380/455/111/100, 620/650/181/164, 870/795/254/230 | VERIFIED | Kyber r2 spec Table 4, PDF p. 25; 2019 script re-run se-2019b/run.log |
| 12 | "112 bits of core-SVP ... without the LWR assumption" for Kyber512; LWR adds 6 bits | VERIFIED | Kyber r3 PDF p. 13, p. 22; NIST IR 8413 PDF p. 38 |
| 13 | Fixed 2021 model gives 111 (b = 382) for Kyber512 with eta = 2 | COMPUTED | coresvp check 2 |
| 14 | pq-crystals commit 75c2694 (2021-03-16) added Kannan +1 and set m step to 1; 71f89f3 (2019-03-21) used step 5 | VERIFIED | git show in scratch clone |
| 15 | FrodoKEM Table 10 values (primal/dual C/Q/P for 640/976/1344) | VERIFIED | FrodoKEM r3 PDF p. 43; 2025 proposal Table A.7 PDF p. 17 |
| 16 | FrodoKEM refined log2 gates 175.1/240.0/305.4, memory 110.4/155.8/202.1 bits; within 16 bits either way for levels 1-2 | VERIFIED | FrodoKEM 2025 proposal Table A.8, PDF p. 18 |
| 17 | FrodoKEM counts b 2^(cb) cycles for plain LWE (footnote 7); msamp ~ n | VERIFIED | FrodoKEM r3 PDF p. 41 |
| 18 | m_max = n + 8 reproduces all of Table 10; n + 16 misses Frodo-640 dual C by 0.1 | COMPUTED | `python acs_frodo_msamp.py` |
| 19 | Practical sieve fit ~2^(0.405b+11) for b = 60..80; 2^20 margin at b = 80; 2^45 at b = 300 by extrapolation | VERIFIED | FrodoKEM r3 PDF p. 41 |
| 20 | NewHope r2 Table 12 values (NewHope512/1024, USENIX rows, BCNS) | VERIFIED | NewHope r2 spec PDF p. 34 |
| 21 | NewHope Table 13 (lwe-estimator): usvp/dec/dual 142/171/163 (512), 289/373/334 (1024) with 2^(0.292b+16.4) | VERIFIED | NewHope r2 PDF p. 35 |
| 22 | Saber core-SVP 118/189/260 C, 107/172/236 Q; estimators agree "up to small rounding differences"; gaps 2^25/2^18/2^12 to AES gates | VERIFIED | Saber r3 Table 1 PDF p. 11; PDF p. 12 |
| 23 | Our LWR estimate: 118/107, 189/171, 260/236 | COMPUTED | coresvp check 3 |
| 24 | All 11 published parameter sets reproduced exactly (Kyber r3, Frodo, NewHope, USENIX) | COMPUTED | coresvp check 1 |
| 25 | 8/8 negative controls fail; monotone in n, sigma, q | COMPUTED | coresvp checks 5-6 |
| 26 | Classical sieve 2^(0.292n+o(n)) | VERIFIED | BDGL16 PDF p. 1 |
| 27 | Quantum sieve (13/9)^(d/2+o(d)) ~ 2^(0.2653d+o(d)) | VERIFIED | Laarhoven thesis Sec. 14.2.10, PDF p. 198 |
| 28 | 2^(0.2570d+o(d)), QRAM 2^(0.0767d), qmem 2^(0.0495d) | VERIFIED | Chailloux-Loyer 2021 Thm. 1, PDF p. 3 |
| 29 | 2^(0.2563d+o(d)) | VERIFIED | Bonnetain et al. 2023 Prop. 4, PDF p. 27 |
| 30 | 3-tuple quantum sieve 2^(0.3098d) -> 2^(0.2846d), memory 2^(0.1887d) | VERIFIED | arXiv 2510.08473, PDF p. 1 |
| 31 | Dimension 400: ~10^13 physical qubits, ~10^31 years, about a 6 GHz core | VERIFIED | arXiv 2410.13759, PDF p. 1 |
| 32 | AGPS20: small quantum speedup under optimistic assumptions | VERIFIED | AGPS20 PDF p. 1 |
| 33 | d4f(b) = b ln(4/3) / ln(b/(2 pi e)) | VERIFIED | Ducas 2018 PDF p. 2; Kyber r3 PDF p. 28 |
| 34 | delta(b) exact limit and approximation (Chen 2013) | VERIFIED | APS15 eq. (1), PDF p. 9 |
| 35 | Exact vs approximate delta agree to 1e-4 of (delta - 1) for b >= 50; delta(406) = 1.003941 | COMPUTED | `python acs_rhf.py` |
| 36 | Kyber512 primal threshold flips between b = 405 and 406 at m = 486 | COMPUTED | `python acs_rhf.py`; `python coresvp.py example` |
| 37 | AES-128/192/256 = 2^143/2^207/2^272 classical gates; 2^170/2^233/2^298 / MAXDEPTH quantum (2016) | VERIFIED | NIST call 2016, PDF p. 18 |
| 38 | Revised quantum 2^157/2^221/2^285 / MAXDEPTH, classical unchanged (2022) | VERIFIED | NIST 2022 signature call, PDF p. 17 |
| 39 | ML-KEM-512/768/1024 = categories 1/3/5 | VERIFIED | FIPS 203 PDF p. 23 |
| 40 | MATZOV: Kyber 137.5/193.5/257.8, Saber 138.4/202.7/264.9, vs 143/207/272 | VERIFIED | MATZOV 2022 PDF p. 4 |
| 41 | MATZOV: ~430 vs ~3,500,000 gates per codeword at rank 400; ~6 bits | VERIFIED | MATZOV 2022 PDF p. 3 |
| 42 | NIST: all three Kyber sets "fall slightly below" targets when memory cost is ignored | VERIFIED | NIST IR 8413-upd1 PDF p. 38 |
| 43 | NIST: worst case may fall below in gate count but likely meets targets with realistic memory cost | VERIFIED | NIST IR 8413-upd1 PDF p. 37 |
| 44 | Ducas-Pulles 2023: dual-sieve-FFT success "presumably significantly overestimated" | VERIFIED | Ducas-Pulles 2023 PDF p. 1 |
| 45 | Pouly-Shen: provable dual attack costs "not competitive"; published Table 1 had wrong numbers, fixed in ePrint | VERIFIED | ePrint 2023/1508 PDF p. 1, p. 23 |
| 46 | (pass 2, revised) The best PROVABLE dual attacks on ML-KEM cost 210/300/410 bits or more, far above primal; the best heuristic dual attack that avoids the independence assumption (Carrier et al. 2025) is 139.5/195.1/259.7 in the RAM gate model, comparable to primal estimates in similar models. No dual attack is known to beat ML-KEM's category targets once memory is costed. | UNVERIFIED (absence part) | papers read: rows 87-92, 94-96; ePrint searches of 2026-09-27 found no counter-example; a full search of 2026 IACR venues was not done |
| 47 | lattice-estimator: Sage module, LGPLv3+, default RC.MATZOV + GSA, max_beta 1754 | VERIFIED | README, conf.py at commit 53da598 |
| 48 | Estimator Kyber512: usvp 2^143.8 (b 406, d 998), bdd 2^140.2, dual 2^149.9, dual_hybrid 2^139.7, bkw 2^178.8 with m 2^166.8; rough usvp 2^118.6, dual_hybrid 2^115.5 | VERIFIED | README at commit 53da598 |
| 49 | Our gates_nn reproduces RC.Kyber(500, 1024) = 176.55419197058822 and MATZOV Kyber512 usvp 143.77 | COMPUTED | coresvp check 4 |
| 50 | Estimator Arora-GB: n = 64, q = 7681, sigma = 3: 2^307.1 (m 2^46.8); UniformMod(7) errors: 2^60.6 (m 2^30.3) | VERIFIED | estimator/gb.py doctest, commit 53da598 |
| 51 | Kyber and FrodoKEM rule out BKW and linearization for lack of samples | VERIFIED | Kyber r3 PDF p. 25; FrodoKEM r3 PDF p. 41 |
| 52 | BKW beats lattice reduction from n ~ 250 only with unbounded samples | VERIFIED | Albrecht et al. 2012 PDF p. 1 |
| 53 | Arora-Ge: slightly subexponential for noise below sqrt(n) | VERIFIED | Arora-Ge 2011 PDF p. 1 |
| 54 | May 2021: ternary MITM ~S^0.25 asymptotically, ~S^0.3 for NTRU/NTRU Prime | VERIFIED | May 2021 PDF p. 1 |
| 55 | Albrecht 2017: HElib/SEAL 80-bit claims -> 62/68 bits | VERIFIED | ePrint 2017/047 PDF p. 1 |
| 56 | Wunderer: earlier hybrid analyses used probabilities as small as 2^-80 set to 1 | VERIFIED | ePrint 2016/733 PDF p. 1 |
| 57 | AGVW17 experiments support the ADPS16 uSVP condition | VERIFIED | AGVW17 PDF p. 1 |
| 58 | Chen 2024 bug note (Step 9; claim does not hold); ePrint received 2024-04-10, revised 2024-04-19 | VERIFIED | Chen PDF p. 1; ePrint 2024/555 page (online, 2026-09-27) |
| 59 | Zhang arXiv 2509.12341: v1 2025-09-15 ... v8 2026-05-14; access model, side information, AC1-AC5 | VERIFIED | arXiv abstract page (online); PDF p. 1 |
| 60 | Apon ePrint 2025/1945 rebuttal (2025-10-28) | VERIFIED | PDF p. 1 |
| 61 | Hhan arXiv 2609.02764v1 (2026-09-02): exact SVP 2^(n/2+o(n)), AI-assisted | VERIFIED | PDF p. 1 |
| 62 | No polynomial-time quantum LWE algorithm is confirmed as of 2026-09-27 (pass 2: two 2026 claims found, rows 97-99) | UNVERIFIED | absence claim; pass-2 searches of ePrint/arXiv on 2026-09-27 found the Simon and Luo claims and nothing else; re-check before quoting |
| 97 | Simon ePrint 2026/1591: claims poly-time quantum DCP, hence LWE with alpha = sqrt(n) polylog(n); draft dated 2026-08-11; received 2026-08-03; 4 revisions, last 2026-08-17; page notes a Lemma 3 error and the 2026/1693 counter-claim | VERIFIED | PDF p. 1; ePrint landing page (online, 2026-09-27) |
| 98 | Gupte-Ragavan-Zhandry ePrint 2026/1693: formal proof that the 2026/1591 algorithm cannot work (simulable from the top third of the Fourier labels up to poly(n) 2^(-n/3)); Lean 4 code | VERIFIED | PDF p. 1; `python eprint_meta.py 2026/1693` |
| 99 | Luo arXiv 2605.17412 v2 (2026-05-25): claims poly-time quantum attack on ML-KEM, gamma <= 21 for ML-KEM-1024; parts I-III 2604.15858, 2604.22900, 2605.17404 | VERIFIED (that the claim exists) / UNVERIFIED (its correctness) | arXiv API metadata and abstracts (2026-09-27); no primary-source confirmation or rebuttal found |
| 100 | Guo-Yang ePrint 2026/1714: one hypothesis of Simon's lemmas is not supplied by the algorithm | VERIFIED | PDF p. 1 |
| 101 | Ogilvie ePrint 2026/279: coefficient isometries give a ~2-3 bit MLWE-LWE gap for Kyber; up to 15 bits for sparse-secret RLWE; Table 2 C0/CC/CN 118.8/137.1/132.2, 170.2/192.7/186.9, 234.8/257.2/252.4 | VERIFIED | PDF p. 1, p. 30 (Table 2), p. 31 (Table 3) |
| 102 | 2026/279 and 2026/366 merged into CRYPTO 2026 "Careful with the Ring! Concrete Hardness Gaps Between LWE and MLWE", DOI 10.1007/978-3-032-35377-1_15 | VERIFIED | ePrint 2026/366 PDF p. 1 (header note) |
| 103 | Hou-Jiang 2026/366: enhanced hybrid decoding; up to 13 bits on FHE sets; 12 of 16 below 128 bits; 17x-114x faster than [KKN+26] on broken instances | VERIFIED | PDF p. 1 |
| 104 | Wenger et al. (S&P 2025): Kyber-like (kappa = 2) sparse binomial secrets of weight 9-11 recovered in 28-36 h (SALSA, Cool & Cruel); MitM decision-LWE up to weight 4 in < 1 h; uSVP nothing in > 1100 h | VERIFIED | arXiv 2408.00882v2 abstract (arXiv API, 2026-09-27) |
| 105 | Pulles-Vie ePrint 2025/1990: GPU Guess+Verify beats Cool & Cruel on almost all Wenger et al. instances | VERIFIED | PDF p. 1 |
| 106 | Bassotto et al. arXiv 2510.02162: sparse-secret recovery for Kyber-like (128, 3), (256, 2); binary secrets n = 350 | VERIFIED | arXiv abstract (API, 2026-09-27) |
| 107 | Estimator docs: Kyber768 bdd 2^201.0 (beta 606, eta 640, d 1420); Kyber1024 bdd 2^270.7 (855, 889, 1867); LightSaber bdd 2^139.9 | VERIFIED | docs/schemes/nist-pqc-round-3.rst, commit 53da598 |
| 108 | Best published dual-hybrid vs primal gap: C0 3.3/12.9/22.0 bits, RAM 3.1/8.3/13.5 bits for Kyber512/768/1024; best dual CC minus NIST -5.9/-14.3/-14.8 | COMPUTED | `python acs_dual_vs_primal.py` (inputs rows 1, 88, 101, 107) |
| 109 | The unmodified lattice-estimator (53da598) run through acs_sage_shim reproduces all 10 published reference outputs (rop to 0.05 bits, identical beta/eta/d); both negative controls fail | COMPUTED | `python acs_estimator_run.py validate` (logs attack-cost/estimator_validate.run2.log, run3.log after shim fixes) |
| 110 | Estimator (shim) Kyber1024: rough dual_hybrid 2^241.8 and full dual_hybrid 2^262.3, equal to the MATZOV C0 241.8 and within 0.1 of CC 262.4 printed by Carrier et al. from [AS22] | COMPUTED vs VERIFIED | estimator_turing_main.log; ePrint 2022/1750 Table 5.1 PDF p. 27 |
| 111 | Estimator (shim) on ~1000-dim candidates, non-hybrid attacks (T6 rows) | COMPUTED | `ACS_ATTACKS=... python acs_estimator_run.py turing`, log attack-cost/estimator_turing_main.log |
| 112 | Estimator rough usvp equals coresvp.py's primal core-SVP within 0.1-1.6 bits on every T6 row (GSA vs q-ary profile explains the MLWE rows) | COMPUTED | T6 vs `python coresvp.py table` |
| 63 | T0: MATZOV-model gates at our (b, d): 143.8/205.5/276.2 (Kyber), 166.2/228.4/291.2 (Frodo); refined - core = 30.5-33.7 | COMPUTED | table (T0) |
| 64 | T1 rows as tabulated in Sec. 7; sigma^2/q invariance at n = 1024 (229.0-229.6) | COMPUTED | table (T1) |
| 65 | T2 minimum sigma values | COMPUTED | table (T2) |
| 66 | T2b narrow-secret costs (249.2 -> 214.1 for sigma_s 0.816) | COMPUTED | table (T2b) |
| 67 | T3 Module-LWE rank 4 values; eta 2 -> 3 adds 13.7 bits at q = 3329 | COMPUTED | table (T3) |
| 68 | T4 Module-LWR values | COMPUTED | table (T4) |
| 69 | T5 quantum constant sensitivity 232.9/225.6/225.0/182.2 | COMPUTED | table (T5) |
| 70 | ~+11.4 bits per +40 in n near n = 1000 (q = 2^15, sigma = 2.8) | COMPUTED | coresvp check 6 (242.5 at 1000, 253.9 at 1040) |
| 71 | pq-crystals security-estimates has no licence file | VERIFIED | scratch clone listing + README content (commit 75c2694); GitHub licence field not checked online |
| 72 | lwe-frodo/parameter-selection is MIT | VERIFIED | LICENSE.txt, README in scratch clone |
| 73 | GSA "misses a 'tail' phenomenon"; dual "significantly more expensive" than core-SVP suggests | VERIFIED | Kyber r3 PDF p. 28 |
| 74 | Sieving beats enumeration from about dimension 80 | VERIFIED | Kyber r3 PDF p. 25, 27 |
| 75 | The lattice-estimator was not run (SageMath absent on Windows and WSL Ubuntu) | VERIFIED | `import sage` fails on both, 2026-09-27 |
| 76 | Saber rounding error std sqrt(((2^13/2^10)^2 - 1)/12) = 2.2913, matching the estimator's "sigma = 2.29" for Saber | COMPUTED / VERIFIED | coresvp check 3; docs/schemes/nist-pqc-round-3.rst (commit 53da598) |
| 77 | Kyber ciphertext-rounding heuristic "e' is independent of s and e" (footnote 4) | VERIFIED | Kyber r3 PDF p. 22 |
| 78 | FrodoKEM 2025 proposal repeats Table 10 as Table A.7 | VERIFIED | FrodoKEM 2025 proposal PDF p. 17 |
| 79 | Printed dual advantage: eps = 4 exp(-2 pi^2 tau^2) (ADPS16, Kyber r3); eps = 2 exp(...) (FrodoKEM r3) | VERIFIED | ADPS16 PDF p. 9; Kyber r3 PDF p. 26; FrodoKEM r3 PDF p. 43 |
| 80 | Scripts: NewHope PQsecurity.py and pq-crystals MLWE_security.py use eps = exp(...); FrodoKEM pqsec.py uses log2 eps = 2 + ... (eps = 4 exp) | VERIFIED | PQsecurity.py line 52; MLWE_security.py line 37; pqsec.py line 133 (scratch clones) |
| 81 | FrodoKEM Table 10 dual rows match F = 4, not the printed F = 2 (which gives 149.9/214.8/280.1 classical) | COMPUTED | `python coresvp.py eps` (E2), log scratch attack-cost/coresvp_eps.log |
| 82 | F = 1 -> 4 lowers dual core-SVP by 0.59-0.89 bits (Kyber, NewHope, FrodoKEM, n = 1024 LWE) | COMPUTED | `python coresvp.py eps` (E1) |
| 83 | Formulas as printed (adps16) move published values by <= 1 bit (Kyber1024 primal 255 vs 256) | COMPUTED | `python coresvp.py eps` (E3) |
| 84 | pq-crystals Kyber.py re-run (pass 2) output identical to pass 1; sample counts equal coresvp's m | COMPUTED | scratch attack-cost/kyber_rerun3.log; coresvp validate log run3 |
| 85 | lattice-estimator HEAD on 2026-09-27 is 53da598 (2026-08-19); licence LGPLv3+ stated in README.rst line 181, no LICENSE file (GitHub licence field null) | VERIFIED | `gh api repos/malb/lattice-estimator/commits`; README.rst in clone |
| 86 | pq-crystals/security-estimates: GitHub licence field null; last push 2021-03-16 (75c2694) | VERIFIED | `gh api repos/pq-crystals/security-estimates` (2026-09-27) |
| 87 | Carrier et al. dual attack avoids the flawed independence assumption; uses a new heuristic backed by experiments | VERIFIED | ePrint 2022/1750 (CRYPTO 2025) PDF p. 1, p. 5 |
| 88 | Carrier et al. Table 5.1: Kyber-512/768/1024 C0/CC/CN = 121.8/139.5/134.5, 173.0/195.1/189.8, 239.0/259.7/254.6; MATZOV per [AS22] 115.4/139.2/134.4, 173.7/196.1/190.6, 241.8/262.4/256.1; "3.5/11.9/12.3 bits below" 143/207/272 | VERIFIED | ePrint 2022/1750 PDF p. 27 (Table 5.1), p. 1 |
| 89 | Carrier et al.: CC ignores memory cost; no comparison with primal attacks | VERIFIED | ePrint 2022/1750 PDF p. 25-26 |
| 90 | Ducas 2022: real BDGL costs about 2^6 more gates than the idealised model near dimension 380 | VERIFIED | ePrint 2022/922 PDF p. 1 |
| 91 | Provable MATZOV-style dual (ePrint 2026/2166): 210/300/410 bits for ML-KEM-512/768/1024, 28/47/68 below Pouly-Shen | VERIFIED | ePrint 2026/2166 PDF p. 1 (preprint, received 2026-09-23) |
| 92 | ePrint 2026/2186: 216/317/426 bits; 2026/1326 LaMS: -22/-31/-41 vs corrected Qu-Xu; 2026/2117: -26.1 to -43.7 bits; 2026/979: -9/-4/-13 vs Pouly-Shen | VERIFIED | each paper PDF p. 1; dates via `python eprint_meta.py` |
| 93 | Ducas-Pulles accurate score prediction published in J. Cryptology 39(1), 2026 | UNVERIFIED | only seen in the reference list of ePrint 2026/1400 (PDF p. 17); settle on the Springer page |
| 94 | NIST Kyber512 FAQ (Dec 2023): 2^151 best attack; Q1-Q8 range 2^135-2^165; MATZOV 2^137 questioned; ~6 of 14 bits independent; estimator bdd 2^142.2 at commit 564470e; hidden overhead 2^5 (2^3 with 2^10 more memory); max category-1 memory 2^96.5 bits; best RAM estimate ~2^147 (2^145) | VERIFIED | nist-kyber512-faq.pdf PDF p. 1-3 |
| 95 | NIST FAQ: core-SVP 2^118 "should not be interpreted as concrete gate counts"; memory exponents 0.349/0.3294/0.3198 (k = 1/2/3), naive gains 21/14/10 bits; best guess ~2^160, range 2^140-2^180 | VERIFIED | nist-kyber512-faq.pdf PDF p. 3-5 |
| 96 | Jaques 2024: 2^(0.2925d+o(d)) in 3 spatial dimensions, 2^(0.3113d+o(d)) in 2; Kyber primal with memory 158.7/229.9/310.2 (+7.2/+14.8/+22.9 over the spec) | VERIFIED | ePrint 2024/080 PDF p. 1; Table 1 PDF p. 17 |

## Open questions

1. **Re-run the lattice-estimator under real SageMath.** Pass 2 ran it through `acs_sage_shim` (validated
   on the 10 published reference outputs, Sec. 5.1). Still open: the primal-hybrid attacks (too slow under
   mpmath for n ~ 1000 in this session), Arora-Gröbner (not supported by the shim), and one confirmation
   run of the final Turing parameter set under SageMath (conda-forge `sage` in WSL, or the estimator's
   docker image), which needs a large download the owner must approve.
2. **Dual attacks.** Pass 2: the Carrier et al. (CRYPTO 2025) analysis avoids the flawed independence
   assumption but still rests on a new, experimentally supported heuristic; provable versions are 70+ bits
   more expensive. Open: will the heuristic hold at cryptographic sizes, and what is the dual-hybrid cost
   for WIDE secrets (sigma >= 2) under Carrier-style analysis? The estimator's MATZOV-style dual_hybrid finds
   no gain over primal for sigma 2.3-2.8 (Sec. 7, T6). Until settled, report min over all attacks and keep
   a margin that absorbs the 22-bit (C0) / 13.5-bit (RAM) gap seen for Kyber1024.
3. **Memory-aware cost models.** NIST's Kyber512 FAQ gives a best guess (~2^160 with memory cost, range
   2^140-2^180) and Jaques 2024 gives +7 to +23 bits for Kyber, but no agreed model exists. A Turing design
   should state which model its margins use and quote core-SVP as the primary comparison number.
4. **LWR heuristic.** If Turing uses rounding instead of sampled noise, the rounding-as-noise estimate is a
   heuristic (T4). Is there a reduction-backed parameter regime at ~1000 dimensions? (lattice-foundations
   topic.)
5. **Claim 46 and 62 are absence claims.** Re-check them with a dated literature search before they are
   quoted in a design document.
6. **NewHope512 label typo** (Sec. 6.3): pass 2 confirmed from the PDF's text layer that the row label
   reads "NewHope512: q = 12289, n = 1024" (PDF p. 34); it is a typo in the spec, harmless for the numbers.
7. **The 2026 quantum claims.** Watch for Simon's response to ePrint 2026/1693 (the ePrint page says he
   is evaluating it) and for any expert assessment or peer-reviewed publication of Luo's arXiv series.
   Neither is accepted today; both would matter to every lattice scheme, not only to Turing.
8. **MLWE vs plain LWE.** Ogilvie's 2-3 bit gap uses power-of-two cyclotomic isometries. Is the gap larger
   against a primal hybrid, or for other rings? Settles whether plain LWE's "no ring" argument is worth
   more than a few bits for Turing.
