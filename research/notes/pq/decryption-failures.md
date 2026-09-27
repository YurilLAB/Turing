# Decryption failures in lattice KEMs: computing the rate and the attacks that use it

This file covers why lattice KEMs can fail to decrypt, how the decryption-failure rate (DFR) is
computed exactly, how the published DFRs of ML-KEM (FIPS 203) and FrodoKEM are reproduced by
`research/scripts/pq/dfr.py` and cross-checked against the designers' own scripts, the gap
between the published (heuristic) ML-KEM DFRs and what has been proven (reproducing the formally
verified bounds of Barbosa et al., CCS 2025), the attacks that exploit failures (failure
boosting, directional and multi-target boosting, timing and fault attacks that create a failure
oracle), what DFR the specifications and NIST treat as safe and why, error-correcting codes and
redundant encodings and their pitfalls, and what DFR a ~1000-dimension Turing design should
target. Date checked: 2026-09-27. Every number is in the claim ledger with its status; the quoted
VERIFIED claims are re-checked against the PDFs by `research/scripts/pq/dfr_verify_sources.py`
(133 checks, all PASS).

How to re-run everything (all deterministic, each prints PASS/FAIL where there is a target):
`timeout 600 python research/scripts/pq/dfr.py validate JSON`, `... dfr.py provable`,
`... dfr.py simulate`, `... dfr.py weakkeys 1000 SEED`, `... dfr.py boost`, `... dfr.py sweep`,
`timeout 900 python research/scripts/pq/dfr_run_frodo_script.py PSS_DIR`,
`timeout 600 python research/scripts/pq/dfr_worked_example.py`,
`timeout 60 python research/scripts/pq/dfr_fo_bound_terms.py`,
`timeout 300 python research/scripts/pq/dfr_verify_sources.py`,
`timeout 400 python research/scripts/pq/dfr_perfect_correctness.py`,
`timeout 300 python research/scripts/pq/dfr_uniform_twist.py` (JSON and PSS_DIR: section 3).

## Key findings

1. **The DFR is computed exactly, not estimated.** The decryption error is a sum of products of
   small independent integers; its law is built by convolution and the message failure rate is
   bounded by the union bound (no independence needed). `dfr.py` reproduces FIPS 203 Table 1
   (2^-138.8 / 2^-164.8 / 2^-174.8) to 0.04 bit and FrodoKEM's published rates (2^-138.7 /
   2^-199.6 / 2^-252.5) at the published precision, and agrees with the designers' own scripts
   (pq-crystals law to 2.7e-10 relative; FrodoKEM's official function to 4 decimals). Negative
   controls move the values by tens of bits. (Sections 2-3.)
2. **Both published figures are slightly conservative, for reasons the prose hides.** ML-KEM's
   uses |err| >= 832 where bit-0 decoding really fails at 833 (the pq-crystals script's
   Python-2 integer division); FrodoKEM's code folds x to min(x, q-x), i.e. a symmetric test, while its
   specification states the asymmetric window. Exact rates are 0.1-0.35 bit (ML-KEM) and
   0.03-0.11 bit (FrodoKEM) lower. The pq-crystals script run under Python 3 today prints values
   0.3-0.4 bit lower than FIPS 203. (Section 3.)
3. **A Gaussian approximation is not acceptable.** With the same variance it is wrong by up to
   84 bits for ML-KEM-768 (too pessimistic, because the dominant rounding error is bounded) and
   up to 16 bits for FrodoKEM (too optimistic, because products have heavy tails). (Section 2.)
4. **ML-KEM's published DFR rests on one heuristic; the best proven bound is far weaker.** The
   ciphertext rounding errors are treated as independent uniform noise. A formally verified
   (EasyCrypt) analysis, Barbosa et al. (ACM CCS 2025), confirms the heuristic numbers are computed
   correctly, but its heuristic-free bound is only 2^-80 for ML-KEM-768 and 2^-95 for ML-KEM-1024
   (Table 1); it calls proving that the heuristic applies to ML-KEM "an open problem". FrodoKEM's
   2^-138 / 2^-199 / 2^-252 are proven in the same work, because FrodoKEM does not compress
   ciphertexts. `dfr.py provable` reproduces all six of that paper's ML-KEM numbers. Toy
   Monte-Carlo runs support the heuristic, and a September-2026 preprint claims a dependency-aware
   2^-164.81 for ML-KEM-768 (unreviewed). (Sections 2, 4.6.)
5. **Failures leak the key, and the FO transform does not stop that.** A failing honest
   ciphertext is a linear hint about the secret; a few dozen failures break Kyber-like schemes
   (PKC 2019 Table 1: 42 failures for round-1 Kyber768). Failure boosting (PKC 2019), directional
   boosting (EUROCRYPT 2020: after the first failure the rest are "essentially for free") and
   levelled multi-target attacks (PKC 2022) mean the design rule is: **make even one failure
   infeasible to find.** (Section 4.)
6. **The DFR relative to the claimed level is what matters.** Saber (DFR 2^-136 at category 3)
   is "theoretically vulnerable" to a multi-target failure attack at 2^145 work against a claimed
   2^172; Kyber768 (2^-164.8) and Kyber1024 are not, Kyber1024 only because its 2^256 message
   space caps the ciphertexts per key. (Section 4.3.)
7. **Two published philosophies for the target.** Kyber/ML-KEM: DFR need not shrink with the
   security level; below about 2^-160 it is excluded from the claims (information-theoretic
   argument plus the 2^64-query limit). FrodoKEM and HQC: DFR about 2^-lambda for lambda-bit
   security; NIST IR 8545 (2025) states the FO transform needs a delta-correct PKE with
   delta <= 2^-lambda and made HQC's stable DFR analysis the decisive factor over BIKE. ML-KEM-768
   and ML-KEM-1024 do not meet 2^-lambda (27.2 and 81.2 bits short); FrodoKEM-1344 is 3.5 bits
   short, which its designers argue is covered. (Section 5.)
8. **Implementation leaks turn failures into an oracle.** A non-constant-time FO comparison gave
   full FrodoKEM key recovery with about 2^30 decapsulations (CRYPTO 2020); Rowhammer during key
   generation made failures frequent enough for key recovery (CCS 2022). A 2026 preprint turns
   wolfSSL's incomplete FO ciphertext comparison (1536 of 1568 bytes checked) into ML-KEM-1024
   key recovery with a few hundred ciphertexts. Constant-time comparison of every byte, no
   observable failure signal, and a key-generation integrity check are required.
   (Section 4.5; details belong to the side-channel sibling topic.)
9. **Error-correcting codes lower the DFR on paper but add three documented risks**: failure
   dependence (LAC-128's real failure rate up to 2^48 times the independence estimate), decoder
   timing (LAC and Ramstake keys recovered in under 2 minutes, LAC with fewer than 2^16 queries),
   and structural preconditions (Round5's XEf needed a different ring and balanced secrets). No
   NIST-standardised lattice KEM uses one. (Section 6.)
10. **For a ~1000-dimension Turing layer** the evidence supports targeting delta <= 2^-lambda
    (below 2^-256 for a 256-bit claim), computed exactly with the conservative rule, with no error
    correcting code, and **met by a proven bound, not only the heuristic one**. At dimension 1024
    with q = 3329 and CBD(2) noise this is not reachable even without ciphertext compression
    (2^-231.0); it needs less noise or a larger q. Example (COMPUTED): q = 7681, eta 2, du 11, dv 5
    has heuristic DFR 2^-615 and a Barbosa-style proven bound 2^-320.6. Each such change alters the
    lattice security that the sibling topic *attack-cost-estimation* must re-estimate. This is a
    measurable way to be more conservative than ML-KEM-1024, grounded in FrodoKEM, HQC, NIST IR
    8545 and Barbosa et al. (Sections 5, 7.)
11. **Failure boosting erodes a small margin, not a large one.** A norm-selection boosting model
    (`dfr.py boost`, bracketed estimate) puts the quantum cost of a first failure about 4 to 9 bits
    below 1/DFR for ML-KEM-768/1024 and about 11 to 19 bits below for a DFR of 2^-231, so a
    2^-lambda DFR alone does not make a first failure cost 2^lambda. At DFR 2^-615 the first
    failure still costs more than 2^570. Under NIST's 2^64 decryption-query limit the attack
    does not apply: even keeping only 2^-320 of all ciphertexts, no parameter set here reaches a
    per-query failure probability above 2^-112, far from the 2^-64 needed. (Section 4.2.)
12. **The per-key DFR spreads widely.** For ML-KEM-768, 2000 random keys give a per-key DFR
    median 2^-175.1 (95% CI of each 1000-key median within [-175.7, -174.3]) with a standard
    deviation of 5.8 bits; the heaviest key seen was 2^-156.5. The average (2^-165.1) is set by
    rare heavy keys. (Section 2, step 5.)
13. **Zero DFR is a real option, at a price in q.** Every noise term is bounded, so an ML-KEM-style
    scheme of dimension 1024 with CBD(2) noise and no ciphertext compression never fails once
    q >= 32778 (ternary noise: q >= 8198); with du = 11 compression no q works. This is the
    NTRU / NTRU Prime choice, it removes the whole failure-attack class, and its cost is lattice
    security at fixed dimension, for *attack-cost-estimation* to quantify. (Section 7.)
14. **A noise "twist" can destroy correctness while looking like a hardening.** Replacing Kyber's
    centred binomial noise by the uniform law over the same range makes LWE harder but moves the
    DFR from 2^-139..2^-175 to 2^-25.4..2^-50.3; a preprint recovers the uniform-Kyber512 key
    from 3,000 failures at about 2^37 work (Shao et al., ePrint 2024/1979; all six DFRs
    reproduced by `dfr_uniform_twist.py`). Every change to the noise, encoding or compression
    needs a fresh exact DFR before anything else. (What this means for Turing, item 5.)

## 1. Why a lattice KEM can fail to decrypt

**The mechanism.** In LWE-style encryption the receiver never sees the message alone. It computes
"encoded message + small error" modulo q and rounds to the nearest valid code point. The error is
built from the secret key and the sender's randomness. If the error is too large, rounding picks
the wrong code point: that is a decryption failure.

**ML-KEM (FIPS 203) in symbols.** Key generation makes `t = A s + e`. Encryption with randomness
`r, e1, e2` makes `u = A^T r + e1` and `v = t^T r + e2 + Decompress_1(m)`, then compresses both
(`Compress_du`, `Compress_dv`). Compression is rounding to fewer bits, so the receiver gets
`u' = u + cu` and `v' = v + cv`, where `cu, cv` are rounding errors. Decryption computes

    w = v' - s^T u' = Decompress_1(m) + [ e^T r + e2 + cv - s^T (e1 + cu) ]

(algebra: `t^T r = s^T A^T r + e^T r` and the `s^T A^T r` terms cancel). The bracket is the
decryption error. Each message bit sits in one of the n = 256 coefficients. Bit 0 is encoded as 0
and bit 1 as `Decompress_1(1) = 1665`; `Compress_1` then asks "is w closer to 0 or to q/2?".
With q = 3329, bit 0 decodes correctly exactly when the centred error satisfies |err| <= 832
(computed in `dfr.py`, function `mlkem_coeff_failure`).

**FrodoKEM.** Plain (unstructured) LWE with matrices. Decryption gives
`M = Encode(mu) + E'''` with `E''' = S'E + E'' - E'S`; each entry of `E'''` is a sum of 2n products
of two error samples plus one more sample (round-3 spec section 2.2.7, PDF page 19). Each entry
carries B bits; Lemma 2.18 (PDF page 18) says an entry decodes correctly when its error lies in
`[-q/2^(B+1), q/2^(B+1))`. With q = 2^16 and B = 3 that half-width is 4096.

**Why schemes accept a non-zero DFR.** The Kyber round-3 specification ("Allowing decapsulation
failures", PDF page 13) states the trade-off: zero failure probability makes CCA transforms and
proofs easier, but requires either much less noise (weaker against lattice attacks) or a larger
dimension (slower, bigger). The designers chose a tiny non-zero rate, judging that attacks on
extremely rare failures are "a much smaller threat" than, for example, hybrid attacks on very
low-noise schemes. (NTRU and NTRU Prime chose perfect correctness instead; NIST IR 8413, PDF
pp.47 and 49.)

**The four knobs.** For a fixed dimension the DFR is controlled by (i) the noise width of s, e, r,
e1, e2 (wider noise: harder LWE, more failures); (ii) q (larger q: fewer failures, but a larger
q/noise ratio weakens LWE, and ciphertexts grow); (iii) compression du, dv (fewer bits: smaller
ciphertexts, more rounding noise, more failures); (iv) bits per coefficient B (more bits: more
throughput per coefficient, a narrower decoding window). Section 7 gives computed trade-offs at a
~1000-dimension point; the security side of that trade-off belongs to *attack-cost-estimation*.

## 2. Computing the DFR exactly

**Step 1: the law of one product.** If X and Y are independent small integers, then
`P(XY = z) = sum over a*b = z of P(X=a) P(Y=b)`. Worked example (script
`research/scripts/pq/dfr_worked_example.py`, all values exact fractions): CBD(2) has
P(0) = 3/8, P(+-1) = 1/4, P(+-2) = 1/16; the product of two CBD(2) values has
P(0) = 39/64, P(+-1) = 1/8, P(+-2) = 1/16, P(+-4) = 1/128.

**Step 2: the law of a sum.** The law of a sum of independent terms is the convolution of their
laws. Summing N copies is done by repeated squaring (about log2 N convolutions). In the worked
example, `e = a1 b1 + ... + a4 b4 + c` (all CBD(2)) has support -18..18 and variance 5, and the
convolution result equals exhaustive enumeration of all 5^9 = 1,953,125 inputs exactly.

**Step 3: tail sum and union bound.** The per-coefficient failure probability is the probability
mass outside the decoding window. The message fails if any coefficient fails; the union bound
`P(any fails) <= sum of P(coefficient i fails)` holds with no independence assumption. In the
worked example with threshold 10: per coefficient 2.011e-4; eight coefficients 8p = 1.608e-3
(if independent, 1 - (1-p)^8 = 1.607e-3). Independence only matters when a scheme needs
"at least k failing coefficients", which is exactly the error-correcting-code case (section 6).

**Why not a Gaussian approximation.** A Gaussian with the same variance can be wrong by many bits,
in either direction (COMPUTED, `dfr.py validate`, section VALIDATE 3). The Gaussian column uses a
continuity correction: the tail beyond 832.5 for ML-KEM and beyond h - 0.5 for FrodoKEM
(h = q/2^(B+1)). The "exact" column is the floor rule for ML-KEM and the exact decode window for
FrodoKEM. An independent fact-check that put the Gaussian threshold at 832 or at h got values
within 0.2 bit of these (e.g. 2^-75.78 instead of 2^-75.88); the conclusion does not depend on the
convention.

| scheme | Gaussian with same variance | exact | direction |
|---|---|---|---|
| ML-KEM-512 | 2^-75.88 | 2^-138.77 | Gaussian far too pessimistic |
| ML-KEM-768 | 2^-81.18 | 2^-164.81 | Gaussian far too pessimistic |
| ML-KEM-1024 | 2^-145.63 | 2^-174.76 | Gaussian too pessimistic |
| Frodo-640 | 2^-148.80 | 2^-138.76 | Gaussian too optimistic |
| Frodo-976 | 2^-213.19 | 2^-199.60 | Gaussian too optimistic |
| Frodo-1344 | 2^-268.24 | 2^-252.61 | Gaussian too optimistic |

Reason. In ML-KEM-512/768 most of the variance comes from `cv`, the rounding error of dv = 4
bits, which is bounded (|cv| <= about q/32 = 104), so the true tail is much lighter than a
Gaussian's. In FrodoKEM the error is a sum of products, and products of two Gaussian-like values
have heavier-than-Gaussian tails. In the worked example the Gaussian is too optimistic by 1.5 to
5.6 bits for thresholds 8 to 12. A 2026 preprint makes the same point for schemes with lattice
codes and reports that a refined method moves CNTR-Prime's DFR bound "at least 84 bits"
upwards (Zhou et al., ePrint 2026/1350, abstract; preprint, not reproduced here).

**Step 4: the independence heuristic (ML-KEM only).** The terms e, r, s, e1, e2 are independent
samples, so their products and sums are handled exactly. The rounding errors `cu, cv` are not
independent samples: they are deterministic functions of the ciphertext. Kyber's analysis (and
the pq-crystals script) models each rounding error as independent, with the law of the rounding
error of a uniform element of Z_q. FrodoKEM has no compression of this kind, so its computation
needs no heuristic. `dfr.py simulate` tests the heuristic on toy versions of ML-KEM with large
eta (so failures are frequent enough to count), a real uniform A and the exact FIPS 203
Compress/Decompress: observed wrong bits vs the per-key model gave z = -0.52, +0.51, -1.07 for
three toys, and z = -0.64, -0.40 for two FrodoKEM-like toys (re-run 2026-09-27). This supports,
but cannot prove, the heuristic at real parameters, where failures are too rare to observe.

**Step 5: average key versus a fixed key.** FIPS 203 defines the failure probability over random
seeds d, z (key generation) and m (encapsulation) (section 3.2, PDF page 24): an average over
keys. An attacker faces one fixed key. `dfr.py weakkeys` computes the DFR of individual keys.
Under the compression heuristic this is exact given the key: for a fixed (s, e), coefficient i of the error
is a sum of independent terms e_j * r_(i-j) and s_j * (e1 + cu)_(i-j), so its law depends only on
how many key coefficients have each absolute value. Two independent runs of 1000 random keys
(seeds 7 and 20260927; `timeout 2400 python research/scripts/pq/dfr.py weakkeys 1000 SEED`):

| parameter set | per-key DFR quartiles (log2), seed 7 | seed 20260927 | sd | min .. max seen (both runs) | average-case DFR |
|---|---|---|---|---|---|
| ML-KEM-768 | -179.0 / -175.3 / -171.4 | -178.8 / -174.9 / -171.0 | 5.75 / 5.82 bits | 2^-195.7 .. 2^-156.5 | 2^-165.12 |
| ML-KEM-1024 | -186.3 / -182.9 / -179.5 | -186.7 / -183.2 / -179.6 | 4.94 / 5.09 bits | 2^-200.8 .. 2^-166.6 | 2^-175.07 |

The 95% confidence intervals of the medians are [-175.7, -174.9] and [-175.3, -174.3]
(ML-KEM-768) and [-183.4, -182.4] and [-183.5, -182.7] (ML-KEM-1024). (An earlier 200-key run gave
a median of 2^-175.9 for ML-KEM-768; an independent fact-check script with another seed gave
2^-174.6; both are within the sampling spread.) The sample mean of the per-key DFRs (2^-167.65 and
2^-165.80 for ML-KEM-768) falls below the average-case value because the average is carried by
rare heavy keys a sample of 1000 seldom contains. A key whose histogram has probability about
2^-64 has DFR about 2^-132.9 (ML-KEM-768) or 2^-143.6 (ML-KEM-1024), a large-deviation (Sanov)
estimate valid to order of magnitude only. This is why weak keys matter in multi-target attacks
(section 4.3). Rough check of the spread: the key-dependent part of the error variance is about
2200 of 5854 for ML-KEM-768; the key's sum of squares varies by about 3%, and the Gaussian-tail
sensitivity of log2 DFR to that variance gives about 5.4 bits, close to the observed 5.8.

**Arithmetic.** `dfr.py` uses float64 with direct (not FFT) convolution: every term is
non-negative, so relative error stays near 1e-12 even at 2^-260, while an FFT would destroy the
tail. Entries below 2^-900 are trimmed. An exact-fraction check on a small law confirms the
float code to 0 relative error.

## 3. Reproducing the published DFRs (`dfr.py`)

Run: `timeout 600 python research/scripts/pq/dfr.py validate PQCRYSTALS_JSON` (about 20 s), with
the JSON from `timeout 300 python research/scripts/pq/dfr_run_pqcrystals.py SE_DIR OUT_JSON`,
where SE_DIR is a checkout of github.com/pq-crystals/security-estimates (commit 75c26949a902,
2021-03-16; kept in the scratch dir, not the repo). FrodoKEM cross-check:
`timeout 900 python research/scripts/pq/dfr_run_frodo_script.py PSS_DIR`, where PSS_DIR is
`FrodoKEM-20200930/Additional_Implementations/Parameter_Search_Scripts` from the NIST round-3
submission zip (csrc.nist.gov, 32,672,473 bytes; scratch dir). All runs end with `RESULT: PASS`
(2026-09-27). Other sub-commands: `simulate` (about 10 min), `weakkeys`, `boost`, `provable`,
`sweep`.

### 3.1 ML-KEM

Parameters (FIPS 203 Table 2, PDF page 48): n = 256, q = 3329; ML-KEM-512 k=2, eta1=3, eta2=2,
du=10, dv=4; ML-KEM-768 k=3, eta1=2, eta2=2, du=10, dv=4; ML-KEM-1024 k=4, eta1=2, eta2=2,
du=11, dv=5.

| parameter set | FIPS 203 Table 1 | dfr.py, 256 x P(abs(err) >= 832) | exact decoding, random m | exact decoding, worst m |
|---|---|---|---|---|
| ML-KEM-512 | 2^-138.8 | 2^-138.775 | 2^-139.036 | 2^-138.943 |
| ML-KEM-768 | 2^-164.8 | 2^-164.812 | 2^-165.123 | 2^-165.010 |
| ML-KEM-1024 | 2^-174.8 | 2^-174.761 | 2^-175.074 | 2^-174.961 |

What the columns mean. The published figure counts a coefficient as failed when |err| >= 832
(= floor(q/4)); true decoding fails for bit 0 only when |err| >= 833, and bit 1 has a slightly
different window because 1665 is not exactly q/2. The exact rate is 0.14 to 0.35 bit below the
published one: the published figures are slightly conservative.

Why the pq-crystals script run today prints 2^-139.1358 / 2^-165.2448 / 2^-175.1961 (0.3-0.4 bit
lower). Its `tail_probability(D, ps.q/4)` sums from `ceil(t)`; under Python 3, `3329/4` is
832.25 so the sum starts at 833, while under Python 2 (for which it was written) integer division
gives 832. Also, Python 3 `round()` rounds exact ties to even inside `mod_switch`, while FIPS 203
rounds ties up (FIPS 203 section 2.3, PDF page 15). `dfr.py` reproduces the script's law under
Python 3 semantics to a maximum relative difference of 2.7e-10 and its printed number to 0.001
bit, and reproduces the FIPS 203 values when Python-2 semantics are emulated. (No Python 2
interpreter was run; the Python-2 reading is inferred from the language semantics and the match.)

Negative controls (a changed parameter must no longer match): ML-KEM-768 with eta1 = 3 gives
2^-95.17; with du = 9 gives 2^-87.35; ML-KEM-512 with eta1 = 2 gives 2^-236.32; ML-KEM-1024 with
dv = 4 gives 2^-153.80. All differ from the table value by far more than 1 bit.

### 3.2 FrodoKEM

Parameters (round-3 Tables 1, 3 and 4, PDF pages 24-25; identical in the 2025 ISO proposal
Tables A.1 and A.3, PDF page 15): n = 640 / 976 / 1344, q = 2^15 / 2^16 / 2^16, B = 2 / 3 / 4,
n-bar = m-bar = 8 (64 entries), error tables in units of 2^-16 (P(0), P(+-1), ...):
Frodo-640 9288 8720 7216 5264 3384 1918 958 422 164 56 17 4 1; Frodo-976 11278 10277 7774 4882
2545 1101 396 118 29 6 1; Frodo-1344 18286 14320 6876 2023 364 40 2. Each table sums to 2^16.

| parameter set | published (round-3 Table 2; 2025 Table A.9) | official `exact_failure_prob_pke` | dfr.py symmetric rule | dfr.py exact decode window |
|---|---|---|---|---|
| Frodo-640 | 2^-138.7 | 2^-138.7282 | 2^-138.7282 | 2^-138.7602 |
| Frodo-976 | 2^-199.6 | 2^-199.5571 | 2^-199.5571 | 2^-199.6028 |
| Frodo-1344 | 2^-252.5 | 2^-252.4924 | 2^-252.4924 | 2^-252.6053 |

A detail the specification text hides. Section 2.2.7 writes the failure sum over
e not in `[-q/2^(B+1), q/2^(B+1))` (asymmetric window, which would round to 2^-138.8 and
2^-252.6 for two sets). The submission's own code (`failure_prob_pke.py`) first folds x to
`min(x, q - x)` and then tests `-b/2 <= x < b/2`, which is the symmetric rule |e| >= q/2^(B+1).
That rule rounds to all three published values, and the official function equals `dfr.py`'s
symmetric rule to four decimals. So, as for ML-KEM, the published figures are slightly
conservative (by 0.03 to 0.11 bit). Negative controls: the official code with B+1 bits gives
2^-34.15 / 2^-50.18 / 2^-63.90 (symmetric rule, as the official code computes it); `dfr.py`
(exact decode window) with Frodo-976 at B = 4 gives 2^-50.21, Frodo-640 with n = 720 gives
2^-124.70, Frodo-1344 with the Frodo-976 table gives 2^-35.86. Under the symmetric rule these three
are 2^-50.18, 2^-124.67 and 2^-35.84 (independent fact-check script). The two Frodo-976 B = 4
figures (2^-50.21 and 2^-50.18) are the same case under the two rules.

### 3.3 What was checked, and how far to trust it

- Checked: published values (both schemes), the designers' scripts' own outputs, value-by-value
  laws (ML-KEM), negative controls, an exact-fraction check of the convolution code, and toy
  Monte-Carlo runs of the real arithmetic.
- Also checked: the formally verified (EasyCrypt) numbers of Barbosa et al. (CCS 2025), both the
  heuristic ones and the heuristic-free "provable" split bound, reproduced by `dfr.py provable`
  (section 4.6).
- Not checked: the compression-independence heuristic at real ML-KEM parameters (no rigorous
  method reaches the heuristic scale except an unreviewed 2026 preprint; section 4.6); the union
  bound's slack (tiny at these rates).

## 4. Attacks that exploit decryption failures

### 4.1 Why one failure leaks the key

A failure means some coefficient of `S^T C + G` crossed the threshold, where S is built from the
secret key and C, G from the ciphertext randomness (notation of D'Anvers et al. PKC 2019,
section 2, PDF p.7). The attacker who made the ciphertext knows C and G. So a failing ciphertext
says "S has an unusually large inner product with this known vector C": a noisy linear hint
about the secret. Many hints give a statistical estimate of S; with the estimate the lattice
problem shrinks. PKC 2019 (section 4, PDF pp.17-19) finds that for schemes whose individual
coefficients fail very rarely (Kyber, Saber, FrodoKEM) "the variance of the secret drastically
reduces upon knowing only a few failing ciphertexts". The FO transform does not stop this: the
attacker submits honestly generated ciphertexts, so the re-encryption check passes; the failure
shows up as a wrong (implicitly rejected) key, which a protocol usually reveals (a handshake
fails). The earliest failure attacks worked on unprotected schemes: Jaulmes and Joux (CRYPTO
2000) on NTRU with chosen invalid ciphertexts, Fluhrer (2016) on ring-LWE key exchange with
reused keys ("cannot be used as a drop in replacement for designs which use Diffie-Hellman static
key shares"), and Guo, Johansson and Stankovski (ASIACRYPT 2016) on QC-MDPC, where decoding
failures reveal the key's distance spectrum; they note that CCA proofs of the time "typically
[do] not include the decoding error possibility".

### 4.2 Failure boosting (D'Anvers, Guo, Johansson, Nilsson, Vercauteren, Verbauwhede, PKC 2019)

Idea (section 3, PDF pp.8-10). Honest parties draw ciphertext randomness at random. An attacker
instead searches for "weak" randomness with a higher-than-average failure probability. Because
FO derives the randomness from a hash of the message, the only way to choose it is brute force
over messages, which Grover can speed up at most quadratically. Sort all (C, G) by their failure
probability F(C, G), pick a threshold f_t, and define

- alpha = probability that random randomness is weak (F >= f_t); finding one costs 1/alpha
  classically, 1/sqrt(alpha) with Grover;
- beta = failure probability of a weak ciphertext (a decryption query cannot be sped up by a
  quantum computer when the oracle is classical, as in NIST's call).

Expected work for one failure: 1/(alpha beta) classically, 1/(sqrt(alpha) beta) quantumly; the
number of decryption queries is 1/beta. The paper computes alpha and beta with a Gaussian model
for `S^T C` given the norm of C (PDF pp.9-11), validated against exhaustive tests on a LAC128
variant (Fig. 1). The worked example (section 2, `dfr_worked_example.py`) shows the same
trade-off on a toy: selection does not lower total work, but it cuts the queries needed (query
budget 2^8 reached with offline work 2^12.96; budget 2^6 needs 2^17.69; no selection: 2^12.28
work and 2^12.28 queries).

Three uses (section 3.1, PDF pp.11-12): (a) without multi-target protection one set of weak
ciphertexts is reused against every public key; Kyber and Saber block this by hashing the public
key into the randomness; (b) under a query limit (NIST's call: 2^64 decryption queries per key)
boosting trades offline work for queries; (c) with a quantum computer, Grover cuts the offline
search.

Numbers (Table 1, PDF p.21; round-1/2 parameter sets, Kyber "original version that includes
rounding" of the public key; cost = quantum work for the whole key recovery, unlimited queries):

| scheme | claimed security | attack cost | failures used | queries |
|---|---|---|---|---|
| Saber | 2^184 | 2^139 | 77 | 2^131 |
| FireSaber | 2^257 | 2^170 | 233 | 2^161 |
| Kyber768 (round 1) | 2^175 | 2^142 | 42 | 2^131 |
| Kyber1024 (round 1) | 2^239 | 2^169 | 159 | 2^158 |
| LAC256 | 2^293 | 2^97 (footnoted) | 106 x 56 | 2^80 |
| FrodoKEM976 | 2^188 | 2^188 | 0 | 0 |

The paper's reading (PDF p.20): the 2^64 decryption limit "rules out a decryption failure attack
on schemes with a low enough failure rate such as Saber and Kyber". Every query count above
exceeds 2^64. The same paper gives a weak-key multi-target attack on ss-ntru-pke (DFR claimed
below 2^-80) below its claimed security (section 7).

**A bracketed boosting estimate (`dfr.py boost`, COMPUTED).** The attacker keeps ciphertexts whose
randomness r and e1 is unusually large. The keep rate alpha is set by a large-deviation (Sanov)
estimate, 2^-(N x KL) for a tilted law; beta is the exact union-bound DFR of a kept ciphertext
against a random key. Two versions bracket the truth. In the "iid" version the kept randomness
fluctuates like the tilted law; this favours the attacker and likely under-states the cost. At
alpha = 1 it equals the average DFR exactly, a built-in check. In the "typical" version every kept
ciphertext has exactly the tilted law's typical histogram; this over-states the cost. (The first
version of this script used only the "typical" point, which made even alpha = 1 give 2^-168.9
instead of the true 2^-165.1 for ML-KEM-768; that version is superseded.) Selection bits are
split between r and e1 on a grid; e2, the message and directional information are ignored.

| parameter set (dimension k x n) | average DFR | cheapest quantum first-failure cost, iid .. typical | queries at that point | largest beta for alpha >= 2^-320 |
|---|---|---|---|---|
| ML-KEM-768 (768) | 2^-165.1 | 2^158.5 .. 2^161.5 | 2^150.5 .. 2^153.5 | 2^-112.1 |
| ML-KEM-1024 (1024) | 2^-175.1 | 2^166.5 .. 2^170.6 | 2^158.5 .. 2^162.6 | 2^-116.1 |
| k=4, q=3329, eta 2/2, no compression | 2^-231.0 | 2^211.9 .. 2^220.5 | 2^195.9 .. 2^204.5 | 2^-143.4 |
| k=4, q=7681, eta 2/2, du 11, dv 5 | 2^-615.4 | 2^572.9 .. 2^593.4 | 2^532.9 .. 2^561.4 | 2^-465.6 |
| k=4, q=7681, eta 3/3, du 11, dv 5 | 2^-328.4 | 2^307.8 .. 2^317.4 | 2^291.8 .. 2^297.4 | 2^-229.3 |

Readings. (a) For ML-KEM the model gives a Grover-assisted first failure about 4 to 9 bits
cheaper than 1/DFR (768: 3.6 to 6.6 bits; 1024: 4.5 to 8.6 bits). (b) The saving grows as the
DFR shrinks (about 11 to 19 bits at 2^-231, 22 to 42 bits at 2^-615), because Grover halves the
cost of the selection step. So a
design that wants the first failure to cost more than 2^lambda even with unlimited queries needs
a DFR some tens of bits below 2^-lambda; the 2^-lambda rule alone does not give that. (c) Every
point needs far more than 2^64 queries: under NIST's query limit none of these attacks applies.
Status: COMPUTED estimate from a simplified model, not the optimised method of the papers; use it
to compare parameter sets, not as a security bound.

### 4.3 Directional failure boosting and multi-target attacks

**"(One) failure is not an option" (D'Anvers, Rossi, Virdia, EUROCRYPT 2020).** After the first
failing ciphertext is found, it points roughly in the direction of the secret. The attacker then
favours new ciphertexts whose C is aligned with that direction ("directional failure boosting").
On a Mod-LWE scheme parametrised like Kyber768/Saber (l = 3, N = 256, q = 8192, sigma = 2.00,
P[F] = 2^-119; Table 1, PDF p.6), the quantum work to find n failures is 2^112.45 for n = 1 and
2^112.77 for n = 2, and stays 2^112.78 from n = 3 on (Table 4, PDF p.21): "After the third
failing ciphertext is found, the following ones are essentially for free." The abstract's
conclusion: these schemes "should be designed so that it is hard to even obtain one decryption
failure". On ss-ntru-pke the multi-target attack drops to 2^96.6 against a claimed 2^198
(Table 6, PDF p.24). The Kyber round-3 specification adopts the conclusion (section 5.5,
PDF p.33): "one should be on the safe side and make sure that it's hard to trigger even one
failure."

**Multitarget attacks on Saber and Kyber (D'Anvers, Batsleer, PKC 2022).** With 2^64 targets,
2^64 queries per target, and a "levelled" strategy (spend queries across many targets for the
first failure, then concentrate), Table 3 (PDF p.26) gives, in log2 (work / queries):

| scheme | claimed quantum security | DFR | 2^64 targets, message space unlimited, no depth limit (levelled) | 2^64 targets, message space 2^256, depth 2^96 (levelled) |
|---|---|---|---|---|
| Kyber512 | 107 | 2^-139 | 131 / 118 | 131 / 118 |
| Kyber768 | 165 | 2^-164 | 175 / 126 | 186 / 126 |
| Kyber1024 | 232 | 2^-174 | 228 / 126 | no attack under 2^256 |
| Saber | 172 | 2^-136 | 141 / 126 | 141 / 126 |

Saber (category 3) is "theoretically vulnerable": 2^145 work and 2^126 queries against a claimed
2^172 core-SVP (PDF p.27); "The other parameter sets of Saber and Kyber are not vulnerable",
Kyber1024 only because the message space of 2^256 caps the number of distinct ciphertexts per
key (PDF p.27). The authors add that practical execution "would not be straightforward" (2^126
queries on the target's hardware). A small inconsistency in the source: the text on PDF p.27
gives 2^145 work for Saber in the 2^64-target, 2^64-query setting, while Table 3 lists 141 in
both levelled 2^64-target columns (and 144 in its reduced-message-space column); either way the
cost is well below the claimed 2^172. Lessons: the DFR relative to the claimed level matters, not
the DFR alone; the size of the message space |M| and the attacker's quantum depth limit are real
parts of the margin. Their code: github.com/KULeuven-COSIC/PQCRYPTO-decryption-failures (not
run here).

**Weak keys.** The published DFR averages over keys; a fixed key can be much weaker (section 2,
step 5). In a multi-target attack the weak-key targets fail first (D'Anvers-Batsleer section 5.1,
PDF p.13). Guo, Johansson and Yang (ASIACRYPT 2019) exploit exactly this against LAC256: one key
among about 2^64 public keys is recovered with complexity 2^79, "if the precomputation cost of
2^162 is excluded" (abstract).

### 4.4 Correctness after many successful queries (Bindel, Schanck, PQCrypto 2020)

Each successful decryption also leaks a little: it says the ciphertext did not fail, which is
information about the key. Bindel and Schanck show an adversary can use this to raise its odds
of a later failure. They quote the Hofheinz-Hovelmanns-Kiltz definition of delta-correctness
(an expectation over keys of the worst-case message failure probability; HHK TCC 2017, PDF p.7;
Bindel-Schanck Definition 1, PDF p.5), argue it is not the right quantity when the key is fixed
and encryption is derandomized, and propose delta(q_d, t)-correctness, which bounds the
adversary's time t and number of decryption queries q_d (Definition 2, PDF p.7). Example:
LightSaber is delta(2^64, 2^128)-correct with delta = 2^64 / 2^84.7 = 2^-20.7 under their
assumptions (PDF p.12). They also call FrodoKEM's claim that the IND-CCA scheme's correctness
equals the one-shot correctness of the PKE "not justified" (PDF p.7). The Kyber round-3
specification (PDF p.32) cites this work and states that its overall running time is not less
than the unrestricted-query attack.

### 4.5 Turning implementation leaks into a failure oracle

**Timing of the FO comparison (Guo, Johansson, Nilsson, CRYPTO 2020).** The FO re-encryption
check compares the received ciphertext with the re-encrypted one. FrodoKEM's reference code used
`memcmp` with short-circuit `&&` (PDF pp.13-14). The attacker adds a value x to the last part of
a valid ciphertext; if decoding still gives the same message the comparison runs longer. That
timing difference is a "did decryption change?" oracle on chosen modifications. By binary search
on x the attacker learns entries of the error E''' and then the key: "the attack code is able to
extract the secret key for all security levels using about 2^30 decapsulation calls" (abstract,
PDF p.1). Lesson: the comparison and the implicit-rejection selection must be constant time.
NIST SP 800-227 (section 3.3, PDF p.22) says "leaking information about failures and aborts
outside of the perimeter of the cryptographic module should be avoided". Constant-time checking
is the sibling topic *side-channels-faults-and-ct-verification*.

**An incomplete FO comparison is a key-recovery bug (Das, ePrint 2026/1682, preprint, August
2026).** wolfSSL's hand-written SIMD decapsulation compared only part of the ciphertext: "The
x86-64 AVX2 path compared 1536 of 1568 bytes; the ARM64 NEON path compared roughly half"
(abstract, PDF p.1). The unchecked bytes carry the tail of the decryption noise, which is a linear
function of the secret, so varying them and watching the output gives a plaintext-checking
oracle. The paper recovers 98.0% of the 2048 ML-KEM-1024 secret coefficients with 400 ciphertexts
(AVX2) and 98.5% with 600 (NEON) against the shipped binaries, and the full key in its reference
model at about 1300 ciphertexts (abstract). It reports the flaws as CVE-2026-10097 and
CVE-2026-6330, fixed in wolfSSL 5.9.2 (PDF pp.2, 7, 9; CVE records not opened here), and draws a
testing lesson that applies directly to Turing: "a comparison routine should be tested on
differences confined to its last bytes" (PDF p.7). Hand-off: *side-channels-faults-and-ct-verification*
and *testing-ci-cd*.

**Fault-induced failures (Fahr et al., "When Frodo Flips", ACM CCS 2022).** Rowhammer bit flips
during FrodoKEM key generation poison the public key with a larger error, which raises the DFR;
the attacker then runs a decryption-failure attack "on the order of only 200,000 core-hours",
tuning the DFR so honest users do not notice (abstract). Key generation lasts about 8 ms; the
authors stretched the window to 1300 ms by degrading SHAKE's performance (section 8.2, PDF p.13).
Algorithmic defences they propose (section 8.2): order operations so nothing slow runs between
sampling S, E and computing B; and "regenerate A, S, and E from randomness and compute B again.
If the two B are not equivalent, then abort key generation."

### 4.6 Is the independence heuristic safe?

- **Toy evidence (this work).** `dfr.py simulate` (section 2, step 4): the model predicts the
  observed failure counts of real ML-KEM arithmetic at inflated noise within 3 standard errors.
- **Barbosa, Kannwischer, Lim, Schwabe, Strub (ACM CCS 2025; ePrint 2025/1562).** The strongest
  primary source on this question. They formalise in EasyCrypt the statistical event behind the
  published ML-KEM numbers and confirm the heuristic values are computed correctly (Table 1,
  "Heur. cu, cv": 2^-164 and 2^-174). They state that "Proving the claim that the heuristic bound,
  which is computed over a simplified distribution, applies to ML-KEM is an open problem"
  (footnote 4, PDF p.3). Their provable route (section 3.2.3, PDF p.8) splits the threshold:
  the rounding-free part `<e,r> - <s,e1> + e2` must stay below `floor(q/4) - 1 - t_max_cv - t_cu`,
  where t_max_cv is the largest possible |cv| (104 for dv = 4, 52 for dv = 5), and `<s,cu>` must
  stay below t_cu. The second event is moved to a uniform u by an MLWE reduction. The price is
  large: provable 2^-80 (ML-KEM-768) and 2^-95 (ML-KEM-1024) (Table 1, PDF p.13; optimal
  t_cu = 296 and 240, section 5.5, PDF p.12). Replacing only cv by its worst case gives 2^-158 and
  2^-169 ("Heur. cu"). FrodoKEM's 2^-138, 2^-199 and 2^-252 are proven with no heuristic beyond
  the random oracle, because FrodoKEM does not compress ciphertexts (section 4, PDF p.8).
  **Reproduced** (`timeout 900 python research/scripts/pq/dfr.py provable`, COMPUTED): with the
  threshold test ">=" all six ML-KEM values truncate to the printed integers (provable 2^-80.48 at
  t_cu = 296, parts 2^-81.09 + 2^-82.03; 2^-95.66 at t_cu = 240, parts 2^-96.23 + 2^-97.27;
  heur(cu) 2^-158.44 and 2^-169.37; heur(cu, cv) 2^-164.38 and 2^-174.33). With the strict ">" of
  the paper's games the values are 0.3 to 0.5 bit lower (2^-80.95, 2^-96.16, 2^-158.87,
  2^-169.81, 2^-164.81, 2^-174.76), and the ML-KEM-1024 part 2^-98.10 would not print as
  "2^-97"; so the paper's code probably counts |n| >= t, one step more conservative than its
  game text. `dfr_barbosa_explore.py` shows this. Negative control: ML-KEM-768 with dv = 5 gives
  heur(cu) 2^-181.51 and provable 2^-92.98, far from the table.
- **Qayyum and Bezzateev (Zenodo artifact, version 1.0.0, 20 July 2026).** Cited by the
  preprint below as a certified, dependency-preserving bound of 2^-127.42 for ML-KEM-768 that
  handles cv only through its worst case |cv| <= 104. UNVERIFIED: the artifact was not opened
  here; the figure is second-hand.
- **Fang, Wang, Zhao (ePrint 2022/212, preprint).** They drop the independence assumption and
  compute per-public-key failure probabilities; abstract: "for Kyber-512 and 768, the failure
  probability resulting from the original paper is relatively conservative, but for Kyber-1024,
  the failure probability of some public keys is worse than claimed". Their Table 2 (PDF p.13)
  gives sample maxima 2^-148 / 2^-166 / 2^-142 and medians 2^-186 / 2^-222 / 2^-232 for
  Kyber512/768/1024. These numbers cannot be compared with this work's per-key medians
  (ML-KEM-768 2^-175.1, ML-KEM-1024 2^-183.1), for reasons the paper itself gives: (i) their
  per-key value lies between a sufficient and a necessary condition whose gap "is usually less
  than 40" in the exponent over their 900 samples (PDF p.10), and the table does not say which
  bound it reports; (ii) they tested 300 keys per set, several hours each (PDF p.11); (iii) the
  theorem they start from (PDF p.9) carries a public-key compression term ct that ML-KEM does
  not have; (iv) their "mean" cannot be an arithmetic mean of the probabilities: an arithmetic
  mean of 300 values whose maximum is 2^-148 is at least 2^-148/300 = 2^-156.2, yet the table
  reports a Kyber512 mean of 2^-188 (and 2^-233 for Kyber768 with maximum 2^-166, whose floor
  would be 2^-174.2); it is probably a mean of exponents. Treat their numbers as UNVERIFIED.
  Their qualitative point, that individual keys can be worse than the average, agrees with
  `dfr.py weakkeys`.
- **Duriez, Tommasini (arXiv 2609.09983v1, 9 September 2026, preprint, 35 pages).** The abstract
  (PDF p.1) claims a certified upper bound Pr[K' != K] <= P* <= 2^-164.81 for ML-KEM-768, with
  -log2 P* = 164.810716..., in an explicit random-function / centred-binomial model that
  "preserves dependencies induced by the public matrix and by both ciphertext-compression terms",
  uses exact FIPS decoding per bit and then a 256-coordinate union bound, for an arbitrary fixed
  message. It states this is "not an exact DFR, not a fixed-SHAKE equivalence theorem, not a new
  IND-CCA reduction, and not an adaptive delta-correctness result". If correct, the heuristic's
  published scale survives a dependency-aware analysis: the certified value is within 0.001 bit of
  this work's floor-rule value (2^-164.8117) and 0.2 bit above its exact-decoding worst-message
  heuristic (2^-165.010). Pages 1-6 and the acknowledgements were read. Its model treats the
  public matrix streams as independent uniform ring elements and secrets as independent CBD(2),
  and it states it is "not an information-theoretic statement about the fixed SHAKE
  instantiation" (PDF p.1). Its own abstract says the result is numerically tight: "164.82 is not
  certified". It discloses that generative AI (ChatGPT and other models) was used for
  "exploratory derivations, code generation/debugging" and other tasks (PDF p.32). Status:
  unreviewed preprint with a long proof chain (Fourier transport, Fincke-Pohst replay) that was
  not checked here; do not rely on it for a design decision until it is peer reviewed or its
  certificate is replayed independently.

### 4.7 Summary of attack preconditions

| attack | needs | stopped by |
|---|---|---|
| failure boosting (PKC 2019) | many decryption queries; offline search | DFR low enough that 1/beta > query limit at any affordable alpha |
| multi-target boosting | many public keys; reusable weak ciphertexts | hashing the public key into the randomness; small DFR relative to level; bounded message space |
| directional boosting (EC 2020) | one first failure | making the first failure infeasible |
| timing of FO comparison (CRYPTO 2020) | variable-time compare or observable rejection | constant-time compare and select; no failure signal |
| fault-poisoned keys (CCS 2022) | Rowhammer during key generation | key-generation integrity check; fast key generation |
| ECC timing / dependence (section 6) | a decoder whose time depends on error count; correlated bit errors | no ECC, or constant-time decoder plus dependency-aware DFR |
| incomplete FO comparison (ePrint 2026/1682) | a re-encryption check that skips some ciphertext bytes | compare every byte in constant time; test with differences in the last bytes |
| noise-distribution change (ePrint 2024/1979) | a "twist" that raises the DFR to a practical level | a fresh exact DFR for every change to noise, encoding or compression |

## 5. What DFR the specifications treat as safe, and why

**The rule in the proofs.** The FO security bounds contain a failure term. HHK (TCC 2017) show
the derandomized PKE is delta1-correct with delta1(q_G) = q_G * delta (Theorem 3.1, PDF p.10;
the revised version corrects this to (q_G + q_P) * delta and the QROM term to
8 (q_G + q_P + 1)^2 delta, PDF p.1). Kyber's Theorem 2 has 4 q_RO delta (classical ROM), Theorem 3
has 8 q_RO^2 delta (QROM) (Kyber round-3 spec section 5.5, PDF p.31). `dfr_fo_bound_terms.py`
evaluates these at the published DFRs (COMPUTED):

| scheme | lambda | log2 delta | lambda + log2 delta | classical term, q = 2^128 | quantum term, q = 2^64 | q where the quantum term reaches 1 |
|---|---|---|---|---|---|---|
| ML-KEM-512 | 128 | -138.8 | -10.8 | 2^-8.8 | 2^-7.8 | 2^67.9 |
| ML-KEM-768 | 192 | -164.8 | +27.2 | 2^-34.8 | 2^-33.8 | 2^80.9 |
| ML-KEM-1024 | 256 | -174.8 | +81.2 | 2^-44.8 | 2^-43.8 | 2^85.9 |
| Frodo-640 | 128 | -138.7 | -10.7 | 2^-8.7 | 2^-7.7 | 2^67.8 |
| Frodo-976 | 192 | -199.6 | -7.6 | 2^-69.6 | 2^-68.6 | 2^98.3 |
| Frodo-1344 | 256 | -252.5 | +3.5 | 2^-122.5 | 2^-121.5 | 2^124.8 |

(lambda = the RBG strength FIPS 203 Table 2 assigns to each ML-KEM set, and the matching NIST
level for FrodoKEM.) For the Turing options in section 7 the same formula (the quantum term
8 q^2 delta reaches 1 at q = 2^((-log2 delta - 3)/2), COMPUTED) gives q = 2^113.8 at
delta = 2^-230.6 (no compression, q = 3329), 2^126.5 at delta = 2^-256 and 2^158.8 at the proven
2^-320.6 (q = 7681); a perfectly correct set has no such term at all.

The quantum term becomes vacuous long before 2^lambda queries for every
scheme; the Kyber specification calls this "a (quadratic) non-tightness in the
decryption-failure probability" (PDF p.19) and argues it does not match a real attack
(sections 4.2-4.3). Hovelmanns, Hulsing and Majenz (2022) give a tighter treatment based on new
"find failing plaintext" properties; Majenz and Sisinni (ePrint 2024/835, preprint) prove one of
them (FFP-NG) from LWE for the PVW scheme with discrete Gaussian errors. That line belongs to the
sibling topic *cca-transforms-and-binding*.

**Which delta goes into the proof: average message or worst message.** HHK call a PKE
delta-correct if E[max over m of Pr[Dec(sk, c) != m | c <- Enc(pk, m)]] <= delta, the
expectation taken over the key pair (HHK p.7). FIPS 203 Table 1 instead averages over a random
message (claim 3). For a per-coefficient encoding like ML-KEM's the gap is at most one bit
(COMPUTED argument): for a fixed key, a message fails only if some coefficient fails, so
Pr[fail | key, m] <= sum over i of max over the bit value b of Pr[coefficient i fails | key, b];
taking the expectation over keys and bounding the max by the sum of both bit values gives
delta_HHK <= 256 x (p0 + p1) = 2 x (the random-message union bound). For ML-KEM-768 this gives
delta_HHK <= 2 x 2^-165.123 = 2^-164.123, which is 0.7 bit above the published 2^-164.8; the
true value is probably close to the worst-message figure 2^-165.010 (in the key-averaged law bit
1 is the worse bit, 2^-173.010 against 2^-173.245 per coefficient; per-key behaviour was not
checked), but the one-bit bound is what can be shown simply. The "worst message" column of
section 3 is the max over m of the key-averaged bound, the other order of max and expectation.
For a Turing target the safe habit is to state delta_HHK with this factor 2 included. NIST IR
8413 notes that for BIKE "the maximum decryption failure rate over all messages is difficult to
compute" because some messages cause more failures (PDF p.39); for coefficient-wise lattice
encodings it is not.

**Kyber / ML-KEM's position (round-3 spec, PDF p.21).** "because in the classical random oracle
model, the decryption failure probability is information-theoretic, we do not see a need for it
to decrease with the security parameter." Levels 3 and 5 have DFR below 2^-160; "We therefore
exclude these attacks from our claims regarding the NIST security estimates." Section 5.5
(PDF p.31) adds: with 2^64 ciphertexts, Kyber768 has "a chance of 2^-100 of a decapsulation
failure ... without any particular effort by the attacker". Kyber512's round-3 change (larger
noise, eta 2 to 3 per NIST IR 8413; one fewer bit dropped from the second ciphertext element,
ciphertext 736 to 768 bytes, "for a 2^-139 decryption error", PDF p.2) shows the DFR being held
near 2^-139 while noise grew; NIST IR 8413 describes it as done "without raising the decryption failure rate above the requisite threshold for security" (PDF
p.38).

**FrodoKEM's position.** DFR close to 2^-lambda: 2^-138.7 (level 1), 2^-199.6 (level 3),
2^-252.5 (level 5). For Frodo-1344 "failure boosting did not provide any improvement over the
intrinsic failure probability of 2^-252.5", judged "consistent with the Level 5 requirement of
256 bits of brute-force security, because the overhead in using decryption failures to win the
CCA security game exceeds 3.5 bits" (round-3 spec section 5.2.5, PDF p.45; 2025 proposal
section 9.3, PDF p.12). The round-3 spec reports running the PKC 2019 scripts on all three sets
and finding no violation of levels 1, 3, 5.

**NIST's position.** The Call for Proposals limits attacks to "no more than 2^64 chosen
ciphertexts" and is "primarily concerned with attacks that use classical (rather than quantum)
queries to the decryption oracle" (section 4.A.2). NIST IR 8413 (2022) defines delta-correct as
failure "with probability at most delta on average over all keys and messages" and, for BIKE,
states the PKE "must be delta-correct ... for delta <= 2^-lambda" to apply the FO transform
(PDF p.39); NIST IR 8545 (March 2025) repeats this (PDF p.19), notes HQC "discarded parameter
sets targeting a higher DFR than 2^-lambda for lambda bits of security" in May 2020, and names
"HQC's stable DFR analysis" as "the decisive factor in favor of HQC relative to BIKE", citing
"previous inaccurate DFR estimates" that let BIKE be "attacked as late as the fourth round"
(PDF pp.18-19). NIST IR 8413 also records that HQC-256-1 "was broken during the second round"
by a decryption failure attack (PDF p.43). NIST SP 800-227 sets no numeric DFR; it requires
correctness "with all but negligible probability" (Definition 2, PDF p.14) and no leakage of
failures outside the module (section 3.3, PDF p.22). NIST did not apply 2^-lambda to ML-KEM:
ML-KEM-768 and -1024 are 27.2 and 81.2 bits above it.

**Why the two positions differ.** The 2^-lambda rule makes the proof's failure term negligible
without any attack-cost argument. Kyber's rule relies on the attack-cost argument: finding a
failure takes more than 2^64 queries at any affordable offline work. The Saber case (PKC 2022)
shows that the attack-cost argument must be redone for each parameter set and attacker model
(multi-target, levelled); the 2^-lambda rule needs no such argument.

## 6. Error-correcting codes and their pitfalls

**Why use one.** With a code that corrects t bit errors, the message fails only when more than t
bits fail, so each bit may fail far more often. LAC (Lu et al., LAC-v3 paper, Table 2, PDF p.16)
uses q = 251 and a BCH code plus a D2 code: e.g. LAC-256-v3a has n = 1024,
BCH[511,256,41]+D2 (corrects up to 20 errors), single-bit error rate 2^-20.01 without BCH and a
claimed decryption error rate 2^-302; LAC-128-v3a uses BCH[255,128,17] (up to 8 errors), 2^-22.26
per bit, 2^-151 overall. The claimed rate assumes bit errors are independent. Round5 uses XEf
codes (TRUNC8/HILA5 style parity registers with a majority rule; corrects f errors); parameter
sets with XE5 need "around 25% lower bandwidth" (Round5 spec draft 2019-01-25, section 1.4.1 and
PDF p.39).

**Pitfall 1: failure dependence.** The coefficients of one error polynomial are not independent:
they share the same key and randomness norms. D'Anvers, Vercauteren and Verbauwhede (PQCrypto
2019) show "the independence assumption is suitable for schemes without error correction, but
... might lead to underestimating the failure probability of algorithms using error correcting
codes. In the worst case, for LAC-128, the failure rate is 2^48 times bigger than estimated"
(abstract). Round5 hit the same issue structurally: with the reduction polynomial Phi_{n+1} a
large top coefficient spreads into many coefficients ("correlation between errors"), so XEf
"cannot be directly employed"; Round5 therefore computes ciphertexts modulo x^{n+1} - 1 and uses
balanced ternary secrets to obtain independent bit failures (Round5 spec, PDF pp.10-11).

**Pitfall 2: decoder timing.** D'Anvers, Tiepelt, Vercauteren and Verbauwhede (TIS 2019): a
variable-time decoder reveals whether a ciphertext had errors before decoding. It recovers
"LAC's secret key for all security levels in under 2 minutes using less than 2^16 decryption
queries and Ramstake's secret key in under 2 minutes using approximately 2400 decryption queries"
(abstract). With such a leak "it might not even be necessary to obtain a decryption failure"
(PKC 2019, PDF p.17): successful decryptions that corrected an error already leak. LAC-v3
later made its BCH decoder constant time (LAC-v3 paper, PDF p.6); Round5 advertises XEf as free
of table look-ups and conditions (Round5 spec, PDF p.5). NIST IR 8413 notes HQC removed its
BCH-repetition decoder and that side-channel attacks were found against HQC (PDF p.43).

**Pitfall 3: attacks target the higher per-bit rate.** With a strong code each bit fails often
(2^-20 for LAC-256), so a failing ciphertext carries several failing bits, which makes failures
easier to exploit once found (PKC 2019 PDF p.18); Guo, Johansson and Yang's LAC attack
(ASIACRYPT 2019) and PKC 2019's 2^97 LAC256 figure (footnoted) exploit this.

**Redundant message encodings: the middle ground, with the same analysis risk.** A scheme with
more ring coefficients than message bits can spread each bit over several coefficients and decode
by a soft rule. NewHope did this at exactly the dimension Turing is considering. NewHope1024
(round-2 specification, PDF p.21 table) uses a ring of dimension n = 1024, q = 12289 and a
centred binomial noise with k = 8, and encodes each of the 256 key bits "into 4 coefficients", a
technique it credits to Guneysu and Poppelmann (PDF p.20). Its decryption error probability is
listed as 2^-216 (PDF p.21), described as "less than 2^-216" from the designers' script
scripts/failure-1024k8.py, following the analysis of the original NewHope paper (PDF p.36). That
computation was not reproduced here. The same page records an attack on a CPA version of NewHope
that needed "about 4000 decryption requests", and argues that Grover search cannot find a failing
ciphertext offline because failure depends on the secret; PKC 2019 later showed that an attacker
can still pre-select ciphertexts with a higher failure probability (section 4.2). Two cautions
carry over from section 6. The four coefficients of one group share the same secret and
randomness, so their errors are dependent, which is exactly where DVV 2019 found the
independence assumption can fail. And the published DFRs of encoding-based schemes have moved by
tens of bits under closer analysis: Zhou et al. (ePrint 2026/1350, preprint) say most DFR
evaluations for lattice-based PKE with message encoding "rely on oversimplified assumptions,
rough approximations", and their refined method moves the DFR upper bound by about 15 bits down
for CNTR, 1 bit for Scloud+ and "at least 84 bits" up for CNTR-Prime (abstract, PDF p.1). A
second 2026 preprint on multidimensional lattice decoders (Fang, Li, Zhao, ePrint 2026/1924)
names the two traps exactly: a bounded-distance-decoding certificate can fail "much more often than an implemented
message failure", and "polynomial multiplication can create nontrivial dependence among
coordinates within a decoder block"; its refined block tail sums for BW-KEM are 6.537 to 7.621
bits lower than the published Chernoff sums, and at a CTRU test point 2,396 certificate exits
contained 26 message failures (abstract, PDF p.1). For a Turing design on a single ring of
dimension 1024, a NewHope-style encoding is a legitimate,
published option, but its DFR would need a dependency-aware computation (or a Monte-Carlo check
at inflated noise, as in section 2 step 4) before its number could be trusted.

**Assessment.** A code lowers the headline DFR cheaply but moves the risk into a dependency
analysis and a constant-time decoder, both of which failed in practice for round-1/2 candidates.
ML-KEM and FrodoKEM use no error-correcting code. For Turing the evidence favours no code;
lowering the DFR through q, noise and compression keeps the exact convolution analysis valid.

## 7. DFR trade-offs near 1000 dimensions

`timeout 1200 python research/scripts/pq/dfr.py sweep` (COMPUTED; DFR only, NOT security
estimates; random message, exact decoding, union bound):

| family | q | eta1 / eta2 or table | du / dv or B | log2 DFR |
|---|---|---|---|---|
| Module-LWE k=4, n=256 (dim 1024) | 3329 | 2 / 2 | 11 / 5 (= ML-KEM-1024) | -175.1 |
| same | 3329 | 2 / 2 | 11 / 6 | -185.6 |
| same | 3329 | 2 / 2 | no compression | -231.0 |
| same | 3329 | 3 / 2 | 11 / 5 | -97.0 |
| same | 3329 | 1 / 1 | 11 / 5 | -589.4 |
| same | 7681 | 2 / 2 | 11 / 5 | -615.4 |
| same | 7681 | 3 / 3 | 11 / 5 | -328.4 |
| same | 7681 | 4 / 4 | no compression | -299.5 |
| plain LWE, n = 976 | 2^16 | Frodo-976 table | B = 2 / 3 / 4 | -703.0 / -199.6 / -50.2 |
| plain LWE, n = 1024 | 2^16 | Frodo-976 table | B = 3 | -191.2 |
| plain LWE, n = 1024 | 2^16 | Frodo-640 table | B = 3 | -89.3 |

Proven (heuristic-free) bounds for three of these rows, by the Barbosa et al. split method
(`dfr.py provable`, threshold test ">=", COMPUTED): k=4, q=3329, eta 2/2, no compression:
2^-229.5 (with no rounding the split is unnecessary and the exact value 2^-230.6 is itself proven);
q = 7681, eta 2/2, du 11, dv 5: 2^-320.6 (t_cu = 812; heuristic 2^-614.3); q = 7681, eta 3/3,
du 11, dv 5: 2^-170.2 (t_cu = 722; heuristic 2^-327.8). Observation (not a theorem): whenever
compression is used, the proven exponent here is about half the heuristic one (ratios 0.49 for
ML-KEM-768, 0.52 for both q = 7681 rows). The split bound pays for the worst-case cv and for
giving each noise part only part of the threshold.

**The zero-DFR option (perfect correctness).** NTRU and NTRU Prime chose perfectly correct
parameters (NIST IR 8413, PDF pp.47, 49), and the Kyber designers note that zero failure needs
less noise or a larger dimension (claim 20). For an ML-KEM-style scheme every noise term is
bounded, so the worst-case error is B = k n eta1 (eta1 + eta2 + max|cu|) + eta2 + max|cv|, and the
scheme never fails if B is at most the safe decoding radius (831 at q = 3329 for both bit values;
about q/4 in general). `timeout 400 python research/scripts/pq/dfr_perfect_correctness.py`
(COMPUTED; n = 256; security NOT assessed):

| k | eta1 / eta2 | du / dv | worst case B | smallest perfectly correct q | next prime q = 1 mod 512 |
|---|---|---|---|---|---|
| 4 | 2 / 2 | none | 8194 | 32778 (2^15.0) | 36353 |
| 4 | 2 / 2 | 13 / 13 | 16390 | 65562 (2^16.0) | 67073 |
| 4 | 2 / 2 | 11 / 5 | grows with q | none below 2^22 | - |
| 4 | 1 / 1 | none | 2049 | 8198 (2^13.0) | 10753 |
| 4 | 1 / 1 | 12 / 6 | 4229 | 16918 (2^14.05) | 17921 |
| 3 | 2 / 2 | none | 6146 | 24586 (2^14.59) | 25601 |
| 4 | 3 / 3 | none | 18435 | 73742 (2^16.17) | 76289 |

(Also COMPUTED: 7681 and 12289 are primes = 1 mod 512; 12289, NewHope's modulus, is above 8198,
so k = 4, eta 1, no compression would be perfectly correct at q = 12289.) Readings. Zero DFR
removes the whole failure-attack class and the delta term of the FO proof, which is the
strongest position on this topic. The cost is a q about ten times ML-KEM's at the same noise
(or ternary noise at about two and a half times), no or very light ciphertext compression, and a larger
q/noise ratio that weakens LWE at a fixed dimension; compensating needs a larger dimension. With
du = 11 compression no q works, because the worst-case rounding error grows as fast as q/4. This
is an option to put before the owner with a security estimate from *attack-cost-estimation*, not
a recommendation by itself.

Readings. (a) With q = 3329 and CBD(2) at dimension 1024, 2^-256 is out of reach even without
compression. (b) One step of eta (2 to 3) costs about 78 bits of DFR; one bit of dv 10 to 21
bits; B = 3 to 4 costs about 150 bits for Frodo-976. (c) A larger q buys hundreds of bits of DFR,
but raises q/noise and so lowers LWE security at a fixed dimension, and changes NTT options (an
integration question for *turing-integration-constraints*). Every row needs a security estimate
from *attack-cost-estimation* before it can be called a parameter set.

## What this means for Turing

1. **Pick the 2^-lambda target and say so.** For a ~1000-dimension lattice layer claiming lambda
   bits, choose parameters with DFR <= 2^-lambda (below 2^-256 for a 256-bit claim). Evidence:
   FrodoKEM and HQC practice; NIST IR 8413/8545 wording; the FO failure term becomes negligible
   without an attack-cost argument (section 5); Saber shows what happens when the DFR is high
   relative to the level (section 4.3). This is a measurable respect in which Turing can be more
   conservative than ML-KEM-1024 (DFR 2^-174.8). Risk: it costs noise, q or bandwidth
   (section 7), and lower noise must be re-checked against lattice attacks. Status: design
   choice for the owner.
2. **Compute it exactly and conservatively, in CI.** Reuse `dfr.py`'s method: exact convolution,
   conservative threshold (as both published figures do), union bound, worst message. Add
   `dfr.py validate` (20 s, deterministic, PASS/FAIL, negative controls; without its optional
   JSON argument it needs no files outside the repository) and `dfr.py provable` to CI as
   regression tests so any parameter or encoding change that moves the DFR is caught.
   (`dfr_verify_sources.py` cannot run in CI: it reads the gitignored PDFs.) Never use a
   Gaussian formula (section 2).
2a. **Make the target hold for a proven bound, not only the heuristic.** Evidence: Barbosa et al.
   (CCS 2025) prove FrodoKEM's DFRs outright but can prove only 2^-80 / 2^-95 for
   ML-KEM-768/1024, whose published 2^-164.8 / 2^-174.8 rest on the compression heuristic; they
   call closing that gap an open problem. Two ways to get a proven DFR at a Turing parameter set:
   (i) no ciphertext compression (then there is no rounding term and the exact convolution is the
   proven bound, up to the random-oracle modelling of the samplers as for FrodoKEM: 2^-230.6 at
   k = 4, q = 3329, eta 2, floor-rule threshold); (ii) compression light enough that the
   split bound still meets the target (q = 7681, eta 2, du 11, dv 5: proven 2^-320.6 against a
   heuristic 2^-614). Cost: bandwidth, or a larger q whose effect on lattice security must be
   estimated by *attack-cost-estimation*. This is a concrete, checkable way for Turing to be
   more conservative than ML-KEM. Status: design option; numbers COMPUTED (`dfr.py provable`).
2b. **Leave a margin below 2^-lambda for boosting.** The bracketed boosting estimate (section
   4.2) makes a first failure cheaper than 1/DFR with Grover-assisted selection and unlimited
   queries: by 4 to 9 bits at ML-KEM's DFRs, 11 to 19 bits at 2^-231 and 22 to 42 bits at
   2^-615. The saving grows as the DFR falls, but the cost itself stays far above 2^256 in the
   last case. With NIST's 2^64-query limit the attack does not apply at all, so the margin
   matters only for an unlimited-query or multi-target claim. Status: estimate from a simplified model; a proper check at the chosen
   parameters is open question 2.
2c. **Or remove failures entirely.** A perfectly correct parameter set (the NTRU / NTRU Prime
   choice) has DFR exactly 0: no failure attacks, no delta term, no heuristic. At dimension
   1024 with CBD(2) noise and no compression this needs q >= 32778 (e.g. the NTT-friendly prime
   36353); with ternary noise q >= 8198 (12289 works); with du = 11 compression it is impossible
   (section 7). The price is lattice security at a fixed dimension and ciphertext size, which
   *attack-cost-estimation* must quantify before this can be compared with 2a. Status: design
   option; numbers COMPUTED (`dfr_perfect_correctness.py`).
3. **Test the implementation against the model.** Run the real Turing implementation with
   deliberately inflated noise (as `dfr.py simulate` does with toy ML-KEM) and require the
   observed failure count to match the model within 3 standard errors. This catches encoding,
   rounding and compression bugs that KATs miss. Hand-off to *testing-ci-cd*.
4. **No error-correcting code.** Evidence in section 6 (2^48 underestimate, sub-2-minute timing
   key recovery, structural preconditions). If a code is ever proposed, it needs a
   dependency-aware DFR analysis and a verified constant-time decoder before anything else.
5. **Twists must not touch the error law without a new analysis.** Any "twist" that changes the
   noise distribution, encoding, compression, or ring reduction changes the DFR and can create
   coefficient dependence (Round5's Phi_{n+1} example). Each such change needs a fresh exact
   computation and a toy simulation, and is a risk flag until it has one. A published example of
   how fast this goes wrong: Shao et al. (ePrint 2024/1979, preprint) replace Kyber's centred
   binomial noise by the uniform law over the same range. The DFR moves from 2^-139.1 / 2^-165.2
   / 2^-175.2 to 2^-25.4 / 2^-50.3 / 2^-47.5 (Table 4, PDF p.7), and they report recovering the
   uniform-noise Kyber512 key from 3,000 failures at about 2^37 work (abstract; PDF p.10).
   `dfr_uniform_twist.py` reproduces all six DFRs to 0.1 bit (COMPUTED). The attack cost is
   quoted, not reproduced. The same change "enhances the LWE hardness" (their abstract), which is
   exactly why such a twist looks attractive and why the DFR check must come first.
5a. **Prefer less compression of v as the first DFR lever.** D'Anvers and Batsleer (PKC 2022,
   section 8.2, PDF p.27) note that the compression error of v can dominate failures when v is
   strongly compressed, and that increasing t (the number of bits kept for v, dv in ML-KEM
   notation) raises the failure-attack cost at "a modest cost in ciphertext size" and "generally
   has no impact on the security of the scheme under non-decryption failure attacks". In the
   sweep (section 7), one more bit of dv at dimension 1024 (dv 5 to 6, +32 bytes of ciphertext)
   lowers the DFR from 2^-175.1 to 2^-185.6, and no compression at all gives 2^-231.0 and makes
   the bound provable (item 2a). The noise width and q, by contrast, change the lattice
   security. The same section warns against the other lever it names, a smaller message space,
   because "a too low value" could weaken security against ordinary attacks.
6. **Keep the standard FO hygiene.** Hash the public key into the encryption randomness
   (multi-target protection, Kyber spec PDF p.33; PKC 2019); keep a 256-bit message space
   (caps ciphertexts per key, PKC 2022); implicit rejection with constant-time comparison and
   selection (CRYPTO 2020; SP 800-227 section 3.3); no observable failure signal. Details:
   *cca-transforms-and-binding* and *side-channels-faults-and-ct-verification*.
7. **Guard key generation.** Recompute B from the seeds and compare before publishing a key
   (Fahr et al. section 8.2): cheap (one extra matrix product) and it defeats fault-poisoned
   keys whose raised DFR enables failure attacks.
8. **Report per-key behaviour, not only the average.** Publish the average DFR (as the
   standards do) and also the per-key spread from a `weakkeys`-style computation, because
   multi-target attackers pick the weakest keys. Rejecting heavy keys at generation is an idea
   with no published analysis for LWE KEMs (it changes the key distribution); treat as open.

## Sources

| file in research/papers/ or "online" | reference | URL | used for |
|---|---|---|---|
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, Module-Lattice-Based KEM Standard, 13 Aug 2024 | https://doi.org/10.6028/NIST.FIPS.203 | Table 1 DFRs, Table 2 parameters, definition, rounding |
| 2021-avanzi-et-al-kyber-round3-specification.pdf | Avanzi et al., CRYSTALS-Kyber round-3 specification v3.02 (2021) | https://pq-crystals.org/kyber/ | DFR method, rationale, sections 5.5, Theorems 2-3 |
| 2021-alkim-et-al-frodokem-round3-specification-20210604.pdf | Alkim et al., FrodoKEM round-3 specification (2021-06-04) | https://frodokem.org/ | failure rule, Table 2, tables, section 5.2.5 |
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | FrodoKEM preliminary standardization proposal (2025) | https://frodokem.org/ | Table A.9, Table A.3, section 9.3 |
| online (scratch: dfr-work/FrodoKEM-Round3.zip) | FrodoKEM NIST round-3 submission package, Parameter_Search_Scripts/failure_prob_pke.py | https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/FrodoKEM-Round3.zip | official failure computation (symmetric rule) |
| online (scratch: attack-cost/security-estimates) | Ducas, Schanck, pq-crystals security-estimates, commit 75c26949a902 | https://github.com/pq-crystals/security-estimates | Kyber_failure.py, proba_util.py |
| 2019-danvers-et-al-decryption-failure-attacks-ind-cca-lattice.pdf | D'Anvers, Guo, Johansson, Nilsson, Vercauteren, Verbauwhede, Decryption failure attacks on IND-CCA secure lattice-based schemes, PKC 2019, pp. 565-598 (35-page full version; download URL not recorded). ePrint 2018/1089 is the earlier three-author preprint "On the impact of decryption failures on the security of LWE/LWR based schemes", which ePrint lists as "A major revision of an IACR publication in PKC 2019" | https://eprint.iacr.org/2018/1089 (related preprint) | failure boosting, Table 1 |
| 2020-danvers-rossi-virdia-one-failure-is-not-an-option.pdf | D'Anvers, Rossi, Virdia, (One) failure is not an option, EUROCRYPT 2020 (ePrint 2019/1399) | https://eprint.iacr.org/2019/1399 | directional boosting, Tables 1, 4, 6 |
| 2022-danvers-batsleer-multitarget-decryption-failure-attacks.pdf | D'Anvers, Batsleer, Multitarget decryption failure attacks and their application to Saber and Kyber, PKC 2022 (ePrint 2021/193) | https://eprint.iacr.org/2021/193 | Table 3, Saber result |
| 2020-bindel-schanck-decryption-failure-more-likely-after-success.pdf | Bindel, Schanck, Decryption failure is more likely after success, PQCrypto 2020 (ePrint 2019/1392) | https://eprint.iacr.org/2019/1392 | delta(q_d,t)-correctness |
| 2020-guo-johansson-nilsson-key-recovery-timing-attack-fo-frodokem.pdf | Guo, Johansson, Nilsson, A key-recovery timing attack on post-quantum primitives using the FO transformation and its application on FrodoKEM, CRYPTO 2020 (ePrint 2020/743) | https://eprint.iacr.org/2020/743 | timing failure oracle, 2^30 calls |
| 2022-fahr-et-al-when-frodo-flips-rowhammer.pdf | Fahr et al., When Frodo Flips: End-to-End Key Recovery on FrodoKEM via Rowhammer, ACM CCS 2022 (ePrint 2022/952) | https://eprint.iacr.org/2022/952 | fault-induced failures, keygen check |
| 2022-fang-wang-zhao-tight-analysis-kyber-dfr-in-reality.pdf | Fang, Wang, Zhao, Tight Analysis of Decrypton Failure Probability of Kyber in Reality, ePrint 2022/212 (preprint) | https://eprint.iacr.org/2022/212 | per-key DFR claims (unverified) |
| 2019-danvers-vercauteren-verbauwhede-impact-of-error-dependencies.pdf | D'Anvers, Vercauteren, Verbauwhede, The impact of error dependencies on Ring/Mod-LWE/LWR based schemes, PQCrypto 2019 (ePrint 2018/1172) | https://eprint.iacr.org/2018/1172 | ECC dependence, 2^48 |
| 2019-danvers-tiepelt-vercauteren-verbauwhede-timing-attacks-on-ecc-pq.pdf | D'Anvers, Tiepelt, Vercauteren, Verbauwhede, Timing attacks on error correcting codes in post-quantum schemes, TIS 2019 (ePrint 2019/292) | https://eprint.iacr.org/2019/292 | decoder timing attack |
| 2019-guo-johansson-yang-cca-attack-decryption-errors-lac.pdf | Guo, Johansson, Yang, A novel CCA attack using decryption errors against LAC, ASIACRYPT 2019 | (ePrint) | weak-key LAC attack |
| 2018-lu-et-al-lac-ring-lwe-byte-level-modulus.pdf | Lu et al., LAC: Practical Ring-LWE based PKE with byte-level modulus (LAC-v3 version) | (ePrint) | BCH parameters, Table 2 |
| 2019-baan-et-al-round5-kem-pke-based-on-glwr.pdf | Baan et al., Round5 specification draft (2019-01-25) | (ePrint / round5.org) | XEf code, independence requirements |
| 2017-hofheinz-hovelmanns-kiltz-modular-analysis-fo-transformation.pdf | Hofheinz, Hovelmanns, Kiltz, A modular analysis of the FO transformation, TCC 2017 (revised ePrint 2017/604) | https://eprint.iacr.org/2017/604 | delta-correctness, q_G delta term |
| 2022-hovelmanns-hulsing-majenz-failing-gracefully-fo.pdf | Hovelmanns, Hulsing, Majenz, Failing gracefully (FO decryption failures) | (ePrint) | tighter failure handling (mentioned) |
| 2024-majenz-sisinni-provable-security-against-decryption-failure-attacks-lwe.pdf | Majenz, Sisinni, Provable security against decryption failure attacks from LWE, ePrint 2024/835 (preprint) | https://eprint.iacr.org/2024/835 | FFP-NG from LWE (mentioned) |
| 2026-zhou-et-al-refined-evaluation-dfr-message-encoding.pdf | Zhou et al., Refined Evaluation Methods of DFR in Lattice-Based PKE with Message Encoding, ePrint 2026/1350 (preprint) | https://eprint.iacr.org/2026/1350 | Gaussian-approximation errors (84 bits) |
| 2025-barbosa-et-al-formally-verified-correctness-bounds-lattice.pdf | Barbosa, Kannwischer, Lim, Schwabe, Strub, Formally Verified Correctness Bounds for Lattice-Based Cryptography, ACM CCS 2025 (ePrint 2025/1562) | https://eprint.iacr.org/2025/1562 | Table 1 provable vs heuristic bounds; split method; open problem |
| 2024-shao-et-al-lwe-kems-under-various-distributions-kyber.pdf | Shao, Liu, Zhou, Shao, On the Security of LWE-based KEMs under Various Distributions: A Case Study of Kyber, ePrint 2024/1979 (preprint) | https://eprint.iacr.org/2024/1979 | uniform-noise twist: DFR 2^-25.4, practical attack |
| 2026-das-incomplete-ciphertext-comparison-ml-kem.pdf | Das, Incomplete Ciphertext Comparison in ML-KEM: From an IND-CCA2 Break to Key Recovery, ePrint 2026/1682 (preprint) | https://eprint.iacr.org/2026/1682 | partial FO comparison as key recovery; test lesson |
| 2026-fang-li-zhao-dfr-multidimensional-lattice-decoders.pdf | Fang, Li, Zhao, Decryption-Failure Rate with Multidimensional Lattice Decoders, ePrint 2026/1924 (preprint) | https://eprint.iacr.org/2026/1924 | DFR pitfalls of lattice-code decoders |
| 2026-duriez-tommasini-dependency-aware-correctness-bounds-ml-kem-768.pdf | Duriez, Tommasini, Dependency-Aware ROM/CBD Correctness Bounds for ML-KEM-768 at the Heuristic Failure Scale, arXiv 2609.09983v1 (9 Sep 2026, preprint) | https://arxiv.org/abs/2609.09983 | claimed certified 2^-164.81 bound |
| 2016-fluhrer-cryptanalysis-rlwe-key-exchange-key-reuse.pdf | Fluhrer, Cryptanalysis of ring-LWE based key exchange with key share reuse, ePrint 2016/085 | https://eprint.iacr.org/2016/085 | early reuse attack |
| 2016-guo-johansson-stankovski-key-recovery-qc-mdpc-decoding-errors.pdf | Guo, Johansson, Stankovski, A key recovery attack on MDPC with CCA security using decoding errors, ASIACRYPT 2016, pp.789-815 | (ePrint) | reaction attack origin |
| 2019-alkim-et-al-newhope-round2-specification.pdf | Alkim et al., NewHope round-2 specification (2019), NIST PQC round-2 submission | download URL not recorded by the earlier run (local copy) | n = 1024 redundant encoding, DFR 2^-216, failure-attack remarks |
| nist-ir-8413-pqc-round3-report.pdf | NIST IR 8413-upd1, Third Round Status Report | https://doi.org/10.6028/NIST.IR.8413-upd1 | delta-correct definition, HQC-256-1, Kyber512 change |
| nist-ir-8545-pqc-round4-report.pdf | NIST IR 8545, Fourth Round Status Report (March 2025) | https://doi.org/10.6028/NIST.IR.8545 | delta <= 2^-lambda, HQC vs BIKE |
| nist-sp800-227-kem-recommendations.pdf | NIST SP 800-227, Recommendations for KEMs (September 2025) | https://doi.org/10.6028/NIST.SP.800-227 | correctness definition, failure leakage |
| nist-pqc-call-for-proposals-2016.pdf | NIST PQC Call for Proposals (2016) | https://csrc.nist.gov/projects/post-quantum-cryptography | 2^64 chosen-ciphertext limit |

## Claim ledger

| # | claim | status | source |
|---|---|---|---|
| 1 | FIPS 203 Table 1 decapsulation failure rates: ML-KEM-512 2^-138.8, ML-KEM-768 2^-164.8, ML-KEM-1024 2^-174.8 | VERIFIED | nist-fips-203-ml-kem.pdf, section 3.2, Table 1, PDF p.24 (printed p.15) |
| 2 | FIPS 203 cites Theorem 1 of [8] (Bos et al., EuroS&P 2018) and the scripts in [15] (Ducas-Schanck, pq-crystals/security-estimates) for Table 1 | VERIFIED | nist-fips-203-ml-kem.pdf, PDF p.24; references PDF pp.50-51 |
| 3 | FIPS 203 defines the failure probability over random seeds d, z, m, with hash functions and XOFs modelled as random | VERIFIED | nist-fips-203-ml-kem.pdf, section 3.2, PDF p.24 |
| 4 | ML-KEM parameters: n=256, q=3329; (k, eta1, eta2, du, dv) = (2,3,2,10,4), (3,2,2,10,4), (4,2,2,11,5); RBG strength 128/192/256 | VERIFIED | nist-fips-203-ml-kem.pdf, section 8, Table 2, PDF p.48 |
| 5 | FIPS 203 rounding: x = y + 1/2 rounds up to y + 1 | VERIFIED | nist-fips-203-ml-kem.pdf, section 2.3, PDF p.15 |
| 6 | Kyber round-3 spec Table 1: delta = 2^-139, 2^-164, 2^-174; computed with the security-estimates script | VERIFIED | 2021-avanzi-et-al-kyber-round3-specification.pdf, section 1.4, Table 1, PDF p.11 |
| 7 | Decryption error of K-PKE is e^T r + e2 + cv - s^T(e1 + cu) | COMPUTED | algebra in section 1; same structure as Kyber_failure.py (commit 75c2694) |
| 8 | dfr.py reproduces FIPS 203 Table 1 with the 832 rule: 2^-138.775, 2^-164.812, 2^-174.761 | COMPUTED | `timeout 600 python research/scripts/pq/dfr.py validate JSON` |
| 9 | Exact-decoding DFR (random message) 2^-139.036, 2^-165.123, 2^-175.074; worst message 2^-138.943, 2^-165.010, 2^-174.961 | COMPUTED | same command |
| 10 | pq-crystals script under Python 3 prints 2^-139.1358, 2^-165.2448, 2^-175.1961 | COMPUTED | `timeout 300 python research/scripts/pq/dfr_run_pqcrystals.py SE_DIR OUT.json` |
| 11 | The 0.4-bit gap comes from q/4 = 832.25 vs 832 and from ties-to-even round() | COMPUTED | code read of proba_util.py `tail_probability`, `mod_switch` (commit 75c2694) + dfr.py emulation of both; Python 2 itself not run |
| 12 | dfr.py law equals the script's law to max relative difference 2.7e-10 | COMPUTED | `dfr.py validate JSON` |
| 13 | Negative controls: ML-KEM-768 eta1=3 -> 2^-95.17; du=9 -> 2^-87.35; ML-KEM-512 eta1=2 -> 2^-236.32; ML-KEM-1024 dv=4 -> 2^-153.80 | COMPUTED | `dfr.py validate` |
| 14 | FrodoKEM published failure rates 2^-138.7, 2^-199.6, 2^-252.5 | VERIFIED | FrodoKEM round-3 spec Table 2, PDF p.24; 2025 proposal Table A.9, PDF p.19 |
| 15 | FrodoKEM n, q, B, n-bar and error tables as listed in section 3.2 | VERIFIED | round-3 spec Tables 1, 3, 4, PDF pp.24-25; 2025 proposal Tables A.1, A.3, PDF p.15 |
| 16 | FrodoKEM decode correct for e in [-q/2^(B+1), q/2^(B+1)) (Lemma 2.18); E''' entry = 2n products + 1 sample; union bound | VERIFIED | round-3 spec section 2.2.7, Lemma 2.18, PDF pp.18-19 |
| 17 | Official failure_prob_pke.py folds x -> min(x, q-x), i.e. symmetric rule | VERIFIED | FrodoKEM-Round3.zip, FrodoKEM-20200930/Additional_Implementations/Parameter_Search_Scripts/failure_prob_pke.py |
| 18 | Official function gives 2^-138.7282, 2^-199.5571, 2^-252.4924 = dfr.py symmetric rule; exact window 2^-138.7602, 2^-199.6028, 2^-252.6053; negative controls B+1 -> 2^-34.15, 2^-50.18, 2^-63.90 | COMPUTED | `timeout 900 python research/scripts/pq/dfr_run_frodo_script.py PSS_DIR` |
| 19 | Gaussian-with-same-variance vs exact values (section 2 table) | COMPUTED | `dfr.py validate`, VALIDATE 3 |
| 20 | Kyber designers: zero failure needs less noise or larger dimension; rare failures judged a much smaller threat than e.g. hybrid attacks | VERIFIED | Kyber round-3 spec, "Allowing decapsulation failures", PDF p.13 |
| 21 | Worked example numbers (product law, 5^9 enumeration, tails, union bound, toy boosting) | COMPUTED | `timeout 600 python research/scripts/pq/dfr_worked_example.py` |
| 22 | Per-key DFR, 2 x 1000 keys: ML-KEM-768 median 2^-175.3 / 2^-174.9 (95% CIs [-175.7,-174.9], [-175.3,-174.3]), sd 5.75 / 5.82 bits, range 2^-195.7..2^-156.5; ML-KEM-1024 median 2^-182.9 / 2^-183.2, sd 4.94 / 5.09, range 2^-200.8..2^-166.6; 2^-64-probability key about 2^-132.9 / 2^-143.6 (Sanov, order of magnitude) | COMPUTED (sample + estimate) | `timeout 2400 python research/scripts/pq/dfr.py weakkeys 1000 7` and `... weakkeys 1000 20260927` (2026-09-27) |
| 23 | Toy Monte-Carlo agrees with the per-key model: z = -0.52, +0.51, -1.07 (ML-KEM-like), -0.64, -0.40 (Frodo-like) | COMPUTED | `timeout 2400 python research/scripts/pq/dfr.py simulate` (2026-09-27) |
| 24 | PKC 2019 failure boosting: alpha/beta definitions, work (alpha beta)^-1 classical, (sqrt(alpha) beta)^-1 quantum; queries 1/beta | VERIFIED | 2019-danvers-et-al...pdf, section 3, PDF pp.8-9 |
| 25 | PKC 2019 Table 1 rows (Saber 2^184/2^139/77/2^131; FireSaber 2^257/2^170/233/2^161; Kyber768 2^175/2^142/42/2^131; Kyber1024 2^239/2^169/159/2^158; LAC256 2^293/2^97/106x56/2^80; FrodoKEM976 2^188/2^188/0/0) | VERIFIED | same, Table 1, PDF p.21 (exponents read with dfr_supertext.py) |
| 26 | PKC 2019: 2^64 limit rules out failure attacks on Saber and Kyber | VERIFIED | same, PDF p.20 |
| 27 | ARV 2020: target scheme l=3, N=256, q=8192, sigma 2.00, P[F]=2^-119; quantum work 2^112.45 (n=1), 2^112.77 (n=2), 2^112.78 (n>=3) | VERIFIED | 2020-danvers-rossi-virdia...pdf, Table 1 PDF p.6, Table 4 PDF p.21 |
| 28 | ARV 2020: ss-ntru-pke claimed 2^198; multitarget 2^96.6 (vs 2^139.5 of Guo et al.) | VERIFIED | same, Table 6, PDF p.24 |
| 29 | Kyber spec: "make sure that it's hard to trigger even one failure"; pk hashed into coins prevents multi-target precomputation | VERIFIED | Kyber round-3 spec section 5.5, PDF p.33 |
| 30 | D'Anvers-Batsleer Table 3 values quoted in section 4.3 | VERIFIED | 2022-danvers-batsleer...pdf, Table 3, PDF p.26 |
| 31 | Saber attack 2^145 W and 2^126 Q vs claimed 2^172; other Saber/Kyber sets not vulnerable; Kyber1024 due to the message-space size | VERIFIED | same, PDF p.27 |
| 32 | D'Anvers-Batsleer is PKC 2022; ARV is EUROCRYPT 2020; Bindel-Schanck PQCrypto 2020; GJN CRYPTO 2020; Fahr CCS 2022; DVV PQCrypto 2019; DTVV TIS 2019; ePrint 2018/1089 (D'Anvers, Vercauteren, Verbauwhede) is 'A major revision of an IACR publication in PKC 2019'; the six-author PKC 2019 paper is at pp. 565-598 | VERIFIED | `timeout 200 python research/scripts/pq/eprint_meta.py 2021/193 2019/1399 2018/1089 2019/1392 2020/743 2022/952 2018/1172 2019/292` (re-run 2026-09-27); PKC pages from Fang-Wang-Zhao reference 6, PDF p.13 |
| 33 | GJY LAC attack: one key among ~2^64 with complexity 2^79 excluding 2^162 precomputation; ASIACRYPT 2019 | VERIFIED | 2019-guo-johansson-yang...pdf abstract PDF p.1; venue from D'Anvers-Batsleer reference 19 |
| 34 | Bindel-Schanck: HHK delta-correctness quoted as Definition 1; delta(q_d,t)-correctness Definition 2; LightSaber delta(2^64,2^128) = 2^-20.7; FrodoKEM claim "not justified" | VERIFIED | 2020-bindel-schanck...pdf, PDF pp.5, 7, 12 |
| 35 | GJN 2020: memcmp with && in FrodoKEM reference Decaps; key recovery with about 2^30 decapsulation calls | VERIFIED | 2020-guo-johansson-nilsson...pdf, abstract PDF p.1; PDF pp.13-14 |
| 36 | SP 800-227: avoid leaking failures/aborts outside the module; correctness with all but negligible probability | VERIFIED | nist-sp800-227-kem-recommendations.pdf, section 3.3 PDF p.22; Definition 2 PDF p.14 |
| 37 | Fahr et al.: Rowhammer-poisoned keygen, ~200,000 core-hours, keygen ~8 ms stretched to 1300 ms, recompute-B defence | VERIFIED | 2022-fahr-et-al...pdf, abstract PDF p.1; section 8.2 PDF p.13 |
| 38 | Fang-Wang-Zhao Table 2 values and abstract claim about Kyber-1024 | VERIFIED (as quoted) | 2022-fang-wang-zhao...pdf, abstract PDF p.1, Table 2 PDF p.13 |
| 39 | Fang-Wang-Zhao's per-key numbers are correct | UNVERIFIED | conflicts with claim 22 (medians differ by 40-50 bits); the paper itself says its upper and lower bounds differ by up to about 40 in the exponent (PDF p.10), starts from a theorem with a public-key compression term (PDF p.9), and its "mean" cannot be arithmetic (claim 71); settling needs their code |
| 40 | arXiv 2609.09983 claims certified Pr[K'!=K] <= P* <= 2^-164.81 (-log2 P* = 164.810716...) for ML-KEM-768 in a ROM/CBD model with dependencies kept | VERIFIED that the paper claims it; the result itself UNVERIFIED | 2026-duriez-tommasini-dependency-aware-correctness-bounds-ml-kem-768.pdf, abstract PDF p.1; proof (35 pages) not checked; unreviewed preprint |
| 41 | HHK: delta-correct definition; delta1(q_G) = q_G delta (Thm 3.1), corrected to (q_G+q_P) delta and QROM 8(q_G+q_P+1)^2 delta | VERIFIED | 2017-hofheinz-hovelmanns-kiltz...pdf, PDF pp.1, 7, 10-11 |
| 42 | Kyber Theorem 2 failure term 4 q_RO delta; Theorem 3 8 q_RO^2 delta; 2^64 ciphertexts give 2^-100 failure chance for Kyber768 | VERIFIED | Kyber round-3 spec PDF p.20 and section 5.5 PDF p.31 |
| 43 | FO bound-term table (section 5) | COMPUTED | `timeout 60 python research/scripts/pq/dfr_fo_bound_terms.py` |
| 44 | Kyber: DFR need not decrease with the security parameter; levels 3 and 5 below 2^-160; failure attacks excluded from claims | VERIFIED | Kyber round-3 spec PDF p.21 |
| 45 | Kyber512 round-3 change: more noise, one less dropped bit in the second ciphertext element, 736 to 768 bytes, 2^-139; eta 2 to 3 | VERIFIED | Kyber round-3 spec, change log PDF p.2; eta from NIST IR 8413 PDF p.38 |
| 46 | NIST IR 8413: Kyber512 change kept DFR below "the requisite threshold"; delta-correct definition; BIKE needs delta <= 2^-lambda; HQC-256-1 broken in round 2 | VERIFIED | nist-ir-8413-pqc-round3-report.pdf, PDF pp.38, 39, 43 |
| 47 | NIST IR 8545: delta <= 2^-lambda; HQC discarded sets with DFR above 2^-lambda (May 2020); stable DFR analysis decisive for HQC over BIKE | VERIFIED | nist-ir-8545-pqc-round4-report.pdf, PDF pp.18-19 |
| 48 | FrodoKEM: failure boosting gives no improvement for Frodo-1344; "overhead ... exceeds 3.5 bits"; PKC 2019 scripts run on all sets | VERIFIED | FrodoKEM round-3 spec section 5.2.5, PDF p.45; 2025 proposal section 9.3, PDF p.12 |
| 49 | NIST Call: no more than 2^64 chosen ciphertexts; classical decryption queries | VERIFIED | nist-pqc-call-for-proposals-2016.pdf, section 4.A.2 (read with pdfgrep.py) |
| 50 | LAC-v3 Table 2 parameters (BCH codes, bit error rates, decryption error rates) | VERIFIED | 2018-lu-et-al-lac...pdf, Table 2, PDF p.16 |
| 51 | LAC-v3 made BCH constant time | VERIFIED | same, PDF p.6 |
| 52 | DVV 2019: independence can underestimate with ECC; LAC-128 up to 2^48 | VERIFIED | 2019-danvers-vercauteren-verbauwhede...pdf, abstract PDF p.1 |
| 53 | DTVV 2019: LAC key < 2 min with < 2^16 queries; Ramstake ~2400 queries | VERIFIED | 2019-danvers-tiepelt...pdf, abstract PDF p.1 |
| 54 | Round5 XEf: table-free majority decoder; needs independent errors; Phi_{n+1} causes correlation; uses x^{n+1}-1 and balanced secrets; ~25% lower bandwidth | VERIFIED | 2019-baan-et-al-round5...pdf, PDF pp.5, 10-11, 39 |
| 55 | NIST IR 8413: HQC removed BCH-repetition decoder; side-channel attacks on HQC found | VERIFIED | nist-ir-8413-pqc-round3-report.pdf, PDF p.43 |
| 56 | NTRU finalist parameter sets are perfectly correct; NTRU Prime eliminates decryption failures | VERIFIED | nist-ir-8413-pqc-round3-report.pdf, PDF pp.47, 49 |
| 57 | Sweep values in section 7 | COMPUTED | `timeout 1200 python research/scripts/pq/dfr.py sweep` |
| 58 | dfr.py boost bracket (iid .. typical), cheapest quantum first-failure cost: ML-KEM-768 2^158.5..2^161.5; ML-KEM-1024 2^166.5..2^170.6; k4 q3329 eta2 no compression 2^211.9..2^220.5; k4 q7681 eta2 du11 dv5 2^572.9..2^593.4; k4 q7681 eta3 2^307.8..2^317.4; no point reaches beta >= 2^-64 | COMPUTED (estimate from a simplified model) | `timeout 1500 python research/scripts/pq/dfr.py boost` (2026-09-27; supersedes the earlier typical-point-only run) |
| 59 | Zhou et al. 2026: refined method moves CNTR-Prime DFR bound at least 84 bits up | VERIFIED (as quoted; preprint) | 2026-zhou-et-al-refined-evaluation-dfr-message-encoding.pdf, abstract PDF p.1 |
| 60 | Majenz-Sisinni: LWE implies FFP-NG for PVW with discrete Gaussian errors (preprint) | VERIFIED (as quoted) | 2024-majenz-sisinni...pdf, abstract and Theorem 1 (informal), PDF pp.1-2 |
| 61 | Fluhrer 2016: RLWE key exchanges broken under key-share reuse; GJS 2016: QC-MDPC key recovery from decoding failures, CCA proofs omitted decoding errors | VERIFIED | 2016-fluhrer...pdf and 2016-guo-johansson-stankovski...pdf, abstracts PDF p.1 |
| 62 | Jaulmes-Joux chosen-ciphertext attack on NTRU, CRYPTO 2000 | VERIFIED (citation only) | reference 21 of 2022-danvers-batsleer...pdf; the paper itself was not read |
| 63 | Guo-Johansson-Stankovski is ASIACRYPT 2016, pp.789-815; Fluhrer is ePrint 2016/085 (preprint); HHK is TCC 2017 (ePrint 2017/604) | VERIFIED | NIST IR 8413 reference [190]; `eprint_meta.py 2016/085 2017/604` |
| 64 | FrodoKEM round-3 spec's failure-boosting check used the PKC 2019 scripts (its reference [50]) | VERIFIED | FrodoKEM round-3 spec PDF p.45 and reference [50] |
| 65 | Barbosa et al. Table 1: ML-KEM-768 provable 2^-80, heur(cu,cv) 2^-164, heur(cu) 2^-158; ML-KEM-1024 2^-95, 2^-174, 2^-169; FrodoKEM-640/976/1344 provable 2^-138, 2^-199, 2^-252 | VERIFIED | 2025-barbosa-et-al-formally-verified-correctness-bounds-lattice.pdf, Table 1, PDF p.13 |
| 66 | Barbosa et al.: optimal t_cu 296 (ML-KEM-768, partial probabilities 2^-81 and 2^-82) and 240 (ML-KEM-1024, 2^-96 and 2^-97) | VERIFIED | same, section 5.5, PDF p.12 |
| 67 | Barbosa et al.: proving that the heuristic bound applies to ML-KEM "is an open problem"; their provable bound "is significantly larger than the heuristic one"; FrodoKEM bound proven without heuristic approximations (except the ROM) | VERIFIED | same, footnote 4 PDF p.3; section 4 PDF p.8; abstract PDF p.1 |
| 68 | Barbosa et al. is ACM CCS 2025, ePrint 2025/1562 | VERIFIED | `timeout 100 python research/scripts/pq/eprint_meta.py 2025/1562` ("Published elsewhere. Minor revision. ACM CCS 2025") |
| 69 | dfr.py reproduces all six ML-KEM values of Barbosa Table 1 (">=" test: 2^-80.48, 2^-164.38, 2^-158.44; 2^-95.66, 2^-174.33, 2^-169.37) and the optimal t_cu (296, 240); ">" test gives 2^-80.95, 2^-164.81, 2^-158.87; 2^-96.16, 2^-174.76, 2^-169.81; negative control dv = 5 moves them | COMPUTED | `timeout 900 python research/scripts/pq/dfr.py provable`; `timeout 600 python research/scripts/pq/dfr_barbosa_explore.py` |
| 70 | Proven (split) bounds for dimension-1024 variants: q3329 eta2 no compression 2^-229.5 (">=" test; exact 2^-230.6 is itself proven); q7681 eta2 du11 dv5 2^-320.6; q7681 eta3 2^-170.2 | COMPUTED | `timeout 900 python research/scripts/pq/dfr.py provable` |
| 71 | An arithmetic mean of 300 probabilities with maximum 2^-148 is at least 2^-156.2 (2^-174.2 for maximum 2^-166) | COMPUTED | log2(2^-148/300) = -148 - log2(300) = -156.23 (arithmetic) |
| 72 | Fang-Wang-Zhao: upper/lower bound gap usually below 40 in the exponent (900 samples); 300 keys per set, several hours each; theorem with ct term | VERIFIED | 2022-fang-wang-zhao...pdf, PDF pp.9-11 |
| 73 | Qayyum-Bezzateev artifact: dependency-preserving bound 2^-127.42 for ML-KEM-768 using abs(cv) <= 104 | UNVERIFIED | second-hand from arXiv 2609.09983 PDF pp.2, 6; Zenodo record 21458662 not opened |
| 74 | Duriez-Tommasini: model assumptions (independent uniform matrix streams, CBD(2)); "164.82 is not certified"; generative-AI use disclosed | VERIFIED (as stated in the preprint) | 2026-duriez-tommasini...pdf, PDF pp.1, 3, 32 |
| 75 | NIST IR 8545: HQC's DFR analysis assumes independent coordinates (footnote 2); a low DFR is needed for the FO proof and against key-reuse attacks; HQC added a salt against multi-ciphertext attacks | VERIFIED | nist-ir-8545-pqc-round4-report.pdf, PDF p.18 |
| 76 | NIST IR 8413: HQC-256-1 broken in round 2 by reference [208], Guo and Johansson, "A new decryption failure attack against HQC" (2020) | VERIFIED | nist-ir-8413-pqc-round3-report.pdf, PDF p.43 and reference list PDF p.78 |
| 77 | D'Anvers-Batsleer: reducing the message-space size or raising t (less compression of v) raises the attack cost; raising t "generally has no impact on the security of the scheme under non-decryption failure attacks" | VERIFIED | 2022-danvers-batsleer...pdf, section 8.2, PDF p.27 |
| 78 | Automated re-check of quoted VERIFIED claims against the PDFs: 133 checks (128 quotations or number groups on the cited page, 5 negative controls), all PASS | COMPUTED | `timeout 300 python research/scripts/pq/dfr_verify_sources.py` |
| 79 | NewHope1024: n = 1024, q = 12289, CBD k = 8, each key bit encoded into 4 coefficients, DFR 2^-216 ("less than" per the designers' script); CPA-version attack needed about 4000 decryption requests | VERIFIED | 2019-alkim-et-al-newhope-round2-specification.pdf, PDF pp.20, 21, 36 |
| 80 | Zhou et al. 2026: encoding DFR methods "rely on oversimplified assumptions, rough approximations"; refined bounds move about 15 bits (CNTR, down), 1 bit (Scloud+), at least 84 bits (CNTR-Prime, up); preprint | VERIFIED (as quoted; preprint) | 2026-zhou-et-al-refined-evaluation-dfr-message-encoding.pdf, abstract PDF p.1; ePrint 2026/1350 metadata "Preprint" via eprint_meta.py |
| 81 | One more bit of dv at k = 4, n = 256 costs 256 bits = 32 bytes of ciphertext and moves the DFR from 2^-175.1 to 2^-185.6 | COMPUTED | 256 coefficients x 1 bit; DFR values from `dfr.py sweep` (claim 57) |
| 82 | HHK delta-correctness: E over keys of max over m of Pr[Dec != m] <= delta | VERIFIED | 2017-hofheinz-hovelmanns-kiltz...pdf, PDF p.7 |
| 83 | For per-coefficient encodings delta_HHK <= 2 x random-message union bound; ML-KEM-768: <= 2^-164.123 | COMPUTED | argument in section 5; 2^-165.123 from `dfr.py validate` plus 1 bit |
| 84 | NIST IR 8413: BIKE PKE must be delta-correct for delta <= 2^-lambda; the maximum DFR over all messages is difficult to compute for BIKE; IR 8413-upd1 dated July 2022 with updates as of 09-26-2022 | VERIFIED | nist-ir-8413-pqc-round3-report.pdf, PDF p.39; PDF p.2 |
| 85 | Safe decoding radius for both bits at q = 3329 is 831 (bit 0 alone 832); ML-KEM-768 worst-case error 9322; max abs(cv) = 104 for dv = 4 | COMPUTED | `timeout 400 python research/scripts/pq/dfr_perfect_correctness.py` (sanity block, PASS) |
| 86 | Smallest perfectly correct q (n = 256): k4 eta2 no compression 32778; k4 eta2 du13 dv13 65562; k4 eta2 du11 dv5 none below 2^22; k4 eta1 no compression 8198; k4 eta1 du12 dv6 16918; k3 eta2 no compression 24586; k4 eta3 73742; next primes = 1 mod 512 as tabulated | COMPUTED | same command |
| 87 | 7681 and 12289 are prime and = 1 mod 512 | COMPUTED | `python -c "from sympy import isprime; print([(q, isprime(q), (q-1) % 512) for q in (7681, 12289)])"` |
| 88 | Re-run of `dfr.py simulate` after this session's edits: same z-values as claim 23 (-0.52, +0.51, -1.07, -0.64, -0.40) | COMPUTED | `timeout 2400 python research/scripts/pq/dfr.py simulate` (2026-09-27) |
| 89 | Shao et al. Table 4: Kyber DFR with CBD 2^-139.1 / 2^-165.2 / 2^-175.2 and with uniform noise over the same range 2^-25.4 / 2^-50.3 / 2^-47.5; key recovery for uniform Kyber512 from 3,000 failures at about 2^37; uniform "enhances the LWE hardness"; preprint | VERIFIED (as quoted; preprint) | 2024-shao-et-al-lwe-kems-under-various-distributions-kyber.pdf, Table 4 PDF p.7; abstract PDF p.1; PDF p.10; ePrint 2024/1979 metadata "Preprint" |
| 90 | dfr.py model reproduces Shao Table 4 (Python-3 reading): 2^-139.14, 2^-25.42, 2^-165.24, 2^-50.25, 2^-175.20, 2^-47.49; FIPS reading 2^-138.77, 2^-25.34, 2^-164.81, 2^-50.11, 2^-174.76, 2^-47.36; negative control uniform [-3,3] for ML-KEM-768 gives 2^-11.08 | COMPUTED | `timeout 300 python research/scripts/pq/dfr_uniform_twist.py` |
| 91 | Das 2026: wolfSSL AVX2 FO check compared 1536 of 1568 bytes, NEON about half; 98.0% of ML-KEM-1024 key at 400 ciphertexts (AVX2), 98.5% at 600 (NEON), full key about 1300 in the reference model; CVE-2026-10097 and CVE-2026-6330 fixed in wolfSSL 5.9.2 (as cited); testing lesson on last-byte differences; preprint | VERIFIED (as stated in the preprint; CVE records not opened) | 2026-das-incomplete-ciphertext-comparison-ml-kem.pdf, abstract PDF p.1; PDF pp.2, 7, 9; ePrint 2026/1682 metadata "Preprint" |
| 92 | Fang-Li-Zhao 2026: decoder certificates fail more often than messages; within-block dependence from polynomial multiplication; BW-KEM block sums 6.537-7.621 bits below published Chernoff sums; CTRU 2,396 exits with 26 message failures; preprint | VERIFIED (as quoted; preprint) | 2026-fang-li-zhao-dfr-multidimensional-lattice-decoders.pdf, abstract PDF p.1; ePrint 2026/1924 metadata "Preprint" |
| 93 | QROM failure term 8 q^2 delta reaches 1 at q = 2^113.8 (delta 2^-230.6), 2^126.5 (2^-256), 2^158.8 (2^-320.6) | COMPUTED | (-log2 delta - 3)/2, `python -c "for d in (230.6,256,320.6): print(d, (d-3)/2)"` |
| 94 | PKC 2019 Table 1 attack cost = S_simplified(i) + i sqrt(1/alpha) (1/beta), unlimited decryption queries; Kyber analysed with its public-key rounding term | VERIFIED | 2019-danvers-et-al...pdf, PDF p.19 |

## Open questions

1. **A proven DFR for ML-KEM at the heuristic scale.** Barbosa et al. (CCS 2025) prove only
   2^-80 / 2^-95 and call the gap an open problem; an unreviewed September-2026 preprint
   (arXiv 2609.09983) claims 2^-164.81 for ML-KEM-768 in a ROM/CBD model, and a Zenodo artifact
   (Qayyum-Bezzateev) is reported at 2^-127.42. What would settle it: peer review of the preprint
   or an independent replay of its certificate. For Turing this matters only if a compressed
   design is chosen; item 2a of "What this means for Turing" avoids the question.
2. **Failure-attack cost at Turing's parameters.** `dfr.py boost` gives a bracketed estimate
   from a simplified model. Once candidate parameters exist, run the KULeuven-COSIC
   decryption-failures code (PKC 2022; github.com/KULeuven-COSIC/PQCRYPTO-decryption-failures,
   not run here) or reimplement its levelled multi-target cost, and compare with 2^-lambda.
3. **Target choice.** 2^-lambda (FrodoKEM/HQC/NIST IR 8545 style), 2^-lambda met by a proven
   bound (Barbosa-style), or ML-KEM's "below about 2^-160 at any level". The owner decides;
   sections 4.2, 4.6 and 5 give the evidence for each.
4. **Per-key behaviour without the heuristic.** This work's per-key medians (2^-175.1 for
   ML-KEM-768) and Fang-Wang-Zhao's (2^-222) are not comparable (section 4.6). With no
   ciphertext compression the per-key computation needs no heuristic at all; for a compressed
   design it is open.
5. **Key rejection for heavy keys.** Rejecting keys whose per-key DFR is high would cut the
   weak-key tail, but changes the secret distribution; no published analysis for LWE KEMs was
   found. Open, and a risk flag if pursued.
6. **Frodo-style plain LWE at n = 1024.** With the Frodo-976 table and B = 3 the DFR is 2^-191.2,
   just above 2^-192; a Turing plain-LWE option would need its own error table and a Renyi
   divergence argument as FrodoKEM has (sibling *pq-families-for-diversity*).
7. **NewHope-style redundant encoding at n = 1024.** Its published 2^-216 was not reproduced,
   and the dependence among the four coefficients of a group was not analysed here. Settling it
   needs NewHope's failure script (NIST round-2 package) or a dependency-aware computation.
8. **Jaulmes-Joux (CRYPTO 2000)** is cited from a reference list only (claim 62); low importance.
