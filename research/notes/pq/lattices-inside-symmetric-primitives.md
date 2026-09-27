# Lattices inside the symmetric layer: LWR PRFs, lattice hashes and cipher cascades

Status: complete for this research pass (2026-09-27). Scripts:
`lis_toys.py` and `lis_costs.py` (both OVERALL: PASS), `lis_findpage.py`
(page checks), `lis_render.py` (page images), `lis_fetch.py` (downloads).

This file covers putting lattice hardness inside Turing's symmetric layer
rather than (or as well as) a public-key KEM: pseudorandom functions built
from Learning With Rounding (LWR), the SPRING family, key-homomorphic PRFs,
the SWIFFT/SWIFFTX lattice hashes, lattice-based block-cipher proposals, and
the theory of combining a lattice primitive with Turing (cascades, XOR of
keystreams, robust combiners). Date checked: 2026-09-27. Lattice basics
(LWE, ring-LWE, module-LWE) are explained in the sibling note
`lattice-foundations.md`; concrete attack-cost methodology is in
`attack-cost-estimation.md`; timing leaks in modular arithmetic are in
`side-channels-faults-and-ct-verification.md`.

## Key findings

1. **There is no lattice-based block cipher to borrow.** No peer-reviewed,
   third-party-analysed lattice block cipher was found. Lattice symmetric
   primitives are PRFs and generators (BPR 2012, SPRING 2014, SPRING-RS 2017,
   GGM module-LWR 2019, LEAP 2025) and hashes (SWIFFT, SWIFFTX). A lattice PRP
   exists only on paper, through a Luby-Rackoff Feistel network (section 6).
2. **Proofs and practicality have never met at Turing's target.** The
   provable lattice PRFs (BPR, BLMR, Banerjee-Peikert) need moduli
   exponential or quasi-polynomial in the input length. SPRING and SPRING-RS
   drop the proof ("No security proof"). The best-founded practical design,
   the GGM module-LWR PRF (Chuengsatiansup-Stehle, SAC 2019), works in
   dimension 768 and gives 128-bit PRF security for at most 2^34 queries at
   39.4 cycles/byte. Nothing published gives a reduction-backed 256-bit PRF
   (sections 2, 3, 3b, 8.3).
3. **LEAP (ToSC 2025) is fast but young.** 1.14-1.61 cycles/byte and a
   claimed 256-bit level, but the parameters are set for "RLWR with hidden
   a", a problem variant published one year ago; no third-party analysis was
   found (section 3b).
4. **SWIFFT-style lattice hashes cannot supply secrecy.** SWIFFT is linear
   (f(x1) + f(x2) = f(x1 + x2)), so it is not a PRF; it gives collision
   resistance only, and its collisions cost about 2^109 bit operations
   (Kirchner 2011). SWIFFTX needed a conventional S-box layer to destroy the
   linearity (section 5).
5. **The historical record warns against home-made lattice twists.** LASH, a
   lattice hash whose parameters were changed for speed, lost its proof and
   was broken (collisions 2^(4x/11)); Rubato, which added LWE-style noise to a
   low-degree cipher, had its key recovered for five of six variants at
   CRYPTO 2023 (e.g. 2^57.06 time for Rubato-80M when q has the factor 12).
   Putting lattice operations inside Turing's rounds or key schedule would be
   new unanalysed structure with no proof (section 6, 8.1 option A).
6. **The research-backed twist is a robust combiner, not a new primitive.**
   Maurer and Massey (1993, Corollary 2) prove that the XOR of keystreams from
   generators with independent keys is at least as hard to predict as the
   hardest one, and recommend cascading generators built on different design
   principles. "Turing-CTR XOR lattice-PRF keystream" is a PRF if EITHER part
   is a PRF (reduction written out in 7.3). The guarantee is the maximum of
   the two, not the sum.
7. **The combiner's conditions are strict.** Keys must be independent (same
   key and function gives an all-zero keystream); a shared key-derivation step
   (cSHAKE256, the KEM's hash) stays a single point of failure; a repeated
   nonce still leaks m1 XOR m2; it protects confidentiality only, and cascade
   is not a robust combiner for IND-CCA2 (Herzberg), so integrity needs its own
   design, e.g. the copy combiner for MACs (section 7).
8. **Re-keying helps against exactly Bombe's attack classes, but needs no
   lattice.** Abdalla and Bellare (2000) prove re-keying extends the safe
   number of encryptions and motivate it by differential, linear and birthday
   attacks. cSHAKE256 already provides it; a lattice-only KDF would add a
   single point of failure (section 7.4).
9. **Key-homomorphic lattice PRFs are features, not strength.** They enable
   key rotation of stored data and key splitting, but carry an error term,
   large parameters and a built-in additive key relation; they must never
   derive Turing keys (sections 4, 7.5).
10. **Costs.** Against Turing's current speed (about 1200 cycles/byte for
    version 2, under a clock assumption) a lattice keystream adds 0.1% to 5%;
    against an AES-NI-class cipher it would cost 3.6x to 143x. Key material
    grows from 32 bytes to 192 bytes-18 KB. Biased rounding forces rejection
    sampling (data-dependent timing) unless the moduli are powers of two;
    non-power-of-2 reduction is the KyberSlash risk (section 8.2).
11. **No lattice PRF has been analysed with Bombe's tools.** None of the
    candidates has published differential, linear, boomerang or degree
    analysis of the Bombe kind; the combiner does not make Turing itself
    harder to break, it adds an independent second line for the encryption
    layer (section 8).

## 1. Background: from LWE to LWR, and why rounding gives a PRF

**LWE in one line.** Pick a secret vector s in Z_q^n. An LWE sample is a
random public vector a and the number b = <a, s> + e mod q, where e is a
small random error. Without e, a few samples and Gaussian elimination give s.
With e, recovering s (or even telling b from random) is believed hard for
large n, classically and quantumly (sibling note `lattice-foundations.md`).

**Why LWE does not directly give a PRF.** A PRF must be deterministic: the
same key and input must always give the same output. LWE needs fresh random
error for every sample. Banerjee, Peikert and Rosen (BPR, EUROCRYPT 2012)
say this directly: earlier noisy-learning symmetric primitives are
"inherently randomized functions" and "this is not an option for
deterministic primitives like PRFs" (BPR, research/papers/2012-banerjee-
peikert-rosen-pseudorandom-functions-lattices.pdf, PDF p. 2).

**Learning With Rounding (LWR).** BPR's fix is to replace the random error
by deterministic rounding. With a modulus p < q, map x in Z_q to
round_p(x) = round((p/q) * x) mod p (BPR eq. 2.1, PDF p. 8). An LWR sample is
(a, round_p(<a, s>)). The "error" is the part of <a, s> that rounding throws
away; it has size about q/p, so the error rate is about 1/p (BPR PDF p. 3).
When q and p are both powers of 2, rounding down is just dropping low bits
(BPR PDF p. 8), which is cheap and constant time.

Worked example (script `research/scripts/pq/lis_toys.py`, section A):
q = 64, p = 8, n = 4. Rounding keeps the top 3 of 6 bits. The script shows
that one LWR sample hides the low 3 bits of <a, s>, and that when p does
not divide q (q = 257, p = 2) the rounded output is biased by exactly 1/q,
which is the bias SPRING has to remove (section 3).

**What is proven about LWR, and for which parameters.**

- BPR Theorem 3.2 (PDF p. 11): for a B-bounded LWE error, if q >= p * B *
  n^omega(1), decision-LWR(n, q, p) is at least as hard as decision-LWE(n, q)
  for the same secret distribution, for ANY number of samples. The modulus is
  super-polynomial, far larger than practical schemes use. BPR add (PDF p. 11)
  that the attacks known to them suggest LWR may be exponentially hard as long
  as q/p >= sqrt(n) is an integer; that is a conjecture, not a proof.
- Bogdanov, Guo, Masny, Richelson, Rosen ("On the hardness of learning with
  rounding over small modulus", research/papers/2016-bogdanov-et-al-hardness-
  lwr-small-modulus.pdf, PDF p. 1-3) prove LWR hard from LWE with a
  polynomial modulus, but only when the number of samples m is at most about
  q/(2Bp) (condition q >= 2mBp, Theorem 3). For UNBOUNDED samples their
  Theorem 5 only reduces from LWE with uniform noise on [-q/2p, q/2p), a
  variant they say "is not known to be as hard as" LWE with Gaussian noise
  (PDF p. 3).

**Why the sample bound matters for Turing.** A KEM public key is a few
hundred LWR samples. A keystream or PRF gives the attacker as many samples as
it produces output, easily 2^40 or more. So a symmetric LWR design sits in
exactly the regime where the polynomial-modulus proofs stop applying, and
where attacks that need many samples (BKW, Arora-Ge) become relevant (BPR PDF
p. 3 names both; SPRING section 4.1 analyses both, see section 3 here).

## 2. Banerjee-Peikert-Rosen (BPR) PRFs, EUROCRYPT 2012

Source: research/papers/2012-banerjee-peikert-rosen-pseudorandom-functions-
lattices.pdf (ePrint 2011/401 version dated August 10, 2011; 25 PDF pages).

**The synthesizer.** S(a, s) = round_p(<a, s>) (BPR eq. 1.2, PDF p. 4). A
"synthesizer" is a two-input function whose m x m table of outputs looks
random for random inputs. Naor and Reingold's tree construction turns a
synthesizer into a PRF on k-bit inputs with about lg k levels (BPR eq. 1.1,
1.3, PDF p. 4). The security proof needs a chain of moduli, and its strongest
assumption is LWR with a "quasi-polynomial inverse error rate
1/alpha ~ q_d = n^O(lg k)" (PDF p. 5).

**The direct "rounded subset-product" PRF.** Key: a public-shaped vector a
and k secret matrices S_1..S_k (or ring elements s_i). For input bits
x_1..x_k:

    F(x) = round_p( a^T * prod_{i: x_i = 1} S_i )          (BPR eq. 1.4, PDF p. 5)

The ring version replaces matrices by ring elements, so each step is one
ring multiplication, done with an NTT in O(n log n) (PDF p. 4-5).

**What is proven.** Theorem 5.2 (PDF p. 17): with the S_i drawn SHORT from a
discrete Gaussian of parameter r, and q >= p * k * (C r sqrt(n))^k * n^omega(1),
F is a PRF under decision-LWE. Theorem 5.3 is the ring version. The modulus
grows exponentially in the input length k, because the proof adds a noise term
after every multiplication and those terms are amplified by the later
multiplications (PDF p. 6). BPR say plainly that this looks like an artifact
of the proof, conjecture that smaller moduli are secure, and call finding
effective attacks "a very interesting and important research direction"
(PDF p. 6-7).

**A built-in pitfall.** If the key elements are uniform and k is too large
relative to q, the ring function breaks: each s_i has each NTT ("Fourier")
coefficient 0 with probability about 1/q, so a product of k = O(q log n)
random s_i is 0 with noticeable probability, and F returns zero on the
all-ones input (PDF p. 7). The countermeasure is to require invertible s_i.
This is a concrete example of why "just use lattice maths" needs parameter
care.

**Speed.** BPR give no implementation. Their instantiation needs moduli like
n^(O(k)), which SPRING's authors call "too large for practical use" (SPRING
abstract, PDF p. 1).

## 3. SPRING (FSE 2014) and its cryptanalysis

Source: research/papers/2014-banerjee-et-al-spring-prf-rounded-ring-products.pdf
(Banerjee, Brenner, Leurent, Peikert, Rosen, "SPRING: Fast Pseudorandom
Functions from Rounded Ring Products", FSE 2014, LNCS 8540; 20 PDF pages).

**Definition.** R = Z[X]/(X^n + 1), n a power of 2. Key: a unit a and units
s_1..s_k in R_p^*. F(x) = S(a * prod s_i^{x_i}), with S a rounding function
(SPRING eq. 1, PDF p. 3). "SPRING" = "subset-product with rounding over a
ring".

**Parameters.** n = 128, p in {257, 514}, k in {64, 128} (PDF p. 4). These
are small: the BPR proof "requires the modulus p to be very large, i.e.,
exponential in the input length k" (PDF p. 3), and SPRING's parameters also
break the proof's other assumption (short seeds). So SPRING has NO security
reduction; its security is heuristic, argued from known attacks (PDF p. 12,
section 4.1: "The concrete security of the SPRING PRF for practical
parameters is not well understood").

**The bias problem.** With p = 257 (odd), rounding a uniform coefficient to
one bit has bias 1/q (PDF p. 4, 7). A biased PRF is not a PRF, so SPRING must
post-process:

- SPRING-BCH: multiply the 128 biased bits by the generator matrix of a
  [128, 64, 22] binary BCH code; the output is 64 bits, "2^-145-far from
  uniform" under an independence heuristic the authors state they assume
  (PDF p. 4, 7). The script `lis_toys.py` (section B) recomputes this bound,
  (1/q)^d * sqrt(2^m) / 2 = 2^-145.1.
- SPRING-CRT: p = 2q = 514; R_2q splits into R_2 x R_q by the Chinese
  remainder theorem; rounding gives n - 1 unbiased bits (PDF p. 5). The
  authors also show this CRT split "can be exploited somewhat in attacks"
  (PDF p. 5).

**Speed (authors' Table 1, PDF p. 6, cycles per output byte).**

| CPU | SPRING-BCH CTR | SPRING-CRT CTR | AES-CTR without AES-NI | AES-CTR with AES-NI |
|---|---|---|---|---|
| Core i7 Ivy Bridge | 46 | 23.5 | 5.4 | 1.3 |
| ARM Cortex A15 | 170 | 77 | 17.8 | N/A |

So SPRING-CRT in counter mode is about 4.5 times slower than AES without
AES-NI and about 18 times slower than AES-NI (23.5 / 1.3). Counter mode uses
a Gray code so each output needs one ring multiplication (PDF p. 5).

**The authors' own attack analysis (section 4, PDF p. 12-14).**

- Lattice attacks: dimension N >= n lg(p/2) >= 896; cost >= 2^(0.48 N) >=
  2^430 time, space >= 2^(0.18 N) >= 2^160 (PDF p. 13). Recomputed in
  `lis_toys.py` section C.
- Arora-Ge linearisation: time and space at least N^2, "at least 2^384 for
  even the most aggressive of all our parameters" (PDF p. 13).
- Birthday attack on SPRING-CRT (section 4.2, PDF p. 14): find inputs y, y'
  whose subset products agree mod 2, so the R_2 part cancels in
  F(y||z) XOR F(y'||z), leaving a 1/q^2 bias to detect. General cost:
  time 2^(n/t) * q^(4t) / (2t). Best case t = 2 gives time "roughly
  2^(64+64-2) = 2^126" (PDF p. 14). `lis_toys.py` section C reproduces
  2^126.0. **Discrepancy found:** the paper's query/space formula for t = 2
  is 2^(n/4) * q^8/(4n), which evaluates to 2^87.0, but the paper's final
  sentence uses 2^(n/2) * q^8/(4n) ~ 2^119 (both on PDF p. 14). The later
  paper by Bouillaguet et al. says of this attack: "[BBL+15] used
  i0 = 4n/kappa log2(q) so that their claimed complexity is 2^126 but this
  is not enough to get a constant advantage" (Springer abstract page,
  footnote 3; the full text was not obtainable, see Sources). Either way,
  SPRING-CRT's margin against its best known attack is below Turing's
  256-bit key target.

**Later analysis: "Fast Lattice-Based Encryption: Stretching SPRING"**
(Bouillaguet, Delaplace, Fouque, Kirchner, PQCrypto 2017, LNCS 10346,
pp. 125-142). Full paper: NOT READ (HAL is behind a bot check, the author
page does not answer, Springer is paywalled). What was read: the authors'
conference slides (research/papers/2017-delaplace-et-al-stretching-spring-
slides.pdf) and the Springer abstract page. From those:

- New variant SPRING-RS: q = 257, n = 128, k = 64, p in {2, 4, 8, 16};
  rejection sampling drops coefficients equal to 256, removing the bias
  (slides p. 11-12).
- Speed: SPRING-RS 6 cycles/byte on Core i7 Ivy Bridge and 2.8 on Haswell
  with AVX2, versus AES-NI 1.3 and 0.68 (slides p. 25). The abstract says
  "about four times slower than AES with hardware acceleration".
- Security: "No security proof", "Seems to be resistant to known attacks";
  rejection sampling brings "possible side channel leaks" (slides p. 24, 27).
  The slides' open questions are "Is there a security proof for SPRING with
  efficient parameters?" and "Are there other attacks?" (slides p. 27).
- The slides' outline says the full paper improves "some previous analysis"
  and studies a variant with part of the key made public, which "may
  undermine the security of SPRING, especially when p = 16" (Springer page,
  footnote 1, quoting the paper's Table 2 which was not read).

**How later work summarises the "Stretching SPRING" analysis.** Heimberger,
Kales, Lolato, Mir, Ramacher, Rechberger, "Leap: A Fast, Lattice-based OPRF
With Application to Private Set Intersection" (EUROCRYPT 2025; ePrint
2025/333; research/papers/2025-heimberger-et-al-leap-lattice-oprf-spring.pdf;
not to be confused with the LEAP generator of section 3b) builds an oblivious
PRF on SPRING and describes it as based on "heuristic lattice assumptions"
(abstract, PDF p. 1). Their summary of the later analysis (PDF p. 10, 22):
"The most efficient attack against Spring-CRT is a subexponential attack
[BDFK17], but the attack is currently computationally infeasible"; BDFK17
concluded that SPRING's parameters "ensure that it is a secure PRF", after
covering a birthday attack on part of the internal state (mainly affecting
counter mode) and Groebner-basis and BKW attacks; SPRING's reference
implementation is "4.5 times slower than AES". This is a secondary summary of
a paper not read here, so the details stay UNVERIFIED.

**Status of SPRING as of 2026-09-27.** No standard, no deployment found, no
proof for the practical parameters, and a published best attack (SPRING-CRT,
about 2^126 time as claimed by its designers; later called subexponential)
well below a 256-bit target. It is still used as a building block in 2025
research (the Leap OPRF), always described as heuristic. Searches for later
breaks found none (recorded in the claim ledger).

## 3b. Later practical lattice PRFs and PRGs: GGM from module-LWR (2019) and LEAP (2025)

Two later designs matter because they are the closest things to a "lattice
keystream generator" that someone has parameterised, implemented and
benchmarked.

**GGM PRF from (module-)LWR** (Chuengsatiansup and Stehle, SAC 2019; ePrint
2021/446; research/papers/2019-chuengsatiansup-stehle-ggm-prf-module-lwr.pdf).

- Idea: build a pseudorandom generator (PRG) from module-LWR, then turn it
  into a PRF with the textbook Goldreich-Goldwasser-Micali (GGM) tree. Unlike
  SPRING, this keeps a real reduction: "Our construction enjoys the security
  proof of the GGM construction and the (module-)LWR hardness assumption"
  (abstract, PDF p. 1). The authors call SPRING's instantiations "heuristic"
  (PDF p. 2).
- Implemented parameters (PDF p. 16): q = 2^16, ring degree d = 256,
  module rank n = 3 (so the lattice dimension is 3 x 256 = 768), m = 16,
  log B = 4, expansion omega = 16. Estimated module-LWR security 167 bits
  (Table 2, PDF p. 15; security is counted in the "quantum core model", PDF p. 4). Because the GGM reduction loses
  a factor per query, "this parameter set allows up to 2^34 PRF queries to still
  preserve 128-bit PRF security" (PDF p. 16). A plain-LWR variant uses n = 800,
  m = 1840, estimated 131 bits (PDF p. 16).
- Speed (Table 3, PDF p. 17, counter mode, AVX2, Skylake): 39.4 cycles
  per output byte (module-LWR), 64.2 (LWR).
- Read for Turing: this is the best-founded practical lattice PRF found in
  this search, and it targets 128-bit PRF security for at most 2^34 queries.
  Turing targets 256-bit keys. Scaling the proof to a 256-bit target and to
  2^40 or more blocks would need new parameters that nobody has published.

**LEAP** (Zhang, Lu, Liu, Yin, Wang, "LEAP: High-Performance Lattice-Based
Pseudorandom Number Generator", IACR ToSC 2025(3), pp. 151-182, published
2025-09-25, DOI 10.46586/tosc.v2025.i3.151-182; ePrint 2025/1509;
research/papers/2025-zhang-et-al-leap-lattice-based-prng.pdf).

- Idea: in ring-LWR the multiplier a is public. In a generator nothing needs
  to be public, so LEAP makes a secret as well ("treats the public parameter
  in the RLWR problem as the key", abstract, PDF p. 1). It reuses a fixed
  vector a of m ring elements with a secret s_j that is refreshed each step
  from part of the previous output (PDF p. 3-4). A second generator, LEAP.GEN,
  based on a "Vectorized-NTRU" assumption, expands a short key into a and s
  (PDF p. 4).
- Parameters (Table 2, PDF p. 14): LEAP.PRNG uses ring degree n = 256,
  q = 3329 (the ML-KEM modulus), p = 1536, m = 208; LEAP.GEN uses N = 512,
  Q = 257. Keys are 224 / 576 / 800 bytes for LEAP-128 / 192 / 256.
- Security argument: Theorem 2 bounds the generator's advantage by
  d^2 * Adv_RLWR + delta_2 (PDF p. 19-21), where d is the number of iterations.
  The concrete numbers, however, are for "RLWR with hidden a" (PDF p. 22-25),
  estimated with the lattice-estimator after mapping to LWE instances; Table 5
  (PDF p. 25) gives 340.9 classical bits (hybrid primal, the lower of its two
  classical columns) for LEAP-256's PRNG part and
  Table 4 (PDF p. 25) gives 287.9 (NTRU part) and 281.7 (RLWR part) for LEAP.GEN-256.
  Note the gap: the THEOREM reduces to ordinary RLWR, but the PARAMETERS were
  chosen with the extra security credited to hiding a, which is a new,
  lightly studied problem.
- Why hiding a could help, in plain terms: if a is public, every output
  coefficient is a linear equation in the unknown s plus a small rounding
  error, which is exactly an LWR instance and can be attacked with the
  standard lattice methods. If a is secret too, each output is a product of
  two unknowns (a_i and s_j) plus rounding error. The authors model the
  attacker's task by "larger lattice dimensions and higher standard deviations
  of error" (abstract, PDF p. 1). Whether that modelling captures every attack
  on a product of two secrets is the question nobody outside the author team
  has yet examined.
- Speed (Table 1, PDF p. 5, same machine): LEAP-256 1.61 cycles/byte (AVX2)
  and 1.14 (AVX512); SPRING-RS 5.32; [CS20] module-LWR 31.39; AES256-CTR
  0.45 with AES-NI and 8.05 without; Keccak (c = 1024) 16.17 (AVX2).
- Status: published one year before this check. No third-party cryptanalysis
  was found (searches recorded in the ledger). Treat it as a young design.

## 4. Key-homomorphic PRFs (BLMR, CRYPTO 2013) and successors

Source: research/papers/2013-boneh-et-al-key-homomorphic-prfs.pdf (Boneh,
Lewi, Montgomery, Raghunathan, full version of CRYPTO 2013, dated February 2,
2014, 41 PDF pages).

**What "key-homomorphic" means.** A PRF F is key-homomorphic if F(k1 + k2, x)
can be computed from F(k1, x) and F(k2, x) (PDF p. 1). This is a feature for
key management, not a strength property. BLMR list the uses (PDF p. 1, 4-5):
rotating the key of data stored in the cloud without downloading it,
one-round distributed (threshold) PRFs, and symmetric proxy re-encryption.

**The lattice constructions are only "almost" key-homomorphic.**

- Random-oracle version: F_lwr(k, x) = round_p(<H(x), k>). It satisfies
  F(k1 + k2, x) = F(k1, x) + F(k2, x) + e with e in {0, 1, 2}, because
  rounding is not linear (PDF p. 2).
- Standard-model version: F(k, x) = round_p( prod_{i=1..l} A_{x_i} * k ) with
  two public binary matrices A_0, A_1 and a secret vector k (eq. 1.1, PDF p. 2).
  The error e is in {0, 1, 2}^m, or {0, 1}^m if p divides q (PDF p. 2).
- Theorem 5.1 (PDF p. 14): pseudorandom under LWE with error rate alpha when
  alpha * m^l * p <= 2^(-omega(log n)). The input length l enters as an
  exponent, so with LWE at alpha = 2^(-omega(log n)) the input length is only
  l = O(1); a long input needs LWE with sub-exponentially small alpha
  (PDF p. 15). In plain words: the proof needs a very large modulus.

**Improvement: Banerjee and Peikert, CRYPTO 2014**
(research/papers/2014-banerjee-peikert-new-improved-key-homomorphic-prfs.pdf,
dated June 13, 2014). They generalise BLMR to any binary tree and weaken the
LWE assumption "from exponential in the input length to exponential in its
logarithm (or less)" (abstract, PDF p. 1). For input length lambda and 2^lambda
security against known lattice algorithms, key size drops from lambda^3 to
lambda bits and public parameters from lambda^6 to lambda^2 bits (abstract;
Figure 1, PDF p. 3). These are asymptotic statements (polylog factors
omitted); the paper gives no concrete parameters or implementation.

**Relevance to Turing.** A key-homomorphic PRF would give Turing a genuinely
new capability (re-keying stored files without decrypting them, or splitting a
key across servers), not a harder-to-break cipher. The price: large moduli
under the proofs, an error term that the output must round away, and a
malleable algebraic structure that must never be used as a MAC or as the only
layer. See section 7 for why key homomorphism is at odds with the related-key
analysis in docs/08.

## 5. SWIFFT and SWIFFTX: lattice hashing, and why SWIFFT is only collision resistant

**SWIFFT** (Lyubashevsky, Micciancio, Peikert, Rosen, FSE 2008,
research/papers/2008-lyubashevsky-et-al-swifft-fft-hashing.pdf).

- Definition: fix m multipliers a_1..a_m in R = Z_p[alpha]/(alpha^n + 1). For
  binary polynomials x_1..x_m, f(x) = sum a_i * x_i in R (eq. 1, PDF p. 4).
  Concrete parameters n = 64, m = 16, p = 257: 1024 input bits, output in
  Z_257^64, about 2^512 values, stored in 528 bits (PDF p. 4-5).
- Guarantee: finding collisions for a random function in the family is at
  least as hard as finding short vectors in ideal lattices over
  Z[alpha]/(alpha^n + 1) in the worst case, asymptotically (PDF p. 1, 9-10).
  One-wayness and second-preimage resistance follow (PDF p. 9).
- Concrete security the authors claim: best collision attack (generalized
  birthday) at least 2^106 time and almost as much space; best inversion
  about 2^448 (PDF p. 11). Buchmann and Lindner later gave experimental
  evidence that pseudo-collisions for SWIFFT are "as hard as breaking a
  68-bit symmetric cipher" by the Lenstra-Verheul heuristic, and proposed
  parameters for 127 bits (research/papers/2008-buchmann-lindner-secure-
  parameters-swifft.pdf, abstract PDF p. 1; ePrint 2008/493). Kirchner
  ("Improved Generalized Birthday Attack", ePrint 2011/377, research/papers/
  2011-kirchner-improved-generalized-birthday-attack.pdf, section 4.2, PDF
  p. 8) finds SWIFFT collisions with 2^109 bit operations, "faster than the
  2^120 bit operations of the algorithm given in" the SWIFFT paper (exponents
  confirmed with pdfspans.py). So the collision margin of the published
  parameters is near 2^109, far below a 256-bit target.
- Speed: 1.5 microseconds per compression, "close to 40 MB/s", versus
  47 MB/s for OpenSSL SHA-256 on the same 3.2 GHz Pentium 4 (PDF p. 7).

**Why SWIFFT is not a PRF: it is linear.** The paper says so itself (section
4.3, PDF p. 9): "Our family of functions is not pseudorandom ... due to
linearity. ... f(x1) + f(x2) = f(x1 + x2)" whenever x1 + x2 is also a valid
(binary) input. Three queries distinguish it from a random function.
`lis_toys.py` section D checks this identity on a random small instance. It
is also not claimed to behave like a random oracle (PDF p. 9-10). The only
non-linearity is the restriction of inputs to bits; that restriction is what
makes collisions hard (PDF p. 3), but it does nothing for pseudorandomness.
The lesson for Turing: a lattice hash of the SWIFFT type can give collision
resistance, never secrecy; putting it inside a cipher as a "mixing" layer
would add a linear map mod 257, not lattice hardness.

**SWIFFTX** (SHA-3 round-1 submission, Arbitman, Dogon, Lyubashevsky,
Micciancio, Peikert, Rosen, October 30, 2008,
research/papers/2008-arbitman-et-al-swifftx-sha3-proposal.pdf).

- Compression 2048 -> 520 bits in HAIFA mode (PDF p. 1). Three layers: three
  parallel SWIFFTs, then conversion from base 257 to bytes and 8-bit S-boxes,
  then one more SWIFFT (PDF p. 3-4).
- The S-box layer exists "to destroy the linear homomorphism of the inner
  layer ... which is a necessary condition for pseudorandomness and defeating
  k-list attacks" (PDF p. 4). The S-boxes are random permutations that "need
  not be designed to resist linear or differential cryptanalysis" (PDF p. 4).
  So the lattice layer supplies collision resistance and a conventional
  S-box layer supplies non-linearity. The same division of labour would apply
  to any Turing hybrid.
- Outcome: SWIFFTX is in the list of 51 first-round candidates (NIST IR 7620,
  research/papers/nist-ir-7620-sha3-round1-report.pdf, PDF p. 8) and is not
  among the 14 second-round candidates (PDF p. 11). NIST IR 7620 states that it
  "focuses on the reasons why candidate algorithms were selected, rather than
  providing detailed justifications for why candidate algorithms were not
  selected" (PDF p. 7). Its stated general rule was that only designs
  "roughly comparable to or better than" SHA-2 in performance advanced
  (PDF p. 11). No NIST statement gives SWIFFTX's specific reason; do not claim
  one.

## 6. Lattice-based block ciphers and other symmetric proposals

**No lattice block cipher was found.** Searches of IACR ePrint, IACR venues,
Springer and arXiv (recorded in the ledger) found no proposal for a
lattice-based block cipher (a keyed permutation on fixed-size blocks whose
security reduces to a lattice problem) that has been published in a peer-
reviewed venue and analysed by others. What exists instead are lattice PRFs
and PRGs (sections 2, 3, 3b), lattice hashes (section 5), and "noisy" ciphers
built for homomorphic encryption. In theory a pseudorandom permutation can be
built from any PRF with a Feistel network (the Luby-Rackoff construction), so a
lattice PRF gives a lattice PRP on paper; no one has parameterised or
implemented that for a lattice PRF, and each Feistel round would cost a full
lattice-PRF evaluation. Luby and Rackoff's construction composes four Feistel
rounds (three for a weaker notion), each evaluating the PRF once (as summarised
by Naor and Reingold, J. Cryptology 12, 1999, abstract, research/papers/1999-
naor-reingold-luby-rackoff-revisited.pdf, PDF p. 1; the 1988 original was not
read).

Two lower-profile lattice stream-cipher proposals were found but not read:
a PRG "based on worst-case lattice problems" turned into a stream cipher
(Cayrel, Meziani, Ndiaye and others, Applicable Algebra in Engineering,
Communication and Computing, 2017, paywalled) and "Pseudorandom Generator
Based on Hard Lattice Problem" (ePrint 2014/002). Neither appears in the
later literature read here (LEAP's comparison covers SPRING and [CS20] only).
They are recorded as UNVERIFIED leads.

The two cases below are the closest real examples. Both are warnings.

**LASH (2006): a lattice-inspired hash whose changed parameters lost the
proof, and was broken.** Source: Contini, Matusiewicz, Pieprzyk, Steinfeld,
Guo, Ling, Wang, "Cryptanalysis of LASH", FSE 2008 (ePrint 2007/430, extended
version; research/papers/2008-contini-et-al-cryptanalysis-of-lash.pdf).

- LASH was based on the provable Goldreich-Goldwasser-Halevi (GGH)
  lattice hash "but changed in an attempt to make it closer to practical":
  different matrix parameters, plus a final transform and a Miyaguchi-Preneel
  structure (PDF p. 1). "LASH is not a provable design": both changes stop the
  GGH proof from applying (PDF p. 2).
- Results (abstract, PDF p. 1): collisions in time as low as 2^(4x/11) and
  preimages in 2^(4x/7) for x-bit output (both use the all-zero IV); with any
  IV, a 2^(7x/8) preimage attack; and "LASH is trivially not a PRF when any
  subset of input bytes is used as a secret key". None of the attacks depend on
  the matrix contents.
- Lesson: taking a lattice construction with a proof, changing its parameters
  for speed and adding symmetric-style layers leaves neither the proof nor
  the maturity of a classical design. This is the most likely failure mode of
  a home-made "lattice twist" inside Turing.

**Rubato (EUROCRYPT 2022): LWE-style noise added to a low-degree cipher,
key recovered at CRYPTO 2023.** Sources: Ha, Kim, Lee, Lee, Son, "Rubato:
Noisy Ciphers for Approximate Homomorphic Encryption" (ePrint 2022/537, full
version; research/papers/2022-ha-et-al-rubato-noisy-ciphers.pdf) and Grassi,
Manterola Ayala, Hovd, Oygarden, Raddum, Wang, "Cryptanalysis of Symmetric
Primitives over Rings and a Key Recovery Attack on Rubato", CRYPTO 2023
(ePrint 2023/822; research/papers/2023-grassi-et-al-key-recovery-attack-on-
rubato.pdf).

- Design: each keystream sample is (a, E_k(a) + e), with E_k a keyed function
  of low algebraic degree over Z_q and e drawn from a discrete Gaussian
  (Rubato PDF p. 4). The authors describe it as a trade-off between LWE
  encryption and conventional symmetric encryption, and say that in LWE "noise
  prevents algebraic attacks" (PDF p. 4). Security was "supported by
  comprehensive analysis including symmetric and LWE cryptanalysis"
  (abstract, PDF p. 1).
- Parameters (attack paper Table 1, PDF p. 18): block size n from 16 to 64, modulus of
  25-26 bits, Gaussian width parameter alpha*q from 1.6 to 11.1, 2 to 5 rounds.
- Attack (attack paper abstract, PDF p. 1, and PDF p. 5-6): for at least 25% of
  the possible moduli q, key recovery costs "significantly lower than the
  claimed security level for five of the six ciphers". The noise is small
  enough to be removed by brute force, after which a linearisation attack
  recovers the key. Example: if q has the factor 12, Rubato-80M falls in time
  2^57.06 with fewer than 250,000 known keystream elements and less than
  25 GB of memory. Suggested fixes include wider noise, more rounds and
  non-polynomial S-boxes.
- Lesson: adding a small LWE-like error to a symmetric design does not import
  LWE hardness. LWE hardness needs a large dimension, a large enough error and
  a linear map in the secret; a low-degree cipher over a ring with small noise
  is a different problem, and a new structure (arithmetic over a composite
  modulus) opened a new attack.

**Where this leaves "lattice inside the block cipher".** The only lattice
symmetric primitives with a security reduction are the BPR/BLMR/BP14 PRFs at
impractical moduli and the GGM/module-LWR PRF of section 3b (128-bit target,
2^34 queries). The practical ones (SPRING, SPRING-RS, LEAP) are stream
generators with heuristic parameters. None is a drop-in round function for a
128-bit SPN, and none has been analysed against the attack families Bombe
implements (differential, linear, boomerang, algebraic, impossible
differential; docs/04).

## 7. Combining a lattice primitive with Turing: cascades, XOR, robust combiners

This is the part of the topic with real theorems behind it. The question is:
if Turing is combined with a lattice primitive, what can be PROVEN about the
result, and under which conditions?

### 7.1 Vocabulary

- A **cascade** encrypts with one cipher, then encrypts the result with a
  second cipher, with **statistically independent keys** (Maurer-Massey,
  research/papers/1993-maurer-massey-cascade-ciphers-importance-of-being-
  first.pdf, J. Cryptology 6(1):55-61, 1993; standing assumption, PDF p. 2,
  and Figure 1, PDF p. 3). If the keys may be related it is a **product
  cipher**, and nothing general can be proven: encrypting twice with the same
  additive stream cipher and the same key returns the plaintext (PDF p. 2).
  `lis_toys.py` section F checks this.
- A **(1,2)-robust combiner** for a primitive P takes two candidate schemes for
  P and yields one scheme that implements P "even if one of the candidates
  fails" (Harnik, Kilian, Naor, Reingold, Rosen, EUROCRYPT 2005,
  research/papers/2005-harnik-et-al-robust-combiners-oblivious-transfer.pdf,
  abstract and Definition 1.1, PDF p. 1-2). Herzberg used the name "tolerant
  construction" for the same idea (same paper, footnote 4, PDF p. 2).

### 7.2 What is proven

1. **A cascade is at least as hard to break as its FIRST cipher** (Maurer-
   Massey, Proposition, PDF p. 5), for very general notions of "breaking",
   assuming encryption and decryption with a known key cost little compared
   with breaking. The older "folk theorem" that a cascade is at least as strong
   as its STRONGEST component was proved by Even and Goldreich (1985), but
   Maurer and Massey show by counterexample that it needs the "uninterestingly
   restrictive assumption" that the attacker cannot use plaintext statistics
   (abstract, PDF p. 1; PDF p. 2). (Even-Goldreich itself was not read; see
   the ledger.)
2. **If the ciphers commute, every component counts as "first"**, so the
   cascade is at least as hard as the hardest component (Corollary 1, PDF
   p. 5). **Additive stream ciphers commute** (PDF p. 6). Hence Corollary 2
   (PDF p. 6): "The bitwise modulo 2 sum of n keystream sequences that are
   generated by devices with independent keys is at least as difficult to
   predict as the most-difficult-to-predict keystream sequence." The authors
   note (PDF p. 6) that the same argument works for distinguishing a
   pseudorandom generator from random.
3. **Maurer and Massey recommend exactly this design** (section 3, PDF p. 6):
   "cascade a small set of keystream generators, each relying on a different
   design principle"; the cascade "can fail only if all applied design
   principles happen to fail simultaneously". They add two costs: the total
   budget (speed, key size) must be shared among the components, and each
   component's key must be large enough to resist exhaustive search on its own.
4. **XOR of pseudorandom generator outputs is the standard combiner for
   PRGs** (Harnik et al., PDF p. 2, citing its use in the construction of
   PRGs from one-way functions by Hastad et al.). One-way functions and the
   primitives equivalent to them, which include "semantically secure private
   key encryption, pseudo-random generators, functions and permutations",
   all have robust combiners (Harnik et al., section 3.2, Lemma 3.1, PDF p. 8;
   these generic combiners go through reductions to one-way functions and are
   not efficient, so the XOR combiner is the one to use in practice).
5. **Cascade encryption is robust for IND-CPA and IND-CCA1, but NOT for
   IND-CCA2** (Herzberg, "Folklore, Practice and Theory of Robust
   Combiners", draft of November 29, 2007 of ePrint 2002/135,
   research/papers/2002-herzberg-folklore-practice-theory-robust-combiners.pdf,
   abstract, PDF p. 1). The "copy" combiner, which sends both MAC tags,
   f_{k'',k'}(m) = f''_{k''}(m) || f'_{k'}(m), is robust for MACs (same
   abstract). So secrecy and integrity need separate combiners.

### 7.3 The XOR combiner for "Turing-CTR XOR lattice keystream", step by step

Let T(k1, x) be Turing used as a PRF on 128-bit counter blocks (that is what
counter mode uses), and L(k2, x) a lattice PRF or PRG producing the same number
of bits. Define the combined keystream function

    C((k1, k2), x) = T(k1, x) XOR L(k2, x),   ciphertext = m XOR C(nonce, ctr).

Claim: if k1 and k2 are independent and uniformly random, then for every
attacker A there is an attacker B, running in about the same time as A plus
the cost of evaluating L, with Adv_prf(C, A) <= Adv_prf(T, B), and
symmetrically for L. So C is a PRF if EITHER T OR L is.

Proof sketch (the standard reduction, written out here; it is the argument
behind Maurer-Massey Corollary 2 and the PRG combiner cited by Harnik et al.):
B is given an oracle O that is either T(k1, .) or a truly random function R.
B picks its own random k2, runs A, and answers each query x with
O(x) XOR L(k2, x). If O = T(k1, .), A sees exactly C. If O = R, A sees
R(x) XOR L(k2, x), which is again a truly random function, because XOR with any
fixed-per-input value maps a uniform random function to a uniform random
function. So B's advantage equals A's. B needs k2 to be independent of k1; if
k2 were derived from k1, B could not simulate. Counter-mode encryption with C
is then IND-CPA secure by the usual counter-mode argument, provided that no
(nonce, counter) input is ever repeated.

What the claim does NOT give, each with its evidence:

- **No sum of strengths.** The proven guarantee is the maximum of the two
  components, not their sum. Maurer and Massey say the cascade can "be
  reasonably conjectured" to be much stronger, but that is a conjecture
  (PDF p. 6).
- **Independent keys are essential.** With the same key and the same
  function the XOR is all zero (`lis_toys.py` section F). With keys derived
  from ONE master key by ONE key-derivation function (Turing's cSHAKE256,
  docs/03), the security becomes "(KDF is a PRF) AND (T or L is a PRF)": the
  KDF is then a single point of failure. The same holds for a KEM shared secret
  that is hashed into both keys. So the combiner does not remove Turing's
  dependence on Keccak; it only removes the dependence on the Turing block
  cipher (or on the lattice PRF).
- **Nonce discipline is still a single point of failure.** Reusing a
  (nonce, counter) pair leaks m1 XOR m2 whatever the components are
  (`lis_toys.py` section F).
- **No integrity.** The XOR combiner gives confidentiality against chosen-
  plaintext attack only. Ciphertexts stay malleable; the AEAD still needs a
  MAC, and Herzberg shows that even the cascade combiner is not robust for
  IND-CCA2 (PDF p. 1). A MAC that must survive a break of one component would
  use the copy combiner (two tags) or a MAC built only from the component one
  trusts more.
- **Black-box only.** The proof treats T and L as black boxes. A timing leak
  in the lattice code that reveals k2 reduces the system to Turing alone (not
  worse, because k1 is independent). A leak that reveals the combined
  keystream or the plaintext breaks everything. In the XOR combiner neither
  generator ever sees the plaintext, which limits what a leaky generator can
  expose. Timing leaks in modular arithmetic are covered by the sibling note
  `side-channels-faults-and-ct-verification.md`.
- **The weaker component must still run correctly.** A bug that makes L output
  a constant is harmless for secrecy (the proof still holds through T), but a
  bug in the XOR or in the counter alignment is not covered by any theorem.
  This is a testing requirement, not a cryptographic one (sibling note
  `testing-ci-cd.md`).

### 7.4 Deriving Turing keys through a lattice PRF

Option: per-message (or per-chunk) Turing keys K_i = L(K, i), where L is a
lattice PRF and K a master key. This is **re-keying** in the sense of Abdalla
and Bellare (ASIACRYPT 2000; research/papers/2000-abdalla-bellare-increasing-
lifetime-of-a-key-rekeying.pdf). Their "parallel method" is exactly
K_i = F(K, i) (PDF p. 3). What it buys and what it does not:

- It limits the data encrypted under any one Turing key. Abdalla and Bellare
  motivate re-keying by attacks that need "lots of encryptions under a single
  key", naming differential and linear cryptanalysis and birthday attacks
  (PDF p. 3), and they prove that re-keying, properly done, increases the
  number of messages that can be safely encrypted (abstract, PDF p. 1).
  Differential and linear attacks are exactly what Bombe measures, so this is
  a real, research-backed benefit against Bombe's attack model.
- The benefit does NOT depend on L being a lattice PRF. Any PRF works; Turing
  already has cSHAKE256. With a lattice PRF, security becomes "L is a PRF AND
  Turing resists attacks with little data per key": the lattice PRF becomes a
  single point of failure (if L is predictable, every derived key is known).
  That is WEAKER than the current design unless L is itself combined with a
  classical KDF, for example K_i = cSHAKE256(K', i) XOR L(K'', i) with
  independent K' and K'' (the XOR combiner of 7.3 again).
- It does not help against an attack that recovers a Turing key from one
  message.

### 7.5 A key-homomorphic PRF as the combiner partner is a bad fit

Section 4's key-homomorphic PRFs satisfy F(k1 + k2, x) = F(k1, x) + F(k2, x) + e
with small e (BLMR, PDF p. 2). Inside a combiner this algebraic relation between
keys is harmless for PRF security (keys are independent and uniform), but it
is the opposite of what a key schedule wants: docs/08 treats related-key
attacks (Biryukov-Khovratovich) as a threat Turing is designed against. If
Turing keys were DERIVED as K_i = F(K, i) with a key-homomorphic F, then two
master keys that differ by a known Delta give derived keys that differ by the
computable amount F(Delta, i), up to the small error e. An attacker who can
cause related master keys would get related Turing keys with a known
difference; a non-homomorphic KDF such as cSHAKE256 gives no such relation.
Keep key homomorphism for its intended feature (re-keying stored data, key
splitting), never for key derivation.

## 8. Honest assessment against Bombe's attack model

Bombe measures differential, linear, boomerang, algebraic (degree, implicit
equations), impossible-differential, symmetry and key-schedule properties of
Turing (docs/04, docs/12), and the security review covers related-key,
biclique, invariant-subspace, chosen/known-key and data-limit issues
(docs/08). The question is whether a lattice component makes Turing harder to
break against those attacks.

### 8.1 Four ways to "put lattices in", ranked by evidence

| Option | What theory guarantees | Effect on Bombe's attacks | New risks | Verdict |
|---|---|---|---|---|
| A. Lattice maths INSIDE the SPN (lattice S-box, SWIFFT-style mixing layer, LWR-rounded round function) | Nothing. No lattice block cipher exists with a proof or third-party analysis (section 6). SWIFFT-type maps are linear (section 5). | Unknown and probably negative: a linear map mod 257 or a rounding step has no Bombe analysis, may lower algebraic degree or create exploitable structure. LASH and Rubato show what happens (section 6). | New unanalysed structure; mixed arithmetic (mod q and GF(2^8)) is the setting where Rubato fell; breaks Turing's existing proofs (active-S-box bounds assume the current layers). | Decoration with risk. Do not do it. |
| B. XOR combiner: Turing-CTR XOR lattice keystream, independent keys | C is a PRF if EITHER component is (Maurer-Massey Corollary 2; section 7.3). | If Bombe (or anyone) finds a differential/linear attack on Turing, the combined keystream still resists it as long as the lattice PRF holds, and vice versa. Covers the encryption layer only. | Independent keys needed; KDF/KEM hash stays a single point of failure; nonce reuse still fatal; lattice code adds timing-leak surface for its own key; more code to test. | Research-backed. Proven "max of the two", not "sum". The only option that is a genuine robustness gain. |
| C. Re-keying: per-message Turing keys from a PRF | Abdalla-Bellare 2000: re-keying increases the safe number of encryptions (section 7.4). | Directly limits the data any one Turing key sees, which caps differential, linear and boomerang attacks that need many texts under one key. | If the KDF is a lattice PRF alone, it is a single point of failure; must be combined with cSHAKE256 (XOR) to avoid weakening. | Research-backed, but the benefit comes from re-keying, not from lattices. cSHAKE256 already does it. |
| D. Key-homomorphic PRF for re-keying stored files or splitting keys | BLMR/BP14: PRF under LWE for large moduli (section 4). | None (a feature, not a strength). | Almost-homomorphic error, large parameters, algebraic key relations; never for key derivation (section 7.5). | Only if the product wants that feature. |

### 8.2 What each option costs

Numbers from `lis_costs.py` (COMPUTED from the cited tables; machines differ,
so treat them as orders of magnitude):

- Turing's current implementation: 4.5 us per block for version 2
  (docs/13), about 1203 cycles/byte if that timing was taken at this
  machine's reported 4.276 GHz (an assumption).
- Published lattice keystreams: LEAP-256 1.61 c/B (AVX2), SPRING-RS 5.32,
  SPRING-CRT 23.5, GGM module-LWR 39.4, GGM plain LWR 64.2.
- So, relative to Turing as it is today, an XOR-combined lattice keystream
  adds between about 0.1% (LEAP) and 5% (plain LWR). The cost is small only
  because Turing is not speed-optimised; next to AES-NI (0.45 c/B for
  AES256-CTR) the same generators take 3.6x to 143x the cipher's own time.
- Key material: LEAP-256 needs an 800-byte key (LEAP Table 1/2); the GGM
  module-LWR PRF a 192-byte key plus 24,576 bytes of public matrix (LEAP
  Table 1 reproducing [CS20]); SPRING-CRT an 18,444-byte key. Turing's key is
  32 bytes. Everything that docs/13 does to protect round keys in memory
  (locked pages, checksums, stack burning) would have to cover this material
  too.
- Constant-time cost: rounding with p not dividing q is biased (1/257 for
  SPRING, `lis_toys.py` A), so SPRING-RS and LEAP remove the bias by REJECTION
  SAMPLING (LEAP Table 3 gives failure probabilities; the SPRING-RS authors
  list "possible side channel leaks" from it, slides p. 24). Rejection makes
  the running time depend on the data. Modular reduction by a non-power-of-2
  q is the operation behind KyberSlash (secret-dependent division timing,
  TCHES 2025; sibling note `side-channels-faults-and-ct-verification.md`,
  which also records that Valgrind-based checkers miss divisions by default).
  A power-of-2 modulus (CS20 uses q = 2^16, p = 2^12) avoids both problems:
  rounding is a shift and is unbiased.

### 8.3 Security targets do not line up with Turing's

Turing claims a 256-bit key (docs/03). The lattice PRFs with published
parameters target less, or target it only heuristically:

| Design | Lattice dimension | Stated security | Basis |
|---|---|---|---|
| SPRING-BCH / -CRT (2014) | ring n = 128; attack lattice N >= 896 | best attack on SPRING-CRT ~2^126 time (designers) | heuristic, no reduction |
| SPRING-RS (2017) | n = 128 | "No security proof" (slides) | heuristic |
| GGM module-LWR PRF (2019) | 3 x 256 = 768 (LWR variant 800) | 128-bit PRF security for <= 2^34 queries (167-bit MLWR estimate) | reduction to MLWR (GGM loss q*d) |
| LEAP-256 (2025) | ring 256, hidden a (m = 208); LEAP.GEN ring 512 | 340.9 / 281.7 / 287.9 classical bits (Tables 4-5) | reduction to RLWR, parameters set for "RLWR with hidden a" |
| SWIFFT (2008) | 64 x 16 = 1024 input bits | collisions 2^109 bit operations (Kirchner 2011) | collision resistance only; linear |

Only LEAP claims a 256-bit level, and its extra margin rests on a problem
variant (hidden a) with one year of public scrutiny. Anything that claims
256-bit PRF security from a reduction would need new parameters; the sibling
note `attack-cost-estimation.md` has the estimator that could produce them.

### 8.4 Quantum

Lattice PRFs are assumed post-quantum, but so is a 256-bit symmetric key:
Grover-type key search is the generic quantum threat to both (sibling note
`quantum-crypto-and-quantum-attacks.md`). A lattice keystream does not raise
Turing's quantum margin against key search on its own; in the XOR combiner an
attacker must break BOTH components, so the combined quantum security should be
at least that of the stronger component by the same black-box argument (the reduction in
7.3 is classical; its quantum version is not analysed here, see open
questions).

## What this means for Turing

**Do not put lattice operations inside the Turing block cipher.** Evidence:
no lattice block cipher exists to learn from (section 6); SWIFFT-type layers
are linear (section 5); LASH and Rubato were broken exactly when lattice or
LWE ideas were bent to fit a fast symmetric design (section 6); every active-
S-box bound Bombe proves (docs/12) assumes the current layers and would have
to be redone for mixed mod-q / GF(2^8) arithmetic, a setting where the Rubato
attack worked. This is the "decoration with risk" option.

**If the owner wants lattice hardness in the symmetric layer, the defensible
design is a dual keystream.** Sketch for the design phase to evaluate, not a
decision:

1. Bulk encryption: keystream = Turing-CTR(k1, nonce, ctr) XOR
   L(k2, nonce, ctr), with L a lattice PRF, k1 and k2 256-bit and independent.
   Proven property: IND-CPA if either Turing or L is a PRF (section 7.3).
2. Key independence: derive k1 and k2 from the file key with cSHAKE256 and
   distinct labels (the existing `xof` convention, docs/03), and state
   honestly that cSHAKE256 and the KEM's hash remain single points of
   failure. Truly independent keys would need two separately wrapped file
   keys, and even then both pass through the same KEM stanza.
3. Integrity: keep the MAC separate from the combiner question. For
   robustness in integrity as well, the literature's tool is the copy
   combiner (two tags, Herzberg); otherwise the MAC relies on whichever
   primitive is chosen for it.
4. Choice of L, by evidence: (a) GGM module-LWR (proof via MLWR, power-of-2
   moduli so no bias and no division; needs new parameters for a 256-bit
   target and for Turing's data volumes, since the published set allows only
   2^34 queries at 128-bit PRF security); (b) LEAP (fast, claims 256-bit, but
   its margin rests on the young hidden-a assumption and it uses rejection
   sampling); (c) SPRING-RS (heuristic, "No security proof", best published
   attack below 256 bits). Option (a) is the only one whose security argument
   a learner can follow from a standard assumption to the parameters.
5. Implementation rules if built: power-of-2 moduli; no secret-dependent
   division, branch or rejection loop; constant-time checks per the sibling
   note `side-channels-faults-and-ct-verification.md` (including the
   division-aware Valgrind patch); differential testing against the authors'
   reference code (the LEAP paper names github.com/cbouilla/spriiiiiiiing for
   SPRING and github.com/BeJade/mlwr-prf for the GGM PRF, LEAP PDF p. 4
   footnotes); the lattice key protected like Turing's round keys (docs/13).

**Re-keying is the cheapest research-backed gain against Bombe's attacks,
and it needs no lattice.** Deriving a fresh Turing key per file or per chunk
with cSHAKE256 caps the data under any one key, which is what differential,
linear and boomerang attacks need (Abdalla-Bellare 2000). If a lattice PRF is
also wanted here, XOR it with the cSHAKE256 derivation (independent inputs)
rather than replace cSHAKE256.

**Key-homomorphic PRFs only if the product needs their feature** (re-keying
stored ciphertext without decrypting, or splitting a key across servers), and
never as the key-derivation function.

**What not to claim.** Not "256-bit lattice security" without estimator-backed
parameters (sibling `attack-cost-estimation.md`); not "sum of strengths" for a
combiner; not novelty for the combiner itself (Maurer-Massey 1993 recommend
it). The novelty would be the specific pairing and its analysis, which is
open research.

## Sources

| file in research/papers/ or "online" | full reference | URL | used for |
|---|---|---|---|
| 2012-banerjee-peikert-rosen-pseudorandom-functions-lattices.pdf | A. Banerjee, C. Peikert, A. Rosen, "Pseudorandom Functions and Lattices", EUROCRYPT 2012 (ePrint 2011/401, version of Aug 10, 2011) | https://eprint.iacr.org/2011/401 | LWR definition, Thm 3.2, degree-k PRF, Thm 5.2/5.3, zero-product pitfall |
| 2016-bogdanov-et-al-hardness-lwr-small-modulus.pdf | A. Bogdanov, S. Guo, D. Masny, S. Richelson, A. Rosen, "On the Hardness of Learning with Rounding over Small Modulus", TCC 2016-A (ePrint 2015/769) | https://eprint.iacr.org/2015/769 | sample-bounded LWR reductions |
| 2014-banerjee-et-al-spring-prf-rounded-ring-products.pdf | A. Banerjee, H. Brenner, G. Leurent, C. Peikert, A. Rosen, "SPRING: Fast Pseudorandom Functions from Rounded Ring Products", FSE 2014, LNCS 8540 | https://www.alonrosen.net/PAPERS/spring/spring.pdf | SPRING definition, parameters, Table 1 speeds, section 4 attacks |
| 2017-delaplace-et-al-stretching-spring-slides.pdf | C. Delaplace (with C. Bouillaguet, P.-A. Fouque, P. Kirchner), slides "Fast Lattice-Based Encryption: Stretching SPRING", PQCrypto 2017 | https://2017.pqcrypto.org/conference/slides/lbcI/Delaplace_pqc17.pdf | SPRING-RS, speeds, open questions |
| online | C. Bouillaguet, C. Delaplace, P.-A. Fouque, P. Kirchner, "Fast Lattice-Based Encryption: Stretching Spring", PQCrypto 2017, LNCS 10346, pp. 125-142 (abstract and footnotes page only) | https://link.springer.com/chapter/10.1007/978-3-319-59879-6_8 | abstract, footnotes 1 and 3 |
| 2008-lyubashevsky-et-al-swifft-fft-hashing.pdf | V. Lyubashevsky, D. Micciancio, C. Peikert, A. Rosen, "SWIFFT: A Modest Proposal for FFT Hashing", FSE 2008, LNCS 5086 | https://cseweb.ucsd.edu/~daniele/papers/SWIFFT.pdf | SWIFFT definition, linearity, attack costs, speed |
| 2008-arbitman-et-al-swifftx-sha3-proposal.pdf | Y. Arbitman, G. Dogon, V. Lyubashevsky, D. Micciancio, C. Peikert, A. Rosen, "SWIFFTX: A Proposal for the SHA-3 Standard", Oct 30, 2008 | https://www.alonrosen.net/PAPERS/lattices/swifftx.pdf | SWIFFTX layers, S-box rationale |
| 2008-buchmann-lindner-secure-parameters-swifft.pdf | J. Buchmann, R. Lindner, "Secure Parameters for SWIFFT" (ePrint 2008/493; INDOCRYPT 2009, LNCS 5922, DOI 10.1007/978-3-642-10628-6_1 per the Springer listing) | https://eprint.iacr.org/2008/493 | 68-bit pseudo-collision estimate |
| nist-ir-7620-sha3-round1-report.pdf | NIST IR 7620, "Status Report on the First Round of the SHA-3 Cryptographic Hash Algorithm Competition" | https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7620.pdf | SWIFFTX round-1 outcome |
| 2019-chuengsatiansup-stehle-ggm-prf-module-lwr.pdf | C. Chuengsatiansup, D. Stehle, "Towards practical GGM-based PRF from (Module-)Learning-with-Rounding", SAC 2019 (ePrint 2021/446) | https://eprint.iacr.org/2021/446 | GGM MLWR PRF: Thm 1, Table 2, 2^34 queries, Table 3 speeds |
| 2025-zhang-et-al-leap-lattice-based-prng.pdf | Y. Zhang, X. Lu, Y. Liu, Y. Yin, K. Wang, "LEAP: High-Performance Lattice-Based Pseudorandom Number Generator", IACR ToSC 2025(3), pp. 151-182, DOI 10.46586/tosc.v2025.i3.151-182 (ePrint 2025/1509) | https://eprint.iacr.org/2025/1509 ; https://tosc.iacr.org/index.php/ToSC/article/view/12468 | LEAP design, Tables 1-5, Theorem 2, reference-code URLs |
| 2025-heimberger-et-al-leap-lattice-oprf-spring.pdf | L. Heimberger, D. Kales, R. Lolato, O. Mir, S. Ramacher, C. Rechberger, "Leap: A Fast, Lattice-based OPRF With Application to Private Set Intersection", EUROCRYPT 2025 (ePrint 2025/333) | https://eprint.iacr.org/2025/333 | secondary summary of the Stretching SPRING analysis; SPRING still in use as heuristic |
| 2013-boneh-et-al-key-homomorphic-prfs.pdf | D. Boneh, K. Lewi, H. Montgomery, A. Raghunathan, "Key Homomorphic PRFs and Their Applications", CRYPTO 2013 (full version Feb 2, 2014) | https://eprint.iacr.org/2015/220 (ePrint entry; the saved PDF is the full version dated February 2, 2014) | definition, eq. 1.1, Thm 5.1, applications, almost-homomorphic error |
| 2014-banerjee-peikert-new-improved-key-homomorphic-prfs.pdf | A. Banerjee, C. Peikert, "New and Improved Key-Homomorphic Pseudorandom Functions", CRYPTO 2014 (version of June 13, 2014) | https://eprint.iacr.org/2014/074 | asymptotic improvements, Figure 1 |
| 2011-kirchner-improved-generalized-birthday-attack.pdf | P. Kirchner, "Improved Generalized Birthday Attack", ePrint 2011/377 (July 11, 2011) | https://eprint.iacr.org/2011/377 | SWIFFT collisions in 2^109 bit operations |
| 2008-contini-et-al-cryptanalysis-of-lash.pdf | S. Contini, K. Matusiewicz, J. Pieprzyk, R. Steinfeld, J. Guo, S. Ling, H. Wang, "Cryptanalysis of LASH", FSE 2008 (ePrint 2007/430, extended version) | https://eprint.iacr.org/2007/430 | LASH not provable; attacks; not a PRF |
| 2022-ha-et-al-rubato-noisy-ciphers.pdf | J. Ha, S. Kim, B. Lee, J. Lee, M. Son, "Rubato: Noisy Ciphers for Approximate Homomorphic Encryption", EUROCRYPT 2022 (ePrint 2022/537, full version) | https://eprint.iacr.org/2022/537 | noisy-cipher design rationale |
| 2023-grassi-et-al-key-recovery-attack-on-rubato.pdf | L. Grassi, I. Manterola Ayala, M. N. Hovd, M. Oygarden, H. Raddum, Q. Wang, "Cryptanalysis of Symmetric Primitives over Rings and a Key Recovery Attack on Rubato", CRYPTO 2023 (ePrint 2023/822) | https://eprint.iacr.org/2023/822 | Rubato parameters (Table 1) and key recovery |
| 1993-maurer-massey-cascade-ciphers-importance-of-being-first.pdf | U. Maurer, J. Massey, "Cascade Ciphers: The Importance of Being First", J. Cryptology 6(1):55-61, 1993 | (file as saved; text layer unreadable, read as rendered page images via lis_render.py) | Proposition, Corollaries 1-2, section 3 design advice |
| 2002-herzberg-folklore-practice-theory-robust-combiners.pdf | A. Herzberg, "Folklore, Practice and Theory of Robust Combiners", ePrint 2002/135, draft of Nov 29, 2007 (extended abstract at CT-RSA 2005 as "On Tolerant Cryptographic Constructions") | https://eprint.iacr.org/2002/135 | cascade robust for IND-CPA/CCA1/rCCA, not IND-CCA2; copy combiner for MACs |
| 2005-harnik-et-al-robust-combiners-oblivious-transfer.pdf | D. Harnik, J. Kilian, M. Naor, O. Reingold, A. Rosen, "On Robust Combiners for Oblivious Transfer and Other Primitives", EUROCRYPT 2005 | https://www.alonrosen.net/PAPERS/combiners/combiners.pdf | definition of robust combiner; XOR combiner for PRGs; Lemma 3.1 |
| 1999-naor-reingold-luby-rackoff-revisited.pdf | M. Naor, O. Reingold, "On the Construction of Pseudo-Random Permutations: Luby-Rackoff Revisited", J. Cryptology 12:29-66, 1999 | https://omereingold.files.wordpress.com/2014/10/lr.pdf | statement of the Luby-Rackoff round counts |
| 2000-abdalla-bellare-increasing-lifetime-of-a-key-rekeying.pdf | M. Abdalla, M. Bellare, "Increasing the Lifetime of a Key: A Comparative Analysis of the Security of Re-Keying Techniques", ASIACRYPT 2000 (full version dated Aug 2, 2021) | https://cseweb.ucsd.edu/~mihir/papers/rekey.pdf | re-keying methods and motivation |
| 2025-bernstein-et-al-kyberslash.pdf | D. J. Bernstein et al., "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations", TCHES 2025(2) | https://kyberslash.cr.yp.to/ | division-timing risk (detail in the side-channel sibling note) |
| online | Turing repository docs/03, 04, 08, 10, 12, 13 (read 2026-09-27) | local | Turing parameters, Bombe's attack set, measured speeds |

## Claim ledger

| # | claim | status | source |
|---|---|---|---|
| 1 | BPR define round_p(x) = round((p/q) x) mod p; with q, p powers of 2, rounding down drops low digits | VERIFIED | BPR 2012, eq. 2.1, PDF p. 8 |
| 2 | BPR Thm 3.2: decision-LWR(n,q,p) at least as hard as decision-LWE when q >= p B n^omega(1) | VERIFIED | BPR 2012, PDF p. 11 |
| 3 | BPR conjecture: LWR appears exponentially hard for p = poly(n) when q/p >= sqrt(n) is an integer | VERIFIED (as a conjecture stated by BPR) | BPR 2012, PDF p. 3 and p. 11 |
| 4 | BPR Thm 5.2: degree-k subset-product PRF is secure under LWE if S_i short and q >= p k (C r sqrt n)^k n^omega(1) | VERIFIED | BPR 2012, PDF p. 17 |
| 5 | Uniform ring seeds with k = O(q log n) give a zero product with noticeable probability; invertible seeds avoid it | VERIFIED | BPR 2012, PDF p. 7 |
| 6 | Bogdanov et al.: LWR hard from LWE when q >= 2mBp (bounded samples); unbounded-sample result only from uniform-noise LWE, not known as hard as Gaussian LWE | VERIFIED | Bogdanov et al., PDF p. 1-3 (Thm 1, Thm 3, Thm 5 summaries) |
| 7 | SPRING parameters n = 128, p in {257, 514}, k in {64, 128} | VERIFIED | SPRING, PDF p. 4 |
| 8 | SPRING has no reduction for its parameters (BPR proof needs p exponential in k and short seeds) | VERIFIED | SPRING, PDF p. 3 and p. 12 |
| 9 | SPRING-BCH output is 2^-145-far from uniform (under stated heuristic) | VERIFIED + COMPUTED (2^-145.1) | SPRING PDF p. 4, 7; lis_toys.py section B |
| 10 | SPRING CTR speeds on Ivy Bridge: BCH 46, CRT 23.5 cycles/byte; AES-CTR 5.4 (no NI), 1.3 (NI) | VERIFIED | SPRING Table 1, PDF p. 6 |
| 11 | SPRING lattice attack: N >= 896, time >= 2^430, space >= 2^160 | VERIFIED + COMPUTED | SPRING PDF p. 13; lis_toys.py section C |
| 12 | SPRING Arora-Ge cost at least 2^384 | VERIFIED | SPRING PDF p. 13 |
| 13 | SPRING-CRT birthday attack time about 2^126 (t = 2) | VERIFIED + COMPUTED (2^126.0) | SPRING PDF p. 14; lis_toys.py section C |
| 14 | SPRING-CRT attack query/space: paper's formula gives 2^87.0 but its text says ~2^119 (internal inconsistency) | COMPUTED | lis_toys.py section C; SPRING PDF p. 14 |
| 15 | Stretching SPRING: SPRING-RS with p in {2,4,8,16}, rejection of coefficient 256; 6 c/B Ivy Bridge, 2.8 c/B Haswell AVX2; "No security proof" | VERIFIED (slides) | Delaplace slides p. 11-12, 24-27 |
| 16 | Stretching SPRING full-paper claims (improved analysis, Table 2 on public seeds) | UNVERIFIED | full paper not obtainable; only Springer abstract/footnotes seen |
| 17 | SWIFFT parameters n=64, m=16, p=257; 1024-bit input; output ~2^512 values in 528 bits | VERIFIED | SWIFFT PDF p. 4-5 |
| 18 | SWIFFT is not pseudorandom: f(x1)+f(x2) = f(x1+x2) | VERIFIED + COMPUTED | SWIFFT section 4.3, PDF p. 9; lis_toys.py section D |
| 19 | SWIFFT collision >= 2^106 time; inversion about 2^448 (authors' estimates) | VERIFIED | SWIFFT PDF p. 11 |
| 20 | SWIFFT ~40 MB/s vs SHA-256 47 MB/s on 3.2 GHz Pentium 4 | VERIFIED | SWIFFT PDF p. 7 |
| 21 | Pseudo-collisions for SWIFFT ~ 68-bit symmetric security (Lenstra-Verheul heuristic) | VERIFIED | Buchmann-Lindner abstract, PDF p. 1 |
| 22 | SWIFFTX: 2048 -> 520-bit compression, HAIFA, S-box layer to destroy linearity | VERIFIED | SWIFFTX PDF p. 1, 3-4 |
| 23 | SWIFFTX was a SHA-3 round-1 candidate and did not advance; NIST gave no per-candidate reason | VERIFIED | NIST IR 7620 PDF p. 7, 8, 11 |
| 24 | BLMR: F(k1+k2,x) = F(k1,x)+F(k2,x)+e with e in {0,1,2} (random-oracle LWR version) and e in {0,1,2}^m, or {0,1}^m if p divides q (standard-model version) | VERIFIED | BLMR PDF p. 2 |
| 25 | BLMR Thm 5.1: PRF under LWE when alpha * m^l * p <= 2^-omega(log n); l = O(1) for alpha = 2^-omega(log n) | VERIFIED | BLMR PDF p. 14-15 |
| 26 | Banerjee-Peikert 2014: key lambda^3 -> lambda bits, public parameters lambda^6 -> lambda^2 bits, runtime lambda^7 -> lambda^(omega+1) (asymptotic, polylog omitted) | VERIFIED | BP14 abstract PDF p. 1, Figure 1 PDF p. 3 |
| 27 | GGM MLWR PRF parameters q = 2^16, d = 256, n = 3, m = 16, log B = 4, omega = 16; MLWR estimate 167 bits | VERIFIED | CS 2019 Table 2 PDF p. 15; text PDF p. 16 |
| 28 | GGM MLWR PRF allows up to 2^34 queries at 128-bit PRF security | VERIFIED + COMPUTED (167 - 128 - log2 32 = 34 from Thm 1's q*d*eps) | CS 2019 PDF p. 16, Thm 1 PDF p. 4; lis_costs.py B |
| 29 | GGM PRF speeds 39.4 c/B (MLWR), 64.2 c/B (LWR), Skylake, counter mode | VERIFIED | CS 2019 Table 3 PDF p. 17 |
| 30 | CS 2019 per-call cycle counts in the text give 77.9 c/B, not the 39.4 of Table 3 | COMPUTED (discrepancy; cause unknown) | lis_costs.py B; CS 2019 PDF p. 16-17 |
| 31 | LEAP bibliographic data: ToSC 2025(3) pp. 151-182, published 2025-09-25 | VERIFIED | ToSC article page (online); ePrint 2025/1509 metadata via eprint_meta.py |
| 32 | LEAP.PRNG parameters n = 256, q = 3329, p = 1536, m = 208; LEAP.GEN N = 512, Q = 257; keys 224/576/800 bytes | VERIFIED | LEAP Table 2 PDF p. 14 |
| 33 | LEAP speeds 1.61 (AVX2) and 1.14 (AVX512) c/B; SPRING-RS 5.32; [CS20] MLWR 31.39; AES256-CTR 0.45 (AES-NI), 8.05 (C) | VERIFIED | LEAP Table 1 PDF p. 5 |
| 34 | LEAP abstract ratios 1.71X key, 3.30X speed vs SPRING-RS are consistent with Table 1 | COMPUTED | lis_costs.py A |
| 35 | LEAP security: Adv <= d^2 Adv_RLWR + delta_2 (Thm 2); concrete estimates for "RLWR with hidden a": LEAP-256 PRNG 340.9 classical (hybrid primal), LEAP.GEN-256 287.9 (NTRU) and 281.7 (RLWR) | VERIFIED | LEAP PDF p. 19-21 (Thm 2), Tables 4-5 PDF p. 25 |
| 36 | No third-party cryptanalysis of LEAP (ToSC 2025) found | UNVERIFIED (absence of evidence) | web searches 2026-09-27 ("LEAP lattice PRNG ... cryptanalysis", "SPRING-RS OR LEAP ... attack 2026"); settle by an IACR/ePrint citation search |
| 37 | Leap OPRF (EUROCRYPT 2025) builds on SPRING under "heuristic lattice assumptions"; states best attack on SPRING-CRT is subexponential [BDFK17] and infeasible; SPRING reference code 4.5x slower than AES | VERIFIED (as that paper's statements) | Heimberger et al. PDF p. 1, 10, 22 |
| 38 | Stretching SPRING (BDFK17) details: subexponential attack cost, Groebner/BKW analysis, public-seed variant | UNVERIFIED | full paper unobtainable (lip6 host refused connection 2026-09-27, Springer paywall); only slides and secondary summary read |
| 39 | SWIFFT collisions in 2^109 bit operations vs 2^120 for the SWIFFT paper's algorithm | VERIFIED (superscripts checked with pdfspans.py) | Kirchner 2011 section 4.2, PDF p. 8 |
| 40 | LASH: not a provable design; collisions 2^(4x/11), preimages 2^(4x/7) (zero IV), 2^(7x/8) preimages for any IV; not a PRF when keyed by input bytes | VERIFIED | Contini et al. abstract PDF p. 1; PDF p. 2 |
| 41 | Rubato: samples (a, E_k(a) + e) with discrete Gaussian e; "noise prevents algebraic attacks" in LWE | VERIFIED | Rubato PDF p. 4 |
| 42 | Rubato parameters: n 16-64, ceil(log2 q) 25-26, alpha*q 1.6-11.1, rounds 2-5 | VERIFIED | Grassi et al. Table 1, PDF p. 18 |
| 43 | Rubato key recovery below claimed security for 5 of 6 variants for >= 25% of q; Rubato-80M 2^57.06 time, < 250,000 keystream elements, < 25 GB when q has factor 12 | VERIFIED | Grassi et al. abstract PDF p. 1; PDF p. 5-6 |
| 44 | No peer-reviewed, third-party-analysed lattice block cipher exists | UNVERIFIED (absence of evidence) | web searches 2026-09-27 recorded in section 6; settle by a systematic IACR proceedings search |
| 45 | Luby-Rackoff: four Feistel rounds (three for weaker security) give a PRP from a PRF | VERIFIED (as stated by Naor-Reingold) | Naor-Reingold 1999 abstract, PDF p. 1; original 1988 paper not read |
| 46 | Maurer-Massey: cascade at least as hard as the first cipher (Proposition); commuting ciphers: at least as hard as the hardest (Cor. 1); XOR of keystreams with independent keys at least as hard to predict as the hardest (Cor. 2); additive stream ciphers commute | VERIFIED | Maurer-Massey PDF p. 5-6 (read as rendered images) |
| 47 | Maurer-Massey: folk theorem (Even-Goldreich) holds only if the attacker cannot exploit plaintext statistics | VERIFIED (Maurer-Massey's statement); Even-Goldreich 1985 itself UNVERIFIED (not read) | Maurer-Massey abstract PDF p. 1, PDF p. 2 |
| 48 | Maurer-Massey recommend cascading keystream generators built on different design principles; each component key must resist exhaustive search | VERIFIED | Maurer-Massey section 3, PDF p. 6 |
| 49 | Herzberg: cascade is robust for IND-CPA, IND-CCA1, IND-rCCA, not for IND-CCA2 or IND-gCCA; copy combiner robust for MACs | VERIFIED | Herzberg abstract PDF p. 1 |
| 50 | Harnik et al.: XOR of outputs is the combiner used for PRG candidates; OWF-equivalent primitives (private-key encryption, PRGs, PRFs, PRPs) have robust combiners | VERIFIED | Harnik et al. PDF p. 2, Lemma 3.1 and text PDF p. 8 |
| 51 | XOR combiner reduction: Adv_prf(C) <= Adv_prf(T) (and <= Adv_prf(L)) with independent uniform keys | COMPUTED (standard reduction written out in section 7.3; not quoted from a source) | section 7.3; lis_toys.py F illustrates the failure cases |
| 52 | Abdalla-Bellare: parallel re-keying K_i = F(K, i); re-keying motivated by differential/linear/birthday attacks needing many encryptions under one key; provably increases the safe number of encryptions | VERIFIED | Abdalla-Bellare abstract PDF p. 1; PDF p. 3 |
| 53 | Turing: 256-bit key, 128-bit block, 24 rounds (v2); 3.0 us/block (v1, 16 rounds, 5.2 MB/s); plain v2 cipher 4.5 us/block | VERIFIED | docs/03 table; docs/10 lines 21-22; docs/13 lines 211-212 |
| 54 | Turing v2 about 1203 c/B at 4.276 GHz; lattice keystream adds 0.1%-5.3% to Turing v2; 3.6x-143x relative to AES256-CTR with AES-NI | COMPUTED (assumes the docs' timings were taken at this machine's WMI MaxClockSpeed 4276 MHz, AMD Ryzen 5 5600X) | lis_costs.py C, D |
| 55 | SWIFFT about 80 cycles per input byte | COMPUTED | lis_costs.py E from SWIFFT PDF p. 7 |
| 56 | SPRING-RS slides: "possible side channel leaks" from rejection sampling; "No security proof" | VERIFIED | Delaplace slides PDF p. 24, 27 |
| 57 | Reference code locations github.com/cbouilla/spriiiiiiiing (SPRING family) and github.com/BeJade/mlwr-prf ([CS20]) | VERIFIED (as cited by LEAP; repositories not opened) | LEAP PDF p. 4 footnotes 1-2 |
| 58 | Other lattice PRG/stream-cipher proposals exist (AAECC 2017 worst-case-lattice PRG; ePrint 2014/002) | UNVERIFIED (titles from search results only; papers not read) | web search 2026-09-27 |

## Open questions

1. **Stretching SPRING, full text.** The exact cost of the "subexponential"
   attack on SPRING-CRT, the Groebner/BKW analysis and the public-seed variant
   (its Table 2) remain unread (ledger 16, 38). Settle by obtaining the
   PQCrypto 2017 paper (LNCS 10346) through a library or the authors.
2. **A reduction-backed lattice PRF at Turing's target.** No published
   parameter set gives 256-bit PRF security with a proof and a query budget of
   2^64 or more blocks. Settle by re-running the GGM/MLWR accounting
   (q*d*eps, CS 2019 Thm 1) with the sibling estimator of
   `attack-cost-estimation.md` for larger module rank, and measuring speed.
3. **LEAP's hidden-a problem.** How LEAP maps "RLWR with hidden a" to LWE
   instances for its estimates (PDF p. 22-25) was not reproduced; no
   third-party cryptanalysis was found (ledger 36). Settle by reproducing
   Tables 4-5 with the lattice-estimator and by a later literature check.
4. **CS 2019 cycle-count discrepancy** (77.9 c/B from the text's counts vs
   39.4 in Table 3; ledger 30). Settle by running the authors' code.
5. **SPRING-CRT query/space formula** (2^87 from the formula vs 2^119 in the
   text; ledger 14). Settle with the Stretching SPRING paper, which revisits
   this attack.
6. **Quantum-query security of the XOR combiner.** The reduction in 7.3 is
   classical. It should carry over to quantum-accessible oracles because the
   simulator only XORs an efficiently computable function, but this was not
   checked against a source (sibling `quantum-crypto-and-quantum-attacks.md`).
7. **Originals not read:** Even-Goldreich 1985 (cascade folk theorem) and
   Luby-Rackoff 1988; both are cited through Maurer-Massey and Naor-Reingold.
8. **Which AEAD Turing adopts (step 9).** The XOR combiner applies to
   counter-style modes only; if step 9 picks a mode that uses Turing as a
   permutation (not as a keystream), the combiner question changes.
9. **Updatable encryption from key-homomorphic PRFs.** Later analyses of the
   BLMR key-rotation scheme (for example Everspaugh et al., CRYPTO 2017) were
   not read; needed only if the owner wants option D.
10. **Test vectors.** No standard test vectors exist for any lattice PRF;
    the reference repositories named by LEAP were not opened or audited.
