# A dual-lattice KEM for Turing: options (proposal, 2026-09-27)

The owner asked whether two lattice schemes of about 1000 dimensions each
can be combined for "extreme security and safety". They can, and the
literature says exactly how and what it buys. This note is a proposal for
the owner to choose from; nothing here is built yet.

Every source claim below was read in the primary document on 2026-09-27
(files in `research/papers/`); every security figure was recomputed with
`tools/coresvp_exhaustive.py`, which reproduces the published Table 1 of
Alkim, Ducas, Poppelmann and Schwabe (2016) first.

## 1. What combining two lattice KEMs buys, and what it does not

**The combination is as strong as its stronger leg.** NIST SP 800-227
(September 2025, section 4.6) defines a composite KEM that runs both KEMs
and derives one key with

    KeyCombineCCA_H: K = H(K1, K2, c1, c2, ek1, ek2, domain_sep),  H from the SHA-3 family,

and states that it "preserves IND-CCA security if H is modeled as a
random oracle", in the sense that "the combined scheme is IND-CCA, provided
at least one of the ingredient KEMs is IND-CCA". It warns that the naive
K = KDF(K1, K2) "does not preserve IND-CCA security, regardless of the
properties of the KDF". The underlying result is Giacon, Heuer and
Poettering (PKC 2018): their combiners are CCA-secure "as long as at least
one of the ingredient KEMs is"; XOR of the keys only preserves CPA
security.

**The dimensions do not add up.** To learn the combined key an attacker
must break both legs, so the cost is about that of the harder one
(2^252.0 + 2^253.5 is about 2^253.9 core-SVP for the pair proposed below),
not that of a 2050-dimension problem. The gain is robustness, not a bigger
exponent: a mistake in one leg no longer breaks the key.

**What it protects against:**

- a flaw in Turing-1026's own choices: its parameters, its transform (the
  exact combination of salting, H(pk) and implicit rejection has no proof
  yet, docs/16), or its code;
- attacks that exploit the algebraic structure of one leg (module or ring
  structure) but not the other;
- errors in one leg's security estimate. This is not hypothetical:
  lattice-estimator issue #219 (open since 2026-07-09) shows its default
  dual-hybrid search can miss the optimum by 7.98 bits on FrodoKEM-976, a
  plain-LWE scheme like Turing-1026.

**What it does not protect against:** a general advance in lattice
reduction, or an efficient quantum algorithm for LWE, would hit both legs.
Hedging against that needs a leg that is not a lattice: X25519 (classical
only, as in X-Wing and TLS hybrids) or a code-based KEM (HQC, selected by
NIST in 2025, whose FIPS 207 draft is not yet public). It also does nothing
for side channels (both legs need constant-time code and, eventually,
masking), and SP 800-227 itself cautions that composite schemes "add a
layer of additional complexity" that "could introduce security
vulnerabilities".

## 2. The second lattice

| | A. ML-KEM-1024 (recommended) | B. Streamlined NTRU Prime | C. A second plain-LWE set |
|---|---|---|---|
| Problem | Module-LWE, rank 4 over Z_3329[x]/(x^256+1) | NTRU over Z_q[x]/(x^p - x - 1), no cyclotomic structure | plain LWE, like Turing-1026 |
| Dimension | 4 x 256 = 1024 | sntrup1013 (p = 1013, q = 7177, w = 448) or sntrup1277 (p = 1277, q = 7879, w = 492), round-3 spec section 3 | about 1000 |
| Status | FIPS 203 (final, August 2024), category 5, required by CNSA 2.0 | round-3 alternate, not selected by NIST | custom |
| Core-SVP (classical primal / dual) | 255.2 / 253.5 | not recomputed here (NTRU is not plain LWE; the estimator above does not model it) | same as Turing-1026 |
| Sizes, public key / ciphertext | 1,568 / 1,568 bytes (FIPS 203 Table 3) | see the spec | about 61 KB / 16 KB |
| Test vectors | NIST ACVP, C2SP CCTV (including "unlucky" and "strcmp" sets), Wycheproof: already fetched to `research/workfiles/pq/vectors/` | submission KATs | none |
| Diversity from Turing-1026 | structured vs unstructured; standard vs custom transform; independent public analysis | a different hard problem (NTRU vs LWE) | none: rejected |
| Work | NTT, sampling, compression, the FIPS 203 input checks | inversion in R/3 and R/q in constant time, harder | little, and useless |

Recommendation: **A, ML-KEM-1024.** It is the only option that is a
finished standard with independent analysis and public test vectors, it is
exactly the kind of "vetted" public-key part docs/02 originally asked for,
and it differs from Turing-1026 in structure, transform and authorship. B
buys a different hard problem at a much higher implementation risk.

## 3. The construction ("Turing-2050", a working name: 1026 + 1024)

- **Key generation.** One 32-byte random seed, as Turing-1026 already uses:
  (seed_T, d, z) = cSHAKE256(seed, "Turing-2050 v1 key generation");
  Turing-1026 keys from seed_T; ML-KEM-1024 from ML-KEM.KeyGen_internal(d, z)
  (FIPS 203, Algorithm 16). FIPS 203 allows storing the seed (d, z) "for
  later expansion using ML-KEM.KeyGen_internal", as sensitive data, but it
  also says the internal functions "should not be made available to
  applications other than for testing purposes" and that the module itself
  samples the randomness. Deriving (d, z) from our own seed inside the
  combined KEM keeps those functions internal to it; it would not be a
  FIPS-validated use, which Turing cannot be anyway (its cipher is not
  approved). Public key ek = ek_T || ek_M (63,160 bytes).
- **Encapsulation.** (K_T, c_T) from Turing-1026, (K_M, c_M) from
  ML-KEM-1024, both always; then
  K = cSHAKE256(K_T || K_M || c_T || c_M || ek_T || ek_M, "Turing-2050 v1 combine"),
  which is SP 800-227's KeyCombineCCA_H with a SHA-3-family H (cSHAKE256,
  SP 800-185) and the label as domain separator. Ciphertext c_T || c_M
  (17,502 bytes). Including both encapsulation keys is not needed for
  IND-CCA but binds the key to the recipient's keys (SP 800-227 says so).
  For this, the most general combiner (it hashes every input), Kramer,
  Struck and Weishaupl (2025) show that "several binding properties follow
  easily ... assuming a collision-resistant hash function"; the others need
  properties of one or both component KEMs, which is worth a table in the
  design document once the second leg is chosen.
- **Decapsulation.** Both decapsulations always run (each rejects
  implicitly, so a bad ciphertext gives a pseudorandom key, never an
  error), then the same combiner. Only wrong lengths are errors. FIPS 203's
  input checks on the ML-KEM keys apply.
- **Cost.** ML-KEM-1024 adds about 3 KB and far less time than Turing-1026's
  13 ms per operation.

## 4. How it would be validated

- ML-KEM-1024 against every public vector set above, and differentially
  against the two independent Python implementations already written by
  the research (`research/scripts/pq/tcc_mlkem_oracle.py`,
  `cca_mlkem_ref.py`): a third implementation, in another language.
- The combiner: known-answer vectors; a test that changing any byte of any
  of its six inputs changes K; planted bugs in `tools/mutate.py` (drop c_T
  from the hash, drop an encapsulation key, XOR the keys, stop after the
  first decapsulation).
- The new CI stages (tools/CI.md) extended to it: rare and out-of-range
  inputs, overflow checks, the maths audit of its sizes and estimates.

## 5. Decisions for the owner

1. The second lattice: A (ML-KEM-1024, recommended) or B (NTRU Prime).
2. ML-KEM itself: written in this repository from FIPS 203 and validated by
   the vectors (Turing's "own code" rule), or a vetted crate. The candidates
   are libcrux-ml-kem 0.0.10 (2026-07-15; its README says it is verified
   with hax and F* to be panic-free and functionally correct where
   indicated, and that compiled code is "not verified to be side-channel
   resistant") and RustCrypto's ml-kem 0.3.2 (2026-05-10). Both are pre-1.0.
3. A third, non-lattice leg: none, X25519 now, or HQC once its standard
   exists.
4. The name.

## Sources

| File in `research/papers/` | Used for |
|---|---|
| nist-sp800-227-kem-recommendations.pdf | section 4.6: composite KEMs, KeyCombineCCA_H, the KDF(K1, K2) warning, the complexity caution |
| 2018-giacon-heuer-poettering-kem-combiners.pdf | CCA security if at least one ingredient is; XOR only for CPA |
| nist-fips-203-ml-kem.pdf | ML-KEM-1024 parameters, sizes, KeyGen_internal(d, z) |
| 2020-bernstein-et-al-ntru-prime-round3-specification.pdf | section 3: sntrup1013 and sntrup1277 parameters |
| 2025-kramer-struck-weishaupl-binding-properties-of-kem-combiners.pdf | binding of combiners |
| 2016-alkim-ducas-poppelmann-schwabe-newhope.pdf | the core-SVP model the figures use |
| online: github.com/malb/lattice-estimator/issues/219 | the estimator's dual-hybrid search error (7.98 bits on FrodoKEM-976) |
| online: crates.io, github.com/cryspen/libcrux | crate versions and verification claims |
