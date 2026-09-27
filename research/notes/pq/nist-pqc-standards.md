# NIST post-quantum standards and government guidance

This file records what the post-quantum standards and the main government authorities say, as
of **2026-09-27**, for the design of a lattice layer in Turing. It covers FIPS 203 (ML-KEM) in
depth; FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) briefly; the status of FN-DSA (FIPS 206) and HQC
(FIPS 207); NIST SP 800-227 (KEMs and hybrid combiners); NIST IR 8547 (transition dates); the
NIST security categories and MAXDEPTH; the additional-signature on-ramp; and the positions of
NSA (CNSA 2.0), BSI, ANSSI, UK NCSC, the EU roadmap and ECCG, and ISO/IEC 18033-2 Amd 2. Every
status was checked on 2026-09-27 against NIST CSRC pages and the primary PDFs in
`research/papers/`. Numbers are recomputed by `research/scripts/pq/nist_pqc_check.py`.

## Key findings

1. **ML-KEM (FIPS 203, 2024-08-13) is the only final NIST post-quantum KEM.** No revision has
   been published; the errata sheet (planning note 2025-11-17) lists two editorial items that do
   not change behaviour (Section 1.7).
2. **ML-KEM-1024 is already a "1000-dimension" lattice scheme**: module rank 4 over `n = 256`,
   1024 secret coordinates, category 5. FrodoKEM-976 (plain LWE, dimension 976) is category 3.
   Dimension alone does not fix a category; `q`, the noise and the cost model do (Section 6.4).
3. **FIPS 203 fixes everything**: `n = 256`, `q = 3329`, `(k, eta1, eta2, du, dv)` =
   (2,3,2,10,4) / (3,2,2,10,4) / (4,2,2,11,5); sizes 800/1632/768, 1184/2400/1088,
   1568/3168/1568 bytes; failure rates `2^-138.8`, `2^-164.8`, `2^-174.8`. All sizes recompute
   exactly (Section 1.3).
4. **Required checks**: the `ek` modulus check, the `dk` hash check, ciphertext length check on
   every Decaps, implicit rejection with a secret, destroyed comparison flag, approved RBG,
   destruction of intermediates, no floating point (Section 1.5).
5. **Any "twist" inside ML-KEM ends conformance.** K-PKE "shall not be used as a stand-alone
   cryptographic scheme"; ANSSI: "It is important to avoid modifying the parameters of the
   standardized instance". A twist can only sit *around* unmodified standard components
   (combiner, second KEM, the symmetric layer).
6. **FN-DSA (FIPS 206) and HQC (FIPS 207) have no public draft as of 2026-09-27.** CSRC lists
   both as "FIPS coming soon". HQC was selected in NIST IR 8545 (March 2025) for diversity of
   hardness assumptions and its mature decryption-failure analysis.
7. **SP 800-227 is final (September 2025).** It approves hybrid combiners built from SP 800-56C
   KDMs over `(S1, ..., St)` if at least one secret comes from an approved scheme, warns that
   `KDF(K1, K2)` alone "does not preserve IND-CCA security", and encourages
   `H(K1, K2, c1, c2, ek1, ek2, domain_sep)` with a SHA-3 hash (Section 4.5).
8. **IR 8547 is still an initial public draft (November 2024).** Its intent: quantum-vulnerable
   public-key schemes at 112 bits deprecated after 2030, all disallowed after 2035.
9. **Authorities disagree on hybrids.** BSI ("should be used in 'hybrid' form"), ANSSI
   ("strongly emphasizes", mandatory in its regulated perimeter) and the EU roadmap recommend
   hybrids; NSA "will not require" them; NCSC treats them as "an interim measure".
10. **Authorities disagree on the default level.** NIST and NCSC: ML-KEM-768. BSI: 768 or 1024
    (not 512). ANSSI: "preferably level-5". CNSA 2.0: ML-KEM-1024 only.
11. **Conservative alternatives now have an ISO standard.** ISO/IEC 18033-2:2006/Amd 2:2026 was
    published 2026-06-05; FrodoKEM and Classic McEliece are in it (per the scheme sites);
    ML-KEM's inclusion is unverified. BSI recommends FrodoKEM-976/1344 and Classic McEliece
    460896 and up; ECCG recommends FrodoKEM-976/1344.
12. **Categories are defined by AES/SHA attack cost**, with quantum gate counts
    `2^157 / 2^221 / 2^285` divided by MAXDEPTH (2022 call; `2^170 / 2^233 / 2^298` in 2016),
    classical `2^143 / 2^207 / 2^272`, and MAXDEPTH between `2^40` and `2^96`. NIST's own
    round-3 report says Kyber's parameters "fall slightly below" their targets if memory cost is
    ignored (Section 6).
13. **Validation cannot prove correctness.** SP 800-227 RM1: implementations "must correctly
    implement the mathematical functionality", while lab testing only samples inputs. Turing
    needs its own differential and property testing on top of the NIST vectors.
14. **Turing's own cipher is not an approved primitive**, so a Turing-based KEM-DEM cannot be
    FIPS-approved as a whole, whatever the KEM. Following FIPS 203 still buys a vetted, tested
    KEM; the final strength is the weaker of the KEM and the Turing cipher.

## 1. FIPS 203 ML-KEM

Source: `nist-fips-203-ml-kem.pdf` (FIPS 203, published 2024-08-13). Page numbers below are the
PDF page (logical page in brackets). The CSRC page (https://csrc.nist.gov/pubs/fips/203/final,
fetched 2026-09-27) still lists only the draft (2023-08-24) and the final (2024-08-13) in its
document history; there is no revision yet.

### 1.1 What ML-KEM is, in one paragraph

ML-KEM is a key-encapsulation mechanism (KEM). A KEM has three algorithms. KeyGen makes a key
pair. Encaps takes the public encapsulation key `ek` and outputs a ciphertext `c` and a 32-byte
shared secret `K`. Decaps takes the private decapsulation key `dk` and `c` and recomputes `K`.
Inside, ML-KEM is built in two layers (FIPS 203 Section 3.2, PDF p. 22-23 [13-14]):

1. **K-PKE**, a public-key encryption scheme whose security rests on Module Learning With Errors
   (MLWE). The public key is a set of noisy linear equations `t = A s + e` over the ring
   `R_q = Z_q[X]/(X^256 + 1)`; the secret is `s`. Encryption forms a fresh random combination of
   those equations and hides one message bit in each of the 256 coefficients of the "constant
   term". K-PKE is only secure against passive attackers (IND-CPA).
2. **A Fujisaki-Okamoto (FO) transform** turns K-PKE into a KEM that is believed IND-CCA2 secure:
   the encryption randomness is derived by hashing the message, and decapsulation re-encrypts
   and compares. FIPS 203 says K-PKE "shall not be used as a stand-alone cryptographic scheme"
   and its three algorithms "are not approved for use as a public-key encryption scheme"
   (Section 3.3, PDF p. 24-25 [15-16]).

The sibling notes explain the maths (`lattice-foundations`) and the FO transform
(`cca-transforms-and-binding`). This section records what the standard fixes.

### 1.2 The algorithms (FIPS 203 Sections 5-7)

| Layer | Algorithm | What it does (as specified) | FIPS 203 location |
|---|---|---|---|
| K-PKE | KeyGen(d) (Alg. 13) | `(rho, sigma) = G(d || k)`; expand `A_hat` from `rho` with SampleNTT; sample `s`, `e` from CBD_eta1 via `PRF(sigma, N)`; `t_hat = A_hat o s_hat + e_hat`; `ek_PKE = ByteEncode12(t_hat) || rho`, `dk_PKE = ByteEncode12(s_hat)` | Sec. 5.1, PDF p. 38 [29] |
| K-PKE | Encrypt(ek_PKE, m, r) (Alg. 14) | re-expand `A_hat`; sample `y` (CBD_eta1), `e1`, `e2` (CBD_eta2) from `PRF(r, N)`; `u = NTT^-1(A_hat^T o y_hat) + e1`; `v = NTT^-1(t_hat^T o y_hat) + e2 + Decompress_1(m)`; `c = ByteEncode_du(Compress_du(u)) || ByteEncode_dv(Compress_dv(v))` | Sec. 5.2, PDF p. 39 [30] |
| K-PKE | Decrypt(dk_PKE, c) (Alg. 15) | decompress `u'`, `v'`; `w = v' - NTT^-1(s_hat^T o NTT(u'))`; `m = ByteEncode1(Compress1(w))` | Sec. 5.3, PDF p. 40 [31] |
| internal | KeyGen_internal(d, z) (Alg. 16) | `ek = ek_PKE`; `dk = dk_PKE || ek || H(ek) || z` | Sec. 6.1, PDF p. 41 [32] |
| internal | Encaps_internal(ek, m) (Alg. 17) | `(K, r) = G(m || H(ek))`; `c = K-PKE.Encrypt(ek, m, r)` | Sec. 6.2, PDF p. 42 [33] |
| internal | Decaps_internal(dk, c) (Alg. 18) | parse `dk`; `m' = Decrypt(dk_PKE, c)`; `(K', r') = G(m' || h)`; `K_bar = J(z || c)`; `c' = Encrypt(ek_PKE, m', r')`; if `c != c'` then `K' = K_bar`; return `K'` | Sec. 6.3, PDF p. 43 [34] |
| external | KeyGen() (Alg. 19) | draw `d`, `z` (32 random bytes each) from an approved RBG; return error if the RBG fails; call KeyGen_internal | Sec. 7.1, PDF p. 44 [35] |
| external | Encaps(ek) (Alg. 20) | draw `m` (32 bytes); call Encaps_internal; `ek` must have been checked | Sec. 7.2, PDF p. 46 [37] |
| external | Decaps(dk, c) (Alg. 21) | call Decaps_internal; `dk` and `c` must have been checked | Sec. 7.3, PDF p. 47 [38] |

Hash and XOF instantiations (Section 4.1, PDF p. 27-29 [18-20]): `H = SHA3-256`,
`J(s) = SHAKE256(s, 8*32)`, `G = SHA3-512` (split into two 32-byte halves),
`PRF_eta(s, b) = SHAKE256(s || b, 8*64*eta)`, and the XOF is SHAKE128 through its incremental
API. The byte `k` appended to `d` in K-PKE.KeyGen is a domain separator between parameter sets
(footnote on PDF p. 38 [29]; added after the draft, Appendix C.2).

"Internal" means derandomised: all randomness is an input. The standard says these interfaces
"should not be made available to applications other than for testing purposes", and the random
seeds "shall be generated by the cryptographic module" (Section 3.3, PDF p. 25 [16]; Section 6,
PDF p. 41 [32]). For Turing this means the internal functions may exist behind a test-only API
(they are what the NIST ACVP test vectors exercise), but the public API must draw its own
randomness.

### 1.3 Parameter sets (Table 2) and sizes (Table 3)

FIPS 203 Section 8, PDF p. 48 [39]. Constants: `n = 256`, `q = 3329`.

| Parameter set | n | q | k | eta1 | eta2 | du | dv | required RBG strength (bits) | claimed category |
|---|---|---|---|---|---|---|---|---|---|
| ML-KEM-512 | 256 | 3329 | 2 | 3 | 2 | 10 | 4 | 128 | 1 |
| ML-KEM-768 | 256 | 3329 | 3 | 2 | 2 | 10 | 4 | 192 | 3 |
| ML-KEM-1024 | 256 | 3329 | 4 | 2 | 2 | 11 | 5 | 256 | 5 |

| Parameter set | encapsulation key | decapsulation key | ciphertext | shared secret |
|---|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

(bytes). The sizes follow from the algorithm headers: `|ek| = 384k + 32`, `|dk| = 768k + 96`,
`|c| = 32(du*k + dv)`. `nist_pqc_check.py` section 1 recomputes Table 3 from Table 2 and these
formulas (all three rows match; the negative control plants a wrong `dk` size and it is caught).

Worked example (ML-KEM-768): `k = 3`, so `ek = 384*3 + 32 = 1184`. Each of the `k*n = 768`
coefficients of `t_hat` takes 12 bits (`3329 < 4096 = 2^12`), `768*12/8 = 1152` bytes, plus the
32-byte seed `rho`. The ciphertext is `32*(10*3 + 4) = 1088`: 768 coefficients of `u` at 10 bits
(960 bytes) and 256 coefficients of `v` at 4 bits (128 bytes).

**The lattice dimension.** The MLWE secret has `k*n` integer coordinates: 512, 768, 1024.
So ML-KEM-1024 is already a "1000-dimension" module lattice scheme, and it is in category 5.
Dimension alone does not set security: FrodoKEM-976 (plain LWE, dimension 976, q = 2^16) is a
category-3 design (see `pq-families-for-diversity` and `attack-cost-estimation`).

The category claims (Section 8, PDF p. 49 [40]): "ML-KEM-512 is claimed to be in security
category 1, ML-KEM-768 is claimed to be in security category 3, and ML-KEM-1024 is claimed to be
in security category 5." NIST "recommends using ML-KEM-768 as the default parameter set", and
also says "When initially establishing cryptographic protections for data, the strongest
possible parameter set should be used" (same page). Section 3.2 (PDF p. 23 [14]) points to
SP 800-57 Part 1 for the definition of the categories; Section 8 points to the Call for
Proposals.

### 1.4 Decapsulation failure rates (Table 1)

FIPS 203 Section 3.2, PDF p. 24 [15], Table 1: ML-KEM-512 `2^-138.8`, ML-KEM-768 `2^-164.8`,
ML-KEM-1024 `2^-174.8`. The probability is over random `d, z, m`, conditioned on no RBG failure,
and assumes the hash functions and XOFs behave like random functions; FIPS 203 cites Theorem 1
of the Kyber paper [8] and the Kyber scripts [15]. Recomputing these numbers is the job of the
`decryption-failures` topic.

### 1.5 Required checks and other "shall" statements

All from FIPS 203 Section 3.3 (PDF p. 24-26 [15-17]) and Section 7 (PDF p. 44-47 [35-38]).

- **Encapsulation-key check** (Section 7.2): (1) type check, `ek` is exactly `384k + 32` bytes;
  (2) modulus check, `ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]`, which ensures every
  12-bit field is in `[0, q-1]`. "ML-KEM.Encaps shall not be run with an encapsulation key that
  has not been checked", but the check need not be repeated by the encapsulating party or on
  every call if assurance is obtained by other means (SP 800-227).
  Worked example (`nist_pqc_check.py` section 5): a 12-bit field holding 3328 re-encodes to
  itself; a field holding 3329 decodes to 0 (because ByteDecode12 reduces mod q) and re-encodes
  to a different byte string, so the check rejects it.
- **Decapsulation input check** (Section 7.3): (1) ciphertext type check, `c` is exactly
  `32(du*k + dv)` bytes; (2) decapsulation-key type check, `dk` is exactly `768k + 96` bytes;
  (3) hash check, `H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]`, i.e. the stored hash of `ek`
  matches the stored `ek`. "Ciphertext checking shall be performed with every execution of
  ML-KEM.Decaps"; the key check may be done once or assured by other means.
- **Implicit rejection** (Alg. 18): on a re-encryption mismatch the output is `J(z || c)`, a
  pseudorandom key the sender cannot predict, not an error. The comparison flag "is a secret
  piece of intermediate data", "shall be destroyed", and "returning the value of the flag as an
  output in any form is not permitted" (Section 6.3, PDF p. 42 [33]). In code this means a
  constant-time compare and a constant-time select (see `side-channels-faults-and-ct-verification`).
- **Optional key-pair check** (Section 7.1, PDF p. 45 [36]): seed consistency, the `ek` check,
  the `dk` check, and a pair-wise consistency test (encapsulate a random `m`, decapsulate,
  compare). FIPS 203 says these checks do not prove the key pair was properly generated.
- **Randomness**: an approved RBG (SP 800-90A/B/C) with security strength at least 128 / 192 /
  256 bits for ML-KEM-512 / 768 / 1024. A fresh 32-byte string for every KeyGen and Encaps.
- **Destruction of intermediate values**: only the designated outputs may remain in memory; the
  two exceptions are the seed `(d, z)` (which "shall be treated with the same safeguards as a
  decapsulation key") and the public matrix `A_hat`.
- **No floating-point arithmetic.**
- **Equivalent implementations** are allowed: any procedure with the same input-output
  behaviour conforms.
- **Shared secret use**: `K` (256 bits) may be used directly as a symmetric key; further keys
  "shall be derived ... in an approved manner, as specified in SP 800-108 and SP 800-56C".
  FIPS 203 warns: "a combined KEM that includes ML-KEM as a component might not meet IND-CCA2
  security" and points to SP 800-227 (Section 3.3, PDF p. 25 [16]).
- **SampleNTT loop bound** (Appendix B, PDF p. 55 [46], Table 4): implementations "should not
  bound this loop, if at all possible"; if they do, the limit shall not be lower than 280
  iterations, whose probability of being reached is `2^-261`. `nist_pqc_check.py` section 6
  recomputes this as a binomial tail: `log2 P = -261.24` (negative control with 250 iterations
  is caught). `samplentt_bound.py` (run: `timeout 300 python research/scripts/pq/samplentt_bound.py`)
gives the same `2^-261.24`, an expected 157.7 iterations, and a fixed-seed Monte Carlo mean of
157.75 over 20000 runs.

### 1.6 Differences from round-3 Kyber (Appendix C, PDF p. 56 [47])

1. The shared secret is fixed at 256 bits (Kyber round 3 allowed variable length).
2. A different FO variant: "ML-KEM.Encaps no longer includes a hash of the ciphertext in the
   derivation of the shared secret", and Decaps is adjusted to match. (Round-3 Kyber derived
   `K = KDF(K_bar || H(c))`; ML-KEM outputs `K` from `G(m || H(ek))` directly.)
3. The round-3 step `m <- H(m)` in Encaps is removed, because the standard requires an approved
   RBG.
4. Explicit input checks (Section 7) are new.
5. Changes after the draft (Appendix C.2): domain separation by `k` in K-PKE.KeyGen, and the
   indices of `A_hat` restored to Kyber's order (the draft had swapped them).

The consequence for testing: round-3 Kyber test vectors do not match ML-KEM. Use the NIST ACVP
ML-KEM vectors (see `rust-pqc-implementations` and `testing-ci-cd`).

### 1.7 Errata and updates since August 2024

The CSRC page carries a planning note dated 11/17/2025: "We've identified an issue that will be
corrected in a future update/revision of this publication" and links an "Errata (potential
updates)" spreadsheet (fetched 2026-09-27; byte-identical to the copy fetched 2026-09-26;
dumped with `nist_xlsx_dump.py`). The spreadsheet says potential corrections "DO NOT introduce
new technical requirements" and "ARE NOT official changes". It lists two items:

| Date identified | Location | Issue | Potential correction |
|---|---|---|---|
| 2025-03-31 | Appendix A | the zeta table includes the value 1 (i = 0), which Algorithms 9 and 10 do not use | add a sentence saying the value 1 is included so the i-th entry equals `zeta^BitRev7(i)` |
| 2025-10-17 | Section 5.3 | Algorithm 15 line 7 comment says "decode plaintext m from polynomial v", but `v` is not used | change the comment to "polynomial w" |

Neither changes input-output behaviour. `nist_pqc_check.py` section 3 recomputes both
Appendix A tables (128 values each) from `zeta = 17` and matches them to the numbers printed in
the PDF, including the leading 1. No revised FIPS 203 has been published as of 2026-09-27.

## 2. FIPS 204 ML-DSA and FIPS 205 SLH-DSA

These are signature standards. Turing could use one to sign release artefacts or file headers.
Both were published 2024-08-13 (CSRC pages, fetched 2026-09-26/27).

### 2.1 FIPS 204 ML-DSA (from CRYSTALS-Dilithium)

`nist-fips-204-ml-dsa.pdf`, Section 4, PDF p. 25-26 [15-16], Tables 1 and 2. All three sets use
`q = 8380417`, `zeta = 1753` (a 512-th root of unity), `d = 13` dropped bits.

| Set | (k, l) | eta | tau | lambda | gamma1 | gamma2 | beta | omega | category | public key | private key | signature |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | (4,4) | 2 | 39 | 128 | 2^17 | (q-1)/88 | 78 | 80 | 2 | 1312 | 2560 | 2420 |
| ML-DSA-65 | (6,5) | 4 | 49 | 192 | 2^19 | (q-1)/32 | 196 | 55 | 3 | 1952 | 4032 | 3309 |
| ML-DSA-87 | (8,7) | 2 | 60 | 256 | 2^19 | (q-1)/32 | 120 | 75 | 5 | 2592 | 4896 | 4627 |

(sizes in bytes; the `gamma1` exponents were read with `pdfspans.py` because plain extraction
flattens `2^17` to "217"). Note ML-DSA-44 is category **2**, not 1.

FIPS 204 errata spreadsheet (fetched 2026-09-27, planning note dated 07/31/2026 on the CSRC
page): mostly editorial items, plus one numeric correction dated 2026-07-31: the "Repetitions"
row of Table 1 becomes 4.36 / 5.14 / 3.91 (was 4.25 / 5.1 / 3.85), and the minimum allowable
loop limit for internal signing in Table 3 becomes 821 (was 814). An implementation that caps
the signing loop at 814 would fall below the corrected minimum. This matters only if Turing
signs with ML-DSA and caps the loop.

### 2.2 FIPS 205 SLH-DSA (from SPHINCS+)

`nist-fips-205-slh-dsa.pdf`, Section 11, PDF p. 53 [43], Table 2. Twelve parameter sets (each row
exists in a SHA2 and a SHAKE version):

| Set (SHA2 / SHAKE) | n | h | d | h' | a | k | lg w | m | category | pk bytes | sig bytes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 128s | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 30 | 1 | 32 | 7 856 |
| 128f | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 34 | 1 | 32 | 17 088 |
| 192s | 24 | 63 | 7 | 9 | 14 | 17 | 4 | 39 | 3 | 48 | 16 224 |
| 192f | 24 | 66 | 22 | 3 | 8 | 33 | 4 | 42 | 3 | 48 | 35 664 |
| 256s | 32 | 64 | 8 | 8 | 14 | 22 | 4 | 47 | 5 | 64 | 29 792 |
| 256f | 32 | 68 | 17 | 4 | 9 | 35 | 4 | 49 | 5 | 64 | 49 856 |

The categories are claimed for EUF-CMA "when each key pair is used to sign at most 2^64
messages" (same page). SLH-DSA's security rests only on the hash function, which makes it the
conservative choice for signing releases.

**SP 800-230 (initial public draft, 2026-04-13; comments closed 2026-06-12; public comments
posted 2026-07-01).** Six additional SLH-DSA parameter sets for categories 1, 3 and 5 with "a
strict limit of 2^24 signatures per signing key", aimed at "the signing of software, firmware,
and digital certificates"; "not approved for general-purpose use" (CSRC abstract, fetched
2026-09-27). Still a draft. Release signing is exactly its target use case, so it is worth
watching, but a draft cannot be cited as approved.

## 3. FN-DSA (FIPS 206) and HQC (FIPS 207)

### 3.1 Status as of 2026-09-27: neither has a published draft

Checked on 2026-09-27 against four CSRC pages:

- The "Selected Algorithms" page lists FALCON (2022) and HQC (2025) each with "FIPS coming
  soon", against FIPS 203/204/205 for the other three.
- The PQC "News and Updates" page: the newest items are IR 8610 (2026-05-14), SP 800-133r3
  ipd (2026-04-17), SP 800-230 ipd (2026-04-13), SP 800-227 final (2025-09-18), HQC selection
  (2025-03-11). No FIPS 206 or FIPS 207 draft is announced.
- The "Workshops and Timeline" page (marked "Updated August 05, 2026") has no FIPS 206 or 207
  entry.
- `https://csrc.nist.gov/pubs/fips/206/ipd` and `.../207/ipd` return HTTP 404 (the URL pattern
  used by FIPS 203/204/205 drafts).

So FN-DSA and HQC are selected but not yet standardised, not even as public drafts. This is
a negative finding from web pages on one date; re-check before citing it.

### 3.2 FN-DSA (Falcon), FIPS 206

Source: Perlner, "FIPS 206 Status Update", NIST, Sixth PQC Standardization Conference
(2025-09-24/26), `2025-perlner-nist-fips-206-fn-dsa-status-slides.pdf`. The slides say NIST
"expect[s] to release an Initial Public Draft soon", "It's basically written, awaiting approval"
(slide 2). Facts marked "provisional" in the slides:

- FN-DSA is a hash-then-sign NTRU-lattice signature over `Z_q[X]/(X^n+1)`, using FFT and an LDL
  tree to approximate discrete Gaussian sampling; "very small signatures and public keys but is
  difficult to implement"; key generation and signing need floating-point arithmetic (slide 3).
- Signing must match KATs exactly, with specified order of operations and no fused
  multiply-add; verification uses no floating point (slide 6).
- Only randomized signing; seeds may not be exported (slide 8).

For Turing: FN-DSA is not available as a standard. Its floating-point signing is the hardest
of all the PQ algorithms to implement safely (the slides say so). If Turing needs a signature,
ML-DSA or SLH-DSA are final standards.

### 3.3 HQC, the fourth-round selection (NIST IR 8545)

The fourth-round report is **NIST IR 8545**, "Status Report on the Fourth Round of the NIST
Post-Quantum Cryptography Standardization Process", March 2025 (`nist-ir-8545-pqc-round4-report.pdf`,
title page; "Approved by the NIST Editorial Review Board on 2025-03-05"). The CSRC news item is
dated 2025-03-11.

What it says (quotes from `nist-ir-8545-pqc-round4-report.pdf`):

- Why a second KEM at all: "NIST values having a variety of computational hardness assumptions
  and aims to reduce the risk that a single cryptanalytic breakthrough will leave no viable
  standard for key establishment" (Section 2.2.1, PDF p. 11-12 [4-5]). The fourth-round KEMs
  were chosen because their security rests on assumptions "that differ significantly from that
  of ML-KEM".
- Why HQC and not BIKE: both need a low enough decryption failure rate (DFR) for IND-CCA2.
  "NIST does not consider the DFR analysis for BIKE to be as mature as that for HQC.
  Additionally, HQC is not believed to require additional modifications to achieve the desired
  security properties. Given the critical need for strong IND-CCA2 security in a
  general-purpose KEM, HQC was selected for standardization" (PDF p. 16 [9]).
- Why not Classic McEliece: limited interest, and it "is currently under consideration for
  standardization by the International Organization for Standardization (ISO)". "After the ISO
  standardization process has been completed, NIST may consider developing a standard for
  Classic McEliece based on the ISO standard" (PDF p. 16 [9]).
- Next step: "NIST will create a draft standard based on HQC and post it for public comment.
  After the comments are adjudicated, NIST will publish a final version in approximately two
  years" (Section 4, PDF p. 25 [18]).

The HQC FIPS will be FIPS 207 ("FIPS 207: HQC-KEM", Robinson, NIST, Sixth PQC Standardization
Conference, `2025-robinson-nist-fips-207-hqc-kem-slides.pdf`). The slides list changes "under
consideration" relative to the round-4 specification: a salted FO transform using
`(ek_KEM, salt)` in the derivation of `K` that "fixes the IND-CCA2 issue that was raised on the
pqc-forum"; removal of `x` from the secret key and addition of `seed_KEM`; SHA3-512 for seed
expansion; shared secret and randomness reduced from 40 to 32 bytes; and a possible one-byte
"confirmation code" from Glabush et al. (Crypto 2025, ePrint 2025/450) against implementations
that skip re-encryption (slides 17-20). None of this is final. Relevance to Turing: HQC is the
only NIST-track KEM whose hardness does not come from lattices. The `pq-families-for-diversity`
note covers its sizes and security; `hybrid-combiners` covers combining it with ML-KEM.

## 4. NIST SP 800-227

**Status: final.** NIST SP 800-227, "Recommendations for Key-Encapsulation Mechanisms"
(Alagic, Barker, Chen, Moody, Robinson, Silberg, Waller), dated September 2025
(`nist-sp800-227-kem-recommendations.pdf`, running header). The CSRC news item "NIST Publishes
SP 800-227" is dated 2025-09-18; the draft was released 2025-01-07 (comments to 2025-03-07).

### 4.1 Scope

It gives definitions and properties of KEMs, requirements for KEM implementations in FIPS 140
modules, rules for using KEMs in applications, and "guidelines for vendors who wish to securely
combine keying material produced via approved post-quantum methods with keying material
produced via other (potentially quantum-vulnerable) methods" (Section 1.2, PDF p. 9-10 [1-2]).
It does not specify any KEM and does not cover migration timing.

### 4.2 What it requires of implementations (Section 1.3, PDF p. 10-11 [2-3])

Requirements testable by a validation lab ("RS", shall) and not testable ("RM", must).
Quoted in short form:

| # | Requirement |
|---|---|
| RS1 | comply with the FIPS/SP that specifies the KEM (ML-KEM: FIPS 203) |
| RS2 | follow FIPS 140-3 and its implementation guidance |
| RS3 | approved components with strength at least the parameter set's required strength |
| RS4 | random bits from SP 800-90A/B/C |
| RS5 | destroy all intermediate values before the algorithm ends, except random seeds and data computable from public information |
| RS6 | an ephemeral key pair is used for one key establishment only and destroyed as soon as possible |
| RS7-RS11 | key-confirmation rules (nonce length, MAC strength, KC key used only for KC, approved MAC: HMAC, AES-CMAC, KMAC, AES-GMAC) |
| RM1 | implementations must correctly implement the mathematical functionality (lab tests cannot prove it) |
| RM2 | choose a parameter set with application-appropriate strength |
| RM3 | an encapsulator using a static key must have assurance of the owner's ownership |
| RM4 | devices must be appropriately secured |
| RM5 | the channel must have application-appropriate integrity |

Section 1.3 says "Requirements RS6, RS7, RS8, RS10, and RS11 pertain to key confirmation (Sec.
4.4), which is recommended but not required". As printed this list looks off: RS6 is the
ephemeral-key rule (Section 4.2) and RS9 is a key-confirmation rule (Section 4.4.2). Appendix D
item 3 says the ephemeral-key "shall" was added after the draft, which may explain a stale
numbering. Read the requirement texts, not the list. Section 3.3 (PDF p. 22 [14]) adds two "should" items: avoid leaking information
about failures and aborts outside the module, and use side-channel countermeasures including
"constant-time implementations". Section 3.1 (PDF p. 20 [12]) stresses that validation tests
only a few inputs, so "validation testing does not guarantee correct functioning on all inputs".
This is the formal reason Turing needs its own differential and property testing beyond the
NIST vectors (see `testing-ci-cd`).

Input checking can be skipped when the module generated the input itself and stored it
unmodifiable, checked it once and stored it unmodifiable, or imported it from a trusted third
party (Section 3.2, PDF p. 21 [13]).

### 4.3 Using the shared secret (Section 4.3, PDF p. 27-28 [19-20])

The KEM key `K` may be used directly, truncated, or split into non-overlapping pieces; the
strength of a shorter key is the minimum of `K`'s strength, the length, and the KDM's strength.
For more keying material, `K` is a key-derivation key for SP 800-108, SP 800-56C or SP 800-133.
Appendix D item 6 says this was added because ML-KEM "outputs 256-bit keys at all security
levels".

### 4.4 Key confirmation (Section 4.4, PDF p. 28-31 [20-23])

"Key confirmation should be used during KEM usage", and "successful use of the shared secret
key for authenticated encryption can act as key confirmation". The explicit method: derive a dedicated `KC_Key`
(first part of the derived keying material, or of `K` itself), MAC the string
`KC_Step_Label || ID_P || ID_R || Eph_P || Eph_R || Extra_P || Extra_R` with an approved MAC,
where `KC_Step_Label` is one of "KC_1_E", "KC_2_E", "KC_1_D", "KC_2_D"; the encapsulator's
ephemeral data is the ciphertext. Our inference for file encryption, where there is no
interactive partner: if the file is authenticated under a key derived from `K`, the tag check
on decryption plays the key-confirmation role that the quoted sentence describes.

### 4.5 Hybrid / composite KEMs (Section 4.6, PDF p. 34-40 [26-32])

- Terms: a *multi-algorithm* scheme combines shared secrets from two or more schemes; a
  *composite KEM* is the case where all parts are KEMs; *PQ/T hybrid* combines one
  post-quantum and one traditional scheme. X-Wing (ML-KEM + X25519) is named as an example of
  a PQ/T hybrid KEM (Section 4.6, PDF p. 34 [26]).
- Composite construction (Section 4.6.1): `ek = ek1 || ek2`, `dk = dk1 || dk2`,
  `c = c1 || c2`, `K = KeyCombine(K1, K2, c1, c2, ek1, ek2, p)`. For "completely general"
  schemes, including "pre-shared keys or shared secrets established via quantum key
  distribution", "an approved key combiner discussed in Sec. 4.6.2 shall be used".
- **Approved combiners** (Section 4.6.2, PDF p. 36-38 [28-30]): (a) an SP 800-56C key
  derivation method applied to `Z = (S1, S2, ..., St)`, approved "for any t > 1 if at least one
  shared secret ... is generated from the key-establishment methods in SP 800-56A or SP 800-56B
  or an approved KEM"; with the two-step (extract-then-expand) method, extraction takes all
  shared secrets as input; `FixedInfo` may carry ciphertexts, keys, parameter sets and domain
  separators. (b) SP 800-133 key combination (concatenation, XOR, HMAC extraction), which
  requires *every* input key to be generated by approved methods; a concatenated result
  "should" pass through a KDF before use.
- Inputs are "comma-separated", not raw concatenation, because `x||y = x'||y'` can happen with
  variable lengths (Section 4.6.2, PDF p. 37 [29]; Appendix D item 4 says this changed after
  the draft).
- **IND-CCA preservation** (Section 4.6.3, PDF p. 39-40 [31-32]): the plain combiner
  `K = KDF(K1, K2)` "does not preserve IND-CCA security, regardless of the properties of the
  KDF". NIST "encourages" combiners that preserve IND-CCA when at least one component is
  IND-CCA, e.g. `KeyCombineCCA_H = H(K1, K2, c1, c2, ek1, ek2, domain_sep)` with `H` from the
  SHA-3 family, which preserves IND-CCA "if H is modeled as a random oracle". The domain
  separator "should be used to uniquely identify the composite scheme in use". The document
  also warns that composites add complexity and choices that may enable downgrade attacks.

How X-Wing's specific combiner (which omits the ML-KEM ciphertext and key from the hash) fits
this rule is analysed in the `hybrid-combiners` note; this note only records what SP 800-227
says.

### 4.6 KEM-DEM encryption (Section 5.2.1, PDF p. 43-44 [35-36])

SP 800-227 gives the KEM-DEM construction as an example (not a requirement): encapsulate to
get `K`, encrypt the message with a symmetric scheme under `K` (derive a key if lengths
differ), send `(c_KEM, c_DEM)`. This is exactly the shape of Turing's planned file encryption:
ML-KEM (or a hybrid) supplies the key, the Turing cipher encrypts the data.

## 5. NIST IR 8547

**Status: still an initial public draft.** NIST IR 8547 ipd, "Transition to Post-Quantum
Cryptography Standards" (Moody, Perlner, Regenscheid, Robinson, Cooper), November 2024
(`nist-ir-8547-pqc-transition.pdf`). The CSRC page (fetched 2026-09-27) shows "Date Published:
November 12, 2024", comments closed 2025-01-10, a planning note of 01/21/2025 saying the
comments are available, and a document history with only "11/12/24: IR 8547 (Draft)".
`https://csrc.nist.gov/pubs/ir/8547/final` returns 404. So the dates below are NIST's stated
intent in a draft, not a final rule. The NIST PQC project page (fetched 2026-09-27) summarises
it as: "Under the transition timeline in NIST IR 8547, NIST will deprecate and ultimately remove
quantum-vulnerable algorithms from its standards by 2035".

Terms (taken from SP 800-131A, Section 4.1, PDF p. 19 [12]): *deprecated* means the algorithm
"may be used, but there is some security risk"; *disallowed* means "no longer allowed for the
stated purpose"; *legacy use* means only to process already-protected data.

### 5.1 Dates for quantum-vulnerable algorithms (Tables 2 and 4, PDF p. 20-21 [13-14])

| Family | 112-bit security strength | at least 128-bit security strength |
|---|---|---|
| ECDSA, RSA signatures (FIPS 186) | deprecated after 2030, disallowed after 2035 | disallowed after 2035 |
| EdDSA (FIPS 186) | (no 112-bit row) | disallowed after 2035 |
| Finite-field DH and MQV (SP 800-56A) | deprecated after 2030, disallowed after 2035 | disallowed after 2035 |
| Elliptic-curve DH and MQV (SP 800-56A) | deprecated after 2030, disallowed after 2035 | disallowed after 2035 |
| RSA key establishment (SP 800-56B) | deprecated after 2030, disallowed after 2035 | disallowed after 2035 |

The earlier plan in SP 800-57 Part 1 was to disallow 112-bit public-key schemes on 2031-01-01;
IR 8547 replaces that with "deprecate" (PDF p. 20 [13]). It adds that "application-specific
guidance ... may require or recommend migration to quantum-resistant key establishment schemes
before the classical schemes are generally disallowed", to address harvest-now-decrypt-later
(PDF p. 22 [15]). Symmetric standards at the 112-bit level "will be disallowed in 2030"
(Section 4.1.3, PDF p. 22 [15]); symmetric primitives with at least 128 bits of classical
security "are believed to meet the requirements of at least Category 1".

Section 4 (PDF p. 18 [11]) cites National Security Memorandum 10 (NSM-10), which "establishes
the year 2035 as the primary target for completing the migration to PQC across Federal
systems", and adds that systems "with long-term confidentiality needs ... may require earlier
transitions".

### 5.2 Security categories as listed in IR 8547 (Table 1, PDF p. 19 [12])

| Category | Attack type | Example |
|---|---|---|
| 1 | key search on a block cipher with a 128-bit key | AES-128 |
| 2 | collision search on a 256-bit hash function | SHA-256 |
| 3 | key search on a block cipher with a 192-bit key | AES-192 |
| 4 | collision search on a 384-bit hash function | SHA3-384 |
| 5 | key search on a block cipher with a 256-bit key | AES-256 |

Table 5 (PDF p. 22 [15]) pairs ML-KEM-512 / 768 / 1024 with 128 / 192 / 256 bits and
categories 1 / 3 / 5. (The draft misprints the last two rows as "ML-DSA-768" and "ML-DSA-1024";
the column header and FIPS 203 make clear ML-KEM is meant.) It states that "ML-KEM is the only
approved post-quantum key-establishment scheme based on public key cryptography".

### 5.3 What IR 8547 says about hybrids (Section 3.2, PDF p. 15-17 [8-10])

- Hybrids "are typically designed to remain secure if at least one of the component algorithms
  is secure" and are "a hedge against a cryptographic or implementation flaw", but "add
  complexity ... which can increase security risks and costs"; they are "typically expected to
  be temporary measures that lead to a second transition to ... only PQC algorithms".
- Hybrid key establishment: SP 800-56C already allows `Z' = Z || T` where `Z` comes from an
  approved scheme and `T` from any other scheme. NIST "intends to update SP 800-56C so that the
  value Z may be generated as specified by any current and future NIST key-establishment
  standards", including FIPS 203, and "any shared secret key generated as specified in FIPS 203
  may be used as the value Z". (SP 800-227 Section 4.6.2, published later, now states the
  approved combiners directly; see Section 4.5 above.)
- Hybrid signatures: dual signatures are accommodated "provided that at least one component
  digital signature algorithm is NIST-approved".
- "NIST will accommodate the use of a hybrid key-establishment mode and dual signatures in FIPS
  140 validation when suitably combined with a NIST-approved scheme."

## 6. NIST security categories

### 6.1 The definitions

The five categories were defined in the 2016 Call for Proposals, Section 4.A.5
(`nist-pqc-call-for-proposals-2016.pdf`, PDF p. 16-18). Each category is "defined by a
comparatively easy-to-analyze reference primitive, whose security will serve as a floor":
"Any attack that breaks the relevant security definition must require computational resources
comparable to or greater than those required for":

1. key search on a block cipher with a 128-bit key (e.g. AES128);
2. collision search on a 256-bit hash function (e.g. SHA256/ SHA3-256);
3. key search on a block cipher with a 192-bit key (e.g. AES192);
4. collision search on a 384-bit hash function (e.g. SHA384/ SHA3-384);
5. key search on a block cipher with a 256-bit key (e.g. AES 256).

The requirement must hold "with respect to all metrics that NIST deems to be potentially
relevant to practical security" (PDF p. 17). FIPS 203, 204 and 205 all say security strength is
"not described by a single number" but by a claim that breaking the scheme costs at least as
much as breaking the reference primitive "using any realistic model of computation" (FIPS 203
Section 8, PDF p. 48-49 [39-40]); they point to SP 800-57 Part 1 for the categories. IR 8547
ipd Table 1 restates them (Section 5.2 above).

### 6.2 MAXDEPTH and the gate counts

"As preliminary guidance to submitters, NIST suggests an approach where quantum attacks are
restricted to a fixed running time, or circuit depth. Call this parameter MAXDEPTH" (PDF p. 17).
Plausible values: `2^40` logical gates ("presently envisioned quantum computing architectures
are expected to serially perform in a year"), `2^64` ("current classical computing
architectures can perform serially in a decade"), "no more than" `2^96` ("atomic scale qubits
with speed of light propagation times could perform in a millennium").

Gate-count estimates for the reference attacks, as printed (exponents were read from the PDF
text, which flattens `2^170` to "2170"; the 2022 values are from the same table layout):

| Reference | 2016 call (PDF p. 18), quantum | 2022 signature call (PDF p. 17), quantum | classical (both) |
|---|---|---|---|
| AES-128 key search | 2^170 / MAXDEPTH | 2^157 / MAXDEPTH | 2^143 |
| SHA3-256 collision | - | - | 2^146 |
| AES-192 key search | 2^233 / MAXDEPTH | 2^221 / MAXDEPTH | 2^207 |
| SHA3-384 collision | - | - | 2^210 |
| AES-256 key search | 2^298 / MAXDEPTH | 2^285 / MAXDEPTH | 2^272 |
| SHA3-512 collision | - | - | 2^274 |

The 2016 quantum figures cite Grassl, Langenberg, Roetteler and Steinwandt (PQCrypto 2016);
the 2022 figures cite Jaques, Naehrig, Roetteler and Virdia (2020), "Implementing Grover Oracles
for Quantum Key Search on AES and LowMC". The 2022 quantum figures are 13, 12 and 13 bits lower
than the 2016 ones; the classical figures did not change. The quantum
figures are gate counts *given a depth limit*: at `MAXDEPTH = 2^64`, AES-128 costs
`2^(157-64) = 2^93` quantum gates in the 2022 table. `nist_pqc_check.py` section 8 prints the
full grid for `MAXDEPTH` in `{2^40, 2^64, 2^96}` and checks the stated order (AES-128 below
SHA3-256, etc.).

Both calls add: Grover "requires a long-running serial computation", and running many smaller
instances in parallel "makes the quantum speedup less dramatic"; and a
hybrid cost metric may rate logical quantum gates "several orders of magnitude more expensive
than classical gates", though for high categories "it is likely prudent to consider the
possibility that this disparity will narrow significantly or even be eliminated" (2022 call,
PDF p. 17).

### 6.3 Memory and cost models (IR 8413, Appendix B)

The third-round report (`nist-ir-8413-pqc-round3-report.pdf`; the file is IR 8413-upd1)
explains why lattice categories are hard to pin down. Appendix B (PDF p. 90-92 [81-83]): the RAM
model "will generally underestimate the cost of attacks that require random access to a large
memory"; parameters that meet their target in the RAM model "should therefore be considered
safe barring new cryptanalysis", while more aggressive parameters might be argued safe in a
local (2D or 3D nearest-neighbour) model where a memory access costs `O(sqrt(n))` or
`O(n^(1/3))`. On Kyber (Section 4.1, PDF p. 38 [29]): dual-attack improvements during round 3
"suggest that all three KYBER parameter sets fall slightly below the security targets for
their claimed security levels when the cost of memory access for the attacker is not explicitly
taken into account". So the category claims of ML-KEM rely partly on memory costs. The
`attack-cost-estimation` note covers the numbers.

### 6.4 Where does a ~1000-dimension lattice scheme land?

There is no rule that maps dimension to category. Two published data points show the spread:

- ML-KEM-1024: module rank `k = 4` over `n = 256`, so 1024 secret coordinates, `q = 3329`,
  CBD with `eta = 2` (standard deviation 1). Claimed category 5 (FIPS 203 Section 8).
- FrodoKEM-976: plain LWE, dimension 976, `q = 2^16`. Claimed category 3 (see the
  `pq-families-for-diversity` note for the FrodoKEM table and source).

A second meaning of "dimension" causes confusion. The *scheme* dimension is the number of
secret coordinates (`k*n`). The *attack* dimension is the size of the lattice the attacker
reduces, which is larger because it also contains the samples. The round-3 Kyber specification,
Table 4 (`2021-avanzi-et-al-kyber-round3-specification.pdf`, PDF p. 21), gives for the primal
attack: lattice dimension `d` = 999 / 1419 / 1885 (core-SVP method) and 1025 / 1467 / 1918
(refined estimate) for Kyber512 / 768 / 1024, BKZ block sizes 406 / 626 / 878 and 413 / 637 /
894, and refined classical cost `log2(gates)` = 151.5 / 215.1 / 287.3 with `log2(memory in
bits)` = 93.8 / 138.5 / 189.7. So a "1000-dimension" attack lattice is what breaking the
*smallest* Kyber needs. Against the 2022-call classical thresholds (2^143 / 2^207 / 2^272) the
margins are 8.5 / 8.1 / 15.3 bits (`nist_pqc_check.py` section 9). These are Kyber round-3
figures. ML-KEM uses the same `(n, k, q, eta1, eta2, du, dv)` as round-3 Kyber (Kyber round-3
spec Table 1, PDF p. 11, matches FIPS 203 Table 2), and none of the Appendix C changes touches
the MLWE instance, so the attack figures carry over; the `attack-cost-estimation` note should
still confirm them with a current estimator.

The category depends on the dimension *and* on `q` and the noise width (the ratio `q/sigma`
fixes how much lattice reduction is needed) and on the cost model. A new ~1000-dimension design
gets a category only from a lattice-estimator run on its exact `(n, q, secret and error
distributions, number of samples)`, with the result compared against the gate counts in 6.2;
that is the job of `attack-cost-estimation`. Any category claimed without such an estimate is
unverified.

## 7. Additional-signature on-ramp

Source: NIST IR 8610, "Status Report on the Second Round of the Additional Digital Signature
Schemes for the NIST Post-Quantum Cryptography Standardization Process", May 2026 ("Approved by
the NIST Editorial Review Board on 2026-05-05"), `nist-ir-8610-pqc-additional-signatures-round2-report.pdf`.
The CSRC news item "NIST Advances 9 Candidates to the 3rd Round of PQC" is dated 2026-05-14.

- The process is now in its **third round**. Nine candidates advance: "FAEST, HAWK, MAYO,
  MQOM, QR-UOV, SDitH, SNOVA, SQIsign, and UOV" (abstract, PDF p. 5 [i]).
- Timeline (Table 1, PDF p. 6-7): call published September 2022; 40 first-round candidates
  July 2023; 14 second-round candidates October 2024 (IR 8528); third round announced May 2026.
- Second-round candidates not advanced include CROSS, LESS, Mirath, PERK and RYDE (Table 2, PDF
  p. 10 [3], compared with the list above). "The algorithms that were not selected for the
  third round are no longer under consideration" (PDF p. 15 [8]).
- On HAWK: "While HAWK is lattice-based, it offers smaller signatures than Falcon and does not
  need floating-point arithmetic" (PDF p. 15 [8]).

For Turing: nothing from the on-ramp is a standard, and nothing will be for years. It is not a
source of a usable signature today.

## 8. Other authorities

### 8.1 NSA CNSA 2.0 (United States, National Security Systems)

Sources: the original advisory "Announcing the Commercial National Security Algorithm Suite
2.0", U/OO/194427-22, PP-22-1338, September 2022, Ver. 1.0
(`nsa-2022-cnsa-2.0-announcement-csa.pdf`), and the FAQ "The Commercial National Security
Algorithm Suite 2.0 and Quantum Computing FAQ", PP-24-4014, December 2024, Ver. 2.1
(`nsa-cnsa-2.0-faq.pdf`). A web search on 2026-09-27 shows a re-issued advisory at a
`media.defense.gov/2025/May/30/...` URL; it returns HTTP 403 to scripted downloads, so its
content is not checked here (UNVERIFIED; open it in a browser to settle).

Algorithms (FAQ, PDF p. 3, "General Purpose Algorithms"):

| Algorithm | Specification | Parameters |
|---|---|---|
| AES | FIPS 197 | 256-bit keys for all classification levels |
| ML-KEM | FIPS 203 | ML-KEM-1024 for all classification levels |
| ML-DSA | FIPS 204 | ML-DSA-87 for all classification levels (any use, including signing firmware and software) |
| SHA | FIPS 180-4 | SHA-384 or SHA-512 |
| LMS, XMSS | SP 800-208 | allowed in specific applications (software/firmware signing); the 2022 advisory says "SHA-256/192 recommended" for LMS (Table I, PDF p. 3) |

The 2022 advisory (Table III, PDF p. 4) named "CRYSTALS-Kyber ... Use Level V parameters" and
"CRYSTALS-Dilithium ... Level V", with specification "TBD"; the FAQ replaces these with the
FIPS names. So NSA requires only the category-5 lattice parameter sets.

Timeline. The 2022 advisory (PDF p. 5-6): "NSA expects the transition to QR algorithms for NSS
to be complete by 2035 in line with NSM-10"; per-technology dates, e.g. software and firmware
signing "exclusively use CNSA 2.0 by 2030", web browsers/servers and cloud services "support
and prefer CNSA 2.0 by 2025, and exclusively use CNSA 2.0 by 2033", traditional networking
equipment exclusive by 2030, operating systems prefer by 2027 and exclusive by 2033, custom
applications and legacy equipment "update or replace by 2033". The FAQ (PDF p. 11-12) adds dates
from the updated CNSSP 15: "by January 1, 2027, all new acquisitions for NSS will be required to
be CNSA 2.0 compliant unless otherwise noted"; "By December 31, 2030, all equipment and services
that cannot support CNSA 2.0 must be phased out unless otherwise noted, and by December 31,
2031, CNSA 2.0 algorithms are mandated for use unless otherwise noted".

Hybrids (FAQ, PDF p. 19-20): "NSA has confidence in CNSA 2.0 algorithms and will not require NSS
developers to use hybrid certified products for security purposes", though "product
availability and interoperability requirements may lead to adopting hybrid solutions". It warns
that hybrids add complexity and "spending limited resources to add cryptographic complexity can
at times weaken security rather than improve it". This is the opposite emphasis to BSI and
ANSSI (below).

### 8.2 BSI TR-02102-1 (Germany)

Current version: **2026-01, "As of: January 23, 2026"** (`bsi-tr-02102-1-cryptographic-mechanisms.pdf`,
title page). The BSI web page (saved 2026-09-26) lists TR-02102-1 to -4 all at "Version:
2026-01". The English text is a courtesy translation; "the German versions take precedence"
(BSI page). The change log (PDF p. 2) says version 2026-01 brought "Updates in the area of PQ
cryptography (including the inclusion of migration periods, updates in key derivation and
hybridization), discontinuation of the sole use of classic asymmetric mechanisms". The TR
targets a security level of at least 120 bits (change log for 2023-01; Section 1).

Recommended quantum-safe KEMs (Section 2.4, PDF p. 37-39 [37-39]):

| KEM | Recommended parameter sets | Note from the TR |
|---|---|---|
| FrodoKEM | FrodoKEM-976, FrodoKEM-1344 (Table 2.5, citing the 2021 round-3 FrodoKEM spec, Section 2.5) | "since FrodoKEM, unlike ML-KEM, is based on unstructured grids [lattices], it is considered the more conservative choice"; being standardised at ISO |
| Classic McEliece | mceliece460896, mceliece6688128, mceliece8192128 and their "f" variants (Table 2.6) | "considered conservative and very thoroughly analysed"; being standardised by ISO |
| ML-KEM | ML-KEM-768, ML-KEM-1024 (Table 2.7), "parameter sets corresponding to NIST Security Strength Categories 3 and 5" | ML-KEM-512 is not recommended |
| HQC | none yet | BSI "intends to include HQC, after the publication of the standard, with parameter sets corresponding to NIST Security Strength Categories 3 and 5" |

Note that the category-1 sets (FrodoKEM-640, mceliece348864, ML-KEM-512) are all left out.

Hybrid use (Sections 2.1-2.2, PDF p. 28-29 [28-29]): "The quantum-safe mechanisms recommended in
Section 2.4 should be used in 'hybrid' form, i.e., in a suitable combination with a classical
method." The reason given: the PQ mechanisms "are generally not yet trusted to the same extent
as the established classical mechanisms, since they have not been as well studied with regard
to side-channel resistance and implementation security". Recommended combiners (Table 2.1):
**CatKDF** from ETSI TS 103 744 V1.2.1 (2025), "with KMAC or HKDF", and **KeyCombine** per
SP 800-227 Section 4.6.1 eq. (9) with Section 4.6.2 eq. (15), with `H` "using a KDF or KMAC
specified in this Technical Guideline". It also stresses that "context-dependent information is
included" in the combination.

Dates: "The sole use of classic key agreement mechanisms is only recommended until the end of
2031"; "For applications with very high protection requirements, the transition to
quantum-safe mechanisms should already take place by the end of 2030", citing a joint statement
by BSI and European partners (Section 2.1, PDF p. 28 [28]). Classical signatures are recommended
until the end of 2035. The TR says "BSI does not recommend QKD protocols at this time"
(PDF p. 29 [29]).

### 8.3 ANSSI (France)

Sources: "ANSSI views on the Post-Quantum Cryptography transition (2023 follow up)", dated
December 21, 2023 (`2023-anssi-pqc-transition-follow-up.pdf`), an addendum to the 2022 opinion
(`2022-anssi-views-on-pqc-transition.pdf`; French original "Publié le 11 avril 2022" per the
ANSSI MesServicesCyber page); and the ANSSI "FaQ sur la Cryptographie post-quantique (PQC)" at
https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/faq-pqc/ (fetched
2026-09-27; identical text to the copy saved 2026-09-26; the page carries no revision date).

- **Hybridation.** 2023 follow-up (PDF p. 2): "ANSSI still strongly emphasizes the necessity of
  hybridation wherever post-quantum mitigation is needed both in the short and medium term",
  because PQ algorithms "are still not mature enough to solely ensure the security". The FAQ
  (2026 page) repeats this ("L'ANSSI insiste fortement sur le caractère essentiel de
  l'hybridation ... partout où ils sont déployés"), exempts only hash-based signatures
  (SLH-DSA, XMSS, LMS), says that for the regulated perimeter "l'hybridation est obligatoire",
  and that ANSSI's PQC recommendations otherwise have no regulatory force.
- **KEM combiners.** The FAQ says ANSSI recommends the **CatKDF and CasKDF** modes (parallel
  concatenate-then-KDF, and cascade), which reach IND-CCA2 if the underlying KEMs do. The 2023
  follow-up (PDF p. 5) explains why simpler methods fail: concatenating keys does not give
  IND-CPA if one key is compromised, and XOR resists passive but not active attackers ("mix and
  match attacks").
- **Parameters.** For Kyber/ML-KEM (2023 follow-up, PDF p. 3): "It is important to avoid
  modifying the parameters of the standardized instance"; use "the highest NIST security level
  as possible, preferably level-5 (i.e. equivalent to AES-256) or level-3"; "use ephemeral keys
  as much as possible"; use the IND-CCA version. FrodoKEM is "a valid and conservative option in
  high security applications where the resulting performance penalty ... is not prohibitive",
  and the Kyber recommendations apply to it too.
- **Symmetric sizing.** ANSSI "encourages to dimension the parameters of symmetric primitives
  as to ensure ... at least the same security level as AES-256 for block ciphers and at least
  the same security level as SHA2-384 for hash functions" (2023 follow-up, PDF p. 2).
- **Dates (FAQ).** ANSSI aims to make PQC mandatory for products entering qualification from
  2027, and says it will not be reasonable to buy products without PQC after 2030. The FAQ
  also reports that in early October 2025 ANSSI issued its first two security visas for
  products with lattice-based PQC (Thales and Samsung, evaluated by CEA-Leti).

### 8.4 UK NCSC

Two web pages, both fetched live on 2026-09-27 and identical to copies saved on 2026-09-26:

- "Timelines for migration to post-quantum cryptography",
  https://www.ncsc.gov.uk/guidance/pqc-migration-timelines, "Published 20 March 2025",
  "Reviewed 20 March 2025", "Version 1.0". Milestones: by 2028 "Define your migration goals",
  complete discovery and an initial plan; by 2031 "Carry out your early, highest-priority PQC
  migration activities"; by 2035 "Complete migration to PQC of all your systems, services and
  products".
- "Next steps in preparing for post-quantum cryptography",
  https://www.ncsc.gov.uk/paper/next-steps-in-preparing-for-post-quantum-cryptography,
  "Published 14 August 2024", "Version 2.0" ("Originally published in November 2023, Updated in
  August 2024"). Algorithms: ML-KEM, ML-DSA, SLH-DSA. "All of these parameter sets provide an
  acceptable level of security for personal, enterprise and OFFICIAL-tier government
  information", and "The NCSC recommends ML-KEM-768 and ML-DSA-65 as providing appropriate
  levels of security and efficiency for most use cases."
- Hybrids: NCSC is neutral to sceptical. PQ/T hybrids have "greater costs", are "more complex
  to implement and maintain", but may be needed for interoperability, implementation security
  or protocol constraints. "If a PQ/T hybrid scheme is chosen, the NCSC recommends it is used as
  an interim measure, and it should be used within a flexible framework that enables a
  straightforward migration to PQC-only in the future." Hybrid mechanisms "should be designed
  carefully to ensure the hybridisation mechanism does not allow additional attacks".

### 8.5 EU coordinated roadmap and ECCG

"A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography", Part 1,
Version 1.1, EU PQC Workstream (NIS Cooperation Group), 11.06.2025
(`2025-nis-cg-eu-pqc-coordinated-roadmap.pdf`):

- Milestones (Section 4.1, PDF p. 7): by 31.12.2026 national roadmaps and first steps; by
  31.12.2030 "The PQC transition for high-risk use cases has been completed" and
  "Quantum-safe software and firmware upgrades are enabled by default"; by 31.12.2035
  medium-risk use cases completed, low-risk "as much as feasible".
- Hybrids (PDF p. 3 and 6): "it is recommended to use standardised and tested hybrid solutions,
  whenever feasible and suitable"; "For high-risk use cases, quantum-vulnerable public-key
  mechanisms shall not be used stand-alone after the end of 2030, analogously after the end of
  2035 for medium-risk use cases."

ECCG (European Cybersecurity Certification Group, Sub-group on Cryptography) "Agreed
Cryptographic Mechanisms" Version 2.0, April 2025 (`2025-eccg-agreed-cryptographic-mechanisms-v2.pdf`,
title page; statements below found with `pdfgrep.py`): lists ML-KEM (FIPS 203) and FrodoKEM as recommended ("R") KEMs, each
with notes on authentication and hybridization; "It is recommended to use the highest possible
standardised parameter size, either ML-KEM-1024 or ML-KEM-768" and "either FrodoKEM-1344 or
FrodoKEM-976"; hybrid modes "shall ensure that all combined pre or post-quantum cryptographic
mechanisms need to be broken simultaneously for the hybrid mode to be broken". Classic
McEliece does not appear in v2. (A v3 draft, 2026, is also in `research/papers/`; not read for
this note.)

### 8.6 ISO/IEC 18033-2 Amendment 2

**Published.** ISO catalogue page https://www.iso.org/standard/86890.html (saved 2026-09-26; a
fresh fetch on 2026-09-27 returned HTTP 403): "ISO/IEC 18033-2:2006/Amd 2:2026", "Status :
Published", "Publication date : 2026-06", "Stage : International Standard published [60.60]",
58 pages, ISO/IEC JTC 1/SC 27. Life cycle: new project approved 2023-05-04, DIS registered
2024-12-10, DIS approved for FDIS 2025-11-26, FDIS ballot 2026-03-05 to 2026-05-01,
"International Standard published" 2026-06-05. The ISO page does not list the contents.

Contents, from the scheme teams' own sites (fetched 2026-09-27):

- FrodoKEM: "FrodoKEM is standardized by ISO as part of ISO/IEC 18033-2:2006/Amd 2:2026"
  (https://frodokem.org/, news entry "June, 2026").
- Classic McEliece: "ISO standardized Classic McEliece in June 2026", with parameter sets
  mceliece460896, mceliece6688128, mceliece6960119, mceliece8192128, each with f, pc and pcf
  variants (https://classic.mceliece.org/iso.html, "version 2026.06.15"). The same page says
  ISO asked for "at least 128 bits of security in the 'quantum model'" with a square-root
  Grover speedup, and that ISO "decided to also standardize mceliece4*".
- ML-KEM: a web search summary (secondary sources only) says the amendment also adds ML-KEM.
  **UNVERIFIED**: the standard is paywalled (CHF 204) and no primary source seen here lists
  its contents.

So the two conservative KEMs that NIST did not standardise (FrodoKEM, Classic McEliece) now
have an international standard. That matters for Turing: a FrodoKEM-based layer can cite an
ISO standard, not only a research paper.

## What this means for Turing

Turing's earlier position (`docs/02-public-key-and-quantum.md`): the public-key layer uses vetted
implementations, and the planned file-encryption KEM is X-Wing (X25519 + ML-KEM-768). The owner
now wants a ~1000-dimension lattice layer "with a twist". The standards constrain that as
follows. Each point gives the evidence.

### A. Standards Turing's lattice layer must follow, or can cite

| If Turing uses... | It must follow | It can cite |
|---|---|---|
| ML-KEM | FIPS 203 in full (Sections 3.3, 7), including input checks, implicit rejection, RBG strength, destruction of intermediates | SP 800-227 for usage, key confirmation, combiners; NIST ACVP vectors for testing |
| a hybrid of ML-KEM with X25519 or another KEM | SP 800-227 Section 4.6.2 approved combiner if FIPS alignment is wanted; BSI Table 2.1 (CatKDF or SP 800-227 eq. 15) for BSI alignment; ANSSI CatKDF/CasKDF | IR 8547 Section 3.2.1, EU roadmap, BSI 2.2, ANSSI 2023 Section 3 |
| FrodoKEM | ISO/IEC 18033-2:2006/Amd 2:2026 (paywalled; the 2025-09-29 FrodoKEM proposal is the public text) | BSI TR-02102-1 2.4.1, ANSSI 2023, ECCG ACM v2 |
| Classic McEliece | ISO/IEC 18033-2:2006/Amd 2:2026 | BSI 2.4.2 |
| HQC | nothing yet (no FIPS 207 draft) | NIST IR 8545 for the selection |
| a signature on releases | FIPS 204 (ML-DSA-65/87) or FIPS 205 (SLH-DSA); SP 800-208 LMS/XMSS for CNSA-style firmware signing | CNSA 2.0 FAQ, ANSSI FAQ (hash-based needs no hybrid) |

### B. Where a "twist" can and cannot go

- **Not inside ML-KEM.** Changing `q`, `k`, `eta`, the compression, the hashes or the FO steps
  makes it no longer ML-KEM: FIPS 203 KATs stop applying, the Table 1 failure rates and the
  category claims stop applying, and ANSSI's first Kyber recommendation is broken ("avoid
  modifying the parameters of the standardized instance", 2023 follow-up p. 3). K-PKE alone is
  IND-CPA only and "shall not be used as a stand-alone cryptographic scheme" (FIPS 203 3.3).
  **Risk: high.** This is the "homemade structure without an estimate" pattern that `docs/02`
  already warns about (Rainbow, SIKE).
- **Around unmodified components: acceptable if done by an analysed method.** Options that the
  standards already cover:
  1. *Multi-KEM composite* (SP 800-227 4.6.1): e.g. ML-KEM-1024 + FrodoKEM-976/1344 (+ X25519).
     This adds a second lattice family (plain LWE, no ring or module structure), which BSI and
     ANSSI call "more conservative". It does **not** add assumption diversity: both are LWE.
     For a non-lattice second KEM, NIST's own reasoning (IR 8545 Section 2.2.1) points to a
     code-based KEM: Classic McEliece (ISO, large keys, suits "a public key ... transferred once
     and then used for several encapsulations (e.g., file encryption ...)", IR 8545 p. 16 [9])
     or HQC (no standard yet). Evidence and sizes: `pq-families-for-diversity`.
  2. *The combiner*: use an SP 800-227 4.6.2 form that includes ciphertexts and keys and a
     Turing-specific `domain_sep`, e.g. `SHA3-256(K1, K2, ..., c1, c2, ..., ek1, ek2, ...,
     domain_sep)` with an unambiguous length encoding. This gives IND-CCA preservation "if H is
     modeled as a random oracle" (SP 800-227 4.6.3). Plain `KDF(K1, K2)` does not. Details:
     `hybrid-combiners`.
  3. *The symmetric layer*: the Turing cipher is where Turing already differs. The shared
     secret feeds a KDF (SP 800-108 / 800-56C, or KMAC) that derives the Turing key and a
     key-confirmation or AEAD key (SP 800-227 4.3, 4.4). Putting lattice hardness *inside* the
     symmetric layer is a separate, research-grade question: `lattices-inside-symmetric-primitives`.
- **More components cost something.** NSA: "spending limited resources to add cryptographic
  complexity can at times weaken security rather than improve it" (CNSA FAQ p. 19-20); NIST IR
  8547 3.2 and SP 800-227 4.6.3 say the same about complexity and downgrade attacks. A
  three-KEM composite is beyond what any authority asks for; it must earn its place by
  analysis, not by count.

### C. Parameter level

- ML-KEM-1024 satisfies every authority read here: category 5 (FIPS 203), CNSA 2.0's only
  allowed set, ANSSI's "preferably level-5", BSI's list, NCSC's "acceptable" list. ML-KEM-768
  satisfies all except CNSA 2.0. `docs/02` chose 256-bit symmetric keys; category 5 matches
  that choice, and ANSSI encourages AES-256-level block ciphers (2023 follow-up p. 2).
- Cost of 1024 over 768: `ek` 1568 vs 1184 bytes, ciphertext 1568 vs 1088 bytes (FIPS 203
  Table 3). For file encryption (one ciphertext per file header) this is small.
- FrodoKEM-976 / -1344 are the only standardised (ISO) plain-LWE sets near 1000 dimensions;
  BSI and ECCG leave out FrodoKEM-640.
- A *new* ~1000-dimension parameter set has no category until `attack-cost-estimation` runs an
  estimator on it and `decryption-failures` computes its failure rate. Claiming a category from
  the dimension is not supported by any source (Section 6.4).

### D. Implementation obligations that turn into tests

From FIPS 203 Sections 3.3 and 7 and SP 800-227 Section 1.3; each becomes a test for
`testing-ci-cd`:

- ACVP/KAT vectors for KeyGen_internal, Encaps_internal, Decaps_internal (internal functions
  behind a test-only interface; FIPS 203 Section 6).
- Negative tests: `ek` with a coefficient >= 3329 must be rejected; wrong-length `ek`, `dk`, `c`
  rejected; `dk` with a corrupted stored hash rejected (see `nist_pqc_check.py` sections 5 and
  14 for the byte-level behaviour).
- Implicit rejection: a modified ciphertext yields `J(z || c)`, not an error, in constant time
  (`side-channels-faults-and-ct-verification`).
- RBG failure returns an error (Algorithms 19, 20), never a key.
- Zeroisation of intermediates; seeds `(d, z)` treated as secret keys.
- If SampleNTT is bounded, the bound is at least 280 iterations (Appendix B).
- Because validation "does not guarantee correct functioning on all inputs" (SP 800-227 3.1),
  add differential testing against independent ML-KEM implementations
  (`rust-pqc-implementations`).

### E. Dates that matter if Turing is used by regulated customers

- US NSS: new acquisitions CNSA 2.0 compliant from 2027-01-01; CNSA 2.0 mandated by
  2031-12-31 (CNSA FAQ, citing CNSSP 15).
- EU: high-risk use cases migrated by 2030-12-31; no stand-alone quantum-vulnerable public-key
  mechanisms for high-risk uses after 2030 (EU roadmap).
- Germany: classical-only key agreement recommended only until the end of 2031 (BSI).
- France: PQC required for product qualification from 2027 (ANSSI FAQ, stated as an aim).
- NIST (draft): 112-bit classical schemes deprecated after 2030, all disallowed after 2035.

A file encrypted today may need to stay secret past 2035. That is the "harvest now, decrypt
later" case every authority cites, and it argues for a PQ KEM from the first release rather
than a later upgrade.

### F. What Turing cannot claim

- Not "FIPS-approved" or "CNSA-compliant" as a product: the Turing cipher is not an approved
  primitive, and SP 800-227 3.1 requires "only approved cryptographic elements" and FIPS 140
  validation for conforming KEM implementations.
- Not "harder to break than ML-KEM" for a modified or new lattice scheme without a published
  analysis. The standards support a narrower claim: "A well-designed multi-algorithm
  scheme will be secure if at least one of the component schemes is secure" (SP 800-227 4.6,
  PDF p. 34 [26]), with IND-CCA preserved for the encouraged combiner in the random-oracle model
  (4.6.3). That is a claim about not being weaker than the best component, bought with size,
  speed and complexity.

## Sources

All files are in `research/papers/` unless marked online. "Scratch" = the saved HTML copies in
`research/workfiles/pq/nist/` (and `nist/fresh/` for 2026-09-27 fetches).

| File | Reference | URL | Used for |
|---|---|---|---|
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, 2024-08-13 | https://doi.org/10.6028/NIST.FIPS.203 | Section 1 |
| online (scratch) | CSRC FIPS 203 page and errata spreadsheet fips-203-potential-updates.xlsx | https://csrc.nist.gov/pubs/fips/203/final | status, errata |
| nist-fips-204-ml-dsa.pdf | NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, 2024-08-13 | https://doi.org/10.6028/NIST.FIPS.204 | Section 2.1 |
| online (scratch) | CSRC FIPS 204 page and errata spreadsheet fips-204-potential-updates.xlsx | https://csrc.nist.gov/pubs/fips/204/final | errata |
| nist-fips-205-slh-dsa.pdf | NIST FIPS 205, Stateless Hash-Based Digital Signature Standard, 2024-08-13 | https://doi.org/10.6028/NIST.FIPS.205 | Section 2.2 |
| online (scratch) | CSRC page, SP 800-230 ipd, Additional SLH-DSA Parameter Sets for Limited Signature Use Cases, 2026-04-13 | https://csrc.nist.gov/pubs/sp/800/230/ipd | Section 2.2 |
| nist-sp800-227-kem-recommendations.pdf | NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms, September 2025 | https://doi.org/10.6028/NIST.SP.800-227 | Section 4 |
| nist-ir-8547-pqc-transition.pdf | NIST IR 8547 ipd, Transition to Post-Quantum Cryptography Standards, November 2024 | https://doi.org/10.6028/NIST.IR.8547.ipd | Section 5 |
| nist-ir-8545-pqc-round4-report.pdf | NIST IR 8545, Status Report on the Fourth Round of the NIST PQC Standardization Process, March 2025 | https://doi.org/10.6028/NIST.IR.8545 | Section 3.3 |
| nist-ir-8413-pqc-round3-report.pdf | NIST IR 8413-upd1, Status Report on the Third Round of the NIST PQC Standardization Process | https://doi.org/10.6028/NIST.IR.8413-upd1 | Section 6.3 |
| nist-ir-8610-pqc-additional-signatures-round2-report.pdf | NIST IR 8610, Status Report on the Second Round of the Additional Digital Signature Schemes, May 2026 | https://doi.org/10.6028/NIST.IR.8610 | Section 7 |
| nist-pqc-call-for-proposals-2016.pdf | NIST, Submission Requirements and Evaluation Criteria for the PQC Standardization Process, 2016, Section 4.A.5 | https://csrc.nist.gov/projects/post-quantum-cryptography | Section 6 |
| nist-pqc-call-additional-signatures-2022.pdf | NIST, Call for Additional Digital Signature Schemes, September 2022 | https://csrc.nist.gov/projects/pqc-dig-sig | Section 6 |
| 2025-perlner-nist-fips-206-fn-dsa-status-slides.pdf | R. Perlner, "FIPS 206 Status Update", Sixth PQC Standardization Conference, September 2025 | https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon | Section 3.2 |
| 2025-robinson-nist-fips-207-hqc-kem-slides.pdf | A. Robinson, "FIPS 207: HQC-KEM", Sixth PQC Standardization Conference, September 2025 | https://csrc.nist.gov/presentations/2025/fips-207-hqc-kem | Section 3.3 |
| online (fresh) | CSRC PQC project pages: News and Updates; Selected Algorithms; Workshops and Timeline (updated 2026-08-05); PQC Standards | https://csrc.nist.gov/projects/post-quantum-cryptography | status of FIPS 206/207, IR 8547, SP 800-227 |
| 2021-avanzi-et-al-kyber-round3-specification.pdf | R. Avanzi et al., CRYSTALS-Kyber Algorithm Specifications and Supporting Documentation (version 3.02), August 4, 2021 | https://pq-crystals.org/kyber/ (URL not re-checked) | Sections 1.6, 6.4 |
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | E. Alkim et al., FrodoKEM: Learning With Errors Key Encapsulation, Preliminary Standardization Proposal, revision 2025-09-29 | https://frodokem.org/ | Section 6.4 |
| nsa-2022-cnsa-2.0-announcement-csa.pdf | NSA, Announcing the Commercial National Security Algorithm Suite 2.0, PP-22-1338, Sep 2022, Ver. 1.0 | media.defense.gov (exact URL not recorded; local copy) | Section 8.1 |
| nsa-cnsa-2.0-faq.pdf | NSA, The CNSA 2.0 and Quantum Computing FAQ, PP-24-4014, December 2024, Ver. 2.1 | media.defense.gov (exact URL not recorded; local copy) | Section 8.1 |
| bsi-tr-02102-1-cryptographic-mechanisms.pdf | BSI TR-02102-1, Cryptographic Mechanisms: Recommendations and Key Lengths, Version 2026-01, 2026-01-23 | https://www.bsi.bund.de/ (TR-02102 page) | Section 8.2 |
| 2023-anssi-pqc-transition-follow-up.pdf | ANSSI, ANSSI views on the Post-Quantum Cryptography transition (2023 follow up), 2023-12-21 | cyber.gouv.fr (exact URL not recorded; local copy) | Section 8.3 |
| 2022-anssi-views-on-pqc-transition.pdf | ANSSI, ANSSI views on the Post-Quantum Cryptography transition, 2022-03-30 | cyber.gouv.fr (exact URL not recorded; local copy) | Section 8.3 |
| online (fresh) | ANSSI, FaQ sur la Cryptographie post-quantique (PQC) | https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/faq-pqc/ | Section 8.3 |
| online (fresh) | UK NCSC, Timelines for migration to post-quantum cryptography, v1.0, 2025-03-20 | https://www.ncsc.gov.uk/guidance/pqc-migration-timelines | Section 8.4 |
| online (fresh) | UK NCSC, Next steps in preparing for post-quantum cryptography, v2.0, 2024-08-14 | https://www.ncsc.gov.uk/paper/next-steps-in-preparing-for-post-quantum-cryptography | Section 8.4 |
| 2025-nis-cg-eu-pqc-coordinated-roadmap.pdf | EU PQC Workstream (NIS Cooperation Group), A Coordinated Implementation Roadmap for the Transition to PQC, Part 1, v1.1, 2025-06-11 | URL not recorded (local copy only) | Section 8.5 |
| 2025-eccg-agreed-cryptographic-mechanisms-v2.pdf | ECCG Sub-group on Cryptography, Agreed Cryptographic Mechanisms, Version 2.0, April 2025 | URL not recorded (local copy only) | Section 8.5 |
| online (scratch) | ISO catalogue, ISO/IEC 18033-2:2006/Amd 2:2026 | https://www.iso.org/standard/86890.html | Section 8.6 |
| online (fresh) | FrodoKEM official site | https://frodokem.org/ | Section 8.6 |
| online (fresh) | Classic McEliece team, "Classic McEliece: ISO", version 2026.06.15 | https://classic.mceliece.org/iso.html | Section 8.6 |

## Claim ledger

Script commands (run from the repo root): `timeout 300 python research/scripts/pq/nist_pqc_check.py`
(all checks pass, exit 0) and `timeout 300 python research/scripts/pq/nist_pqc_check.py
--negative-control` (four planted errors, all caught, exit 0). Output saved in
`research/workfiles/pq/nist/check_run.out`. Spreadsheets dumped with
`timeout 60 python research/scripts/pq/nist_xlsx_dump.py FILE.xlsx`; HTML read with
`nist_html2txt.py`.

| # | claim | status | source |
|---|---|---|---|
| 1 | FIPS 203 published 2024-08-13 | VERIFIED | nist-fips-203-ml-kem.pdf p. 1; CSRC FIPS 203 page (fetched 2026-09-27) |
| 2 | FIPS 203 document history: draft 08/24/23, final 08/13/24, no revision | VERIFIED | CSRC FIPS 203 page, "Document History" (2026-09-27) |
| 3 | Planning note 11/17/2025 announces an issue to be corrected in a future update/revision | VERIFIED | CSRC FIPS 203 page |
| 4 | Errata rows: 2025-03-31 Appendix A (value 1 for i = 0); 2025-10-17 Section 5.3 Alg. 15 comment "v" -> "w"; corrections "DO NOT introduce new technical requirements" | VERIFIED | fips-203-potential-updates.xlsx (identical md5 on 2026-09-26 and 2026-09-27); dates converted by nist_xlsx_dump.py |
| 5 | n = 256, q = 3329 for all ML-KEM sets | VERIFIED | FIPS 203 Sec. 8 Table 2, PDF p. 48 [39] |
| 6 | (k, eta1, eta2, du, dv) = (2,3,2,10,4), (3,2,2,10,4), (4,2,2,11,5); RBG strength 128/192/256 | VERIFIED | FIPS 203 Table 2, PDF p. 48 [39]; Sec. 3.3 PDF p. 25 [16] |
| 7 | Sizes ek/dk/c/K = 800/1632/768/32, 1184/2400/1088/32, 1568/3168/1568/32 bytes | VERIFIED + COMPUTED | FIPS 203 Table 3, PDF p. 48 [39]; nist_pqc_check.py section 1 |
| 8 | ML-KEM-512/768/1024 claimed categories 1/3/5 | VERIFIED | FIPS 203 Sec. 8, PDF p. 49 [40]; Sec. 3.2 PDF p. 23 [14] |
| 9 | NIST recommends ML-KEM-768 as default; "strongest possible parameter set should be used" when initially establishing protection | VERIFIED | FIPS 203 Sec. 8, PDF p. 49 [40] |
| 10 | Decapsulation failure rates 2^-138.8, 2^-164.8, 2^-174.8 | VERIFIED | FIPS 203 Sec. 3.2 Table 1, PDF p. 24 [15] |
| 11 | H = SHA3-256, J = SHAKE256 (32 bytes), G = SHA3-512, PRF_eta = SHAKE256(s||b, 8*64*eta), XOF = SHAKE128 | VERIFIED | FIPS 203 Sec. 4.1, PDF p. 27-29 [18-20] |
| 12 | Algorithms 13-21 as summarised in Section 1.2 (incl. dk = dk_PKE||ek||H(ek)||z; (K,r) = G(m||H(ek)); K_bar = J(z||c)) | VERIFIED | FIPS 203 Sec. 5-7, PDF p. 38-47 [29-38] |
| 13 | Encapsulation-key check = type check + modulus check ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k] | VERIFIED | FIPS 203 Sec. 7.2, PDF p. 45 [36] |
| 14 | Decapsulation input check = c length, dk length, hash check; ciphertext check on every Decaps | VERIFIED | FIPS 203 Sec. 7.3, PDF p. 46 [37] |
| 15 | A 12-bit field holding 3329 fails the modulus check; 3328 passes (ByteDecode_12 reduces mod q) | COMPUTED + VERIFIED | nist_pqc_check.py section 5; mod-q rule: FIPS 203 Alg. 6, PDF p. 31 [22] |
| 16 | dk hash check passes for an intact layout and fails after one flipped bit in the stored ek | COMPUTED | nist_pqc_check.py section 14 (synthetic bytes, not a real key) |
| 17 | Implicit-reject flag is secret, shall be destroyed, may not be output | VERIFIED | FIPS 203 Sec. 6.3, PDF p. 42 [33] |
| 18 | K-PKE shall not be used stand-alone; not approved as PKE | VERIFIED | FIPS 203 Sec. 3.3, PDF p. 24-25 [15-16] |
| 19 | Internal (derandomised) interfaces "should not be made available to applications other than for testing purposes" | VERIFIED | FIPS 203 Sec. 3.3, PDF p. 25 [16] |
| 20 | No floating-point arithmetic; destruction of intermediates with two exceptions (seed, A_hat) | VERIFIED | FIPS 203 Sec. 3.3, PDF p. 25-26 [16-17] |
| 21 | SampleNTT: should not be bounded; if bounded, limit >= 280, probability 2^-261 | VERIFIED + COMPUTED | FIPS 203 App. B Table 4, PDF p. 55 [46]; nist_pqc_check.py section 6 gives log2 P = -261.24 |
| 22 | Appendix A zeta tables (2 x 128 values) equal recomputation from zeta = 17 | COMPUTED | nist_pqc_check.py section 3 (parses the PDF) |
| 23 | Differences from round-3 Kyber: 256-bit K; FO variant without H(c) in K; no m <- H(m); input checks; after ipd: domain separation by k, A_hat indices restored | VERIFIED | FIPS 203 App. C, PDF p. 56 [47] |
| 24 | Round-3 Kyber derived K = KDF(K_bar || H(c)), rejection KDF(z || H(c)), and hashed m <- H(m) | VERIFIED | 2021-avanzi-et-al-kyber-round3-specification.pdf, Alg. 8-9, PDF p. 10 |
| 25 | Round-3 Kyber parameters equal FIPS 203 Table 2 | VERIFIED | Kyber round-3 spec Table 1, PDF p. 11 |
| 26 | Kyber r3 primal attack dims 999/1419/1885 (core-SVP) and 1025/1467/1918 (refined); log2 gates 151.5/215.1/287.3; log2 memory bits 93.8/138.5/189.7 | VERIFIED | Kyber round-3 spec Table 4, PDF p. 21 |
| 27 | Margins over 2^143/2^207/2^272: 8.5/8.1/15.3 bits | COMPUTED | nist_pqc_check.py section 9 |
| 28 | ML-DSA parameters and categories 2/3/5; sizes 2560/1312/2420, 4032/1952/3309, 4896/2592/4627 | VERIFIED + COMPUTED | FIPS 204 Tables 1-2, PDF p. 25-26 [15-16]; gamma1 exponents via pdfspans.py p. 25; nist_pqc_check.py section 12 |
| 29 | FIPS 204 errata (2026-07-31): repetitions 4.36/5.14/3.91; min signing loop limit 821 (was 814); CSRC planning note 07/31/2026 | VERIFIED | fips-204-potential-updates.xlsx row 27; CSRC FIPS 204 page |
| 30 | SLH-DSA Table 2 values; categories 1/3/5 for n = 16/24/32; claims for at most 2^64 signatures per key | VERIFIED + COMPUTED | FIPS 205 Sec. 11 Table 2, PDF p. 53 [43]; nist_pqc_check.py section 13 |
| 31 | SP 800-230 ipd 2026-04-13; comments closed 2026-06-12; six extra SLH-DSA sets for categories 1/3/5 with 2^24 signatures per key; not for general use | VERIFIED | CSRC SP 800-230 page (2026-09-27) |
| 32 | No FIPS 206 or FIPS 207 draft published as of 2026-09-27 | VERIFIED (negative, web) | CSRC Selected Algorithms ("FIPS coming soon"), PQC News, Timeline (updated 2026-08-05) pages; /pubs/fips/206/ipd and /207/ipd return 404 (2026-09-27) |
| 33 | NIST expected to release a FIPS 206 ipd "soon" ("basically written, awaiting approval") | VERIFIED | Perlner slides p. 2; presented at the Sixth PQC Standardization Conference (CSRC presentation page); conference dates 2025-09-24/26 (CSRC timeline) |
| 34 | FN-DSA keygen and signing need floating point; only randomized signing | VERIFIED | Perlner slides p. 3, 8 (marked provisional) |
| 35 | Fourth-round report is NIST IR 8545, March 2025 (ERB approval 2025-03-05); news item 2025-03-11 | VERIFIED | nist-ir-8545 title pages; CSRC PQC news |
| 36 | HQC selected; BIKE DFR analysis "not ... as mature"; diversity of assumptions as the goal | VERIFIED | IR 8545 Sec. 2.2.1 PDF p. 11-12 [4-5]; PDF p. 16 [9] |
| 37 | NIST will publish a final HQC standard "in approximately two years" after a public draft | VERIFIED | IR 8545 Sec. 4, PDF p. 25 [18] |
| 38 | A final HQC FIPS around 2027 | UNVERIFIED | projection from row 37 only; settle when NIST publishes a FIPS 207 draft with a schedule |
| 39 | FIPS 207 changes under consideration (salted FO, 32-byte K, SHA3-512 seed expansion, confirmation code) | VERIFIED (as proposals) | Robinson slides p. 17-20 |
| 40 | SP 800-227 final, September 2025; CSRC news 2025-09-18 | VERIFIED | SP 800-227 running header; CSRC PQC news |
| 41 | SP 800-227 requirements RS1-RS11, RM1-RM5 as tabulated | VERIFIED | SP 800-227 Sec. 1.3, PDF p. 10-11 [2-3] |
| 42 | Approved combiners: SP 800-56C KDM over (S1..St) if one secret is from 56A/56B or an approved KEM; SP 800-133 methods need all keys approved | VERIFIED | SP 800-227 Sec. 4.6.2, PDF p. 36-38 [28-30] |
| 43 | KDF(K1, K2) does not preserve IND-CCA; H(K1,K2,c1,c2,ek1,ek2,domain_sep) with SHA-3 preserves it in the ROM | VERIFIED | SP 800-227 Sec. 4.6.3, PDF p. 39 [31] |
| 44 | X-Wing named as a PQ/T hybrid KEM example | VERIFIED | SP 800-227 Sec. 4.6, PDF p. 34 [26] |
| 45 | Key-confirmation labels KC_1_E, KC_2_E, KC_1_D, KC_2_D; approved MACs HMAC, AES-CMAC, KMAC, AES-GMAC | VERIFIED | SP 800-227 Sec. 4.4.1 PDF p. 29 [21]; RS10 PDF p. 11 [3] |
| 46 | System "at best as secure as the weakest element"; conforming implementations use only approved elements and pass FIPS 140 validation | VERIFIED | SP 800-227 Sec. 3.1, PDF p. 19 [11] |
| 47 | IR 8547 is still ipd (Nov 12, 2024); comments closed 2025-01-10; no final | VERIFIED | IR 8547 PDF title; CSRC IR 8547 page and /final 404 (2026-09-27) |
| 48 | IR 8547 dates: 112-bit classical signatures and key establishment deprecated after 2030, all disallowed after 2035 | VERIFIED | IR 8547 Tables 2 and 4, PDF p. 20-21 [13-14] |
| 49 | 112-bit symmetric standards "will be disallowed in 2030"; >= 128-bit symmetric meets at least category 1 | VERIFIED | IR 8547 Sec. 4.1.3, PDF p. 22 [15] |
| 50 | IR 8547 Table 5 misprints "ML-DSA-768/1024" in the ML-KEM table | VERIFIED | IR 8547 Table 5, PDF p. 22 [15] |
| 51 | IR 8547 hybrid statements (temporary measures; SP 800-56C Z||T; FIPS 203 K usable as Z; FIPS 140 accommodation) | VERIFIED | IR 8547 Sec. 3.2, PDF p. 15-17 [8-10] |
| 52 | Category definitions (AES-128, SHA-256, AES-192, SHA-384, AES-256 reference attacks) | VERIFIED | 2016 CFP Sec. 4.A.5, PDF p. 16-17; IR 8547 Table 1 PDF p. 19 [12] |
| 53 | MAXDEPTH plausible range 2^40 to 2^96 (with 2^64 as the decade figure) | VERIFIED | 2016 CFP PDF p. 17; 2022 call PDF p. 16 |
| 54 | Gate counts: 2016 call 2^170/2^233/2^298 per MAXDEPTH, 2022 call 2^157/2^221/2^285 per MAXDEPTH; classical 2^143/2^207/2^272; SHA3 collisions 2^146/2^210/2^274 | VERIFIED | 2016 CFP PDF p. 18; 2022 call PDF p. 17 (exponents flattened in text extraction, e.g. "2170") |
| 55 | At MAXDEPTH 2^64 the 2022 AES-128 figure is 2^93 quantum gates (and the full grid) | COMPUTED | nist_pqc_check.py section 8 |
| 56 | IR 8413: Kyber sets "fall slightly below the security targets" if memory access cost is ignored | VERIFIED | IR 8413-upd1 Sec. 4.1, PDF p. 38 [29] |
| 57 | IR 8413: RAM-model estimates underestimate large-memory attacks; RAM-safe parameters "should therefore be considered safe" | VERIFIED | IR 8413-upd1 App. B, PDF p. 90 [81] |
| 58 | FrodoKEM-976: n = 976, q = 65536, level 3 (AES-192); FrodoKEM-1344 level 5 | VERIFIED | 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf, Scope PDF p. 3, Table A.1 PDF p. 15 |
| 59 | IR 8610 (May 2026): nine third-round candidates FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV | VERIFIED | IR 8610 abstract, PDF p. 5; CSRC news 2026-05-14 |
| 60 | HAWK "does not need floating-point arithmetic" | VERIFIED | IR 8610 PDF p. 15 [8] |
| 61 | CNSA 2.0: ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512; LMS/XMSS for firmware/software signing | VERIFIED | CNSA 2.0 FAQ v2.1 (Dec 2024) PDF p. 3; 2022 CSA Table I PDF p. 3 |
| 62 | CNSSP 15 dates: new NSS acquisitions CNSA 2.0 compliant by 2027-01-01; phase-out by 2030-12-31; mandated by 2031-12-31 | VERIFIED (via FAQ) | CNSA 2.0 FAQ PDF p. 11. CNSSP 15 itself not read |
| 63 | 2022 per-technology CNSA dates (signing exclusive 2030; browsers/cloud 2033; networking 2030; OS 2033; legacy 2033) and 2035 overall | VERIFIED | 2022 CSA PDF p. 4-6 |
| 64 | NSA "will not require" hybrids | VERIFIED | CNSA 2.0 FAQ PDF p. 19 |
| 65 | Content of the re-issued NSA advisory at media.defense.gov/2025/May/30/... | UNVERIFIED | HTTP 403 to curl and WebFetch on 2026-09-27; open in a browser |
| 66 | BSI TR-02102-1 current version 2026-01 (2026-01-23) | VERIFIED | TR PDF p. 1-2; BSI TR-02102 page (saved 2026-09-26) |
| 67 | BSI recommends FrodoKEM-976/1344, Classic McEliece 460896/6688128/8192128 (+f), ML-KEM-768/1024; HQC after its standard | VERIFIED | TR-02102-1 Sec. 2.4, Tables 2.5-2.7, PDF p. 37-39 |
| 68 | BSI: PQ KEMs "should be used in 'hybrid' form"; combiners CatKDF (ETSI TS 103 744 V1.2.1) or SP 800-227 eq. (9)+(15) | VERIFIED | TR-02102-1 Sec. 2.1-2.2, Table 2.1, PDF p. 28-29; ref. [38] |
| 69 | BSI: classical-only key agreement until end of 2031; very high protection by end of 2030; classical signatures until end of 2035 | VERIFIED | TR-02102-1 Sec. 2.1 and 2.3, PDF p. 28-30 |
| 70 | ANSSI 2023: hybridation necessary; avoid modifying standardized parameters; prefer level 5 or 3; ephemeral keys; FrodoKEM a valid conservative option; AES-256/SHA2-384 symmetric sizing | VERIFIED | 2023-anssi-pqc-transition-follow-up.pdf PDF p. 1-3 |
| 71 | ANSSI FAQ: hybridation mandatory in regulated perimeter; CatKDF/CasKDF; hash-based signatures exempt; PQC for qualification from 2027 (aim); first lattice-PQC visas early October 2025 | VERIFIED | ANSSI FAQ page (fetched 2026-09-27) |
| 72 | NCSC milestones 2028 / 2031 / 2035 (v1.0, 2025-03-20) | VERIFIED | NCSC timelines page (fetched 2026-09-27) |
| 73 | NCSC recommends ML-KEM-768 and ML-DSA-65; hybrids as "an interim measure" (v2.0, 2024-08-14) | VERIFIED | NCSC next-steps page (fetched 2026-09-27) |
| 74 | EU roadmap v1.1 (2025-06-11) milestones 31.12.2026 / 2030 / 2035; no stand-alone quantum-vulnerable public key for high-risk uses after 2030 | VERIFIED | 2025-nis-cg-eu-pqc-coordinated-roadmap.pdf PDF p. 3, 6-7 |
| 75 | ECCG ACM v2.0 (April 2025): ML-KEM and FrodoKEM recommended; prefer ML-KEM-1024/768 and FrodoKEM-1344/976 | VERIFIED | 2025-eccg-agreed-cryptographic-mechanisms-v2.pdf (pdfgrep hits "61-ML-KEM Parameters", "62-FrodoKEM Parameters") |
| 76 | ISO/IEC 18033-2:2006/Amd 2:2026 published 2026-06-05, stage 60.60, 58 pages | VERIFIED | ISO catalogue page 86890 (saved 2026-09-26; fresh fetch 403) |
| 77 | FrodoKEM is in Amd 2:2026 | VERIFIED (scheme team) | https://frodokem.org/ (2026-09-27) |
| 78 | Classic McEliece is in Amd 2:2026 with 4-, 6-, 8-series parameter sets (f, pc, pcf variants) | VERIFIED (scheme team) | https://classic.mceliece.org/iso.html, version 2026.06.15 |
| 79 | ML-KEM is in Amd 2:2026 | UNVERIFIED | only a search-engine summary; settle with the ISO text or its table of contents |
| 80 | ANSSI English 2022 paper dated 2022-03-30; French "Avis" page says published 2022-04-11 | VERIFIED | 2022-anssi-views-on-pqc-transition.pdf p. 1; MesServicesCyber page (2026-09-27) |

## Open questions

1. **Does ISO/IEC 18033-2:2006/Amd 2:2026 include ML-KEM, and is its FrodoKEM text identical
   to the 2025-09-29 public proposal (salted variant, eFrodoKEM)?** Needs the paywalled ISO
   text or its table of contents. Matters if Turing cites ISO for FrodoKEM test vectors.
2. **When will the FIPS 206 and FIPS 207 initial public drafts appear, and will FIPS 207 adopt
   the salted FO and confirmation code?** Re-check CSRC before any design step that depends on
   HQC.
3. **Will IR 8547 be finalised with the same 2030/2035 dates?** It has been a draft since
   November 2024.
4. **What does the re-issued NSA CNSA 2.0 advisory (May 2025 URL) change, and what exactly does
   the updated CNSSP 15 say?** Only the FAQ's summary of CNSSP 15 was read.
5. **Is X-Wing's combiner an SP 800-227 approved combiner?** SP 800-227 approves SP 800-56C
   KDMs over several shared secrets when one comes from an approved KEM, and its IND-CCA
   discussion uses a combiner over all ciphertexts and keys. How X-Wing's specific inputs fit
   is owned by `hybrid-combiners`.
6. **Does the owner want FIPS 140 / CNSA / BSI alignment at all?** The Turing cipher already
   rules out FIPS approval of the whole product. If alignment is not a goal, the standards still
   decide what has been analysed, but not what is allowed. This is a design decision for the
   owner.
7. **ETSI TS 103 744 V1.2.1 (CatKDF) and the ECCG ACM v3 draft (2026)** were not read here.
   `hybrid-combiners` should confirm the exact CatKDF construction BSI and ANSSI point to.
8. **Category of any new ~1000-dimension parameter set**: open until `attack-cost-estimation`
   and `decryption-failures` produce numbers for it.
