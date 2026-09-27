# 18 — The hybrid key encapsulation: two lattices, and insurance beyond lattices (design)

The owner's decisions of 2026-09-27: Turing's key encapsulation combines
**two lattice KEMs of about 1000 dimensions** — Turing-1026, Turing's own
(docs/16), and ML-KEM-1024, the NIST standard — and offers **optional
insurance that is not lattice-based**, so that a breakthrough against
lattices would not break every key: **Classic McEliece**, **X25519** and
**HQC**. This document is the design, written before any of it is built;
the research behind it is in research/notes/pq/ (dual-lattice-design.md for
the combiner, pq-families-for-diversity.md for the families). Every number
below was read in the cited source on 2026-09-27 or recomputed by
`tools/mathaudit.py` and `tools/coresvp_exhaustive.py`.

## 1. What the combination buys

**The combined key is as strong as its strongest enabled part.** NIST SP
800-227 (September 2025, section 4.6) defines composite KEMs and a key
combiner, KeyCombineCCA_H(K1, K2, c1, c2, ek1, ek2) = H(K1, K2, c1, c2,
ek1, ek2, domain_sep) with H from the SHA-3 family, which "preserves
IND-CCA security if H is modeled as a random oracle": the composite is
IND-CCA "provided at least one of the ingredient KEMs is IND-CCA". It warns
that the naive KDF(K1, K2) "does not preserve IND-CCA security, regardless
of the properties of the KDF". Giacon, Heuer and Poettering (PKC 2018)
prove the general case for any number of ingredient KEMs: CCA-secure "as
long as at least one of the ingredient KEMs is".

**Each part guards against something different:**

| Part | Hard problem | Guards against |
|---|---|---|
| Turing-1026 | plain LWE, no ring structure (docs/16) | attacks on the module structure of ML-KEM; a flaw in the standard |
| ML-KEM-1024 | Module-LWE, rank 4 over Z_3329[x]/(x^256 + 1) (FIPS 203) | a flaw in Turing-1026's own parameters, transform (its proof is docs/17's open work) or code |
| Classic McEliece (optional) | decoding binary Goppa codes (1978) | a breakthrough against lattices, classical or quantum |
| HQC (optional) | decoding quasi-cyclic codes (NIST's 2025 selection) | a breakthrough against lattices |
| X25519 (optional) | elliptic-curve discrete logarithm | a breakthrough against lattices, until quantum computers exist |

**What it does not buy.** The dimensions do not add: breaking the
combination means breaking every enabled part, so it costs about as much
as the hardest part (2^252.0 + 2^253.5 ≈ 2^253.9 core-SVP for the two
lattices), not a 2050-dimension problem. Without an insurance part, a
general advance in lattice reduction or a quantum algorithm for LWE breaks
both lattices. Nothing here protects against side channels, which each part
needs on its own. And SP 800-227 itself cautions that composite schemes
"add a layer of additional complexity" that "could introduce security
vulnerabilities": the combiner and the key format below are where that
complexity lives, so they get their own tests.

## 2. The parts, with their sizes

| Part | Parameter set | Public key | Ciphertext | Source |
|---|---|---|---|---|
| Turing-1026 | n = 1026, q = 2^15, CBD(18) | 61,592 | 15,934 | docs/16 |
| ML-KEM-1024 | k = 4, n = 256, q = 3329 (category 5) | 1,568 | 1,568 | FIPS 203, Table 3 |
| **Core: both lattices, always** | | **63,160** | **17,502** | |
| Classic McEliece | mceliece8192128: m = 13, n = 8192, t = 128 (category 5) | 1,357,824 | 208 | round-4 spec (2022-10-23), section 7.9; sizes from m, n, t |
| (or) | mceliece6960119: m = 13, n = 6960, t = 119 (category 5) | 1,047,319 | 194 | section 7.7 |
| HQC | HQC-5 (NIST level 5), DFR < 2^-256 | 7,237 | 14,421 | HQC specification (2025-08-22), Tables 5-6 |
| X25519 | Curve25519 | 32 | 32 | RFC 7748 |

The Classic McEliece sizes follow from the parameters: the public key is
the m·t x (n − m·t) matrix, row by row in whole bytes; the round-4
ciphertext is the m·t-bit syndrome alone (Encap outputs C = Encode(e, T) and
K = H(1, e, C); the spec has no confirmation hash, so Rosenpass's 188-byte
figure for mceliece460896 is the older round-3 format). Its large key suits
file encryption, where a recipient's key is fetched once and every file
carries only the 208-byte ciphertext; Rosenpass (whitepaper of 2026-09-24)
uses Classic McEliece 460896 with Kyber512 for the same reason.

**The state of each insurance part, as of 2026-09-27:**

- Classic McEliece is the oldest post-quantum scheme still standing and is
  in ISO/IEC 18033-2 Amd 2:2026. New algebraic analysis exists: a
  subexponential distinguisher (Randriambololona 2024) and a conjectured
  subexponential key recovery (Briaud, Lemoine, Randriambololona, Tillich
  2026), which broke challenge instances built with weak parameters; its
  authors put it "at best of complexity of order 2^454" for the smallest
  real parameter set, and the Classic McEliece team's notes (2025, 2026)
  rebut both claims as affecting the scheme. This is the part to watch.
- HQC was selected by NIST in March 2025 (IR 8545) for diversity of hardness
  assumptions; its FIPS 207 draft is not public yet, so the specification
  could still change before a standard exists. It has had timing attacks on
  its decoder in the past (research/papers/2022-guo-et-al-dont-reject-this-hqc-bike.pdf).
- X25519 protects only against attackers without a quantum computer.

## 3. The construction

**Keys.** One 32-byte random seed (`random::new_key`) is the whole secret
key, as for Turing-1026; each part's own seed is derived from it with
cSHAKE256 under its own label ("Turing hybrid v1 seed <part>"). ML-KEM uses
ML-KEM.KeyGen_internal(d, z), which FIPS 203 allows for a stored seed (d, z)
while saying the internal functions "should not be made available to
applications other than for testing"; here they stay inside the hybrid KEM.
The public key lists the parts it has (a **mode**: the core, plus any of
McEliece, HQC, X25519), then each part's key.

**Encapsulation** runs every part the recipient's key has, always all of
them (a sender cannot drop one), and derives the key with SP 800-227's
combiner, generalised to n parts as Giacon-Heuer-Poettering do:

    K = cSHAKE256(X = mode || for each part in a fixed order:
                       len(K_i) || K_i || len(c_i) || c_i || H(ek_i),
                  S = "Turing hybrid v1 combine")

cSHAKE256 is a SHA-3-family function (SP 800-185). Every ciphertext goes in
whole (they bind the key to what was sent); each public key goes in as its
cSHAKE256 hash, which the proof allows for a collision-resistant hash and
which spares hashing McEliece's 1.36 MB every time. The mode goes first, so
a key made for one set of parts never equals a key for another: stripping
an insurance part from a ciphertext changes the key and the file fails to
decrypt. X25519 enters as a KEM the way X-Wing uses it: the ciphertext is
the ephemeral public key and the shared secret is hashed together with both
public keys.

**Decapsulation** runs every part's decapsulation whatever happens (each
rejects implicitly, so a bad ciphertext gives a pseudorandom key and never
an error or an early exit), then the same combiner. Only a wrong length or
an unknown mode is an error. The combined key keys Turing-256.

## 4. How each part will be validated

Every part is written in this repository (the project's rule since
docs/02: Turing depends on no post-quantum library) and trusted only after:

- **ML-KEM-1024**: the NIST ACVP vectors (keyGen, encapDecap), the C2SP CCTV
  sets (accumulated, "unlucky" and "strcmp" vectors) and the Wycheproof
  ML-KEM tests, all already fetched to research/workfiles/pq/vectors/; and
  differential tests against the two independent Python implementations the
  research wrote (research/scripts/pq/tcc_mlkem_oracle.py, cca_mlkem_ref.py),
  a third implementation in another language.
- **X25519**: RFC 7748's vectors and iterated test, and the Wycheproof
  X25519 set.
- **Classic McEliece**: the known-answer files of the official submission
  package, and a reference written from the spec in another language.
- **HQC**: its specification's known-answer files, pinned to the 2025-08-22
  version until FIPS 207 exists.
- **The combiner**: known-answer vectors; a test that changing any byte of
  any input changes K; the robustness suite (tools/CI.md) on every length
  and mode; and planted bugs in `tools/mutate.py`: dropping a ciphertext or
  a key hash from the combiner, XORing the keys instead of hashing them,
  stopping after the first part, and a mode byte the key ignores.
- Every part through the CI runner: overflow checks, the constant-time
  stage (no secret division), dudect timing, the memory-residue scans.

## 5. Order of work

1. ML-KEM-1024 and the combiner for the two-lattice core: the parts the
   owner wants always on, and the most complete public test vectors.
2. X25519: small, and fully specified by RFC 7748.
3. Classic McEliece: the insurance with the longest record and the largest
   implementation (Goppa-code key generation in constant time).
4. HQC: last, so that a FIPS 207 draft can settle its details first.

Each step ends with its vectors passing, its planted bugs caught and its
numbers in `tools/mathaudit.py`, before the next begins.

## Sources

| File in research/papers/ (or online) | Used for |
|---|---|
| nist-sp800-227-kem-recommendations.pdf | composite KEMs, KeyCombineCCA_H, the KDF(K1, K2) warning, the complexity caution |
| 2018-giacon-heuer-poettering-kem-combiners.pdf | combiners for any number of KEMs, secure if one is |
| nist-fips-203-ml-kem.pdf | ML-KEM-1024 parameters, sizes, KeyGen_internal and its use |
| 2022-bernstein-et-al-classic-mceliece-spec-20221023.pdf | parameter sets (section 7), Encap and Decap (section 5) |
| 2024-randriambololona-syzygy-distinguisher.pdf, 2026-briaud-lemoine-randriambololona-tillich-heuristic-subexponential-mceliece.pdf | the new algebraic analysis of Classic McEliece |
| 2025-classic-mceliece-team-notes-2-529-distinguisher.pdf, 2026-classic-mceliece-team-notes-2-610-key-recovery.pdf | the Classic McEliece team's responses |
| 2025-aguilar-melchor-et-al-hqc-specification-20250822.pdf | HQC-5 parameters and sizes (Tables 5-6) |
| nist-ir-8545-pqc-round4-report.pdf | HQC's selection |
| rosenpass-whitepaper.pdf | a deployed protocol combining Classic McEliece, a lattice KEM and a pre-shared key |
| 2024-barbosa-et-al-x-wing-hybrid-kem.pdf | X25519 as a KEM leg |
| online: RFC 7748 | X25519 |
