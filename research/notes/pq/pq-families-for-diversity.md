# Post-quantum KEM families near 1000 dimensions and beyond lattices

This file surveys the post-quantum key-encapsulation (KEM) families that could serve as the core
of a Turing lattice layer, or as a second, independent "diversity" partner next to it. It covers
FrodoKEM in depth, the NTRU family, the other round-2/3 lattice candidates (Saber, NewHope, Round5,
LAC, ThreeBears) and the Korean KpqC selections (NTRU+, SMAUG-T), the code-based schemes (HQC, Classic McEliece, BIKE), and the lessons of the
broken families, and ends with a comparison table and the options for Turing. Every number is in
the claim ledger with its source. Status checked 2026-09-27 against primary sources (NIST reports,
specifications, BSI/ANSSI/EU documents, the scheme teams' official sites, IETF datatracker,
OpenSSH release notes, eBACS). Scripts: `research/scripts/pq/pq_family_sizes.py` (sizes and
tables recomputed from parameters), `toy_families.py` (toy FrodoPKE, NTRU, Niederreiter),
`fam_compare.py` (ratios and hybrid sizes), `ebacs_kem_extract.py` (benchmark extraction),
`fam_ebacs_versions.py` (which specification version each benchmark measures). A continuation
run on 2026-09-27 re-ran every script, re-checked the key tables against the PDFs, re-fetched the
NIST status pages, settled claim 82 and the benchmark-version question, and added the KpqC
selections, the 2026 HQC implementation attacks and the Rowhammer countermeasures.

## Key findings

1. "About 1000 dimensions" already exists as a vetted lattice KEM: FrodoKEM-976 (plain LWE,
   n = 976, q = 2^16) and FrodoKEM-1344 (n = 1344). ML-KEM-1024 (4 x 256) is the structured
   counterpart. No new parameters are needed to meet the dimension goal (Sections 1-2).
2. FrodoKEM's status on 2026-09-27: not a NIST standard (removed in 2022 for performance, IR 8413
   p. 17-18), but part of ISO/IEC 18033-2:2006/Amd 2:2026 (June 2026, per the scheme teams' sites;
   the ISO text itself could not be opened; per the designers it contains FrodoKEM-976 and -1344
   but not -640), recommended at levels 3 and 5 by BSI TR-02102-1 v2026-01 and by the EU ECCG
   agreed-mechanisms list (v2 applicable; v3 a public-review draft since 2 June 2026), and called
   "a valid and conservative option" by ANSSI. BSI, the ECCG and ANSSI all require or insist on
   hybrid use with a classical scheme. For long-lived keys only the salted (standard) variant
   qualifies; its multi-target security has a tight proof since 2025 (Section 2.3).
3. FrodoKEM's cost: public key 15,632 and ciphertext 15,792 bytes at level 3 (13.8x ML-KEM-768),
   40-63x the cycles of ML-KEM-768. Affordable for file encryption (one ciphertext per recipient
   per file), not for high-rate protocols (Sections 2.7, 7).
4. FrodoKEM's security estimates depend strongly on the cost model: the 2025 journal paper's
   refreshed core-SVP numbers are 11-27 bits below the September 2025 proposal's Table A.7, and
   memory-aware (C-2D-Sieve) numbers are 20-45 bits above the refreshed core-SVP ones
   (`fam_compare.py` part 6). A security claim for any ~1000-dimension set is meaningless
   without naming the model (Section 2.6; sibling `attack-cost-estimation`).
5. The practical attacks on FrodoKEM were implementation attacks: a timing leak in the FO
   re-encryption check (key recovery with about 2^30 queries) and Rowhammer faults during key
   generation. Neither touched LWE itself (Section 2.6).
6. NTRU (HPS/HRSS) and NTRU Prime were not selected; NIST found MLWE "marginally more
   convincing" and NTRU Prime's special ring's benefit "not particularly convincing". NTRU Prime's
   one large deployment is sntrup761 + X25519 in OpenSSH (default 2022-2025, RFC 9941 in April
   2026), replaced by ML-KEM-768 + X25519 as the default in OpenSSH 10.0 (Section 3).
7. Saber, NewHope, Round5, LAC and ThreeBears were dropped without being broken; the recurring
   reasons were a less-studied assumption (MLWR, I-MLWE), inflexible structure (NewHope), and new
   components that became the attack surface (LAC's error correction, Round5's matrix
   generation) (Section 4).
8. HQC is NIST's second KEM (selected March 2025) because its decryption-failure analysis is
   stable; its specification changed again in August 2025 and FIPS 207 had not appeared as a
   draft on 2026-09-27. Level-3 ciphertext 8,978 bytes. Its implementations were broken again in
   2026 (compiler-induced cache-timing leak in the official AVX2 code: hqc-1 key recovery with
   under 10 s of trace collection, CRYPTO 2026; power attacks on its sampler) (Section 5.1).
9. Classic McEliece: ISO standard since June 2026 and BSI-recommended, but not a NIST standard.
   Ciphertexts of 156-208 bytes against public keys of 0.5-1.3 MB and key generation of 10^8-10^9
   cycles. New structural attacks are conjectured subexponential but cost 2^454 or more at the
   smallest set, far above ISD's roughly 2^150; NIST says the "especially conservative" case is
   somewhat weaker than it was (Section 5.2). A 2026 preprint shows that all three code-based KEMs
   lose security roughly as the square root of the number M of ciphertexts under one key
   (mceliece348864 below 143 bits from M = 2^21) and advises regular key rotation; HQC's salt
   does not stop it (Section 5.4).
10. BIKE lost to HQC because its failure rate is estimated, not computed; weak keys once pushed it
    to at least 2^-117 at level 1 (Section 5.3). Lattice KEMs whose failure rate can be computed
    exactly have an advantage here.
11. Broken or doubted families (SIKE, Rainbow, rank-metric codes, LEDAcrypt, CSIDH's quantum
    parameters) share one pattern: extra public algebraic structure or a subexponential quantum
    attack (Section 6).
12. Public benchmark numbers lag the specifications: eBACS/SUPERCOP (checked in the 20260831
    source) measures FrodoKEM round 2 (unsalted), HQC round 4 and "2020.04", BIKE "2020.05".
    HQC-3's cost relative to ML-KEM-768 is 12x with the round-4 build but 29x with the 2020.04
    build, so speed claims must name the version (Section 7, `fam_ebacs_versions.py`).
13. Outside NIST, Korea's KpqC selected two more lattice KEMs (January 2025): NTRU+ (NTRU over
    x^n - x^(n/2) + 1, n up to 1152, with a new re-encryption-free CCA transform) and SMAUG-T
    (MLWE + MLWR, k n up to 1024); both were proposed as Korean Industrial Standards in 2026 and
    have had little independent analysis (Section 4.1).
14. For Turing: the literature supports a "twist" by composition (for example X25519 + ML-KEM +
    FrodoKEM, combined with a proven combiner; or a code-based partner such as Classic McEliece for
    diversity against lattice-wide advances), plus low-cost hardening details from the standards
    (salting, pk hashing, fresh matrix per key, constant-time implicit rejection, a recompute-and-
    compare check in key generation against faults). It does not support new rings,
    error-correction layers, shortcut matrix generation, new CCA transforms or home-made parameter
    sets without their own analysis (What this means for Turing).

## 1. What "about 1000 dimensions" means in each family

"Dimension" is used loosely. In lattice KEMs it usually means the number of secret integers per
LWE (or NTRU) instance: n for plain LWE, k times n for Module-LWE, p or n for NTRU-type rings.
The attacker does not work in that dimension exactly. A primal attack embeds the samples in a
lattice whose dimension grows with the secret dimension plus the number of samples used, and its
cost is driven by the BKZ block size beta needed to find the planted short vector; the FrodoKEM
authors model BKZ as "8(d - beta) calls to an SVP solver on rank-beta blocks to reduce a
d-dimensional lattice" (CiC 2025, Sec. 7.2.3, p. 25). So two schemes with the same "dimension"
can have very different security, depending on the modulus q and the error size. The sibling
notes `lattice-foundations` and `attack-cost-estimation` explain and compute this.

Schemes with a secret dimension near 1000 (computed by `pq_family_sizes.py`, "dimension table"):

| scheme | assumption | dimension | status |
|---|---|---|---|
| FrodoKEM-976 | plain LWE, q = 2^16 | n = 976 | ISO/IEC 18033-2 Amd 2 (2026); BSI, ANSSI, ECCG recommended |
| ML-KEM-1024 | Module-LWE, q = 3329 | k n = 4 x 256 = 1024 | FIPS 203 (sibling `nist-pqc-standards`) |
| FireSaber | Module-LWR, q = 2^13 | k n = 4 x 256 = 1024 | not selected (IR 8413) |
| NewHope1024 | Ring-LWE, q = 12289 | n = 1024 | not advanced (IR 8309) |
| sntrup1013 / ntrulpr1013 | NTRU / Ring-LWR over x^p - x - 1, q = 7177 | p = 1013 | not selected; no standard |
| ntruhps40961229 | NTRU over x^n - 1, q = 4096 | n = 1229 | not selected |
| NTRU+1152 | NTRU over x^n - x^(n/2) + 1, q = 3457 | n = 1152 | KpqC selection (Korea, 2025); KS proposal submitted 2026 |
| SMAUG-T256 | Module-LWE (keys) + Module-LWR (ciphertexts), q = 2048 | k n = 4 x 256 = 1024 | KpqC selection (Korea, 2025); KS proposal submitted 2026 |

(NewHope's n in {512, 1024} and q = 12289: NewHope round-2 spec, PDF p. 8, "optimized for
dimensions n = 512 or n = 1024" and "designed for q = 12289"; its public key and ciphertext are
1824 and 2176 bytes at n = 1024, PDF p. 11. ML-KEM's q = 3329 = 2^8 x 13 + 1: FIPS 203, Sec. 2.3
symbols list.)

Code-based schemes have "dimensions" in the thousands to tens of thousands (HQC-3 works with
binary vectors of length n = 35,851; Classic McEliece mceliece6688128 with code length 6688),
because they work over F_2 with Hamming-weight errors and their lengths are set by the cost of
information-set decoding, not of lattice reduction. Comparing their n with a lattice n says
nothing about security.

The practical conclusion: "a lattice layer at about 1000 dimensions" already exists as a vetted,
standardised object in two forms: FrodoKEM-976 (unstructured) and ML-KEM-1024 (module-structured).
Neither needs new parameters.

## 2. FrodoKEM in depth

### 2.1 Idea and rationale

FrodoKEM is built on plain LWE. The public key contains samples B = A S + E (mod q), where A is
an n x n matrix of uniformly random integers mod q, S (n x n-bar) and E (n x n-bar) have small
entries. Plain means that A has no algebraic structure: its n^2 entries are independent. ML-KEM
instead uses a matrix of polynomials, so one ring element stands for a whole structured block of
the matrix. That structure saves a factor of about n in key size and time. NIST IR 8413 puts it as
"a quadratic savings" (Sec. 4.3.1, p. 38). FrodoKEM pays that cost to avoid depending on any
ring or module structure: "FrodoKEM could remain secure even in a future world where structured
lattices are broken" (NIST IR 8413, Sec. 4.3.1, p. 38).

The underlying encryption scheme, FrodoPKE, follows Lindner and Peikert: the ciphertext is
(C1, C2) = (S'A + E', S'B + E'' + Encode(u)), and decryption computes C2 - C1 S = Encode(u) +
(S'E + E'' - E'S). The last bracket is small noise, and Decode rounds it away. Each entry of the
8 x 8 matrix carries B bits (B = 2, 3, 4 for the three levels), so 64 entries carry 128, 192 or
256 bits. The toy script `research/scripts/pq/toy_families.py` shows this with n = 64: with B = 2
the noise never reaches the threshold q/8, with B = 4 the threshold q/32 is exceeded and entries
decode wrongly. That is exactly why larger B requires a narrower error distribution (sigma 1.4 for
FrodoKEM-1344 against 2.8 for FrodoKEM-640).

The KEM is obtained with a Fujisaki-Okamoto transform with implicit rejection (proposal Sec. 8.3,
step 15: if re-encryption does not match, the shared secret is derived from the secret value s
instead of the decrypted seed). The CCA transform itself is the topic of the sibling note
`cca-transforms-and-binding`.

### 2.2 Parameter sets (FrodoKEM Preliminary Standardization Proposal, revision 2025-09-29)

| set | D (q = 2^D) | n | n-bar | B | d (table length) | len_sec | SHAKE | sigma | Renyi order | Renyi divergence |
|---|---|---|---|---|---|---|---|---|---|---|
| (e)FrodoKEM-640 | 15 (32768) | 640 | 8 | 2 | 12 | 128 | SHAKE128 | 2.8 | 200 | 0.324 x 10^-4 |
| (e)FrodoKEM-976 | 16 (65536) | 976 | 8 | 3 | 10 | 192 | SHAKE256 | 2.3 | 500 | 0.140 x 10^-4 |
| (e)FrodoKEM-1344 | 16 (65536) | 1344 | 8 | 4 | 6 | 256 | SHAKE256 | 1.4 | 1000 | 0.264 x 10^-4 |

Source: Tables A.1 and A.3. The error distribution is given as integer probabilities in units of
2^-16 (Table A.3) and sampled by inversion from a cumulative table T_chi (Table A.4, Sec. 7.5).
`pq_family_sizes.py` checks that the two tables agree: Pr[0] = 2(T(0)+1)/2^16 and
Pr[+k] = Pr[-k] = (T(k) - T(k-1))/2^16 reproduce every Table A.3 entry, and the standard deviation
of each table is 2.8146, 2.3178, 1.4291 (the rounded sigma column says 2.8, 2.3, 1.4).

Seed and salt lengths (Table A.2): the standard (salted) sets use len_SE = len_salt = 256, 384,
512 bits; the ephemeral sets use len_SE = 128, 192, 256 and no salt.

Sizes in bytes (Tables A.5 and A.6), recomputed from the Sec. 8 bit-length formulas
pk = len_A + D n n-bar, sk = 2 len_sec + len_A + D n n-bar + 16 n n-bar,
ct = D n n-bar + D n-bar^2 + len_salt:

| set | secret key | public key | ciphertext | shared secret |
|---|---|---|---|---|
| FrodoKEM-640 | 19,888 | 9,616 | 9,752 | 16 |
| FrodoKEM-976 | 31,296 | 15,632 | 15,792 | 24 |
| FrodoKEM-1344 | 43,088 | 21,520 | 21,696 | 32 |
| eFrodoKEM-640 | 19,888 | 9,616 | 9,720 | 16 |
| eFrodoKEM-976 | 31,296 | 15,632 | 15,744 | 24 |
| eFrodoKEM-1344 | 43,088 | 21,520 | 21,632 | 32 |

### 2.3 Variants

- Matrix generation: A is expanded from a 128-bit seed with AES128 (8 entries per block call,
  Sec. 7.7.1) or with SHAKE128 (one call per row, Sec. 7.7.2). A is fresh for every key pair
  (Sec. 6.1, 9.4), so there is no fixed system matrix that could be backdoored or attacked once
  for all users. The security argument models AES128 as an ideal cipher or SHAKE128 as a random
  oracle (Sec. 9.2, item 3).
- Standard versus ephemeral: the standard sets add a public random salt to each ciphertext and a
  longer seed_SE, against multi-ciphertext attacks on one public key (Sec. 9.5.2). eFrodoKEM drops
  the salt and is "exclusively intended for applications that guarantee that only a small number
  of ciphertexts (e.g., 2^8) are produced per public key" (Sec. 9.6). The salt is a post-NIST
  change: the round-3 ciphertext sizes equal today's eFrodoKEM sizes. The CFRG Internet-Draft
  (draft-longa-cfrg-frodokem-03, 22 June 2026, Sec. 8-9) specifies the same twelve parameter sets
  (three levels, AES or SHAKE matrix generation, standard or ephemeral) and turns the proposal's
  guidance into a rule: "Ephemeral FrodoKEM MUST NOT be used in applications in which a single
  public key may produce 2^8 ciphertexts or more." For Turing file encryption, where a recipient's
  long-term public key receives many ciphertexts, only the standard (salted) sets qualify.
- The encapsulation hashes the public key (pkh) into the randomness (Sec. 8.2 step 3) to reduce
  batch attacks across many keys (Sec. 9.5.1); the proposal states that the round-3 analysis
  "does not formally cover security in the multi-target setting". The 2025 CiC paper closes that
  gap for the salted version: with the salted FO (SFO) transform "FrodoKEM is also shown to
  tightly achieve multi-target security ... based on the multi-target IND-CPA security of
  FrodoPKE" (abstract). Why the salt was added: "In 2021, a multi-ciphertext attack against the
  Round-3 FrodoKEM-640 parameters ... was identified by NIST", exploiting the 128-bit message
  length, and the team found a similar attack on the 128-bit seedSE; the attacks "do not
  invalidate any of the security claims" but "may be of concern for applications with long-lived
  public keys" (CiC 2025, Sec. 1, PDF p. 5). Turing's file-encryption use (long-lived recipient
  keys) is exactly that case.
- Reusing A across key pairs saves time (generating A can be "roughly 40%" of encapsulation and
  decapsulation cost) but opens an all-for-the-price-of-one attack on the keys that share it
  (Sec. 10.2).

### 2.4 Claimed security

Core-SVP estimates for one LWE instance, log2 of cost (Table A.7):

| set | attack | classical | quantum | plausible |
|---|---|---|---|---|
| Frodo-640 | primal / dual | 150.8 / 149.6 | 137.6 / 136.5 | 109.6 / 108.7 |
| Frodo-976 | primal / dual | 216.0 / 214.5 | 196.7 / 195.4 | 156.0 / 154.9 |
| Frodo-1344 | primal / dual | 281.6 / 279.8 | 256.3 / 254.7 | 202.6 / 201.4 |

Refined gate-count estimates (Table A.8, computed with the leaky-LWE-estimator following the
Kyber round-3 method): log2(gates) = 175.1, 240.0, 305.4 and log2(memory in bits) = 110.4,
155.8, 202.1 for 640, 976, 1344. The proposal repeats the Kyber team's statement that for levels
1 and 2 the true classical cost is estimated to be within 16 bits of this figure in either
direction (Annex C).

Decryption failure rates (Table A.9): 2^-138.7, 2^-199.6, 2^-252.5. Reduction-based IND-CCA
security (classical ROM, Theorem 5.1 of the spec): 141, 206, 268 bits. For FrodoKEM-1344 the
proposal argues that failure boosting gives no gain over the intrinsic 2^-252.5 and that this is
consistent with level 5 "because the overhead in using decryption failures to win the CCA
security game exceeds 3.5 bits" (Sec. 9.3). The design team claims levels 1, 3, 5
(Introduction). The attack-cost methodology belongs to the sibling note `attack-cost-estimation`;
failure-rate computation to `decryption-failures`.

Security reductions (Sec. 9.2): tight classical ROM reduction from IND-CPA of FrodoPKE with a
rounded Gaussian; non-tight QROM reduction from OW-CPA (which "does not concretely support the
bit-security" of the sets); tight reduction from decision LWE to IND-CPA; non-tight worst-case
reduction from BDDwDGS to LWE with rounded Gaussian error. The parameters "were specifically
chosen to be covered by the reductions" (Sec. 9). NIST IR 8413 adds that these theorems "do not
hold for the concrete parameter choices used in Frodo" but show "fundamental soundness"
(Sec. 4.3.1, p. 37). The two statements read as if they conflict, but the team's own round-3
specification settles it (claim 82, now VERIFIED). It says that "the known worst-case reduction
does not yield any meaningful 'end-to-end' security guarantee for our concrete parameters",
because the reduction "is non-tight" (round-3 spec, PDF p. 7), and that it chose the error width
sigma "comfortably above" the smoothing parameter of Z, which it treats as "an important
qualitative threshold for LWE error" (same page), so that the parameters "conform to a nontrivial
reduction from the worst-case BDDwDGS problem" (PDF p. 23). So "covered by the reductions" means
"inside the regime where the theorems apply", not "the theorems give these parameters a number of
bits of security"; the bit-security numbers come from attack estimates (Annexes B and C) instead.
The proposal's Annex D says the same: its reduction-derived claims (Table A.9) "are assumed to be
weaker than the ones supported by analyses based on concrete cryptanalytic attacks". The design
phase should not treat the worst-case reduction as a concrete security guarantee for any
parameter set, including a Turing-specific one; what it does give is a reason to keep sigma above
the smoothing parameter if Turing ever sets its own parameters.

### 2.5 Standardisation status (as of 2026-09-27)

- NIST: round-3 alternate; removed in July 2022. NIST IR 8413-upd1 Sec. 2.3 (pp. 17-18): "three
  other KEM alternates (BIKE, HQC, and SIKE) are better suited than FrodoKEM for this role.
  FrodoKEM has generally worse performance than these three and so will not be considered further
  for standardization."
- ISO: the FrodoKEM site states "FrodoKEM is standardized by ISO as part of ISO/IEC
  18033-2:2006/Amd 2:2026" (news item dated June 2026). The Classic McEliece site says "ISO
  standardized Classic McEliece in June 2026" (page version 2026.06.15). The ISO catalogue page
  (iso.org/standard/86890.html) refuses automated access (HTTP 403 / JavaScript challenge), so the
  amendment text itself was not read. The amendment number and date therefore rest on the two
  scheme teams' official sites. History on frodokem.org: in October 2022 ISO/IEC JTC 1/SC 27/WG 2
  established a preliminary work item; in April 2023 WG 2 agreed to standardise FrodoKEM "as an
  approved mechanism in a revision of ISO/IEC 18033-2"; the team's proposal of 2023-03-14 was
  revised 2024-12-05 (Table A.4 typo for FrodoKEM-1344 corrected) and 2025-09-29 (packing octet
  order corrected; proposal revision history, p. 17).
- What the ISO text contains, per the FrodoKEM team: their "Security Considerations for FrodoKEM"
  draft (draft-longa-cfrg-frodokem-security-considerations-00, 2026-06-23, Sec. 5.1) states that
  draft-longa-cfrg-frodokem-03 "is fully aligned with the ISO standard [ISO18033-2-AMD2], with
  the sole exception that the FrodoKEM-640 parameter set is *not* included", and that ISO does
  not describe the draft's optional seed-based private-key format. So ISO/IEC 18033-2 Amd 2
  covers FrodoKEM-976 and FrodoKEM-1344 (AES and SHAKE; standard and ephemeral) according to the
  designers; the ISO text itself remains unread (Open question 1). The same draft recommends the
  standard (salted) variant by default, "either FrodoKEM-976 or FrodoKEM-1344" for most
  applications, and hybrid use "employing a security-analyzed combiner" (Sec. 4.1, 5.4); it
  quotes beyond-core-SVP estimates of 149.8, 212.6 and 266.8 bits, which are the minima of the
  C-LSF-Sieve rows of CiC Table 7 (`fam_compare.py` part 6; note these are not the memory-aware
  C-2D-Sieve figures). It also lists a C++ implementation in Botan besides the team's C and Python
  code (Sec. 5.6), a second implementation useful for differential testing.
- IETF/IRTF: FrodoKEM is an individual Internet-Draft aimed at CFRG, draft-longa-cfrg-frodokem,
  revision 03 dated 2026-06-22 on the IETF datatracker (state "I-D Exists", no RFC). An
  individual SSH draft, draft-josefsson-ssh-frodokem-00 (2025-09-19), defines
  frodokem976x25519-sha512 as a hybrid with X25519.
- BSI (Germany): TR-02102-1 version 2026-01 (23 January 2026), Sec. 2.4.1 and Table 2.5 (pp. 37-38):
  FrodoKEM-976 and FrodoKEM-1344 are "cryptographically suitable for the long-term protection of
  confidential information", to be used in hybrid form (Sec. 2.1-2.2). FrodoKEM-640 is not listed.
  BSI first recommended FrodoKEM and Classic McEliece in version 2020-01 (version history, p. 2).
- ANSSI (France): the 2023 follow-up (21 December 2023, p. 3) calls FrodoKEM "a more conservative
  variant of CRYSTALS-Kyber" and would "encourage including FrodoKEM as a valid and conservative
  option in high security applications where the resulting performance penalty ... is not
  prohibitive". The 2022 paper (30 March 2022, p. 5) names FrodoKEM among "good options for first
  deployments" and says a product with hybrid FrodoKEM should be able to get a French security visa
  whether or not NIST standardises it. ANSSI "traditionally does not provide any closed list"
  (2023, p. 2).
- EU certification (ECCG Agreed Cryptographic Mechanisms): version 2.0 (April 2025) and the
  version 3 working draft (April 2026) list FrodoKEM as "R" (recommended) next to ML-KEM, with Note
  "It is recommended to use the highest possible standardised parameter size, either FrodoKEM-1344
  or FrodoKEM-976", and Note 63 (v3 draft): "(M)LWE based cryptographic mechanisms shouldn't be
  used in a standalone way ... but should be combined with a classical cryptomechanism" (v3 draft
  pp. 36-37). Classic McEliece and HQC are not in that table. Status of these documents on
  2026-09-27 (ENISA "EUCC Guidelines on Cryptography" page): version 2 (6 May 2025) is the
  "Applicable version"; version 3 is a "Draft for public review" published 2 June 2026 (review
  until the end of July 2026). The local v3 file is byte-identical (MD5) to ENISA's
  20260507-acm-draft.pdf.
- Netherlands: according to the CiC 2025 paper (footnote 1, PDF p. 2), the Dutch PQC migration
  handbook (AIVD, CWI, TNO, 2024) calls FrodoKEM and Classic McEliece more conservative options,
  "strongly support[s] ongoing initiatives aiming to standardise them" and classifies both as
  "acceptable" until standardisation is complete (the handbook itself was not read).

### 2.6 Known attacks and implementation issues

- No cryptanalytic result has reduced FrodoKEM's parameters; NIST calls its cryptanalysis history
  "largely positive" (IR 8413, Sec. 4.3.1, p. 37).
- The refreshed analysis in the 2025 journal paper (Glabush, Longa, Naehrig, Peikert, Stebila,
  Virdia, IACR CiC 2025(3), dated 2025-10-07) gives LOWER core-SVP numbers than the proposal's
  Table A.7, because it uses newer cost models (quantum random-walk sieving, the dual-sieve-FFT
  attack, which the authors include although its assumptions are "controversial"). Table 6 of the
  paper, Frodo-640: primal uSVP 138.5 (classical C-LSF-Sieve), 123.0 (Q-RW-Sieve); Frodo-1344:
  dual-sieve-FFT 254.8 classical, 227.6 quantum. The paper's own claimed security (Table 4,
  IND-CPA, beyond-core-SVP / core-SVP classical / core-SVP quantum): 145/134/119 (640),
  208/195/173 (976), 262/250/223 (1344); IND-CCA (ROM) beyond/classical core-SVP: 140/130,
  204/192, 258/246. In a memory-aware model (C-2D-Sieve, Table 7) the attack costs (primal
  uSVP, BDD and dual-sieve-FFT) rise to about 158.6-164.4 (640), 225.4-231.6 (976), 282.4-300.1 (1344). `fam_compare.py` part 6
  computes the spread: the refreshed core-SVP values are 11.1 to 27.1 bits below the proposal's
  Table A.7 (same team, one month earlier), and the C-2D-Sieve values are 20.1 to 45.3 bits above
  the cheapest refreshed core-SVP classical value. Lesson for Turing: the same parameter set
  carries estimates tens of bits apart depending on the cost model, so a "1000-dimension" claim
  is meaningless without naming the model. This is the sibling topic
  `attack-cost-estimation`'s job to settle.
- Timing attack on the FO re-encryption check: the round-2 reference implementation leaked
  whether the re-encrypted ciphertext matched (the CiC paper describes it as "branching in the
  computation of ss in FrodoKEM.Decaps"), which gave full key recovery "for all security
  levels using about 2^30 decapsulation calls" (Guo, Johansson, Nilsson, CRYPTO 2020, abstract);
  IR 8413 ref. [229]; fixed by the team (IR 8413, p. 38). The CiC paper footnote 11 (p. 27)
  states the fix: read both k' and s, compare B'||C and B''||C' without early termination, select
  with data-independent evaluation. The flaw was in the generic FO step, not in LWE: any KEM
  Turing builds inherits this risk (sibling topic `side-channels-faults-and-ct-verification`).
- Rowhammer: Fahr et al., "When Frodo Flips" (2022) poison key generation with Rowhammer bit
  flips so that the public key carries a larger error, then run a decryption-failure attack of
  "on the order of only 200,000 core-hours"; KeyGen runs "on the order of 8 milliseconds", which
  made the fault timing hard (abstract, p. 1). The attackers stretched that window "from 8ms to
  1300ms" by slowing the software SHAKE with cache-line flushes (Sec. 8.2, PDF p. 13). The paper's
  countermeasures (Sec. 8.2, PDF p. 13): (a) hardware-accelerated primitives (AES-NI) leave little
  room for this slow-down; (b) order key generation so that no expensive operation runs between
  sampling S, E and computing B (expand A and all sampling randomness first); (c) "regenerate A,
  S, and E from randomness and compute B again", aborting key generation if the two B differ, so
  that an attacker must produce exactly the same bit flips twice; (d) keep E and check that its
  values or distribution are normal; (e) watch for the large number of filtered ciphertexts a
  failure attack needs. The current official reference KeyGen applies part of (b) (one SHAKE call
  produces all sampling randomness first) but not (c) (Open question 7, ledger 107). Lesson: key
  generation is a fault target, and (c) is a cheap, testable guard (one extra B computation per
  key pair) that a Turing KEM layer could adopt.

### 2.7 Performance

From the CiC 2025 paper, Table 8 (Intel Core i7-8700 at 3.2 GHz, TurboBoost off, gcc -O3
-march=native; thousands of cycles, rounded):

| set | KeyGen | Encaps | Decaps |
|---|---|---|---|
| FrodoKEM-640-AES (AES-NI) | 938 | 1,105 | 1,044 |
| FrodoKEM-976-AES | 2,017 | 2,105 | 1,983 |
| FrodoKEM-1344-AES | 3,353 | 3,597 | 3,326 |
| FrodoKEM-640-SHAKE (4-way AVX2) | 2,806 | 2,941 | 2,877 |
| FrodoKEM-976-SHAKE | 6,026 | 6,096 | 5,994 |
| FrodoKEM-1344-SHAKE | 10,725 | 10,643 | 10,497 |

Full KEM (KeyGen + Encaps + Decaps) with AES: 0.97 ms, 1.91 ms, 3.22 ms (text, p. 28). Without
AES-NI the AES variants are "more than 20-fold" slower (p. 28). On an ARM Cortex-A72 without
crypto extensions, plain-C SHAKE is "more than 3x faster" than plain-C AES (p. 29, Table 9:
FrodoKEM-976-SHAKE total 53,331 thousand cycles for Encaps+Decaps). The compact implementation is
"slightly more than 250 lines of plain C code" (p. 27). For comparison the same paper's Table 10
(taken from SUPERCOP 20241022 on an i3-8109U) gives Kyber768 KeyGen/Encaps/Decaps 39/53/42
thousand cycles, so FrodoKEM-976-AES is 40 to 52 times slower per operation and its public key
plus ciphertext (31,424 bytes) 13.8 times larger than Kyber768's (2,272 bytes) (ratios computed by
`fam_compare.py`, part 3; the paper's table labels the Kyber row "Kyber678", evidently a typo for
Kyber768 given its sizes 1,184 and 1,088). On one current machine in eBACS (Intel Core 5 210H,
supercop-20260627) the ratio is 63x for KeyGen+Encaps+Decaps (`fam_compare.py`, part 2). Two small
inconsistencies inside the paper: Table 10 lists FrodoKEM-640-AES KeyGen as 957 against 938 in
Table 8, and the text quotes "3.29 ms" for FrodoKEM level 5 in one place and 3.22 ms in another.
Neither changes any conclusion.

For Turing the practical reading is: FrodoKEM-976 costs about 15.6 KB of public key and 15.8 KB
of ciphertext per encapsulation and a few million cycles. For file encryption (one encapsulation
per file or per recipient) that is affordable; for a high-rate protocol it is not.

## 3. The NTRU family

### 3.1 Textbook NTRU in one paragraph

NTRU (Hoffstein, Pipher, Silverman, 1996/1998) works in the ring Z_q[x]/(x^n - 1). The secret key
is two small polynomials f and g with coefficients in {-1, 0, 1}; the public key is h = g/f mod q
(times 3 in some versions). To encrypt a small message m with a small random r: c = 3hr + m mod q.
To decrypt: a = cf mod q = 3gr + fm, which has small coefficients if q is large enough, so it can
be lifted to the integers; then a mod 3 = fm mod 3, and multiplying by f^-1 mod 3 gives m
(NIST IR 8413, Sec. 4.3.2, p. 38). The hard problem ("Search-NTRU", IR 8413 Problem 3.6,
Sec. 3.2.3) is: given h, find a pair (f, g) with small norms such that h f = g mod q. Viewed as
lattices, (f, g) is an unusually short vector in the lattice of all pairs (a, b) with h a = b mod q;
the sibling note `lattice-foundations` develops that view. The toy in
`research/scripts/pq/toy_families.py` runs this with n = 11, q = 64 and checks the correctness
condition (every coefficient of 3gr + fm inside (-q/2, q/2)); the largest value seen over 200
trials was 18 against the bound 32.

### 3.2 NTRU (NIST round-3 finalist: NTRU-HPS and NTRU-HRSS)

- A merger of NTRUEncrypt and NTRU-HRSS-KEM. All parameter sets are "perfectly correct" (no
  decryption failures for honest ciphertexts) (IR 8413, Sec. 4.3.2, p. 38).
- NTRU-HPS uses fixed-weight sampling; NTRU-HRSS samples each coefficient uniformly in {-1,0,1}
  and takes q = 2^ceil(7/2 + log2 n) (round-3 spec 2020-09-30, Sec. 1.3.3, p. 6).
- Recommended round-3 sets (spec Sec. 1.6, p. 9): ntruhps2048509, ntruhps2048677, ntruhps4096821
  (n = 509, 677, 821 with q = 2048, 2048, 4096) and ntruhrss701 (n = 701, q = 8192). Level-5 sets
  were added later in round 3 at NIST's request (IR 8413, p. 39): IR 8413 Table 6 lists
  NTRU-HPS40961229 and NTRU-HRSS1373.
- Sizes in bytes (public key, private key, ciphertext), IR 8413 Table 6 (p. 86), recomputed by
  `pq_family_sizes.py` from pk = ct = ceil((n-1) log2 q / 8):

| set | claimed level | pk | sk | ct |
|---|---|---|---|---|
| ntruhps2048677 | 1 | 930 | 1,234 | 930 |
| ntruhrss701 | 1 | 1,138 | 1,450 | 1,138 |
| ntruhps4096821 | 3 | 1,230 | 1,590 | 1,230 |
| ntruhps40961229 | 5 | 1,842 | 2,366 | 1,842 |
| ntruhrss1373 | 5 | 2,401 | 2,983 | 2,401 |

- Why not selected: NIST found "the MLWE problem, which KYBER depends upon, marginally more
  convincing than the other assumptions like MLWR or the NTRU problem", appreciated Kyber's
  "thorough and detailed security analysis", and noted Kyber was "near the top (if not the top)
  in most benchmarks" (IR 8413, Sec. 2.3, p. 18). Patents were "a factor"; a footnote said NIST
  "may consider selecting NTRU instead of KYBER" if the patent agreements were not executed by the
  end of 2022, and that NTRU's own U.S. patents "were dedicated to the public in 2007" (p. 18).
  NTRU key generation is "noticeably slower"; sizes "about 25% larger" than the other lattice
  finalists (p. 39).

### 3.3 NTRU Prime (NIST round-3 alternate)

- Two schemes: Streamlined NTRU Prime (sntrup, NTRU-style) and NTRU LPRime (ntrulpr, a
  Ring-LWR scheme in the Lyubashevsky-Peikert-Regev style), both over the ring
  Z_q[x]/(x^p - x - 1) with p prime, q prime, and x^p - x - 1 irreducible mod q, so the ring mod q
  is a field (spec Sec. 2.1, p. 7). The designers chose "a prime-degree number field with a large
  Galois group and an inert modulus, minimizing the number of ring homomorphisms available to the
  attacker" (spec Sec. 4, p. 24). Rounding replaces random noise, and the parameters have no
  decryption failures (IR 8413, Sec. 4.3.3, p. 40).
- Parameter sets (round-3 spec 2020-10-07, Sec. 3.4-3.15, pp. 21-23): (p, q) = (653, 4621),
  (761, 4591), (857, 5167), (953, 6343), (1013, 7177), (1277, 7879); sntrup weights w = 288, 286,
  322, 396, 448, 492; ntrulpr weights w = 252, 250, 281, 345, 392, 429. Two sets sit near 1000:
  p = 953 and p = 1013.
- Sizes in bytes (spec Table 1, p. 42; recomputed by `pq_family_sizes.py` from the spec's Encode
  function):

| set | sk | pk | ct | IR 8413 Table 7 claimed level |
|---|---|---|---|---|
| sntrup653 | 1,518 | 994 | 897 | 1 |
| sntrup761 | 1,763 | 1,158 | 1,039 | 2 |
| sntrup857 | 1,999 | 1,322 | 1,184 | 2/3 |
| sntrup953 | 2,254 | 1,505 | 1,349 | 3/4 |
| sntrup1013 | 2,417 | 1,623 | 1,455 | 4 |
| sntrup1277 | 3,059 | 2,067 | 1,847 | 5 |
| ntrulpr653 | 1,125 | 897 | 1,025 | 1 |
| ntrulpr761 | 1,294 | 1,039 | 1,167 | 2 |
| ntrulpr857 | 1,463 | 1,184 | 1,312 | 2/3 |
| ntrulpr953 | 1,652 | 1,349 | 1,477 | 3/4 |
| ntrulpr1013 | 1,773 | 1,455 | 1,583 | 4 |
| ntrulpr1277 | 2,231 | 1,847 | 1,975 | 5 |

  IR 8413 Table 7 prints the sntrup653 private key as "15 158"; the spec says 1,518, so the IR
  entry is a typo (the IR's claimed levels are taken from Table 7 and "some parameter sets for
  NTRU Prime claim two different security levels, depending on their interpretation of NIST's
  security requirements").
- Why not selected: NIST judged the case "relies substantially on the claim that its unusual
  choice of ring provides a security benefit", found the evidence "not particularly convincing",
  noted that "no algebraic attack has been published that directly impacts the concrete or
  asymptotic security of any of the third-round structured lattice candidates", and that "an
  unexpected breakthrough in cryptanalysis of any structured lattice scheme would reduce the
  community's confidence in all such schemes, including NTRU Prime" (IR 8413, Sec. 4.3.3, p. 41).
  NIST also noted that "relatively little is known about the security of cryptographic schemes
  that use the NTRU Prime ring" (p. 40). Performance: Streamlined NTRU Prime key generation
  500-2500 thousand cycles, NTRU LPRime 50-100 thousand (p. 41).
- Deployment: OpenSSH (official release notes, openssh.com/releasenotes.html):
  8.5 (2021-03-03) replaced the experimental sntrup4591761x25519 method with
  sntrup761x25519-sha512@openssh.com; 8.9 (2022-02-23) added it to the default KEX list;
  9.0 (2022-04-08) made it the default; 9.9 (2024-09-19) added mlkem768x25519-sha256; 10.0
  (2025-04-09) made mlkem768x25519-sha256 the default. sntrup761 is still supported and
  maintained: 9.9 added the IANA name sntrup761x25519-sha512, 10.1 (2025-10-06) warns when a
  connection negotiates "a non-post quantum key agreement algorithm", and 10.3 (2026-04-02)
  improved "performance of keying the sntrup761 key agreement algorithm". The OpenSSH PQ page
  (openssh.com/pq.html, fetched 2026-09-27) names exactly two post-quantum key agreements,
  mlkem768x25519-sha256 and sntrup761x25519-sha512. The SSH method is RFC 9941 (Informational,
  April 2026; Friedl, Mojzis, Josefsson), which calls it "a widely deployed hybrid key exchange
  method". ANSSI's SSHv2 transition note (ANSSI-FT-116, 2 February 2026) describes both OpenSSH
  hybrids without ranking them. NTRU Prime itself has no NIST, ISO or RFC specification of the primitive (an
  individual draft draft-josefsson-ntruprime-streamlined-00 of 2023 expired).
- A parameter trap specific to NTRU: when q is large compared with the secret (the "overstretched"
  regime), NTRU becomes much easier than LWE-style estimates suggest. The sibling note
  `lattice-foundations` (item 2 of its structure section) gives the evidence (Albrecht-Bai-Ducas
  2016, Kirchner-Fouque 2017, Ducas-van Woerden 2021) and the "fatigue point" q about 0.004
  n^2.484, far above the q = O(n) of the NTRU KEMs. Any NTRU-style Turing variant would have to
  stay well below it.
- Lesson: the only large deployment of NTRU Prime is inside a hybrid with X25519. OpenSSH's own
  words (9.0 notes): X25519 is paired "as a backstop against any weaknesses in NTRU Prime that may
  be discovered in the future".

## 4. Other lattice candidates and what happened to them

None of these was broken as a hard problem. Each was dropped for a reason that teaches something
about how a Turing lattice layer should be designed.

| scheme | assumption and structure | fate | NIST's stated reason (primary source) | lesson |
|---|---|---|---|---|
| Saber (LightSaber, Saber, FireSaber) | Module-LWR over Z[X]/(X^256 + 1), rank k = 2, 3, 4; power-of-2 moduli q = 2^13, p = 2^10 | round-3 finalist, not selected (July 2022) | MLWE judged "better studied than the MLWR problem on which the security of Saber is entirely based"; no reason "to standardize multiple different structured lattice KEMs"; dual-attack improvements suggest all three sets "fall slightly below the security targets" when memory cost is ignored (IR 8413 Sec. 4.3.4, pp. 42-43) | rounding instead of noise is a legitimate design, but the reductions to MLWR "are not concretely applicable" (IR 8309 Sec. 3.4, p. 11); a newer, less-studied assumption loses a tie-break |
| NewHope (NewHope512, NewHope1024) | Ring-LWE over a power-of-2 cyclotomic, n = 512 or 1024 | round 2, not advanced (July 2020) | "the security of NewHope is never better than that of KYBER" by a tight RLWE-to-MLWE reduction; no category-3 set possible "because of the relaxation in algebraic structure" Kyber has and NewHope lacks; NIST preferred "low-rank MLWE schemes over RLWE schemes" (IR 8309 Sec. 3.12, p. 16) | a ring of dimension exactly 1024 is less flexible than a module; module rank is a cheap knob |
| Round5 | General LWR (ring and non-ring), plus the XEf error-correcting code | round 2, not advanced | spec "significantly more complicated than all of the other second-round candidates"; no royalty-free licence; of three ways to generate A, NIST "only finds confidence in the security of one of the techniques (tau = 0)"; two minor attacks (IR 8309 Sec. 3.15, p. 17) | complexity and unproven matrix-generation shortcuts cost trust even when performance is excellent |
| LAC | Ring-LWE with byte-level modulus q = 251 and a heavy error-correcting code (BCH) | round 2, not advanced | attacks "worked by artificially increasing the decryption failure rate" and side channels in "non-constant-time implementations of the error-correction procedures"; "the cryptanalysis of LAC seems to involve precisely those aspects of LAC's design, particularly the use of error correction, that distinguish it" (IR 8309 Sec. 3.10, p. 15). Guo, Johansson, Yang (2019): recover one LAC256 key among about 2^64 public keys with complexity 2^79 after a 2^162 precomputation (abstract) | an error-correcting code that tolerates a high raw failure rate turns decryption failures into a CCA key-recovery channel; every "novel" component becomes the attack surface |
| ThreeBears | Integer Module-LWE (I-MLWE) over integers mod a generalised Mersenne prime, with a Melas error-correcting code | round 2, not advanced | "the I-MLWE hardness assumption was essentially created for the sake of submission ... and has not undergone enough rigorous review"; "less attention by third-party researchers" (IR 8309 Sec. 3.17, pp. 18-19) | a new variant of a hard problem, even with a reduction, is judged by the amount of independent cryptanalysis it has had, not by its elegance |

Round5 also had non-ring sets near 1000 dimensions. In the January 2019 draft (ePrint 2018/725,
Table 4, PDF p. 43) the IND-CPA KEM sets R5N1_{1,3,5}KEM_0c use d = 594, 881, 1186 with
q = 2^13, 2^13, 2^15 and rounding to p = 2^10, 2^10, 2^12; public keys 5,214 / 8,834 / 14,264
bytes, ciphertexts 5,236 / 8,866 / 14,288 bytes, failure rates 2^-66, 2^-65, 2^-77 (exponents read
with pymupdf span sizes). Rounding makes these keys roughly half the size of FrodoKEM's at similar
dimension, but the failure rates are only acceptable for ephemeral IND-CPA use, and these are
draft figures, not the final round-2 specification (not read).

Two points apply directly to the "twist" the project owner wants. First, NewHope1024 (Ring-LWE,
n = 1024) and FireSaber (Module-LWR, k n = 4 x 256 = 1024) show that "about 1000 dimensions" was
already on the table in 2019-2022; the dimension alone is not what made any scheme more or less
trusted. Second, the schemes that added their own novel element (LAC's error correction, Round5's
fast A generation, ThreeBears' integer ring, NTRU Prime's ring) were exactly the ones whose novel
element became the focus of attacks or of NIST's doubt.

### 4.1 Outside NIST: the Korean KpqC selections (NTRU+ and SMAUG-T)

Korea ran its own competition (KpqC). On January 16, 2025 it announced its final algorithms: two
KEMs, NTRU+ and SMAUG-T, and two signatures, AIMer and HAETAE (kpqc.or.kr, "Selected Algorithms
from the KpqC Competition Round 2"). The final specification documents are dated January 30, 2026
(NTRU+) and February 4, 2026 (SMAUG-T). A KpqC notice of 2026-04-22 says that proposals to make the
two KEMs Korean Industrial Standards (KS) have been submitted, and that the algorithms may still
change during standardisation. Both are lattice KEMs; both are relevant to Turing only as examples
of what other designers did with "a twist" near 1000 dimensions.

- NTRU+ (Kim and Park): an NTRU variant over Z_q[x]/(x^n - x^(n/2) + 1), a "cyclotomic trinomial"
  of degree n = 2^i 3^j chosen because it allows a fast NTT like x^n + 1 while giving more choices
  of n. q = 3457 for all sets; n = 768, 864, 1152. Public key = ciphertext = 1152, 1296, 1728
  bytes; secret key 2336, 2624, 3488 bytes; worst-case correctness error log2 = -379, -340, -260;
  claimed security (classical/quantum, LWE view) 156/139, 179/160, 248/222 (spec Tables 6-7, PDF
  pp. 44-46). Its twist is in the transforms, not the ring: a new encoding (SOTP) and a transform
  (ACWC2) that makes the worst-case correctness error close to the average one, and an FO variant
  that checks the recovered randomness instead of re-encrypting (spec abstract and Sec. 1,
  Figure 1). NTRU+1152 is the one set near 1000 dimensions.
- SMAUG-T (Cheon et al.): Module-LWE for the key (with a sparse, fixed-weight secret) and
  Module-LWR for the ciphertext, n = 256 with rank k = 2, 3, 4, so SMAUG-T256 has k n = 1024.
  q = 1024 or 2048. SMAUG-T256: public key 1440, ciphertext 1376 bytes, classical/quantum core-SVP
  250.1/221.0, "Beyond core-SVP" 269, decryption failure probability 2^-194.2 (spec Table 3, PDF
  p. 26). The spec lists as its own limitation that MLWR "has been studied shorter than MLWE or LWE
  problems" (Sec. 1.2, PDF p. 5), the same point NIST made against Saber.

What this adds: neither scheme is an international standard, and their distinctive parts (NTRU+'s
re-encryption-free FO variant; SMAUG-T's MLWE/MLWR mix with sparse secrets) have had far less
independent analysis than ML-KEM or FrodoKEM. The literature reviewed here found no break of
either (a search of ePrint for 2025-2026 cryptanalysis returned implementation papers only, for
example an "Optimized Native Rust Implementation of the KpqC Algorithms", ePrint 2026/1420; this
absence is UNVERIFIED as a complete survey). For Turing they are evidence that national programmes
also chose structured lattices near 768-1152 dimensions, not candidates to adopt ahead of the
NIST/ISO schemes.

## 5. Code-based KEMs: HQC, Classic McEliece, BIKE

Code-based schemes replace "small error in a lattice" with "few flipped bits in a codeword". The
hard problem is syndrome decoding: given a random-looking parity-check matrix H and a syndrome
s = H e, find the low-weight error vector e. The best generic attacks are information-set
decoding (ISD), which began with Prange in 1962. NIST IR 8545 notes that ISD improvements have
had "fairly modest" net effect and that "most of the change in concrete security is due to
improvements that were discovered more than 30 years ago" (Sec. 3.3, p. 15). Quantum ISD is a
Grover-type speed-up of classical ISD (same page). The toy in `toy_families.py` shows the
Niederreiter mechanics with the [7,4] Hamming code (t = 1): the public key hides H as S H P, the
ciphertext is the syndrome of a weight-1 error, and only the holder of S, H, P can decode it.

### 5.1 HQC (selected by NIST, March 2025; FIPS 207 not yet published)

- Design: an LPR-like scheme over R = F_2[x]/(x^n - 1) with n prime such that x^n - 1 has only
  two irreducible factors mod 2. Secret (x, y) of low weight; public (h, s = x + h y). Ciphertext
  (u, v) = (r1 + h r2, mG + s r2 + e) with G a public concatenated Reed-Muller/Reed-Solomon code;
  decryption decodes v - u y. No trapdoor is hidden in a code, so the security reduction only
  needs the decisional quasi-cyclic syndrome decoding (QCSD) assumption (NIST IR 8545, Sec. 3.1,
  p. 10). This is structurally the same "noisy linear algebra" idea as LWE, but over F_2 with
  Hamming weight instead of Euclidean length.
- Parameters (HQC specification 2025-08-22, Table 5, p. 29): HQC-1 (n1, n2, n, k, w, w_r = w_e)
  = (46, 384, 17,669, 128, 66, 75), DFR < 2^-128; HQC-3 = (56, 640, 35,851, 192, 100, 114),
  DFR < 2^-192; HQC-5 = (90, 640, 57,637, 256, 131, 149), DFR < 2^-256. n is "the smallest
  primitive prime greater than n1 n2"; `pq_family_sizes.py` re-derives n = 17,669, 35,851,
  57,637 from n1 n2 = 17,664, 35,840, 57,600 (2 must generate (Z/nZ)*).
- Sizes in bytes (Table 6, p. 29): encapsulation key 2,241 / 4,514 / 7,237; decapsulation key
  2,321 / 4,602 / 7,333 (or a 32-byte seed in the compressed format); ciphertext 4,433 / 8,978 /
  14,421; shared key 32. These differ from NIST IR 8545 Table 7 (2,249 / 4,497 for HQC-1, the
  round-4 version) because the 2025-08-22 revision changed the formats (for example "reducing the
  sizes of K and theta from 40 to 32 bytes", changelog p. 2); the byte-by-byte difference was not
  traced.
- Post-selection changes (spec changelog 2025/08/22, p. 2): salted SFO transform with implicit
  rejection "fixing the rejection of the scheme" after M.-J. O. Saarinen's pqc-forum comment "IND-CCA2
  issue in HQC" (2025, ref. [34]); seed added to the decapsulation key; unbiased fixed-weight
  sampler with rejection sampling; SHA3-512 seed expansion and 32-byte K and theta "to align HQC
  specifications with design choices made in FIPS-203". NIST's FIPS 207 slides (Robinson, 2025,
  pp. 17-20) list these changes and a proposed 1-byte confirmation code against implementations
  that skip re-encryption (Glabush et al., ePrint 2025/450).
- Performance (spec Tables 7-8, pp. 30-31, Intel i7-11850H): optimized AVX2 KeyGen / Encaps /
  Decaps = 76 / 150 / 353 (HQC-1), 181 / 355 / 732 (HQC-3), 363 / 720 / 1,435 (HQC-5) thousand
  cycles; the portable reference code is about 40-90 times slower (HQC-1: 4,557 / 9,116 /
  13,918; ratios 39x to 92x across the three sets, computed in `fam_compare.py`; the two
  builds used different gcc versions, 11.4.0 and 8.2.1, so the ratio is indicative only).
- Why selected over BIKE: "The decisive factor in favor of HQC relative to BIKE is HQC's stable
  DFR analysis"; HQC's IND-CCA2 security "has not been successfully attacked since May 2020 when
  HQC discarded parameter sets targeting a higher DFR than 2^-lambda" (IR 8545, Sec. 3.1,
  pp. 11-12). NIST will "publish a final version in approximately two years" (IR 8545, Sec. 4,
  p. 18).
- Status on 2026-09-27: the NIST PQC news page (fetched 2026-09-27) lists "HQC Announced as a 4th
  Round Selection" (March 11, 2025) and no FIPS 207 draft; csrc.nist.gov/pubs/fips/207/ipd returns
  404. NIST slides planned "FIPS 207 - in 2026". BSI TR-02102-1 v2026-01 Sec. 2.4.4 (p. 39)
  "intends to include HQC, after the publication of the standard, with parameter sets
  corresponding to NIST Security Strength Categories 3 and 5". The authoritative status of FIPS
  207 belongs to the sibling note `nist-pqc-standards`.
- Implementation history: key-recovery timing attacks "due to rejection sampling in HQC and
  BIKE" (Guo et al., TCHES 2022(3)), fixed by constant-time sampling (spec changelog 2022/10/01).
  Two 2026 papers show that implementation attacks continue after selection. Dong and Guo
  (ePrint 2026/693, CRYPTO 2026 per ePrint) found that compiler optimisations turned the "secure,
  mask-based conditional selection" of the official AVX2 implementation into secret-dependent
  control flow in the Reed-Muller decoder, and recovered an hqc-1 secret key "with less than 10
  seconds of online trace collection" by Flush+Reload (abstract). Hesse et al. (ePrint 2026/1462,
  preprint) attack HQC's fixed-weight vector sampling by power analysis: key recovery with "a 100%
  success rate using 900,000 distinguisher calls", and a single-trace attack on a masked
  implementation; they conclude that "a combination of masking and hiding is required"
  (abstract). Lesson for Turing, the same as KyberSlash for ML-KEM: constant-time source code is
  not enough; the compiled binary has to be checked (sibling `side-channels-faults-and-ct-verification`).

### 5.2 Classic McEliece (ISO standard June 2026; not a NIST standard)

- Design: Niederreiter form of McEliece's 1978 scheme with binary Goppa codes; perfectly correct
  (no decryption failures); a merger with NTS-KEM (IR 8545, Sec. 3.3, p. 14). Security rests on
  the one-wayness of the 1978 scheme; the team's analysis explicitly does not rely on Goppa codes
  being indistinguishable from random codes (team notes, 17 April 2025, p. 1).
- Parameter sets (spec 2022-10-23, Sec. 7, pp. 15-16): mceliece348864 (m = 12, n = 3488,
  t = 64), mceliece460896 (13, 4608, 96), mceliece6688128 (13, 6688, 128), mceliece6960119
  (13, 6960, 119), mceliece8192128 (13, 8192, 128); each with an "f" variant (semi-systematic
  (mu, nu) = (32, 64), faster key generation, same keys and ciphertexts).
- Sizes in bytes (IR 8545 Table 8, p. 7; recomputed by `pq_family_sizes.py` as
  pk = m t ceil(k/8), ct = ceil(m t / 8)):

| set | claimed level | public key | private key | ciphertext |
|---|---|---|---|---|
| mceliece348864 | 1 | 261,120 | 6,492 | 96 |
| mceliece460896 | 3 | 524,160 | 13,608 | 156 |
| mceliece6688128 | 5 | 1,044,992 | 13,932 | 208 |
| mceliece6960119 | 5 | 1,047,319 | 13,948 | 194 |
| mceliece8192128 | 5 | 1,357,824 | 14,120 | 208 |

  (IR 8413 Table 6 prints the mceliece6688128 public key as "104 992", a dropped digit; round-3
  ciphertexts were 32 bytes longer because of plaintext confirmation, which round 4 removed.)
- Performance (IR 8545 Table 5, p. 6, OQS benchmarks, thousands of cycles): KeyGen
  137,345 (348864) to 686,110 (8192128), f variants 114,189 to 453,985; Encaps 45-206; Decaps
  120-274. Key generation is "three orders of magnitude more costly than HQC" (p. 6).
- NIST decision: no longer under consideration; "After the ISO standardization process has been
  completed, NIST may consider developing a standard for Classic McEliece based on the ISO
  standard" (IR 8545, Sec. 2.3, p. 9). NIST remains "confident in the security of Classic
  McEliece, although recent progress in cryptanalysis somewhat undermines the case for treating it
  as an especially conservative choice" (Sec. 3.3, p. 16). Footnote 5: independent ISD estimates
  suggest mceliece460896 falls short of category 3; NIST is "confident that these parameter sets
  at least meet the criteria for Category 2 security". The NIST PQC news page re-checked on
  2026-09-27 (updated August 5, 2026) carries no announcement about Classic McEliece after the
  June 2026 ISO publication, so no NIST McEliece standard or draft exists yet (ledger 90).
- ISO history (classic.mceliece.org/iso.html): October 2022 slides said WG 2 had solicited
  "comments on proposed inclusion of FrodoKEM, Classic McEliece, and CRYSTALS-Kyber"; the team's
  draft of 2023-04-19 (local file 2023-classic-mceliece-team-iso-draft-20230419.pdf) specified only
  the mceliece6* and mceliece8* sets because ISO asked for 128 bits of security in a "quantum
  model" with a square-root Grover speed-up; ISO later "decided to also standardize mceliece4*".
- ISO: "ISO standardized Classic McEliece in June 2026"; the ISO text contains mceliece460896,
  6688128, 6960119, 8192128, each in plain, f, pc and pcf forms (pc = plaintext confirmation);
  mceliece348864 is not in the ISO list; the team recommends the mceliece6* sizes for long-term
  security (classic.mceliece.org/iso.html, version 2026.06.15). The IETF draft
  draft-josefsson-mceliece-05 (June 2026) describes itself as "a transcribed version of the
  proposed ISO Classic McEliece draft, which ISO standardized in June 2026".
- BSI TR-02102-1 v2026-01 Table 2.6 (p. 38): mceliece460896, 6688128, 8192128 and their f
  variants are suitable for long-term protection (hybrid use). mceliece6960119 and 348864 are not
  listed. The ECCG agreed-mechanisms tables (v2.0 and v3 draft) do not list Classic McEliece.
- Recent structural cryptanalysis (the live debate): Randriambololona's syzygy distinguisher
  (EUROCRYPT 2025, ePrint 2024/1193) and Briaud, Lemoine, Randriambololona, Tillich, "A heuristic
  subexponential attack on the McEliece cryptosystem" (ASIACRYPT 2026, ePrint 2026/1232; local
  PDF built 2026-09-17) give a key-recovery method for
  binary Goppa codes whose cost they conjecture to be subexponential "in the security level".
  Concrete numbers: the abstract says the attack "is at best of complexity of order 2^454 for
  NIST level 1 Classic McEliece parameters"; the paper's Table 6.1 gives 2^454 to 2^610 for
  mceliece348864 depending on the linear-algebra method. The team's rebuttal (notes of 17 April
  2025 and 23 June 2026) points out that all of these costs are far above the 2^256 cost of simply
  guessing the 256-bit key-generation seed, that the largest demonstrated break is a toy
  (n, t) = (482, 7), and that ISD, the attack that sets the parameters, costs "about 2^150 bit
  operations" for (3488, 64). Reading: no current threat to the parameters; but the claim
  "McEliece is safe because 45 years of attacks failed" is weaker than it was, as NIST says. A
  subexponential structural attack, if the conjectures hold, would eventually matter for larger
  parameters.

### 5.3 BIKE (not selected)

- Design: Niederreiter-style scheme with quasi-cyclic moderate-density parity-check (QC-MDPC)
  codes; secret sparse (h0, h1), public h0^-1 h1; decryption by an iterative bit-flipping decoder
  (IR 8545, Sec. 3.2, p. 12).
- Parameters (round-4 spec v5.1, 10/10/2022, Table 4, p. 13): (r, w, t) = (12,323, 142, 134),
  (24,659, 206, 199), (40,973, 274, 264) for levels 1, 3, 5, with estimated DFR 2^-128,
  2^-192, 2^-256 for the BGF decoder. Public key r bits: 1,541 / 3,083 / 5,122 bytes;
  ciphertext 1,573 / 3,115 / 5,154 bytes (IR 8545 Table 6, p. 7; recomputed).
- Why not selected: "Iterative bit-flipping decoders for QC-MDPC codes are difficult to analyze
  in closed form, and the anticipated DFR is too low to compute directly" (IR 8545, Sec. 3.2,
  p. 12); the spec itself says the low-DFR assumption "remains partly heuristic" (Sec. 3.4, "More
  About Low DFR", PDF pp. 16-17). Weak keys with the "gathering property" gave an average DFR of at least
  2^-117 at level 1, "defeating the IND-CCA2 security of BIKE"; a model predicted r = 13,477 would
  be needed for a conservative 2^-129.5 (IR 8545, Sec. 3.2, p. 13). NIST: "BIKE would likely
  require post-selection tweaks to achieve IND-CCA2 security" (p. 12).
- Lesson for Turing: a decryption failure rate that is estimated by extrapolation rather than
  computed is an attack surface. Lattice KEMs such as FrodoKEM and ML-KEM have failure rates that
  can be computed exactly by convolution (sibling note `decryption-failures`); that is a real
  advantage over MDPC-style decoders.

### 5.4 Two 2026 preprints on code-based security margins (all three code-based KEMs)

Both are ePrint preprints, not yet peer reviewed; they are listed on the Classic McEliece team's
own papers page (version 2026.06.13) among ISD papers.

- Multi-instance degradation (May and Sa Diogo, ePrint 2026/517, revised 2026-06-12). When one
  public key produces M session keys, an attacker who wants any one of them can decode "one out
  of many" syndromes (Sendrier's DOOM technique) and gains roughly a square-root-of-M speed-up
  ("the (average) slope of degradation is (slightly below) 1/2", Sec. 3). Level-1 sets fall below
  the 143-bit target for "M >= 2^34 (HQC-1), M >= 2^11 (BIKE-1), respectively M >= 2^21
  (mcecliece3488-64)" (abstract; exponents read from span sizes); HQC-3 at M >= 2^64, HQC-5 at
  M >= 2^38 (Sec. 3); mceliece8192128 at M >= 2^59 (Sec. 5, Table 7). Their conclusion: "the
  public keys of all three code-based KEMs should be updated regularly." They also report that
  with a pure time metric (the HQC and BIKE teams' convention, which does not charge for memory
  as the Classic McEliece team does) their single-instance MMT estimates for mceliece460896,
  6688128 and 6960119 (192.43, 264.33, 264.30) are "already below the desired security levels"
  (Table 7 and text, PDF p. 18). So McEliece's level claims, like FrodoKEM's, depend on whether
  memory is charged.
- Better ISD against HQC (Yu et al., ePrint 2026/633, April 2026). A "progressive sieving-ISD"
  lowers the best known attack cost on all three HQC categories by 7-9 bits, "making their
  security levels 5.1/2.1/5.7 bits below the NIST requirements (143/207/272 bits)" (abstract).

What this means: the attack works on HQC as specified with its 128-bit salt (the paper's
simplified HQC.Encaps, Algorithm 2, includes the salt), so salting the FO transform, which
protects FrodoKEM against message-space search (Section 2.3), does not remove it: the speed-up
comes from decoding one of M syndrome-decoding instances. Whether a comparable one-out-of-many
speed-up exists against the LWE instances of FrodoKEM or ML-KEM ciphertexts was not examined here
(Open question 12). A Turing design that uses a code-based partner with long-lived recipient keys
would need a key-rotation rule, and its security margin should be quoted under a named cost model.
Neither result threatens the level-5 sets at realistic M.

## 6. Broken families and lessons

docs/02 already records Rainbow (key recovery at level 1 in about 53 hours on a laptop,
Beullens, CRYPTO 2022) and SIKE (SIKEp434 key recovery in about 10 minutes, Castryck-Decru). NIST
IR 8545 adds for SIKE that "attempts to patch the vulnerabilities were ineffective or had
weaknesses in some instances", and that the attack "relied on the information provided by the
image of a torsion subgroup in the SIKE public key", so it does not reach isogeny schemes that
publish no torsion points (Sec. 3.4, pp. 16-17). Three more cases matter here.

- Rank-metric codes (ROLLO, RQC): new algebraic attacks during round 2 gave "a near-complete
  break"; all ROLLO II/III and RQC levels fell below 128 bits (IR 8309 Sec. 3.14 and 3.16,
  pp. 16-18). Algebraic structure again.
- LEDAcrypt: the product structure of its secret key enabled "a large class of weak keys" (IR
  8309 Sec. 3.11, p. 15).
- CSIDH (commutative isogeny key exchange, Castryck, Lange, Martindale, Panny, Renes, ASIACRYPT
  2018, ePrint 2018/383): not
  broken classically, but its quantum security is disputed because recovering a CSIDH key is a
  hidden-shift problem, for which Kuperberg-type quantum algorithms run in subexponential time.
  Bonnetain and Schrottenloher (EUROCRYPT 2020) show "only 2^35 quantum equivalents of a
  key-exchange are sufficient to break the 128-bit classical, 64-bit quantum security parameters
  proposed, instead of 2^62", and that level 1 needs "a base field of at least 1024 bits ...
  instead of 512 bits" (abstract). Peikert ("He gives C-sieves on the CSIDH", EUROCRYPT 2020) estimates CSIDH-512 key recovery at
  "only about 2^16 quantum evaluations using 2^40 bits of quantumly accessible classical memory",
  concludes CSIDH-512 "can therefore be broken using significantly less than 2^64 quantum T-gates"
  under a "best case" evaluation-cost assumption, and that CSIDH-1024 and -1792 also fall short of
  level 1 except near the high end of the MAXDEPTH range (abstract). The debate is about constants
  of a known subexponential quantum algorithm, not a new break; it shows that a scheme whose best
  quantum attack is subexponential is hard to parameterise with confidence.

Lessons for Turing, each with its evidence:

1. Extra public structure is where the attacks land: SIKE's torsion points (IR 8545 p. 17), rank
   metric's extension-field equations (IR 8309 p. 17), LEDAcrypt's product keys (IR 8309 p. 15),
   and the Goppa-code structure now under study (Section 5.2).
2. A decryption-failure channel is a key-recovery channel when the failure rate is high or only
   estimated: LAC (IR 8309 p. 15), BIKE's weak keys (IR 8545 p. 13), and the FrodoKEM Rowhammer
   attack, which manufactured failures by raising the key's error (Fahr et al. 2022).
3. The generic FO transform leaks if its re-encryption check is not constant time, whatever the
   hard problem (Guo-Johansson-Nilsson 2020 on FrodoKEM, 2^30 queries).
4. Years of survival are evidence, not proof: Rainbow and SIKE had survived the first rounds of
   the NIST process; NIST now says Classic McEliece's long history is a weaker argument than it
   was (IR 8545 p. 16).

## 7. Comparison table

Sizes are bytes (public key / ciphertext). Speed is the eBACS median in thousands of cycles
(KeyGen / Encaps / Decaps) on one machine: "amd64; Raptor Cove; 2024 Intel Core 5 210H, P
cores; freshwrap,big", supercop-20260627 (bench.cr.yp.to, page saved 2026-09-26, extracted with
`ebacs_kem_extract.py`, ratios by `fam_compare.py`). eBACS reports the fastest implementation it
has for each primitive; a "T:" flag means constant time was not listed as a goal for the
implementation measured, "C:" that IND-CCA2 is not listed as a goal. None of the benchmarked
builds is the current specification of its scheme (checked in the SUPERCOP 20260831 source by
`fam_ebacs_versions.py`): `frodokem976aes` is "FrodoKEM-976-AES (NISTPQC round 2)" with the
unsalted ciphertext of 15,744 bytes (today's eFrodoKEM size), not the salted ISO version;
`hqc192round4`/`hqc256round4` (used below) are round-4 builds with a 64-byte shared secret, not the
2025-08-22 HQC specification (32-byte shared secret, encapsulation key 4,514 bytes); eBACS's plain
`hqc192`/`hqc256` are the "2020.04 version" and 2-4 times slower; `bikel3` is the "2020.05
version". For FrodoKEM this matters little: the CiC paper reports that the salted KEM's timings
"roughly match the cost of eFrodoKEM in an ephemeral setting (the overhead is about 1% or less)"
(CiC 2025, Sec. 8, PDF p. 28). For HQC the gap between versions shows that its speed is still
moving. The last column is my
assessment, with the evidence named.

| scheme | assumption, structure | "dimension" | pk / ct | speed (kcycles) | standard status (2026-09-27) | attack history | from-scratch Rust difficulty (assessment) |
|---|---|---|---|---|---|---|---|
| ML-KEM-768 (baseline) | Module-LWE, cyclotomic ring, NTT | 3 x 256 | 1,184 / 1,088 | 34 / 33 / 34 | FIPS 203 | no break of the assumption; implementation timing bugs (KyberSlash: keys recovered "within minutes" to "a few hours"; reference code affected) | medium: NTT, compression, constant-time division pitfalls |
| ML-KEM-1024 | same | 4 x 256 | 1,568 / 1,568 | 48 / 47 / 50 | FIPS 203 | same | medium |
| FrodoKEM-976 | plain LWE, no ring, q = 2^16 | n = 976 | 15,632 / 15,792 | 1,756 / 2,337 / 2,233 (AES, T:; round-2 build) | ISO/IEC 18033-2 Amd 2 (2026, per scheme site); BSI and ECCG recommended (hybrid); ANSSI supportive; IETF individual draft | no parameter break; FO timing attack on round-2 code (2^30 queries); Rowhammer key-generation poisoning (2022) | low: "slightly more than 250 lines of plain C"; power-of-2 modulus; constant-time table sampler and FO comparison are the pitfalls |
| FrodoKEM-1344 | same | n = 1344 | 21,520 / 21,696 | 3,180 / 3,950 / 3,798 (AES, T:; round-2 build) | same | same | low |
| sntrup1013 | NTRU over Z_q[x]/(x^p - x - 1), q prime | p = 1013 | 1,623 / 1,455 | 1,253 / 47 / 63 | no standard for the primitive; the SSH method sntrup761x25519 is RFC 9941 (Informational) | no break; NIST doubted the claimed benefit of the ring and noted the ring is little studied | medium-hard: prime q, ring not NTT-friendly (IR 8413 p. 41), polynomial inversion in key generation |
| ntrulpr1013 | Ring-LWR over the same ring | p = 1013 | 1,455 / 1,583 | 40 / 67 / 80 | none | as above | medium-hard |
| ntruhps40961229 / ntruhrss701 | NTRU over x^n - 1, q = 2^k | n = 1229 / 701 | 1,842 / 1,842 and 1,138 / 1,138 | (ntruhrss701) 204 / 17 / 40 | none (NIST finalist, not selected) | NTRU problem unbroken since 1996 (IR 8413 p. 39) | medium |
| HQC-3 / HQC-5 | QCSD, Hamming metric over F_2[x]/(x^n - 1) | n = 35,851 / 57,637 bits | 4,514 / 8,978 and 7,237 / 14,421 | (hqc192round4) 159 / 398 / 646; (hqc256round4) 324 / 767 / 1,264 (T:; round-4 build, not the 2025 spec) | NIST selected March 2025; FIPS 207 not yet published; BSI intends to add it after the standard | IND-CCA2 FO rejection issue fixed 2025; rejection-sampling timing attacks (2022); DFR analysis stable since May 2020 | medium-hard: GF(2) polynomial multiplication, constant-time RMRS decoding and fixed-weight sampling; spec still moving until FIPS 207 |
| mceliece6688128 | binary Goppa codes, syndrome decoding | n = 6688 bits | 1,044,992 / 208 | 369,473 / 94 / 270 | ISO June 2026 (per scheme site); BSI recommended; not NIST | ISD progress "fairly modest" since 1962; structural distinguishers and key recovery conjectured subexponential, concrete cost 2^454 to 2^610 at the smallest set | hard: Goppa key generation with Gaussian elimination, Benes-network control bits, constant-time sorting, 1 MB keys |
| BIKE-L3 | QC-MDPC codes | 2r = 49,318 bits | 3,083 / 3,115 | 1,224 / 205 / 4,351 (C:T:) | not selected; no standard | weak keys gave DFR >= 2^-117 at level 1 (IR 8545 p. 13) | hard: constant-time bit-flipping decoder; DFR unresolved |

Relative cost against ML-KEM-768 (`fam_compare.py` parts 1 and 2): public key plus ciphertext is
13.8x for FrodoKEM-976, 19.0x for FrodoKEM-1344, 1.4x for sntrup1013, 5.9x for HQC-3, 2.7x for
BIKE-L3 and 460x for mceliece6688128 (of which only 208 bytes is ciphertext). Total cycles are
63x (FrodoKEM-976), 109x (FrodoKEM-1344), 13.6x (sntrup1013, almost all in key generation),
12.0x (HQC-3, round-4 build; 28.9x with the 2020.04 build), 57.7x (BIKE-L3) and 3,690x for
mceliece6688128 (almost all key generation; its Encaps plus Decaps is only 5.5x).

## What this means for Turing

The owner's goal is a lattice layer near 1000 dimensions, built on published standards, "with a
twist" that makes Turing's public-key encryption harder to break. From this topic's evidence:

1. A vetted ~1000-dimension lattice KEM already exists and is exactly the conservative choice the
   goal describes: FrodoKEM-976 (n = 976) or FrodoKEM-1344 (n = 1344). It removes the ring and
   module structure that the other lattice KEMs rely on, it is an ISO standard since June 2026
   (per the FrodoKEM and Classic McEliece teams' sites; the 976 and 1344 sets, not 640, per the
   designers), and BSI, ANSSI and the EU ECCG recommend it at levels 3 and 5, always in hybrid
   form (Sections 2.4-2.5). For Turing's long-lived recipient keys only the salted (standard)
   variant fits: the CFRG draft forbids eFrodoKEM once a key may see 2^8 ciphertexts (Section
   2.3). Risk: low for the design; the risks are implementation ones (constant-time FO comparison
   and sampler, fault attacks on key generation; Section 2.6).
2. The strongest literature-backed "twist" is composition, not a new hard problem: run ML-KEM
   (Module-LWE), FrodoKEM (plain LWE) and X25519 side by side and combine the shared secrets with
   a proven combiner, so the file key stays safe if any one of them holds. NIST argues for
   assumption diversity itself (IR 8413 p. 41: "NIST will consider standardizing a KEM that is
   not based on lattices"; IR 8545 pp. 4-5). How to combine three KEMs with a proof is the
   sibling note `hybrid-combiners`, which describes flat and nested three-way constructions. Cost
   per recipient (`fam_compare.py` part 5): X-Wing alone 1,120 bytes; adding FrodoKEM-976 gives
   16,912 bytes; X25519 + ML-KEM-1024 + FrodoKEM-1344 gives 23,296 bytes, plus a few million
   cycles. For file encryption, where each file header carries one ciphertext per recipient, that
   is acceptable. FrodoKEM-976's shared secret is 24 bytes (192 bits): inside a combiner whose
   output feeds Turing's 256-bit key this is fine, but FrodoKEM-976 alone would not match Turing's
   256-bit key target, and ANSSI asks for "preferably NIST level V" (2022, p. 5). Both point to
   FrodoKEM-1344 if the extra 5.9 KB per recipient is acceptable.
3. What FrodoKEM does and does not diversify against. It protects against attacks that exploit
   ring or module structure (IR 8413 p. 38). It does not protect against a general improvement in
   lattice reduction, which would hit ML-KEM and FrodoKEM together; IR 8413 p. 41 says a
   breakthrough on any structured lattice scheme "would reduce the community's confidence in all
   such schemes". Only a non-lattice partner (code-based) diversifies against a lattice-wide
   advance. The two code-based options fit Turing differently:
   - Classic McEliece (mceliece6688128, or mceliece460896 which NIST places at "at least"
     category 2): ciphertext only 208 or 156 bytes, but a 1,044,992- or 524,160-byte public key
     and 10^8 to 10^9 cycles of key generation. Public comments reported by NIST noted that this
     profile may perform better for applications where "a public key can be transferred once
     and then used for several encapsulations (e.g., file
     encryption and virtual private networks [VPNs])" (IR 8545 p. 9). ISO standard;
     BSI-recommended. Risks: the structural-attack debate (Section 5.2), a hard from-scratch
     implementation, and the 2026 multi-instance result: reusing one key for many encapsulations
     (exactly the file-encryption pattern that favours McEliece) costs roughly a square root of
     the number of ciphertexts, so keys should be rotated (Section 5.4).
   - HQC: NIST-selected, but FIPS 207 is not published (re-checked 2026-09-27); the
     specification changed in August 2025 and NIST was still considering changes (Section 5.1).
     Its implementations are still being broken in 2026 (a compiler-induced cache-timing leak in
     the official AVX2 code, key recovery in under 10 seconds of trace collection; power attacks
     on its fixed-weight sampler), and public benchmarks do not yet measure the 2025 version
     (Section 7). Implementing it from scratch now means chasing a moving target; wait for
     FIPS 207 and for a constant-time-verified reference.
4. Twists that the literature marks as risky, with the evidence:
   - A new ring or number field (NTRU Prime's x^p - x - 1, ThreeBears' integer ring): NIST found
     the benefit "not particularly convincing" and the structure little studied (IR 8413
     pp. 40-41; IR 8309 pp. 18-19).
   - Error-correcting codes on top of LWE to allow a higher raw failure rate (LAC, Round5): the
     code became the attack surface (IR 8309 p. 15; Guo-Johansson-Yang 2019).
   - Shortcut generation of the public matrix: NIST trusted only one of Round5's three generation
     methods (IR 8309 p. 17). FrodoKEM's own guidance: a fresh A per key pair; caching A "needs to
     be done in a very careful manner" (proposal Sec. 10.2).
   - Home-made parameters "at about 1000 dimensions": FrodoKEM's own estimates for one parameter
     set move by 11-45 bits between cost models (Section 2.6). Any custom set needs a documented
     estimate under several models (sibling `attack-cost-estimation`) and an exactly computed
     failure rate (sibling `decryption-failures`) before it can be called harder to break than a
     standard set.
   - A family whose best quantum attack is subexponential (CSIDH): its parameters cannot be set
     with confidence (Section 6).
   - A new CCA transform, even a proven one: NTRU+ replaces FO re-encryption with a
     randomness-recovery check and adds a new encoding (ACWC2/SOTP) (Section 4.1). Its authors
     give reductions, but the construction has had far less independent study than the standard
     FO with implicit rejection, and the FrodoKEM, HQC and KyberSlash histories show that the FO
     step is where implementations break (Sections 2.6, 5.1). For Turing: keep the transform of the
     standard being implemented (sibling `cca-transforms-and-binding`).
5. Twists that are supported by published analysis and cost little: salted encapsulation for
   multi-ciphertext security (FrodoKEM proposal Sec. 9.5.2; the SFO transform of the CiC 2025
   paper), hashing the public key into the encapsulation randomness against multi-target attacks
   (Sec. 9.5.1), a fresh matrix A per key pair (Sec. 9.4), implicit rejection with a constant-time
   comparison (Sec. 8.3 and 10.3.1), and the proposed 1-byte confirmation code against
   implementations that skip re-encryption (NIST FIPS 207 slides p. 20; ePrint 2025/450), and a
   key-generation integrity check against fault attacks: regenerate A, S, E from the seeds,
   recompute B and abort on mismatch (Fahr et al. 2022, Sec. 8.2; one extra matrix product per key
   pair). A Turing-specific KEM layer can adopt and test all of these without inventing new
   mathematics.
6. Implementation order suggested by difficulty and maturity (assessment): FrodoKEM is the easiest
   lattice KEM to implement and audit from scratch (no NTT, power-of-two modulus, about 250 lines
   of C in the reference; the team's C and Python code and Botan's C++ code give two independent
   oracles for differential tests, Section 2.5), which suits a learning project; ML-KEM should
   come from a vetted crate
   or be tested against one (sibling `rust-pqc-implementations`); Classic McEliece and HQC are the
   hardest to get right and should not be hand-written before a differential oracle and test
   vectors are in place (sibling `testing-ci-cd`).
7. Deployment precedent: the only large deployment of a non-NIST lattice KEM (sntrup761 in
   OpenSSH, the default from 9.0 in April 2022 until 10.0 in April 2025) was always a hybrid with
   X25519, and OpenSSH moved its default to ML-KEM-768 + X25519 in 10.0. Every government source
   read here (BSI, ANSSI, ECCG) requires the same pattern: post-quantum component plus classical
   component, combined.

## Sources

Local files are in research/papers/ (gitignored). "Scratch" means the local working directory
`research/workfiles/pq/`.
ePrint numbers and venues were checked on the ePrint landing pages with `eprint_meta.py` on
2026-09-27. "URL not re-checked" means the PDF was read locally but its download URL was not
confirmed in this run.

| file in research/papers/ | full reference | URL | used for |
|---|---|---|---|
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | FrodoKEM team, "FrodoKEM: Learning With Errors Key Encapsulation, Preliminary Standardization Proposal", revision 2025-09-29 | https://frodokem.org/ | FrodoKEM algorithm, parameters, sizes, estimates, variants |
| 2025-alkim-et-al-frodokem-cic-practical-lwe-kem.pdf | L. Glabush, P. Longa, M. Naehrig, C. Peikert, D. Stebila, F. Virdia, "FrodoKEM: A CCA-Secure Learning With Errors Key Encapsulation Mechanism", IACR Communications in Cryptology 2025(3), document dated 2025-10-07 | https://frodokem.org/ (links the CiC paper and ePrint) | refreshed estimates, SFO, performance, binding properties |
| 2021-alkim-et-al-frodokem-round3-specification-20210604.pdf | FrodoKEM round-3 specification, 2021-06-04 | https://frodokem.org/ | background (not cited for numbers) |
| 2016-bos-et-al-frodo-take-off-the-ring.pdf | J. Bos et al., "Frodo: Take off the ring! Practical, Quantum-Secure Key Exchange from LWE", ACM CCS 2016 | https://eprint.iacr.org/2016/659 | history |
| 2020-guo-johansson-nilsson-key-recovery-timing-attack-fo-frodokem.pdf | Q. Guo, T. Johansson, A. Nilsson, "A key-recovery timing attack on post-quantum primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM", CRYPTO 2020 | https://eprint.iacr.org/2020/743 | FO timing attack |
| 2022-fahr-et-al-when-frodo-flips-rowhammer.pdf | M. Fahr Jr. et al., "When Frodo Flips: End-to-End Key Recovery on FrodoKEM via Rowhammer", ACM CCS 2022 | https://eprint.iacr.org/2022/952 | Rowhammer attack |
| nist-ir-8413-pqc-round3-report.pdf | G. Alagic et al., NIST IR 8413-upd1, Status Report on the Third Round of the NIST PQC Standardization Process, 2022 | https://doi.org/10.6028/NIST.IR.8413-upd1 | reasons for FrodoKEM, NTRU, NTRU Prime, Saber decisions; Tables 6-7 |
| nist-ir-8309-pqc-round2-report.pdf | G. Alagic et al., NISTIR 8309, Status Report on the Second Round of the NIST PQC Standardization Process, July 2020 | https://doi.org/10.6028/NIST.IR.8309 | NewHope, Round5, LAC, ThreeBears, ROLLO, RQC, LEDAcrypt, Saber |
| nist-ir-8545-pqc-round4-report.pdf | G. Alagic et al., NIST IR 8545, Status Report on the Fourth Round of the NIST PQC Standardization Process, March 2025 | https://doi.org/10.6028/NIST.IR.8545 | HQC selection, BIKE, Classic McEliece, SIKE; Tables 3-8 |
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, August 2024 | https://doi.org/10.6028/NIST.FIPS.203 | ML-KEM q; sizes (via pq_family_sizes.py) |
| 2025-aguilar-melchor-et-al-hqc-specification-20250822.pdf | C. Aguilar-Melchor et al., Hamming Quasi-Cyclic (HQC) specification, 22/08/2025 | https://pqc-hqc.org (as named in the spec) | HQC parameters, sizes, changelog, performance |
| 2025-robinson-nist-fips-207-hqc-kem-slides.pdf | A. Robinson (NIST), "FIPS 207: HQC-KEM", slides, 2025 | csrc.nist.gov (URL not re-checked) | FIPS 207 changes under consideration |
| 2025-moody-nist-pqc-road-ahead-slides.pdf | D. Moody (NIST), "NIST PQC: The Road Ahead", slides (title page dated October 3, 2023, content mentions a 2026 plan) | csrc.nist.gov (URL not re-checked) | "FIPS 207 - in 2026" plan |
| 2022-bernstein-et-al-classic-mceliece-spec-20221023.pdf | Classic McEliece team, "Classic McEliece: conservative code-based cryptography: cryptosystem specification", 2022-10-23 | https://classic.mceliece.org/ | parameter sets (Sec. 7), private-key control bits |
| 2025-classic-mceliece-team-notes-2-529-distinguisher.pdf | Classic McEliece team, "Notes on a recent claim that a mceliece348864 distinguisher uses only 2^529 operations", 17 April 2025 | https://classic.mceliece.org/ | rebuttal of the syzygy distinguisher's impact |
| 2026-classic-mceliece-team-notes-2-610-key-recovery.pdf | Classic McEliece team, "Notes on recent speculation that a mceliece348864 key-recovery attack uses only 2^610 operations", 23 June 2026 | https://classic.mceliece.org/ | rebuttal; ISD cost about 2^150 for (3488, 64) |
| 2026-briaud-lemoine-randriambololona-tillich-heuristic-subexponential-mceliece.pdf | P. Briaud, A. Lemoine, H. Randriambololona, J.-P. Tillich, "A Heuristic Subexponential Attack on the McEliece Cryptosystem", ASIACRYPT 2026 (ePrint: minor revision; local PDF built 2026-09-17) | https://eprint.iacr.org/2026/1232 | structural attack claims and costs |
| 2024-randriambololona-syzygy-distinguisher.pdf | H. Randriambololona, "The syzygy distinguisher", EUROCRYPT 2025 (ePrint: major revision) | https://eprint.iacr.org/2024/1193 | background |
| 2022-aragon-et-al-bike-round4-specification.pdf | N. Aragon et al., BIKE: Bit Flipping Key Encapsulation, round-4 submission, version 5.1, 10/10/2022 | URL not re-checked | BIKE parameters, DFR discussion |
| 2022-guo-et-al-dont-reject-this-hqc-bike.pdf | Q. Guo, C. Hlauschek, T. Johansson, N. Lahr, A. Nilsson, R. L. Schroder, "Don't reject this: Key-recovery timing attacks due to rejection-sampling in HQC and BIKE", TCHES 2022(3) (per HQC spec ref. [20]) | URL not re-checked | HQC/BIKE timing attacks |
| 2020-chen-et-al-ntru-round3-specification.pdf | C. Chen et al., NTRU: algorithm specifications and supporting documentation, round 3, 2020-09-30 | URL not re-checked | NTRU parameters, q formula |
| 2020-bernstein-et-al-ntru-prime-round3-specification.pdf | D. J. Bernstein et al., "NTRU Prime: round 3", 20201007 | URL not re-checked | NTRU Prime parameter sets and Table 1 |
| 2019-alkim-et-al-newhope-round2-specification.pdf | E. Alkim et al., NewHope round-2 specification | URL not re-checked | NewHope n, q, sizes |
| 2018-lu-et-al-lac-ring-lwe-byte-level-modulus.pdf | X. Lu et al., "LAC: Practical Ring-LWE Based Public-Key Encryption with Byte-Level Modulus" | https://eprint.iacr.org/2018/1009 | LAC design (q = 251, BCH code) |
| 2019-guo-johansson-yang-cca-attack-decryption-errors-lac.pdf | Q. Guo, T. Johansson, J. Yang, "A Novel CCA Attack using Decryption Errors against LAC", ASIACRYPT 2019 | https://eprint.iacr.org/2019/1308 | LAC attack costs |
| 2019-baan-et-al-round5-kem-pke-based-on-glwr.pdf | H. Baan et al., "Round5: KEM and PKE based on GLWR", draft of 25 January 2019 | https://eprint.iacr.org/2018/725 | background only |
| 2020-danvers-et-al-saber-round3-specification.pdf | J.-P. D'Anvers et al., Saber round-3 specification | URL not re-checked | background only |
| 2025-bernstein-et-al-kyberslash.pdf | D. J. Bernstein et al., "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations", 15 January 2025 | URL not re-checked | ML-KEM implementation pitfall |
| 2020-bonnetain-schrottenloher-quantum-security-analysis-csidh.pdf | X. Bonnetain, A. Schrottenloher, "Quantum Security Analysis of CSIDH", EUROCRYPT 2020 (ePrint: major revision) | https://eprint.iacr.org/2018/537 | CSIDH quantum cost |
| 2020-peikert-he-gives-c-sieves-on-the-csidh.pdf | C. Peikert, "He Gives C-Sieves on the CSIDH", EUROCRYPT 2020 | https://eprint.iacr.org/2019/725 | CSIDH quantum cost |
| 2018-castryck-lange-martindale-panny-renes-csidh.pdf | W. Castryck, T. Lange, C. Martindale, L. Panny, J. Renes, "CSIDH: An Efficient Post-Quantum Commutative Group Action", ASIACRYPT 2018 | https://eprint.iacr.org/2018/383 | CSIDH origin |
| bsi-tr-02102-1-cryptographic-mechanisms.pdf | BSI TR-02102-1, Cryptographic Mechanisms: Recommendations and Key Lengths, version 2026-01 (23 January 2026) | https://www.bsi.bund.de (URL not re-checked) | BSI positions on FrodoKEM, Classic McEliece, ML-KEM, HQC, hybrids |
| 2022-anssi-views-on-pqc-transition.pdf | ANSSI, "ANSSI views on the Post-Quantum Cryptography transition", 30 March 2022 | https://cyber.gouv.fr (URL not re-checked) | ANSSI position, level V preference |
| 2023-anssi-pqc-transition-follow-up.pdf | ANSSI, "ANSSI views on the Post-Quantum Cryptography transition (2023 follow up)", 21 December 2023 | https://cyber.gouv.fr (URL not re-checked) | ANSSI position on FrodoKEM |
| 2025-eccg-agreed-cryptographic-mechanisms-v2.pdf | European Cybersecurity Certification Group, Sub-group on Cryptography, Agreed Cryptographic Mechanisms, version 2.0, April 2025 | URL not re-checked | EU certification status |
| 2026-eccg-agreed-cryptographic-mechanisms-v3-draft.pdf | ECCG Sub-group on Cryptography, Agreed Cryptographic Mechanisms, working draft, April 2026 | URL not re-checked | EU certification status |
| 2021-alkim-et-al-frodokem-round3-specification-20210604.pdf (again) | FrodoKEM round-3 specification, 2021-06-04, Sec. 1 and 2.2 | https://frodokem.org/ | what the worst-case reduction does and does not give (claim 82) |
| 2026-anssi-ft-116-transition-post-quantique-sshv2.pdf | ANSSI, "Transition post-quantique de SSHv2", fiche technique ANSSI-FT-116, 2 February 2026 | https://messervices.cyber.gouv.fr/documents-guides/transition_post_quantique_ssh_v2.pdf | ANSSI description of the OpenSSH hybrids |
| 2026-kim-park-ntru-plus-kpqc-final-specification.pdf | J. H. Park, J. Kim, "NTRU+: Compact Construction of NTRU Using Simple Encoding Method", KpqC final specification, January 30, 2026 | https://www.kpqc.or.kr/images/pdf2/NTRU+.pdf | NTRU+ parameters, sizes, security, transforms |
| 2026-cheon-et-al-smaug-t-kpqc-final-specification.pdf | J. H. Cheon et al., "SMAUG-T: the Key Exchange Algorithm based on Module-LWE and Module-LWR", KpqC final specification, February 4, 2026 | https://www.kpqc.or.kr/images/pdf2/SMAUG-T.pdf | SMAUG-T parameters, sizes, security, stated limitation |
| online (scratch families/kpqc-comp2.html, kpqc-algos.html, kpqc-notice12.html, fetched 2026-09-27) | KpqC research group pages: "Selected Algorithms from the KpqC Competition Round 2" (January 16, 2025); "KpqC Algorithms" (January 30, 2026); notice "KpqC 알고리즘 표준화 관련 안내" (2026-04-22) | https://www.kpqc.or.kr/competition_02.html ; https://www.kpqc.or.kr/contents/03_exhibit/sub_03.html | KpqC selection and KS status |
| online (scratch families/primitives-kem.html, impl-*.html, fetched 2026-09-27) | eBACS primitive list and implementation pages | https://bench.cr.yp.to/primitives-kem.html | which scheme version each benchmark measures |
| online (scratch supercop-20260831.tar.xz, fetched 2026-09-27) | SUPERCOP 20260831 source tree (crypto_kem/*/api.h) | https://bench.cr.yp.to/supercop.html | sizes identifying the benchmarked versions |
| online (scratch families/openssh-pq.html, fetched 2026-09-27) | OpenSSH, "Post-Quantum Cryptography" | https://www.openssh.com/pq.html | OpenSSH's two PQ key agreements; 10.1 warning |
| 2026-dong-guo-breaking-optimized-hqc-cache-timing.pdf | H. Dong, Q. Guo, "Breaking Optimized HQC: The First Cache-Timing Full Decryption Oracle Key-Recovery Attack in Post-Quantum Cryptography", CRYPTO 2026 (ePrint: minor revision) | https://eprint.iacr.org/2026/693 | compiler-induced timing leak in HQC AVX2 code |
| 2026-hesse-et-al-hqc-fixed-weight-sampling-side-channels.pdf | D. Hesse, M. Krausz, R. Murugananthan, T. Wollinger, T. Guneysu, "Power Reveals, Timing Conceals: Side-Channel Attacks and Hiding Countermeasures for HQC's Fixed-Weight Vector Sampling", preprint 2026 | https://eprint.iacr.org/2026/1462 | power attacks on HQC sampling |
| online (scratch families/draft-longa-cfrg-frodokem-03.txt, fetched 2026-09-27) | P. Longa et al., "FrodoKEM: key encapsulation from learning with errors", draft-longa-cfrg-frodokem-03, 22 June 2026 | https://www.ietf.org/archive/id/draft-longa-cfrg-frodokem-03.txt | parameter sets; ephemeral-use rule |
| online (scratch families/draft-longa-cfrg-frodokem-security-considerations-00.txt, fetched 2026-09-27) | P. Longa et al., "Security Considerations for FrodoKEM", draft-longa-cfrg-frodokem-security-considerations-00, 23 June 2026 | https://datatracker.ietf.org/doc/draft-longa-cfrg-frodokem-security-considerations/ | ISO scope per designers; defaults; security figures |
| online (scratch families/eucc-crypto.html, fetched 2026-09-27) | ENISA, EUCC Guidelines on Cryptography page (ACM v2 applicable; v3 draft for public review 2 June 2026) | https://certification.enisa.europa.eu/publications/eucc-guidelines-cryptography_en | ECCG ACM status |
| 2026-may-sa-diogo-multi-instance-security-code-based-kems.pdf | A. May, G. Sa Diogo, "Multi-Instance Security Degradation of Code-Based KEMs", preprint (ePrint revised 2026-06-12) | https://eprint.iacr.org/2026/517 | multi-instance degradation of HQC, BIKE, Classic McEliece |
| 2026-yu-et-al-progressive-sieving-style-isd.pdf | T. Yu, H. Jiang, H. Wang, R. Chen, Q. Cheng, X. Huang, Y. Zhu, "Progressive Sieving-Style Information-Set Decoding Algorithm", preprint 2026 | https://eprint.iacr.org/2026/633 | improved ISD costs for HQC |
| online (scratch frodokem-org.html, saved 2026-09-26) | FrodoKEM team web site | https://frodokem.org/ | ISO status, history, drafts |
| online (scratch families/mce-iso-now.html, fetched 2026-09-27) | Classic McEliece team, "Classic McEliece: ISO", page version 2026.06.15 | https://classic.mceliece.org/iso.html | ISO status and parameter sets |
| online (scratch families/openssh-releasenotes.html, saved 2026-09-26) | OpenSSH release notes (latest entry: 10.5, 2026-08-11) | https://www.openssh.com/releasenotes.html | sntrup761 and mlkem768 key-exchange history |
| online (scratch families/rfc9941.txt, fetched 2026-09-27) | M. Friedl, J. Mojzis, S. Josefsson, RFC 9941, April 2026, Informational | https://www.rfc-editor.org/rfc/rfc9941.txt | SSH sntrup761x25519-sha512 |
| online (scratch families/dt2-*.json, fetched 2026-09-27) | IETF datatracker API records | https://datatracker.ietf.org/api/v1/doc/document/ | draft revisions and states |
| online (scratch families/pqc-news-now.html, fetched 2026-09-27) | NIST CSRC, Post-Quantum Cryptography: News and Updates | https://csrc.nist.gov/projects/post-quantum-cryptography/news | absence of a FIPS 207 draft |
| online (scratch families/ebacs-kem-freshwrap-big.html, saved 2026-09-26) | eBACS, KEM measurements on amd64 freshwrap,big, supercop-20260627 | https://bench.cr.yp.to/results-kem/amd64-freshwrap,big.html | cycle counts |
| online (scratch families/ebacs-kem-pi5.html, saved 2026-09-26) | eBACS, KEM measurements on aarch64 pi5, supercop-20251222 | https://bench.cr.yp.to/results-kem.html | ARM cross-check (not quoted in the tables) |

## Claim ledger

| # | claim | status | source |
|---|---|---|---|
| 1 | FrodoKEM parameters D, q, n, n-bar, B, d, len_sec, SHAKE per level as in Sec. 2.2 table | VERIFIED | FrodoKEM proposal 2025-09-29, Table A.1 (PDF p. 15) |
| 2 | len_SE/len_salt = 256/256, 384/384, 512/512 (standard); 128/0, 192/0, 256/0 (ephemeral) | VERIFIED | proposal Table A.2 (p. 15) |
| 3 | sigma 2.8/2.3/1.4, Renyi order 200/500/1000, divergence 0.324e-4, 0.140e-4, 0.264e-4 | VERIFIED | proposal Table A.3 (p. 15); exponents read with pdfspans.py |
| 4 | Table A.4 CDF tables reproduce Table A.3 probabilities; table SDs 2.8146, 2.3178, 1.4291 | COMPUTED | `python research/scripts/pq/pq_family_sizes.py` |
| 5 | FrodoKEM and eFrodoKEM sizes (sk, pk, ct, ss) as in Sec. 2.2 | VERIFIED + COMPUTED | proposal Tables A.5, A.6 (p. 16); formulas Sec. 8 (p. 5); `pq_family_sizes.py` (its `--negative-control` reports the 2 planted mismatches) |
| 6 | eFrodoKEM intended for about 2^8 ciphertexts per public key | VERIFIED | proposal Sec. 9.4 and 9.6 (p. 9); superscript read with pdfspans.py |
| 7 | Generating A can be roughly 40% of encaps/decaps cost; reusing A needs care | VERIFIED | proposal Sec. 10.2 (pp. 9-10) |
| 8 | Core-SVP primal/dual costs (classical/quantum/plausible) as in Sec. 2.4 | VERIFIED | proposal Table A.7 (p. 13) |
| 9 | Refined log2(gates) 175.1/240.0/305.4; log2(memory bits) 110.4/155.8/202.1 | VERIFIED | proposal Table A.8 (p. 14) |
| 10 | Failure rates 2^-138.7, 2^-199.6, 2^-252.5; IND-CCA (reduction) 141/206/268 bits | VERIFIED | proposal Table A.9 (p. 15) |
| 11 | Failure boosting gives FrodoKEM no loss; for 1344 the overhead "exceeds 3.5 bits" | VERIFIED | proposal Sec. 9.3 (p. 8) |
| 12 | pkh is hashed into the randomness; the analysis "does not formally cover" multi-target | VERIFIED | proposal Sec. 9.5.1 (p. 9) |
| 13 | CiC 2025 Table 6 core-SVP values (Frodo-640 primal uSVP 138.5 C-LSF-Sieve, 123.0 Q-RW-Sieve; Frodo-1344 dual-sieve-FFT 254.8 / 227.6) | VERIFIED | CiC 2025 paper, Table 6 (p. 25) |
| 14 | CiC 2025 Table 4 IND-CPA B/C/Q = 145/134/119, 208/195/173, 262/250/223; IND-CCA B/C = 140/130, 204/192, 258/246 | VERIFIED | CiC 2025, Table 4 (p. 20) |
| 15 | CiC 2025 Table 7 C-2D-Sieve primal costs 158.6-164.4 (640), 225.4-231.6 (976), 282.4-300.1 (1344) | VERIFIED | CiC 2025, Table 7 (p. 26) |
| 16 | CiC includes dual-sieve-FFT although improvements are "controversial"; BKZ modelled as 8(d - beta) SVP calls | VERIFIED | CiC 2025, Sec. 7.2.3 (pp. 25-26) |
| 17 | FrodoKEM Table 8 cycles (i7-8700); full KEM 0.97/1.91/3.22 ms; >20x slower without AES-NI; ~250 lines of C | VERIFIED | CiC 2025, Sec. 8, Table 8, pp. 27-29 |
| 18 | CiC Table 10: Kyber768 39/53/42 and FrodoKEM-976-AES 2,043/2,125/2,042 kcycles; ratio 40-52x; pk+ct ratio 13.8x | VERIFIED + COMPUTED | CiC 2025, Table 10 (p. 31); `python fam_compare.py` part 3 |
| 19 | Round-2 FrodoKEM reference code: key recovery with about 2^30 decapsulation calls via FO timing | VERIFIED | Guo-Johansson-Nilsson abstract (exponent via pdfspans.py); CRYPTO 2020 per ePrint 2020/743 and IR 8413 ref. [229] |
| 20 | Rowhammer attack: about 200,000 core-hours; KeyGen about 8 ms | VERIFIED | Fahr et al., abstract p. 1; ACM CCS 2022 per ePrint 2022/952 |
| 21 | NIST removed FrodoKEM: BIKE, HQC, SIKE "better suited"; FrodoKEM "generally worse performance" | VERIFIED | NIST IR 8413-upd1, Sec. 2.3, pp. 17-18 |
| 22 | NIST: FrodoKEM "could remain secure even in a future world where structured lattices are broken"; structure gives "a quadratic savings" | VERIFIED | IR 8413, Sec. 4.3.1, p. 38 |
| 23 | FrodoKEM and Classic McEliece standardised in ISO/IEC 18033-2 in June 2026 (FrodoKEM: "ISO/IEC 18033-2:2006/Amd 2:2026") | VERIFIED (scheme-team sites only) | frodokem.org (Standardization; News "June, 2026"); classic.mceliece.org/iso.html v2026.06.15; draft-josefsson-mceliece-05 abstract; iso.org page not readable (HTTP 403) |
| 24 | ISO McEliece sets: 460896, 6688128, 6960119, 8192128, each plain/f/pc/pcf; 348864 absent | VERIFIED (team site) | classic.mceliece.org/iso.html v2026.06.15 |
| 24a | ISO history: WG 2 solicited comments in October 2022; team ISO draft 2023-04-19 had only 6* and 8* sets (128-bit "quantum model"); ISO added 4* | VERIFIED (team site) | classic.mceliece.org/iso.html v2026.06.15 |
| 24b | FrodoKEM ISO history: preliminary work item October 2022; WG 2 agreed April 2023; proposal revisions 2023-03-14, 2024-12-05, 2025-09-29 | VERIFIED | frodokem.org News; proposal revision history, p. 17 |
| 25 | draft-longa-cfrg-frodokem at revision 03 (2026-06-22), no RFC; draft-josefsson-ssh-frodokem-00 (2025-09-19) | VERIFIED | IETF datatracker API, fetched 2026-09-27 |
| 26 | BSI TR-02102-1 v2026-01 recommends FrodoKEM-976/1344 (hybrid), not 640 | VERIFIED | TR-02102-1 v2026-01, Sec. 2.4.1, Table 2.5, pp. 37-38; hybrid use: Sec. 2.1-2.2, pp. 28-29 |
| 27 | BSI first recommended FrodoKEM and Classic McEliece in version 2020-01 | VERIFIED | TR-02102-1 v2026-01, version history, p. 2 |
| 28 | BSI recommends mceliece460896, 6688128, 8192128 and their f variants | VERIFIED | TR-02102-1 v2026-01, Sec. 2.4.2, Table 2.6, p. 38 |
| 29 | BSI intends to add HQC (categories 3 and 5) after the standard is published | VERIFIED | TR-02102-1 v2026-01, Sec. 2.4.4, pp. 38-39 |
| 30 | ANSSI: FrodoKEM a "valid and conservative option in high security applications" | VERIFIED | ANSSI 2023 follow-up, p. 3 |
| 30a | ANSSI "insiste sur la nécessité de l'hybridation" wherever quantum protection is needed | VERIFIED | ANSSI FAQ "Cryptographie post-quantique (PQC)" page (saved in scratch families/anssi-faq.html by the earlier run, cyber.gouv.fr) |
| 31 | ANSSI 2022: security level "preferably NIST level V"; FrodoKEM among first-deployment options; hybrid FrodoKEM visa possible regardless of NIST | VERIFIED | ANSSI 2022, p. 5 |
| 32 | ECCG ACM v2.0 and v3 draft list FrodoKEM as R, prefer FrodoKEM-1344 or -976, require hybrid; no McEliece or HQC entry | VERIFIED | ECCG ACM v2.0, p. 35; v3 draft, pp. 36-37 (Notes 63, 65) |
| 33 | NTRU round-3 parameters (509/677/821 with q 2048/2048/4096; hrss701 with q 8192); HRSS q = 2^ceil(7/2 + log2 n) | VERIFIED | NTRU round-3 spec, Sec. 1.3.3 (p. 6), Sec. 1.6 (p. 9) |
| 34 | NTRU sizes including the level-5 sets 1229 and 1373 | VERIFIED + COMPUTED | IR 8413 Table 6 (p. 86); `pq_family_sizes.py` |
| 35 | NIST: MLWE "marginally more convincing than ... MLWR or the NTRU problem"; patent footnote; NTRU patents dedicated to the public in 2007 | VERIFIED | IR 8413, Sec. 2.3, p. 18 |
| 36 | NTRU sets perfectly correct; sizes about 25% larger; key generation slower | VERIFIED | IR 8413, Sec. 4.3.2, pp. 38-39 |
| 37 | NTRU Prime (p, q, w) for all 12 sets; p and q prime, x^p - x - 1 irreducible mod q; "large Galois group and an inert modulus" | VERIFIED | NTRU Prime round-3 spec, Sec. 3.4-3.15, pp. 21-23; Sec. 2.1, p. 7; Sec. 4, p. 24 |
| 37a | NTRU problem: given h, find small (f, g) with h f = g mod q | VERIFIED | IR 8413, Sec. 3.2.3, Problem 3.6 |
| 38 | NTRU Prime sizes (Table 1); IR 8413 Table 7 prints 15158 for the sntrup653 secret key (spec: 1518) | VERIFIED + COMPUTED | NTRU Prime spec Table 1 (PDF p. 42); IR 8413 Table 7 (p. 87); `pq_family_sizes.py` |
| 39 | NIST reasons for dropping NTRU Prime; ring "relatively little" studied; key generation 500-2500 kcycles (sntrup), 50-100 (ntrulpr) | VERIFIED | IR 8413, Sec. 4.3.3, pp. 40-41 |
| 40 | OpenSSH: 8.5 (2021-03-03) sntrup761x25519 replaces sntrup4591761; 8.9 (2022-02-23) in the default list; 9.0 (2022-04-08) default; 9.9 (2024-09-19) mlkem768x25519-sha256 added; 10.0 (2025-04-09) mlkem768x25519-sha256 default | VERIFIED | openssh.com/releasenotes.html (saved 2026-09-26) |
| 41 | RFC 9941 (April 2026, Informational) specifies sntrup761x25519-sha512 for SSH | VERIFIED | rfc-editor.org/rfc/rfc9941.txt, header and abstract |
| 42 | draft-josefsson-ntruprime-streamlined-00 (2023) expired; no RFC for the NTRU Prime primitive found | VERIFIED for the draft (datatracker state "expired"); UNVERIFIED for "no other document" | datatracker API; a complete RFC search for an NTRU Prime primitive was not run |
| 43 | Saber: MLWR, q = 2^13, p = 2^10, k = 2/3/4; dual-attack improvements put sets "slightly below" targets when memory cost is ignored; Kyber preferred because MLWE "better studied" | VERIFIED | IR 8413, Sec. 4.3.4, pp. 42-43 |
| 44 | NewHope reasons (RLWE-to-MLWE reduction; no category-3 set; preference for low-rank MLWE) | VERIFIED | IR 8309, Sec. 3.12, p. 16 |
| 45 | NewHope n in {512, 1024}, q = 12289; pk/ct 1824/2176 bytes at n = 1024 | VERIFIED | NewHope round-2 spec, PDF pp. 8 and 11 |
| 46 | Round5 reasons (complexity, no royalty-free licence, only tau = 0 trusted, two minor attacks) | VERIFIED | IR 8309, Sec. 3.15, p. 17 |
| 47 | LAC reasons; LAC q = 251 with a BCH code | VERIFIED | IR 8309, Sec. 3.10, p. 15; LAC paper (sections on q = 251 and BCH) |
| 48 | LAC256 attack: one key among about 2^64 with complexity 2^79 after 2^162 precomputation; LAC256-v2: 2^171 | VERIFIED | Guo-Johansson-Yang abstract (exponents via pdfspans.py); ASIACRYPT 2019 per ePrint 2019/1308 |
| 49 | ThreeBears reasons (I-MLWE new; little third-party study) | VERIFIED | IR 8309, Sec. 3.17, pp. 18-19 |
| 50 | ROLLO and RQC near-complete breaks; LEDAcrypt weak keys | VERIFIED | IR 8309, Sec. 3.11, 3.14, 3.16, pp. 15-18 |
| 51 | HQC parameters (n1, n2, n, k, w, w_r = w_e, DFR) | VERIFIED | HQC spec 2025-08-22, Table 5, p. 29 |
| 52 | HQC n = smallest primitive prime greater than n1 n2 | COMPUTED | `pq_family_sizes.py` (HQC section) |
| 53 | HQC sizes 2,241/2,321/4,433 (HQC-1), 4,514/4,602/8,978 (HQC-3), 7,237/7,333/14,421 (HQC-5) | VERIFIED + COMPUTED | HQC spec Table 6, p. 29; `pq_family_sizes.py` |
| 54 | HQC 2025-08-22 changes (salted SFO, Saarinen's IND-CCA2 issue, keypair format, sampler, SHA3-512, 32-byte K) | VERIFIED | HQC spec changelog, p. 2; ref. [34] |
| 55 | HQC performance Tables 7 and 8; reference/optimized ratio 39x-92x | VERIFIED + COMPUTED | HQC spec, pp. 30-31; `fam_compare.py` part 4 |
| 56 | NIST selected HQC for its stable DFR; not attacked since May 2020; final standard in about two years | VERIFIED | IR 8545, Sec. 3.1, pp. 11-12; Sec. 4, p. 18 |
| 57 | No FIPS 207 draft on the NIST PQC news page on 2026-09-27; /pubs/fips/207/ipd returns 404 | VERIFIED (absence on the fetched pages) | csrc.nist.gov PQC news page and URL, fetched 2026-09-27 |
| 58 | NIST planned "FIPS 207 - in 2026" | VERIFIED (slide text; deck date unclear) | Moody slides, PDF p. 17 |
| 59 | FIPS 207 changes under consideration include a 1-byte confirmation code (ePrint 2025/450, CRYPTO 2025) | VERIFIED | Robinson slides, pp. 17-21; ePrint 2025/450 landing page |
| 60 | Classic McEliece parameter sets (m, n, t) and f variants | VERIFIED | Classic McEliece spec 2022-10-23, Sec. 7, pp. 15-16 |
| 61 | Classic McEliece sizes; IR 8413 Table 6 prints 104 992 for mceliece6688128 (formula: 1,044,992) | VERIFIED + COMPUTED | IR 8545 Table 8 (p. 7); IR 8413 Table 6 (p. 86); `pq_family_sizes.py` |
| 62 | Classic McEliece cycle counts (IR 8545 Table 5) and the "three orders of magnitude" key-generation remark | VERIFIED | IR 8545, Table 5 and text, p. 6 |
| 63 | NIST: McEliece no longer considered; may standardise after ISO; progress "somewhat undermines" the conservative case; mceliece460896 at least category 2 | VERIFIED | IR 8545, Sec. 2.3, p. 9; Sec. 3.3, pp. 14-16, footnote 5 |
| 64 | ISD progress "fairly modest"; most change from improvements more than 30 years old | VERIFIED | IR 8545, Sec. 3.3, p. 15 |
| 65 | Briaud et al. 2026: attack "at best of complexity of order 2^454" at level 1; paper's Table 6.1 gives 2^454 to 2^610 for mceliece348864 | VERIFIED | Briaud et al. abstract (exponent via pdfspans.py) and table text; team note of 23 June 2026, p. 3; ASIACRYPT 2026 per ePrint 2026/1232 |
| 66 | Team rebuttal: 2^256 seed-search bound; largest demo (482, 7); ISD about 2^150 bit operations for (3488, 64) | VERIFIED | Classic McEliece team notes, 23 June 2026, pp. 1-4 |
| 67 | Syzygy distinguisher conjectured at about 2^529 for (3488, 64) | VERIFIED | team notes, 17 April 2025, pp. 1-2 |
| 68 | BIKE (r, w, t) and DFR targets; version 5.1 of 10/10/2022 | VERIFIED | BIKE spec, Table 4 (p. 13); title page |
| 69 | BIKE sizes; r prime with 2 primitive | VERIFIED + COMPUTED | IR 8545 Table 6 (p. 7); `pq_family_sizes.py` |
| 70 | BIKE weak keys: DFR at least 2^-117 at level 1; r = 13,477 for 2^-129.5; "post-selection tweaks" | VERIFIED | IR 8545, Sec. 3.2, pp. 12-13 |
| 71 | BIKE's low-DFR assumption "remains partly heuristic" | VERIFIED | BIKE spec, Sec. 3.4, PDF pp. 16-17 |
| 72 | SIKE patches "ineffective or had weaknesses"; the attack used torsion-point images | VERIFIED | IR 8545, Sec. 3.4, pp. 16-17 |
| 73 | CSIDH: 2^35 quantum key-exchange equivalents instead of 2^62; level 1 needs a field of at least 1024 bits | VERIFIED | Bonnetain-Schrottenloher abstract (exponents via pymupdf spans); EUROCRYPT 2020 per ePrint 2018/537 |
| 74 | CSIDH-512 key recovery about 2^16 quantum evaluations with 2^40 bits of QRACM; below 2^64 T-gates under best-case evaluation cost; prior 2^32.5 evaluations and 2^31 qubits | VERIFIED | Peikert abstract (exponents via pymupdf spans); EUROCRYPT 2020 per ePrint 2019/725 |
| 75 | KyberSlash: keys recovered "within minutes" (KyberSlash2) or "a few hours" (KyberSlash1); reference code affected | VERIFIED | KyberSlash paper (15 January 2025), abstract |
| 76 | ML-KEM q = 3329; parameter sets (k, eta1, eta2, du, dv) and sizes: ML-KEM-768 ek 1184, dk 2400, ct 1088; ML-KEM-1024 1568/3168/1568; shared secret 32 bytes | VERIFIED + COMPUTED | FIPS 203, Sec. 2.3 (PDF p. 14), Tables 2-3 (PDF p. 48); `pq_family_sizes.py` (ML-KEM section) |
| 77 | eBACS medians in Section 7 (supercop-20260627, Core 5 210H) and the meaning of T: and C: | VERIFIED | eBACS page saved 2026-09-26; raw rows spot-checked; legend on the page |
| 78 | Relative sizes and cycle ratios against ML-KEM-768 (13.8x, 19.0x, 460x; 63x, 109x, 12.0x for HQC-3 round-4 build, 57.7x BIKE-L3, 3,690x, etc.) | COMPUTED | `python research/scripts/pq/fam_compare.py` parts 1-2 (re-run 2026-09-27 after switching HQC to the round-4 builds; its `--negative-control` fails as intended) |
| 79 | Per-recipient hybrid ciphertext sizes (1,120; 16,912; 23,296; 10,098; 1,328 bytes) | COMPUTED | `fam_compare.py` part 5 (assumes a 32-byte X25519 share and plain concatenation; the real format belongs to `hybrid-combiners`) |
| 80 | Responses to NIST (reported in IR 8545) noted McEliece may perform better where a public key is transferred once and reused, "e.g., file encryption and virtual private networks" | VERIFIED | IR 8545, Sec. 2.3, p. 9 |
| 81 | Toy FrodoPKE, NTRU and Niederreiter examples behave as described (noise 363 < 512 at B = 2; failures at B = 4; NTRU maximum 18 < 32) | COMPUTED | `python research/scripts/pq/toy_families.py` |
| 82 | The FrodoKEM team states the worst-case reduction gives no "end-to-end" guarantee for its concrete parameters (non-tight); sigma is chosen "comfortably above" the smoothing parameter so the parameters "conform to a nontrivial reduction" from BDDwDGS; hence NIST's remark and the proposal's "covered by the reductions" are consistent | VERIFIED | FrodoKEM round-3 spec 2021-06-04, PDF p. 7 (Sec. 1 design rationale) and PDF p. 23 (Sec. 2.2 error distributions); proposal Annex D, PDF p. 19 |
| 83 | Implementation-difficulty ranking in Section 7 | UNVERIFIED (assessment) | based on the cited evidence (CiC p. 27; IR 8413 p. 41; KyberSlash; Guo et al. 2022; McEliece spec control bits); settle by building prototypes against test vectors |
| 84 | NIST: a structured-lattice breakthrough "would reduce the community's confidence in all such schemes, including NTRU Prime"; NIST "will consider standardizing a KEM that is not based on lattices" | VERIFIED | IR 8413, Sec. 4.3.3, p. 41 |
| 85 | NIST values "a variety of computational hardness assumptions" (fourth-round rationale) | VERIFIED | IR 8545, Sec. 2.2.1, pp. 4-5 |
| 86 | Refreshed core-SVP (CiC Table 6) is 11.1-27.1 bits below proposal Table A.7; C-2D-Sieve (CiC Table 7) is 20.1-45.3 bits above the cheapest refreshed core-SVP classical value | COMPUTED | `python research/scripts/pq/fam_compare.py` part 6, from proposal Table A.7 and CiC Tables 6-7 |
| 87 | Proposal Table A.9 LWE security (C/Q/P, for 2 n-bar LWE instances with Gaussian error): 145/132/104 (640), 210/191/150 (976), 275/250/197 (1344); these reduction-derived claims "are assumed to be weaker" than the attack-based Annexes B and C | VERIFIED | proposal Annex D, Table A.9 (PDF p. 19, printed p. 15) |
| 88 | Proposal Annex C: a refined quantum gate count "seems to be essentially irrelevant" because a quantum speed-up for sieving is "rather tenuous" (citing AGPS20); CiC 2025 likewise ignores conjectured quantum speed-ups in its beyond-core-SVP Table 7 | VERIFIED | proposal Annex C (PDF p. 18, printed p. 14); CiC 2025 Sec. 7.2.3 (PDF p. 26) |
| 89 | CiC 2025 Table 7 C-Para-Enum (parallel pruned enumeration) costs: 195.9-201.9 (640), 304.3-313.1 (976), 426.2-438.3 (1344), far above the sieving models | VERIFIED | CiC 2025, Table 7 (PDF p. 26) |
| 90 | Re-check 2026-09-27 (continuation run): NIST PQC news page (footer "Updated August 05, 2026") has no FIPS 207 item; newest items are IR 8610 (May 14, 2026), SP 800-133r3 ipd (April 17, 2026), SP 800-230 ipd (April 13, 2026); csrc.nist.gov/pubs/fips/207/ipd returns HTTP 404 | VERIFIED (absence on fetched pages) | scratch families/pqc-news-0927b.html and fips207-0927b.html, fetched 2026-09-27 |
| 91 | ANSSI technical note ANSSI-FT-116 "Transition post-quantique de SSHv2" (2 February 2026) describes both OpenSSH hybrids (NTRU Prime and ML-KEM with ECDH), says ML-KEM + ECDH is the OpenSSH default since 10.0, cites the sntrup761 SSH document as an Internet-Draft ("Pour l'instant, il n'y a pas de standards officiels"), and names neither FrodoKEM nor Classic McEliece | VERIFIED | research/papers/2026-anssi-ft-116-transition-post-quantique-sshv2.pdf, Sec. 3.2.1 and ref. [5] (pdfgrep) |
| 92 | Rowhammer paper: KeyGen window stretched "from 8ms to 1300ms"; countermeasures: hardware-accelerated primitives, operation ordering, regenerate A, S, E and recompute B (abort if different), keep and check E, monitor ciphertext distribution | VERIFIED | Fahr et al. 2022, Sec. 8.1-8.2, PDF p. 13 |
| 93 | OpenSSH: 9.9 added the IANA name sntrup761x25519-sha512; 10.1 (2025-10-06) warns on non-post-quantum key agreement (WarnWeakCrypto); 10.3 (2026-04-02) sped up sntrup761 keying; latest release 10.5 (2026-08-11) | VERIFIED | openssh.com/releasenotes.html (scratch families/openssh-rn.txt, saved 2026-09-27), sections 9.9, 10.1, 10.3, 10.5 |
| 94 | OpenSSH PQ page names two PQ key agreements, mlkem768x25519-sha256 and sntrup761x25519-sha512; PQ key agreement default since 9.0 | VERIFIED | https://www.openssh.com/pq.html fetched 2026-09-27 (scratch families/openssh-pq.html) |
| 95 | eBACS/SUPERCOP builds are older versions: frodokem976aes = "FrodoKEM-976-AES (NISTPQC round 2)" with api.h pk 15632, sk 31296, ct 15744, ss 24 (unsalted); frodokem976 has ct 15768 (an older version whose ciphertext adds a 24-byte field, per its apiorig.h comment); hqc192round4 api.h pk 4522, sk 4586, ct 8978, ss 64 (IR 8545 Table 7 lists hqc-192 ek 4,522, ct 9,042; the 2025-08-22 spec lists ek 4,514, ct 8,978, K 32 bytes); hqc192 = "HQC-192 (2020.04 version)"; bikel3 = "BIKE Level 3 (2020.05 version)"; hqc192round4 medians on the Core 5 210H: 159,282 / 397,628 / 645,720 cycles (T:) | VERIFIED + COMPUTED | eBACS primitive list (bench.cr.yp.to/primitives-kem.html, fetched 2026-09-27); SUPERCOP 20260831 crypto_kem/*/api.h; IR 8545 Table 7 (p. 7); `python research/scripts/pq/fam_ebacs_versions.py PRIMS MACHINE --supercop DIR` (negative control fails as intended) |
| 96 | KpqC announced its final algorithms on January 16, 2025: KEMs NTRU+ and SMAUG-T; signatures AIMer and HAETAE; final specifications dated January 30, 2026 (page) | VERIFIED | kpqc.or.kr competition_02.html and contents/03_exhibit/sub_03.html, fetched 2026-09-27 |
| 97 | KpqC notice 2026-04-22: KS (Korean Industrial Standard) proposals submitted for NTRU+ and SMAUG-T; signatures under review; algorithms may change during standardisation | VERIFIED (my translation from Korean) | kpqc.or.kr board_competition no=12, fetched 2026-09-27 |
| 98 | NTRU+: ring Z_q[x]/(x^n - x^(n/2) + 1), n = 2^i 3^j in {768, 864, 1152}, q = 3457; pk = ct = 1152/1296/1728 bytes, sk 2336/2624/3488; log2 worst-case error -379/-340/-260; security (C/Q, LWE) 156/139, 179/160, 248/222; ACWC2 + re-encryption-free FO variant | VERIFIED + COMPUTED | NTRU+ final spec (2026-01-30), abstract, Sec. 1, Sec. 7 Tables 6-7, PDF pp. 1-5, 44-46; pk/ct re-derived as 12 n / 8 bytes by `pq_family_sizes.py` (KpqC section) |
| 99 | SMAUG-T: MLWE keys (sparse secret) + MLWR ciphertexts; n = 256, k = 2/3/4; SMAUG-T256 q = 2048, pk 1440, ct 1376 bytes, core-SVP C/Q 250.1/221.0, beyond core-SVP 269, DFP 2^-194.2; MLWR "studied shorter" stated as a limitation | VERIFIED + COMPUTED | SMAUG-T final spec (2026-02-04), Table 1 (PDF p. 5), Table 3 (PDF p. 26), Sec. 1.2 (PDF p. 5); pk/ct re-derived by bit packing in `pq_family_sizes.py` (KpqC section) |
| 100 | draft-longa-cfrg-frodokem-03 (22 June 2026, expires 24 December 2026) specifies twelve parameter sets (640/976/1344 x AES/SHAKE x standard/ephemeral); "Ephemeral FrodoKEM MUST NOT be used" when a public key may produce 2^8 ciphertexts or more; standard FrodoKEM doubles seedSE and adds a salt; the draft text does not mention ISO | VERIFIED | https://www.ietf.org/archive/id/draft-longa-cfrg-frodokem-03.txt (scratch families/), Sec. 8 (p. 16) and Sec. 9; grep for ISO/18033 found none |
| 101 | Dong and Guo: compiler-introduced secret-dependent control flow in the official AVX2 HQC Reed-Muller decoder; hqc-1 key recovery with less than 10 s of online Flush+Reload trace collection; CRYPTO 2026 (minor revision per ePrint) | VERIFIED | ePrint 2026/693 abstract (research/papers/2026-dong-guo-breaking-optimized-hqc-cache-timing.pdf, p. 1); venue via eprint_meta.py |
| 102 | Hesse et al.: power side-channel on HQC fixed-weight vector sampling, 100% success with 900,000 distinguisher calls; single-trace attack on a masked implementation; masking plus hiding needed (preprint) | VERIFIED | ePrint 2026/1462 abstract (research/papers/2026-hesse-et-al-hqc-fixed-weight-sampling-side-channels.pdf, p. 1) |
| 103 | Round5 draft (25 January 2019) R5N1_{1,3,5}KEM_0c: d = 594/881/1186; q = 2^13/2^13/2^15, p = 2^10/2^10/2^12; pk 5,214/8,834/14,264, ct 5,236/8,866/14,288 bytes; failure rates 2^-66/2^-65/2^-77 | VERIFIED (draft) | research/papers/2019-baan-et-al-round5-kem-pke-based-on-glwr.pdf, Table 4, PDF p. 43; exponents from pymupdf span sizes (superscript 7.0 pt) |
| 104 | Overstretched NTRU fatigue point q about 0.004 n^2.484 (for n > 100) and its distance from NTRU KEM parameters | VERIFIED in sibling note | `lattice-foundations.md` item 2 (its ledger [L71], [C14]); not re-read here |
| 105 | CiC 2025: salted FrodoKEM timings "roughly match the cost of eFrodoKEM in an ephemeral setting (the overhead is about 1% or less)" | VERIFIED | CiC 2025, Sec. 8, PDF p. 28 |
| 106 | NIST PQC news page (updated August 5, 2026) has no Classic McEliece item after IR 8545 | VERIFIED (absence on the fetched page) | scratch families/pqc-news-0927b.html, fetched 2026-09-27 |
| 107 | Official FrodoKEM KeyGen: one SHAKE call yields the randomness for S and E before sampling; A is generated on the fly inside B = AS + E; no recompute-and-compare of B; file last changed 2023-08-26 ("Add salted variant of FrodoKEM") | VERIFIED (code read) | https://github.com/microsoft/PQCrypto-LWEKE FrodoKEM/src/kem.c, crypto_kem_keypair (scratch families/frodo-kem.c, fetched 2026-09-27); commit date via GitHub API |
| 108 | FrodoKEM team: draft-longa-cfrg-frodokem-03 "is fully aligned with the ISO standard [ISO18033-2-AMD2], with the sole exception that the FrodoKEM-640 parameter set is *not* included"; ISO omits the optional seed-based private-key format; default = standard (salted) FrodoKEM-976 or -1344; hybrid with a security-analysed combiner; Botan has a C++ implementation | VERIFIED (designers' statement; ISO text unread) | draft-longa-cfrg-frodokem-security-considerations-00 (2026-06-23), Sec. 4.1, 5.1, 5.4, 5.6 (scratch families/, datatracker API record) |
| 109 | Beyond-core-SVP estimates 149.8 / 212.6 / 266.8 bits quoted in the security-considerations draft equal the minima of the C-LSF-Sieve rows of CiC Table 7 | VERIFIED + COMPUTED | draft Sec. 5.2; CiC 2025 Table 7 (PDF p. 26); `python research/scripts/pq/fam_compare.py` part 6 |
| 110 | CiC 2025: SFO transform gives FrodoKEM tight multi-target security from multi-target IND-CPA of FrodoPKE; the 2021 multi-ciphertext attack on round-3 FrodoKEM-640 (identified by NIST, also Bernstein 2022) exploited the 128-bit message; the team found a similar one on the 128-bit seedSE; eFrodoKEM is identical to round-3 FrodoKEM | VERIFIED | CiC 2025 abstract (PDF p. 1) and Sec. 1 (PDF p. 5) |
| 111 | ENISA EUCC cryptography page (fetched 2026-09-27): ACM version 2 (6 May 2025) is the applicable version; version 3 draft published for public review 2 June 2026 (until end of July 2026); local v3 draft PDF is byte-identical to 20260507-acm-draft.pdf | VERIFIED | certification.enisa.europa.eu/publications/eucc-guidelines-cryptography_en and news item of 2026-06-02; MD5 52fdd171...eeca for both files |
| 112 | Dutch PQC migration handbook (AIVD, CWI, TNO, 2024): FrodoKEM and Classic McEliece "acceptable" until standardised; authors "strongly support" their standardisation | VERIFIED as reported by CiC 2025 (secondary); handbook not read | CiC 2025 footnote 1, PDF p. 2 |
| 113 | May and Sa Diogo (preprint): 1-out-of-M session-key recovery via DOOM; level-1 sets fall below 143 bits for M >= 2^34 (HQC-1), 2^11 (BIKE-1), 2^21 (mceliece348864); HQC-3 at 2^64, HQC-5 at 2^38; mceliece8192128 at 2^59 (MMT); degradation slope slightly below 1/2; "public keys ... should be updated regularly"; pure-time single-instance MMT estimates for mceliece460896/6688128/6960119 (192.43/264.33/264.30) already below target | VERIFIED | ePrint 2026/517 (research/papers/2026-may-sa-diogo-multi-instance-security-code-based-kems.pdf): abstract p. 1 (exponents from span sizes, 6 pt superscripts), Sec. 3, Sec. 5 Table 7 (PDF p. 18); revision date via eprint_meta.py |
| 114 | Yu et al. (preprint): progressive sieving-ISD improves on previous sieving-ISD by 5-12 bits and on the state of the art for HQC by 7-9 bits, putting HQC-1/3/5 5.1/2.1/5.7 bits below 143/207/272 | VERIFIED | ePrint 2026/633 abstract (research/papers/2026-yu-et-al-progressive-sieving-style-isd.pdf, p. 1) |

## Open questions

1. The ISO/IEC 18033-2:2006/Amd 2:2026 text was not read (iso.org returns HTTP 403 to automated
   access, re-tried 2026-09-27). Its contents rest on the designers' statements: for FrodoKEM,
   "fully aligned" with draft-longa-cfrg-frodokem-03 except that FrodoKEM-640 is not included
   (ledger 108); for Classic McEliece, the four set families listed on classic.mceliece.org
   (ledger 24). Settle: obtain the amendment (paid ISO document) or its OBP preview.
2. FIPS 207 (HQC): no draft on 2026-09-27. Its final parameters, key format and whether it adds the
   1-byte confirmation code are open. Settle: watch csrc.nist.gov (sibling `nist-pqc-standards`).
3. (Answered in the continuation run.) SUPERCOP's builds are older versions: FrodoKEM round 2
   (unsalted), HQC round 4 (64-byte shared secret) and HQC "2020.04", BIKE "2020.05"
   (`fam_ebacs_versions.py`, ledger 95). Still open: cycle counts for the salted FrodoKEM and the
   2025-08-22 HQC on the same machine. Settle: build the teams' current reference code (or wait for
   SUPERCOP to add them) and benchmark under WSL (sibling `testing-ci-cd`).
4. FrodoKEM's level under the newest cost models: CiC 2025 Table 6 gives quantum core-SVP values
   of 123-129 for Frodo-640 and 227.6 (dual-sieve-FFT) for Frodo-1344. How these compare with the
   NIST category definitions is for the sibling `attack-cost-estimation`.
5. Classic McEliece structural attacks: the Briaud et al. conjectures (subexponential key
   recovery, ASIACRYPT 2026) and the team's rebuttal are both from 2026. Settle: follow ePrint
   2026/1232 revisions and any independent verification of the conjectures.
6. ANSSI: no ANSSI position newer than December 2023 that names FrodoKEM or Classic McEliece was
   found. The newest ANSSI document read, the SSHv2 transition note ANSSI-FT-116 (2 February
   2026), names neither. Settle: check cyber.gouv.fr for a revised position paper.
7. (Answered.) The Rowhammer paper's countermeasures are summarised in Section 2.6. The official
   reference KeyGen (microsoft/PQCrypto-LWEKE, FrodoKEM/src/kem.c, last changed 2023-08-26 "Add
   salted variant of FrodoKEM") draws all randomness for S and E in one SHAKE call before
   sampling, but then generates A on the fly while computing B = AS + E, and has no
   recompute-and-compare step (ledger 107). A Turing implementation would have to add that guard
   itself if fault attacks are in its threat model.
8. (Answered.) Claim 82 is now VERIFIED from the round-3 specification (Section 2.4).
9. The Moody "Road Ahead" deck carries a 2023 title date but a 2026 plan; its true date is
   unknown. Nothing in the design depends on it.
10. Round5's non-ring parameter sets were extracted from the January 2019 draft only (Section 4,
    ledger 103); the final round-2 specification's R5N1 sets (and its CCA sets) were not read.
    Nothing in the design depends on them.
11. For a three-way hybrid, is FrodoKEM-976 (level 3, 192-bit shared secret) or FrodoKEM-1344
    (level 5, 256-bit shared secret, 5.9 KB more per recipient) the right partner for Turing's
    256-bit symmetric key? This is a design decision for the owner; the evidence is in "What this
    means for Turing", items 2 and 3.
12. Multi-instance security of the lattice KEMs: the 2026 DOOM result for code-based KEMs (Section
    5.4) raises the question whether an attacker who sees M ciphertexts under one FrodoKEM or
    ML-KEM key gains a comparable speed-up in recovering one of their session keys. The CiC 2025
    paper reduces FrodoKEM's multi-target security tightly to the multi-target IND-CPA security
    of FrodoPKE, which moves the question to that assumption. Settle: sibling
    `cca-transforms-and-binding` (multi-target bounds) and `attack-cost-estimation`.
