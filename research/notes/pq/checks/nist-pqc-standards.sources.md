# Fact-check audit: nist-pqc-standards.md

Independent fact-check of `research/notes/pq/nist-pqc-standards.md`. Lens: numbers, status,
primary sources. Started 2026-09-27. This file is the audit trail, updated
as the check went.

## Method
For every VERIFIED/COMPUTED claim in the notes' claim ledger (and the prose), open the primary
source myself (PDF page/section/table) rather than trusting the citation, re-run COMPUTED claims
with an independent script (`research/scripts/pq/check_nist-pqc-standards_sources.py`, new file,
not editing the author's `nist_pqc_check.py`), and check that cited URLs resolve.

## Row-by-row check record

| # | claim checked | OK/WRONG/UNVERIFIABLE | evidence |
|---|---|---|---|
| L1-14 | FIPS 203 numeric claims: Table 2 (n,q,k,eta1,eta2,du,dv,RBG strength), Table 3 (sizes), Table 1 (failure rates 2^-138.8/-164.8/-174.8), category claims quote, "NIST recommends ML-KEM-768 as default", "strongest possible parameter set" quote | OK | Read PDF directly via pdfgrep.py on nist-fips-203-ml-kem.pdf: Table 2/3 text extracted verbatim matches notes exactly; Table 1 rates match exactly; category-claim sentence and default-parameter-set sentence quoted verbatim, match notes word-for-word |
| script | `nist_pqc_check.py` (author's script) run fresh, no negative control | OK | `timeout 120 python research/scripts/pq/nist_pqc_check.py` -> ALL CHECKS PASSED (sizes, categories, decap rates via Table1/2/3 parse, SampleNTT 2^-261.24, zeta tables, FIPS204/205 sizes all match) |
| script | `nist_pqc_check.py --negative-control` | OK | 4 planted errors (ML-KEM-768 sizes, SLH-DSA-128s, SampleNTT, zeta table) all caught -> NEGATIVE CONTROL OK |
| 2,3,4 | FIPS 203 CSRC page: doc history (draft 08/24/23, final 08/13/24, no revision), planning note 11/17/2025 exact text, errata spreadsheet link | OK | WebFetch csrc.nist.gov/pubs/fips/203/final: doc history table matches exactly; planning note text "We've identified an issue that will be corrected in a future update/revision of this publication..." matches notes' paraphrase; errata xlsx link present |
| 32 | No FIPS 206/207 draft as of 2026-09-27; CSRC Selected Algorithms shows FALCON/HQC "FIPS coming soon"; /pubs/fips/206/ipd and /207/ipd return 404 | OK | WebFetch csrc.nist.gov/.../selected-algorithms confirms FALCON (2022) "FIPS coming soon", HQC (2025) "FIPS coming soon" vs FIPS 203/204/205 final; WebFetch of both /206/ipd and /207/ipd returned HTTP 404 directly |
| 32 (news) | PQC News and Updates newest items: IR 8610 (2026-05-14), SP800-133r3 ipd (2026-04-17), SP800-230 ipd (2026-04-13), SP800-227 final (2025-09-18), HQC selection (2025-03-11); no FIPS206/207 | OK | WebFetch csrc.nist.gov/Projects/post-quantum-cryptography/news lists exactly these items with matching dates, nothing newer re FIPS 206/207 |
| 32 (timeline) | Workshops and Timeline page "Updated August 05, 2026", no FIPS 206/207 entry | OK | WebFetch of that page confirms "Updated August 05, 2026" and no FIPS206/207 row |
| 40 | SP 800-227 final Sept 2025, draft 2025-01-07, comments to 2025-03-07, CSRC news 2025-09-18 | OK | WebFetch csrc.nist.gov/pubs/sp/800/227/final gives draft 2025-01-07 -> final 2025-09-18; WebFetch of News page confirms draft comment window "through March 7, 2025" i.e. 2025-03-07 exactly as notes state |
| 47 | IR 8547 still ipd, Date Published Nov 12 2024, comments closed 2025-01-10, planning note 01/21/2025, no final link | OK | WebFetch csrc.nist.gov/pubs/ir/8547/ipd: Date Published Nov 12 2024, comment period closed Jan 10 2025, planning note 01/21/2025 "public comments received are now available", no final version link present |
| 36 | IR 8545 BIKE-vs-HQC quote: "NIST does not consider the DFR analysis for BIKE to be as mature as that for HQC. Additionally, HQC is not believed to require additional modifications..." + Classic McEliece "currently under consideration for standardization by the International Organization for Standardization (ISO)" | OK | Extracted nist-ir-8545-pqc-round4-report.pdf with pypdf; exact quotes found verbatim (lines ~715-728 of dump) |
| 36 (2.2.1) | "NIST values having a variety of computational hardness assumptions and aims to reduce the risk that a single cryptanalytic breakthrough will leave..." | OK | verbatim in dump (Sec 2.2.1 area, line ~407-414) |
| 37 | "NIST will create a draft standard based on HQC...publish a final version in approximately two years" | OK | verbatim in dump, Section 4 |
| 61 | CNSA 2.0 FAQ table: AES 256-bit all levels; ML-KEM-1024 FIPS 203 all levels; ML-DSA-87 FIPS 204 all levels (any use incl. firmware/software signing); SHA-384/512 | OK | Extracted nsa-cnsa-2.0-faq.pdf with pypdf; table text matches notes verbatim |
| 62 | CNSSP 15 dates: new acquisitions CNSA2.0-compliant by 2027-01-01; phase-out by 2030-12-31; mandated by 2031-12-31 | OK | verbatim in FAQ dump: "by January 1, 2027, all new acquisitions for NSS will be required to be CNSA 2.0 compliant...By December 31, 2030, all equipment and services that cannot support CNSA 2.0 must be phased out...by December 31, 2031, CNSA 2.0 [algorithms are mandated]" |
| 64 | NSA "will not require" hybrid certified products | OK | verbatim: "NSA has confidence in CNSA 2.0 algorithms and will not require NSS developers to use hybrid certified products for security purposes" |
| 64 (extra) | "spending limited resources to add cryptographic complexity can at times weaken security" | OK | verbatim in FAQ dump line 705 |
| 66 | BSI TR-02102-1 version 2026-01, "As of: January 23, 2026"; changelog text | OK | Extracted bsi-tr-02102-1-cryptographic-mechanisms.pdf with pypdf; title page and changelog table match notes verbatim, including the exact 2026-01 change-log wording |
| 67 | BSI Table 2.5/2.6/2.7: FrodoKEM-976/1344; McEliece 460896/6688128/8192128 (+f); ML-KEM-768/1024 "categories 3 and 5"; HQC "intends to include...after publication" | OK | verbatim in BSI dump, Sections 2.4.1-2.4.4 |
| 67 (frodo reason) | "since FrodoKEM, unlike ML-KEM, is based on unstructured grids, it is considered the more conservative choice"; McEliece "considered conservative and very thoroughly analysed" | OK | verbatim in BSI dump |
| 68 | BSI: "should be used in 'hybrid' form"; reason = PQ mechanisms "not yet trusted to the same extent...side-channel resistance and implementation security" | OK | verbatim in BSI dump Section 2.2 |
| 69 | BSI dates: classical-only key agreement until end of 2031; very-high-protection transition by end of 2030; classical signatures until end of 2035; BSI "does not recommend QKD protocols at this time" | OK | verbatim in BSI dump Section 2.1 |

| 70 | ANSSI 2023 follow-up: "strongly emphasizes the necessity of hybridation"; "not mature enough to solely ensure the security"; avoid modifying params; prefer level-5/3; ephemeral keys; FrodoKEM "valid and conservative option...not prohibitive"; AES-256/SHA2-384 symmetric sizing; mix-and-match / IND-CPA reasoning for concat/XOR combiners | OK | Extracted 2023-anssi-pqc-transition-follow-up.pdf with pypdf; every quoted phrase found verbatim |
| 71 | ANSSI FAQ (online, fetched fresh): CatKDF/CasKDF recommended; hybridation "obligatoire" in regulated perimeter; SLH-DSA/XMSS/LMS exempted; PQC qualification obligations targeted from 2027; first 2 lattice-PQC visas (Thales, Samsung) "début octobre 2025" | OK | WebFetch of cyber.gouv.fr FAQ page returns all five quoted French sentences verbatim, matching notes' paraphrase exactly |
| 72,73 | NCSC timelines page (v1.0, 2025-03-20): 2028/2031/2035 milestones; NCSC next-steps page (v2.0, 2024-08-14): ML-KEM-768/ML-DSA-65 recommendation, hybrid "interim measure" | OK | WebFetch of both pages confirms exact publish/review dates, version numbers, and milestone/recommendation text |
| 74 | EU roadmap v1.1 (2025-06-11): milestones 31.12.2026/2030/2035; "quantum-vulnerable public-key mechanisms shall not be used stand-alone after the end of 2030" (high-risk), "analogously...2035" (medium-risk); "standardised and tested hybrid solutions, whenever feasible and suitable" | OK | Extracted 2025-nis-cg-eu-pqc-coordinated-roadmap.pdf with pypdf; all quoted text found verbatim, dates match |
| 75 | ECCG ACM v2.0 (April 2025): ML-KEM + FrodoKEM recommended ("R"); "highest possible standardised parameter size, either ML-KEM-1024 or ML-KEM-768" / "either FrodoKEM-1344 or FrodoKEM-976"; hybrid "shall ensure...broken simultaneously"; Classic McEliece absent from v2 | OK | Extracted 2025-eccg-agreed-cryptographic-mechanisms-v2.pdf with pypdf (53 pages); title page confirms "Version 2.0 April 2025"; quoted notes lines found verbatim; grep for "mceliece"/"Classic Mc" returns zero hits anywhere in the 53-page text, confirming its absence |
| 76,77,78 | ISO/IEC 18033-2:2006/Amd 2:2026: catalogue page returns 403 to fresh fetch (both WebFetch and curl); FrodoKEM site "June, 2026: FrodoKEM is standardized by ISO..."; Classic McEliece site lists all 16 mceliece parameter-set variants (460896/6688128/6960119/8192128 x plain/f/pc/pcf), "at least 128 bits of security in the 'quantum model'" with Grover sqrt speedup, "ISO decided to also standardize mceliece4*", page version "2026.06.15" | OK | curl -sIL confirms ISO page 403 (both today and matches notes' claim of a 403 on 2026-09-27); WebFetch of frodokem.org confirms exact quote; curl+strip-tags of classic.mceliece.org/iso.html confirms full parameter list (16 variants, matching notes' "6960119" addition the notes list explicitly) and all quoted phrases verbatim |
| 79 | ML-KEM's inclusion in Amd 2:2026 is UNVERIFIED (only secondary/search-engine sources say so; no primary ISO text seen) | OK (correctly flagged) | WebSearch for "ISO/IEC 18033-2 Amendment 2 2026 ML-KEM" returns only secondary sources (postquantum.com) claiming ML-KEM is included; the primary ISO catalogue page 403s and no ISO table of contents was retrievable; Classic McEliece's own site's "History" section shows only that ML-KEM's predecessor CRYSTALS-Kyber was solicited for comment in Oct 2022, not that it made the final Amd 2 text. The notes' UNVERIFIED tag is the correct call — no primary confirmation exists from any source reachable here. |
| URLs | Sample of 9 cited/DOI/scheme-site URLs resolve as the notes imply | OK | `curl -sIL --max-time 25` on doi.org/10.6028/NIST.{FIPS.203,SP.800-227,IR.8547.ipd,IR.8545} (all 302->200 to nvlpubs.nist.gov), iso.org/standard/86890.html (403, matches notes), frodokem.org (200), classic.mceliece.org/iso.html (200), ncsc.gov.uk pqc-migration-timelines (200), cyber.gouv.fr faq-pqc (200) |

**Interim note:** every claim checked so far in FIPS 203, CSRC status pages, IR 8545, CNSA 2.0 FAQ, and BSI TR-02102-1 matches the notes' quotes and numbers exactly. No discrepancy found yet. Continuing to ANSSI, NCSC, EU roadmap, ECCG, ISO 18033-2, IR 8413, MAXDEPTH/2016+2022 call PDFs, FIPS 204/205 detail, SP 800-227 requirement list numbering anomaly (notes already flags this itself).

| 53,54 | 2016 CFP MAXDEPTH range (2^40/2^64/2^96) and gate-count table (AES-128/192/256 quantum 2^170/2^233/2^298 "MAXDEPTH", classical 2^143/2^207/2^272, SHA3-256/384/512 classical 2^146/2^210/2^274); cites Grassl/Langenberg/Roetteler/Steinwandt, LNCS 9606 (PQCrypto 2016 proceedings) | OK | Extracted nist-pqc-call-for-proposals-2016.pdf; text (with flattened exponents "2170" etc. exactly as notes warn) matches verbatim including footnote citation and LNCS vol 9606 = PQCrypto 2016 |
| 54 | 2022 additional-signatures call: same gate-count table with 2^157/2^221/2^285 quantum, cites "Jaques, Samuel & Naehrig, Michael & Roetteler, Martin & Virdia, Fernando (2020)" | OK | Extracted nist-pqc-call-additional-signatures-2022.pdf; verbatim match including full author list and year 2020 |
| 52 | "comparatively easy-to-analyze reference primitive" + 5 category definitions listed verbatim + "all metrics that NIST deems to be potentially relevant to practical security" | OK | verbatim in 2016 CFP dump, Section 4.A.5 |
| 56 | IR 8413: "These results suggest that all three KYBER parameter sets fall slightly below the security targets for their claimed security levels when the cost of memory access for the attacker is not explicitly taken into account" (Section 4.1.1, dual-attack para) | OK — initially flagged as a possible misattribution (grep for the phrase only surfaced Saber/Dilithium instances because the PDF hyphenates "K Y-\nBER" across the line break, breaking a simple substring grep), but a full read of the Kyber subsection (4.1.1) confirms the identical sentence appears there too, verbatim, for Kyber specifically. Physical PDF page located via pypdf = 38; printed-page footer sequence (27→28→29, offset +9 from physical) confirms this text is on printed page 29 — so the notes' citation "PDF p. 38 [29]" is exactly correct on both counts. | pypdf page search + manual page-marker reconstruction in nist-ir-8413-pqc-round3-report.pdf.txt |
| 57 | IR 8413 App. B: "will generally underestimate the cost of attacks that require random access to a large memory" / "should therefore be considered safe barring new cryptanalysis" | OK | pypdf locates this at physical PDF page 90 with printed-page footer 81 -> matches notes' "PDF p. 90 [81]" exactly |
| 50 | IR 8547 Table 5 misprints "ML-DSA-768" / "ML-DSA-1024" (should be ML-KEM); "ML-KEM is the only approved post-quantum key-establishment scheme based on public key cryptography" | OK | verbatim in nist-ir-8547-pqc-transition.pdf dump: Table 5 literally prints "ML-DSA-768 192 bits 3" and "ML-DSA-1024 256 bits 5" under a "ML-KEM [FIPS203]" row header — the misprint is real and exactly as notes describe |
| 49 | "will be disallowed in 2030" (112-bit symmetric); ">=128 bits classical...believed to meet...at least Category 1" | OK | verbatim in IR 8547 dump, directly following Table 5 |
| 26 | Kyber r3 spec Table 4 (PDF p. 21, confirmed via pypdf): core-SVP dims 999/1419/1885, BKZ-beta 406/626/878, classical/quantum core-SVP hardness 118/183/256 and 107/166/232; refined estimate dims 1025/1467/1918, BKZ 413/637/894, sieving dim beta' 375/586/829, log2(gates) 151.5/215.1/287.3, log2(memory bits) 93.8/138.5/189.7 | OK | Extracted 2021-avanzi-et-al-kyber-round3-specification.pdf with pypdf; Table 4 text matches notes exactly; pypdf page search confirms physical PDF page 21 |
| 25 | Kyber r3 spec Table 1 (PDF p. 11): n=256, k=2/3/4, q=3329, eta1=3/2/2, eta2=2/2/2, (du,dv)=(10,4)/(10,4)/(11,5) — identical to FIPS 203 Table 2 | OK | verbatim match; pypdf confirms physical PDF page 11 |
| 58 | FrodoKEM-976: n=976, q=65536 (2^16), level 3 (192-bit); FrodoKEM-1344: n=1344, level 5 (256-bit); sigma 2.3/1.4 (matches author script's independently-derived sigma 2.30/1.40 in nist_pqc_check.py section 10) | OK | Extracted 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf with pypdf; Table A.1 (n,q,lensec) and Table A.3 (sigma) match exactly; pypdf confirms Table A.1 is on physical PDF page 15, matching notes' citation |

| 39 | HQC FIPS 207 changes under consideration (Robinson slides): salted FO SFO_m^perp using (ek_KEM, salt); removal of x from dk_PKE; addition of seed_KEM; SHA3-512 seed expansion; K/theta reduced 40->32 bytes; 1-byte confirmation code (Glabush et al., Crypto'25, eprint 2025/450) against skipped re-encryption; "fixes the IND-CCA2 issue that was raised on the pqc-forum" | OK | Extracted 2025-robinson-nist-fips-207-hqc-kem-slides.pdf with pypdf; every element matches verbatim, including the exact eprint number |
| 33,34 | FN-DSA (Perlner slides): "We expect to release an Initial Public Draft soon" / "It's basically written, awaiting approval"; KeyGen and Signing need floating point; verification uses no floating point; "Only allows randomized signing" / "Forbids export of seeds" | OK | Extracted 2025-perlner-nist-fips-206-fn-dsa-status-slides.pdf with pypdf; all quotes verbatim |
| 59,60 | IR 8610: nine 3rd-round candidates "FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, and UOV"; HAWK "does not need floating-point arithmetic"; CROSS/LESS/Mirath/PERK/RYDE among not-advanced 2nd-round candidates; "no longer under consideration for standardization by NIST" | OK | Extracted nist-ir-8610-pqc-additional-signatures-round2-report.pdf with pypdf; all verbatim, including confirming Mirath (merger of MIRA/MiRitH) explicitly named as not advancing |
| 41 | SP 800-227 Sec 1.3 RS1-RS11/RM1-RM5 as tabulated, incl. the internally-odd sentence "Requirements RS6, RS7, RS8, RS10, and RS11 pertain to key confirmation (Sec. 4.4), which is recommended but not required" even though RS6's own text is the ephemeral-key rule (Sec 4.2), not a key-confirmation rule | OK | Extracted nist-sp800-227-kem-recommendations.pdf with pypdf; the odd sentence is verbatim in the standard itself (not a notes transcription error) — the notes' own commentary "As printed this list looks off... Read the requirement texts, not the list" is an accurate, well-caught observation, not an error |
| 42,43,44 | SP 800-227 4.6.2/4.6.3: KDF(K1,K2) "does not preserve IND-CCA security, regardless of the properties of the KDF"; KeyCombineCCA_H = H(K1,K2,c1,c2,ek1,ek2,domain_sep) preserves IND-CCA "if H is modeled as a random oracle"; domain_sep "should be used to uniquely identify the composite scheme in use"; X-Wing named as PQ/T hybrid KEM (ML-KEM + X25519) example | OK | verbatim in SP 800-227 dump; also confirms open question #5 in the notes is well-founded: the standard itself notes "[25] does not incorporate encapsulation keys into the combiner" for X-Wing's own construction |
| 40 | SP 800-227 authors "Alagic, Barker, Chen, Moody, Robinson, Silberg, Waller" | OK | pypdf dump citation line: "Alagic G, Barker EB, Chen L, Moody D, Robinson A, Silberg H, Waller N (2025)" |
| 18 | FIPS 203: K-PKE "shall not be used as a stand-alone cryptographic scheme"; its 3 algorithms "are not approved for use as a public-key encryption scheme" | OK | pdfgrep.py on nist-fips-203-ml-kem.pdf finds both phrases verbatim, Section 3.3 |
| 29 | FIPS 204 errata (independently re-dumped, not trusting the notes' own script output): row dated 46234 [2026-07-31] (Excel serial matches 2026-07-31), Sec 4/App C, "new numbers are 4.36, 5.14, and 3.91 (instead of 4.25, 5.1, and 3.85)"; minimum loop-limit for internal signing "821 (instead of 814)"; spreadsheet C1 = "Last updated 7/31/2026" | OK | Ran `research/scripts/pq/nist_xlsx_dump.py` (shared helper) myself directly on the cached fips-204-potential-updates.xlsx in the scratch dir — independent of the author's cited script output — row 27 matches notes exactly, character for character |
| 28 | FIPS 204 Table 1: ML-DSA-44 category 2 (not 1); (k,l), eta, beta=tau*eta 78/196/120, omega 80/55/75, Repetitions (pre-errata) 4.25/5.1/3.85 | OK | pypdf dump of nist-fips-204-ml-dsa.pdf, Table 1 area, matches notes exactly; also cross-checked against the errata row (old values 4.25/5.1/3.85 match Table 1 exactly, confirming both the table and the errata are read correctly) |
| 31 | SP 800-230 ipd 2026-04-13; comments closed 2026-06-12; "six additional SLHsig parameter sets for security levels 1, 3, and 5"; "strict limit of 2^24 signatures per signing key"; "the signing of software, firmware, and digital certificates"; "not approved for general-purpose use" | OK | WebFetch of csrc.nist.gov/pubs/sp/800/230/ipd returns all quoted phrases verbatim, matching notes exactly |

### Omission found (minor, in-scope but not reported)
- **FIPS 204 Sec 3.6.1**: "If an approved RBG with at least 128 bits of security but less than 192 bits of security is used, then the claimed security strength of ML-DSA-44 is reduced from category 2 to category 1." The notes state flatly that ML-DSA-44 is category 2 (correct, matches Table 1) but do not mention this RBG-strength-conditioned downgrade. This is a genuine, verifiable detail from the primary source that is missing. Severity: **minor** — the topic's own assigned scope explicitly says FIPS 204/205 should be covered only "briefly (signing release artefacts or files may use them)", so a full accounting of every conditional footnote was not required; and it does not affect any of the notes' load-bearing claims about ML-KEM or the lattice-layer design.

## Issues found

1. **Minor / omission** — FIPS 204 Sec. 3.6.1: ML-DSA-44's claimed category can be reduced from
   2 to 1 if the implementation's RBG has security strength between 128 and 192 bits. The notes'
   Section 2.1 states ML-DSA-44 is category 2 without this conditional caveat. Verified against
   `nist-fips-204-ml-dsa.pdf` directly (quoted in the check table above). Low severity: the topic
   scope for FIPS 204/205 was explicitly "briefly", and this does not touch any load-bearing
   ML-KEM/lattice-layer claim.

No other issues were found. Every other VERIFIED and COMPUTED claim checked (see table above and
below) matched the primary source exactly, including exact quotes, table values, page numbers,
dates, and version numbers. One apparent discrepancy (the IR 8413 "fall slightly below" quote
appearing to be about Saber/Dilithium, not Kyber) was investigated fully and found to be a false
alarm caused by my own grep pattern missing a mid-word PDF line-hyphenation ("K Y-BER" split
across a line break) — the identical sentence does appear, verbatim, in the Kyber subsection, and
the notes' page citation (PDF p. 38, logical p. 29) is exactly correct once the page-marker
sequence is reconstructed correctly.

## Confirmed highlights
- FIPS 203 Tables 1, 2, 3 (parameters, sizes, decapsulation-failure rates) verified verbatim from
  the primary PDF and independently recomputed by the author's script (`nist_pqc_check.py`), which
  I re-ran fresh (all pass) and re-ran with `--negative-control` (all 4 planted errors caught).
- FIPS 203's exact "shall not be used as a stand-alone" / "not approved for use as a public-key
  encryption scheme" / implicit-rejection / category-claim / "NIST recommends ML-KEM-768" quotes
  all verified verbatim.
- CSRC status pages (FIPS 203 doc history + errata planning note, FIPS 206/207 both still 404 and
  "FIPS coming soon", IR 8547 still ipd, SP 800-227 final with correct draft/final dates and exact
  comment-close date 2025-03-07, News/Timeline pages) all verified live via WebFetch on 2026-09-27.
- NIST IR 8545's HQC-vs-BIKE selection reasoning and the "approximately two years" HQC-FIPS
  timeline quoted verbatim and confirmed.
- IR 8413's Kyber "fall slightly below the security targets" quote and its RAM-model-underestimate
  quote both confirmed verbatim with correct PDF page citations (physical + logical page verified
  independently via pypdf).
- CNSA 2.0 FAQ table (AES-256/ML-KEM-1024/ML-DSA-87/SHA-384-512), CNSSP 15 dates, and the "will not
  require hybrid" / complexity-risk quotes all confirmed verbatim.
- BSI TR-02102-1 version/date, FrodoKEM/McEliece/ML-KEM recommendations and reasoning, hybrid
  mandate and reasoning, and all cited dates (2030/2031/2035) confirmed verbatim.
- ANSSI 2023 follow-up and the live ANSSI FAQ page (fetched fresh) both confirm every quoted
  sentence, including the CatKDF/CasKDF combiner names and the October 2025 Thales/Samsung visas.
- NCSC's two guidance pages, the EU coordinated roadmap's exact milestone dates and hybrid
  language, and the ECCG v2.0 ML-KEM/FrodoKEM recommendations (with Classic McEliece's absence
  from v2 confirmed by a zero-hit grep across the full 53-page text) all verified verbatim.
- ISO/IEC 18033-2 Amd 2:2026: confirmed the catalogue page 403s to a fresh fetch (matching notes);
  confirmed FrodoKEM's and Classic McEliece's own team pages state inclusion, with the full
  16-variant McEliece parameter list and "quantum model"/Grover-sqrt-speedup quote verified
  verbatim; independently confirmed that ML-KEM's inclusion has **no primary source** anywhere
  reachable here (only a secondary/search-engine summary) — the notes' UNVERIFIED tag for this is
  the correct call, not an oversight.
- The 2016 Call for Proposals' and 2022 additional-signatures call's MAXDEPTH/gate-count tables
  (including the flattened-exponent extraction artifact the notes warn about) verified verbatim
  against both source PDFs directly, with correct citations (Grassl et al. PQCrypto 2016 LNCS 9606;
  Jaques, Naehrig, Roetteler, Virdia 2020).
- Kyber round-3 spec Tables 1 and 4 (parameters and the primal-attack dimension/BKZ/gate/memory
  figures) verified verbatim with correct PDF page citations confirmed via pypdf page search.
- FrodoKEM-976/1344 parameters (n, q, sigma, security level) verified verbatim against the
  FrodoKEM team's own 2025-09-29 standardization proposal, including the exact page (15) for
  Table A.1, and cross-checked against the author's own independently-derived sigma values.
- FIPS 204's errata correction (Repetitions 4.36/5.14/3.91, loop limit 821) independently re-dumped
  from the cached spreadsheet using the shared `nist_xlsx_dump.py` tool myself (not reusing the
  author's script output) — matches character for character.
- The FN-DSA and HQC PQC-conference slide decks (Perlner, Robinson) both verified verbatim,
  including the precise eprint number (2025/450) for the confirmation-code proposal.
- IR 8610's nine third-round candidates and the HAWK floating-point claim verified verbatim.
- SP 800-227's requirement-numbering anomaly (RS6 "pertains to key confirmation" despite being the
  ephemeral-key rule) is a genuine artifact of the standard's own text, not a notes error — the
  notes' handling of it ("read the requirement texts, not the list") is accurate and appropriately
  cautious.

## Status
COMPLETE — full pass across every section of the notes file and all 80 claim-ledger rows either
directly checked or covered by a checked table/quote in the same section. One minor omission
found (see Issues); no wrong numbers, dates, statuses, or misquotes found anywhere else.
