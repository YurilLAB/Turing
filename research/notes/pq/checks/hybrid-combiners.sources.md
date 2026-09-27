# Fact-check audit trail: hybrid-combiners.md

Independent fact-check of D:/Dev/Turing/research/notes/pq/hybrid-combiners.md.
Checked against primary sources on 2026-09-27. This file is the working audit
trail: one row per claim checked, appended as I go, not a final report.

Status codes: OK (matches primary source) | WRONG (contradicts primary source,
with correction) | UNVERIFIABLE (could not confirm, with reason).

## Progress log

- Read full notes file (1319 lines) end to end.
- Loaded WebSearch/WebFetch via ToolSearch.
- Confirmed local research/papers/ already holds every PDF this note cites
  (GHP18, Bindel19, X-Wing, ABK25, Starfighters, KSW25, StarHunters,
  StarFortress, Millerjord-Stebila-Steckel, Kang-Lee-Son, Rosenpass
  whitepaper, FIPS 203, FrodoKEM proposal, Classic McEliece 2022 spec,
  SP 800-227, SP 800-56C Rev.2, Signal specs, Schmieg 2024, Mattsson 2025,
  ETSI TS 103 744, Fiedler-Gunther); none needed downloading.
- Wrote and ran research/scripts/pq/check_hybrid-combiners_sources.py
  (independent recomputation of the note's COMPUTED numeric claims:
  ABK25 Thm 9 crossover queries, McEliece ciphertext formula, sum-of-costs
  bits, X-Wing/X-Wing-Hash-CT input sizes, nested-hybrid KDF-input sizes).
  Result: ALL CHECKS PASSED (exit 0), matching the note's own figures to
  within its stated rounding/counter-byte margins.
- Verified via IETF datatracker API: draft-connolly-cfrg-xwing-kem (rev 11,
  ISE stream, "Submission Received"; no draft-irtf-cfrg-xwing-kem exists,
  404), draft-irtf-cfrg-hybrid-kems-12 (IRTF, "Waiting for Document
  Shepherd", header date 6 July 2026), draft-irtf-cfrg-concrete-hybrid-kems-04
  (same IRTF state), draft-ietf-tls-mlkem-11 (RFC-Editor queue, "Blocked"),
  draft-ietf-lamps-pq-composite-kem-21 (IESG Evaluation).
- Verified via rfc-editor.org: RFC 9954, 10024, 9941, 10042, 9980 headers
  (dates, status, authors, codepoints) and their errata (9954 #9136;
  10042 #9160 + #9159; 9980 #9023; 9941 none).
- Verified via Crossref API: ABK25 (ACNS 2026, LNCS pp.32-74, online
  2026-07-22), KSW25 (SCN 2026, LNCS pp.455-473, online 2026-09-27),
  StarFortress (IACR CiC 3(1), 2026-05-04); ePrint page for ABK25 (2025/1444)
  still shows "Preprint".
- Verified via primary PDFs (pdfgrep, exact-text matches): GHP18 Theorem 1 +
  Lemma 6 statements and bounds; X-Wing Theorems 1-3 exact statements;
  ABK25 Theorem 8/9 exact statements and the "Proof sketch" / TCC-2025
  wording; Rosenpass whitepaper sizes and quotes; FIPS 203 Table 3; Classic
  McEliece 2022 spec ciphertext formula and mceliece460896 parameters;
  FrodoKEM proposal Table A.5; SP 800-227 eq.(14)/(15) and "does not
  preserve IND-CCA ... regardless of the properties of the KDF" quote;
  Kang-Lee-Son Theorem 1 / Lemma 2 / Corollary 1; Starfighters CT-PK/CT-K
  prose (Open Question 4's table/text tension is real and already flagged
  by the note itself, not newly found).
- Verified via web: age GitHub releases (v1.3.0 2025-12-27, v1.3.2
  2026-08-29) and C2SP age.md (MLKEM768-X25519 HPKE construction, 1120-byte
  enc, 128-bit file key); OpenSSH release notes (9.9/10.0/10.3/10.4/10.5,
  including the "available by default" and "used by default" wording, and
  independently reconfirmed 10.3 vs 10.4 attribution after a first summary
  mis-sectioned it); docs/03-design-spec.md in this repo (X-Wing version 10
  / March 2026 and the "also binds the ciphertexts and public keys" line);
  SP 800-56C CSRC page + the 6 Jan 2026 revision-announcement bullets;
  RFC 9180 Sec. 1 / 9.1.2 HPKE security-claim wording.
- Two apparent discrepancies surfaced by WebFetch's summarizing model did
  NOT hold up on a second, more targeted fetch of the primary source (both
  were WebFetch errors, not notes errors): (a) a first fetch said RFC 10024
  was "August 2024" — the RFC's own header, re-fetched verbatim, says
  "August 2026"; (b) a first fetch attributed the ML-DSA-44+Ed25519
  composite-signature bullet to OpenSSH 10.3 — a second, targeted fetch
  confirmed it is under 10.4 as the notes say, and the sntrup761-keying
  speed-up is under 10.3 as the notes say. Neither is a notes error; logged
  here so the pattern (WebFetch's fast model can mis-attribute or invent
  dates) is on record for later checks.
- Checked for omissions: draft-ounsworth-cfrg-kem-combiners (an earlier
  individual CFRG draft, predecessor of the ideas in hybrid-kems) is
  Expired since 2024 with no formal "replaced-by" pointer; its content
  living on informally in the now-adopted draft-irtf-cfrg-hybrid-kems is
  not something the notes needed to name, so this is not an omission.
  A web search for "three-KEM file encryption format" and for "2026 KEM
  combiner attack" turned up nothing that overturns the note's claims
  (its own Sec. 5 / row 83 already hedges the "no 3-KEM file format found"
  claim as a negative result of a survey, correctly).

## Overall verdict

Exceptionally well-verified note. Of roughly 65 distinct claims/ledger rows
spot-checked against primary sources (IETF datatracker, rfc-editor.org,
Crossref, the actual PDFs in research/papers/, CSRC, GitHub releases,
openssh.org, and this repo's own docs/03), none were found to be wrong.
Every VERIFIED ledger row checked reproduced the primary source's exact
wording/numbers; every COMPUTED row checked reproduced independently in
research/scripts/pq/check_hybrid-combiners_sources.py; every UNVERIFIED
row checked was in fact not settled by the sources available (correctly
labelled, not an overclaim). No newer attack, withdrawal or superseding
draft was found that the note misses. No findings are reported as errors.

## Claim check table

| # | claim (paraphrase) | status | evidence |
|---|---|---|---|
| L1-3 | X-Wing draft-11: Active/ISE/"Submission Received"; expires 2027-03-27; no draft-irtf-cfrg-xwing-kem exists | OK | datatracker API document + state 1/150/68 records; 404 on the irtf name (fetched live) |
| L16,23,25 | hybrid-kems-12 & concrete-hybrid-kems-04: IRTF stream, "Waiting for Document Shepherd", header date 6 July 2026 | OK | datatracker API state 59; draft text header (fetched live) |
| L60 | draft-ietf-tls-mlkem-11 in RFC-Editor queue, "Blocked" | OK | datatracker API state 217 |
| L74 | LAMPS composite-kem-21 in IESG Evaluation | OK | datatracker API state 12 |
| L57,58,59 | RFC 9954 (July 2026, Informational) and RFC 10024 (Aug 2026, Standards Track) headers, codepoints 4588/4587/4589, Sec.6 transcript/RNG warnings | OK | rfc-editor.org rfc9954 / rfc10024.txt header re-fetch (first pass wrongly said "Aug 2024" for 10024; corrected on literal re-fetch of the header block) |
| L62,63,64 | RFC 9941/10042/9980 headers, combiner formulas, algorithm IDs | OK | rfc-editor.org headers |
| L114 | Errata: 9954 #9136 Verified/Editorial; 10042 #9160 Verified/Editorial + #9159 Reported/Technical; 9980 #9023 Reported/Technical; 9941 none | OK | errata.rfc-editor.org pages for each RFC |
| L47 | ABK25: ePrint 2025/1444, received 2025-08-08; ACNS 2026 LNCS pp.32-74, DOI 10.1007/978-3-032-32560-0_2, online 2026-07-22; ePrint still "Preprint" | OK | Crossref API for the DOI; eprint.iacr.org/2025/1444 page fetch |
| L106 | KSW25: SCN 2026 LNCS pp.455-473, DOI 10.1007/978-3-032-36264-3_23, online 2026-09-27 | OK | Crossref API for the DOI |
| L24 | StarFortress: IACR CiC 3(1), 2026-05-04, DOI 10.62056/ahmp-49p1 | OK | Crossref API for the DOI |
| L94 | MSS26: IACR CiC 2(4), DOI 10.62056/ah890lmol | OK | doi.org redirect resolves to cic.iacr.org/p/2/4/17 |
| L40,42 | GHP18 Theorem 1 bound (2·(Adv_KEMi+Adv_skPRF), C makes ≤qd+1 queries) and Lemma 6 bound (Adv≤qH·ε) | OK | exact text match, 2018-giacon-heuer-poettering-kem-combiners.pdf |
| L11,12,13 | X-Wing Theorems 1, 2, 3 exact bounds | OK | exact text match, 2024-barbosa-et-al-x-wing-hybrid-kem.pdf |
| L48,49,102 | ABK25 Theorem 8 (n-KEM, "Proof sketch") and Theorem 9 (4·sqrt((q²+q)/\|Ki\|)); "submitted to TCC 2025, except for Sections 3.3 and 4" | OK | exact text match, 2025-alagic-bajaj-kocoglu...pdf |
| L15 | X-Wing hashes 134 bytes; X-Wing-Hash-CT variant 1222 bytes | OK | exact text match (paper's own benchmarking section, Sec.8); independently recomputed 134+1088(ct_M)=1222 in check script |
| L51 | ABK25 Thm 9 bound reaches 1 at q=2^126/2^94/2^62 for 256/192/128-bit keys | OK | recomputed independently (mpmath-equivalent quadratic solve), check_hybrid-combiners_sources.py part 1 |
| L71 | Rosenpass sizes (McEliece ct188/sk13568/pk524160; Kyber-512 ct768/pk800/sk1632); round-3 versions; whitepaper 89a8805 (2026-09-24) | OK | exact text match, rosenpass-whitepaper.pdf |
| L75 | FIPS 203 Table 3 sizes (512:800/1632/768/32; 768:1184/2400/1088/32; 1024:1568/3168/1568/32) | OK | exact text match, nist-fips-203-ml-kem.pdf |
| L76 | FrodoKEM Table A.5 sizes (976: pk15632/ct15792/ss24; 1344: pk21520/ct21696/ss32) | OK | exact text match, FrodoKEM proposal PDF |
| L112 | McEliece 2022 spec ciphertext = ceil(mt/8); m=13,t=96 -> 156 bytes | OK | exact text/formula match + independently recomputed = 156 |
| L29,30,32 | SP 800-227 eq.(14) "for any t>1 if at least one shared secret..."; eq.(15) KeyCombine example; "does not preserve IND-CCA security, regardless of the properties of the KDF" | OK | exact text match, nist-sp800-227-kem-recommendations.pdf |
| L28 | SP 800-227: "extended in the obvious way to composite constructions that use more than two component KEMs" | OK | exact text match (search needed "obvious"/"extended" separately due to PDF hyphen-break) |
| L34 | SP 800-56C Rev.2 still current; 6 Jan 2026 revision-announcement bullets (KEM secrets in Z, hybrid-secret flexibility, KMAC in two-step) | OK | csrc.nist.gov SP800-56Cr2 page + linked news item, fetched live |
| L118 | RFC 9180 Sec.1/9.1.2 IND-CCA2 claim, GDH+HKDF-as-RO assumptions, [ABHKLR20] Auth-mode bounds | OK | rfc-editor.org rfc9180.html, fetched live |
| L65,66 | age v1.3.0 (2025-12-27) / v1.3.2 (2026-08-29); MLKEM768-X25519 HPKE recipient, 1120-byte enc, 128-bit file key | OK | GitHub releases API; raw C2SP age.md |
| L61 | OpenSSH 9.9 mlkem768x25519-sha256 "available by default"; 10.0 "used by default"; 10.3 sntrup761 speed-up; 10.4 ML-DSA-44+Ed25519 composite sig (experimental); 10.5 latest (2026-08-11) | OK | openssh.org/releasenotes.html, re-fetched with a targeted query after a first summary mis-sectioned 10.3 vs 10.4 |
| L89 | docs/03-design-spec.md names X-Wing draft version 10 (March 2026) and says the combiner "also binds the ciphertexts and public keys" | OK | read docs/03-design-spec.md lines 13-15, 90-92 directly in this repo |
| L98,100 | Kang-Lee-Son Theorem 1 (X25519 second preimage via inversion) and Lemma 2/Corollary 1 (multi-target N-factor, salting fix) | OK | exact text match, 2026-kang-lee-son...pdf |
| Open Q4 | Starfighters: prose says QSF fails HON/LEAK-BIND-CT-PK and MAL-BIND-CT-K/CT-PK; note flags a table/text tension as open, not resolved | OK (as an open question) | exact prose match, 2025-connolly-et-al-starfighters...pdf; genuine ambiguity, correctly left open by the note rather than asserted either way |
| — | draft-ounsworth-cfrg-kem-combiners (predecessor individual draft) | checked, not an omission | datatracker: Expired since 2024-08, no formal replaced-by; its ideas live on in the now-adopted hybrid-kems draft the note already covers |
| — | Search for a newer (post-2026-09-27) KEM-combiner break or a 3-KEM file-encryption standard | none found | WebSearch turned up nothing that contradicts or supersedes the note's Sec.5 / row 83 hedge |
