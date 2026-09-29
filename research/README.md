# Research archive

This folder holds everything Turing's design and its attacks were checked
against, kept for later work. Design decisions live in `docs/` (one document
per step); the sources behind them are here.

- `papers/`: the primary sources as PDFs. They are third-party copyrighted
  papers, so they stay local: the folder is gitignored, and most entries
  below link to where the paper can be downloaded again.
- `notes/verified-facts.md`: every number and claim taken from a paper, with
  the file and section it came from, and which ones Bombe reproduces.
- `notes/derivations.md`: the short proofs behind Bombe's predictions (exact
  boomerang and differential-linear rates, the symmetry argument, the
  provable-bound windows, and others).
- `notes/pq/` and `scripts/pq/`: the post-quantum research (lattices,
  attack costs, decryption failures, transforms, side channels), with the
  scripts that reproduce its numbers. The `scripts/pq/t1026_*.py` scripts
  compute Turing-1026's parameter search, per-key failure rates and
  lattice-estimator runs, including `t1026_real_sage.py` (the estimator under
  real SageMath) and `t1026_optimizer_audit.py` (its greedy MATZOV search and
  primal beta range, issues #219 and #149). `turing1026_py.py` is a third
  implementation of the KEM (Python, pycryptodome, NumPy) that reproduces the
  known-answer vectors from the docs/16 specification.
- `scripts/turing256_py.py`: a third implementation of Turing-256 v2
  (Python, standard library only, its own Keccak) that derives every
  constant from its label and reproduces `vectors/turing-256-v2.txt` (CI
  stage `turing256-py`).
- `scripts/`: research helpers:
  - `pdfgrep.py`: keyword windows in a PDF;
  - `decode_glyph_pdf.py`: old TeX Type-3 PDFs whose text extracts as
    `/C1/D1…`;
  - `boomerang_exact.py`, `boomerang_predict.py`: the 2-round boomerang rate,
    exact and naive.
- Tools whose results the docs cite are in `tools/`:
  - `asm_branches.py`: conditional jumps in the release assembly, with
    `--loads` indexed memory accesses (table lookups), and with `--divs`
    division instructions;
  - `mutate.py`: planted-bug checks, `--step8`, `--step9`, `--round3`,
    `--round4` and the default set;
  - `wsl_linux.py`: builds for Linux on Windows and runs the tests in WSL.

One rule applies throughout: a number from a search-engine summary is not a
source, and the primary PDF is.

## Papers

| File in `papers/` | Reference | Used for | Where |
|---|---|---|---|
| 2000-ferguson-et-al-improved-cryptanalysis-of-rijndael.pdf | Ferguson, Kelsey, Lucks, Schneier, Stay, Wagner, Whiting. FSE 2000. [schneier.com](https://www.schneier.com/wp-content/uploads/2016/02/paper-rijndael.pdf) | partial sums (2^50 S-box lookups per 2^32 structure), 7 rounds of AES-256 for 2^172 | docs/14 |
| 2003-park-sung-lee-lim-upper-bound-medp-melp-spn.pdf | Park, Sung, Lee, Lim. FSE 2003. [iacr.org/archive/fse2003](https://www.iacr.org/archive/fse2003/28870263/28870263.pdf) | Theorems 1-2: provable 2-round MEDP/MELP bounds | docs/12 |
| 2003-rosenthal-polynomial-description-of-rijndael.pdf | Rosenthal. J. Algebra Appl. 2003, [arXiv cs/0205002](https://arxiv.org/abs/cs/0205002) | AES S-box polynomial (9 terms) | docs/11 |
| 2004-kim-umeno-hasegawa-corrections-nist-test-suite.pdf | Kim, Umeno, Hasegawa. [ePrint 2004/018](https://eprint.iacr.org/2004/018) | NIST spectral test corrections | docs/10 |
| 2005-bernstein-cache-timing-aes.pdf | Bernstein. Cache-timing attacks on AES. 2005, [cr.yp.to](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf) | secret-indexed table lookups leak through the cache | docs/13 |
| 2005-keliher-sui-exact-2-round-aes-medp-melp.pdf | Keliher, Sui. [ePrint 2005/321](https://eprint.iacr.org/2005/321); IET Inf. Sec. 2007 | exact AES 2-round MEDP 53/2^34, lower-bound method | docs/12 |
| 2006-daemen-rijmen-two-round-aes-differentials.pdf | Daemen, Rijmen. SCN 2006, [ePrint 2006/039](https://eprint.iacr.org/2006/039) | background: 2-round AES differentials | docs/12 |
| 2008-halderman-et-al-cold-boot-attacks.pdf | Halderman et al. USENIX Security 2008 | keys in memory | docs/08, 11 |
| 2009-biryukov-khovratovich-related-key-aes-192-256.pdf | Biryukov, Khovratovich. ASIACRYPT 2009, [ePrint 2009/317](https://eprint.iacr.org/2009/317) | related-key attack model | docs/07, 08, 11 |
| 2009-dinur-shamir-cube-attacks.pdf | Dinur, Shamir. EUROCRYPT 2009, [ePrint 2008/385](https://eprint.iacr.org/2008/385) | cube attacks, 767-round Trivium | docs/11 |
| 2009-prouff-rivain-bevan-second-order-dpa.pdf | Prouff, Rivain, Bévan. IEEE Trans. Computers 58(6) 2009, [ePrint 2010/646](https://eprint.iacr.org/2010/646) | second-order CPA with the centred product (Hamming-weight model) | docs/13 |
| 2010-rivain-prouff-higher-order-masking-aes.pdf | Rivain, Prouff. CHES 2010, [ePrint 2010/441](https://eprint.iacr.org/2010/441) | masking x^254 (Algorithm 2 = Turing's inv8) | docs/11 |
| 2011-goodwill-et-al-tvla.pdf | Goodwill, Jun, Jaffe, Rohatgi. NIST NIAT 2011 | TVLA: Welch t, 4.5, two independent groups | docs/13 |
| 2011-mouha-wang-gu-preneel-milp-differential-linear.pdf | Mouha, Wang, Gu, Preneel. Inscrypt 2011, [mouha.be](https://mouha.be/wp-content/uploads/milp.pdf) | active S-box counting | docs/09 |
| 2013-coron-prouff-rivain-roche-mask-refreshing.pdf | Coron, Prouff, Rivain, Roche. FSE 2013, [ePrint 2015/359](https://eprint.iacr.org/2015/359) | the refreshing flaw at order ⌈d/2⌉ + 1 | masked.rs, docs/13 |
| 2013-li-wang-4-uniform-permutations-from-inverse-revisited.pdf | Li, Wang, Yu. [ePrint 2013/731](https://eprint.iacr.org/2013/731) | Theorem 1: when swapping two outputs of the inverse keeps it 4-uniform | docs/13 |
| 2014-andreeva-et-al-release-of-unverified-plaintext.pdf | Andreeva, Bogdanov, Luykx, Mennink, Mouha, Yasuda. ASIACRYPT 2014, [ePrint 2014/144](https://eprint.iacr.org/2014/144) | no plaintext before verification (step 9) | docs/13 |
| 2014-equivalent-condition-switching-4-uniform-from-inverse.pdf | An equivalent condition for the switching construction (background to Li-Wang-Yu) | background | — |
| 2014-new-construction-4-uniform-permutations-arxiv-1407-4884.pdf | [arXiv 1407.4884](https://arxiv.org/abs/1407.4884): a further 4-uniform construction from the inverse | background | — |
| 2013-derbez-fouque-exhausting-demirci-selcuk-mitm.pdf | Derbez, Fouque. FSE 2013. [di.ens.fr](https://www.di.ens.fr/~fouque/pub/fse13b.pdf) | Property 5 (25 parameters, 24 for differences), the 10-parameter table of Derbez-Fouque-Jean | docs/14 |
| 2015-banik-et-al-midori.pdf | Banik et al. ASIACRYPT 2015, [ePrint 2015/1142](https://eprint.iacr.org/2015/1142) | Midori-64 layer for the invariant-attack check | docs/11 |
| 2015-schneider-moradi-leakage-assessment-methodology.pdf | Schneider, Moradi. CHES 2015, [ePrint 2015/207](https://eprint.iacr.org/2015/207) | higher-order TVLA, centred product | docs/13 |
| 2015-todo-integral-cryptanalysis-full-misty1.pdf | Todo. CRYPTO 2015, [ePrint 2015/682](https://eprint.iacr.org/2015/682) | first attack on full MISTY1 | docs/11 |
| 2015-todo-structural-evaluation-generalized-integral-property.pdf | Todo. EUROCRYPT 2015, [ePrint 2015/090](https://eprint.iacr.org/2015/090) | the division property | docs/11 |
| 2016-biryukov-perrin-udovenko-reverse-engineering-kuznyechik-sbox.pdf | Biryukov, Perrin, Udovenko. EUROCRYPT 2016, [ePrint 2016/071](https://eprint.iacr.org/2016/071) | hidden S-box structure | docs/08 |
| 2016-grassi-rechberger-ronjom-subspace-trail-cryptanalysis.pdf | Grassi, Rechberger, Rønjom. ToSC 2016, [ePrint 2016/592](https://eprint.iacr.org/2016/592) | subspace trails | docs/08 |
| 2016-todo-leander-sasaki-nonlinear-invariant-attack.pdf | Todo, Leander, Sasaki. ASIACRYPT 2016, [ePrint 2016/732](https://eprint.iacr.org/2016/732) | nonlinear invariants | docs/11 |
| 2017-beierle-canteaut-leander-rotella-invariant-attacks-round-constants.pdf | Beierle, Canteaut, Leander, Rotella. CRYPTO 2017, [ePrint 2017/463](https://eprint.iacr.org/2017/463) | W_L(D) criterion, Midori invariant factors | docs/08, 11 |
| 2017-reparaz-balasch-verbauwhede-dudect.pdf | Reparaz, Balasch, Verbauwhede. DATE 2017, [ePrint 2016/1123](https://eprint.iacr.org/2016/1123) | timing test | docs/10 |
| 2017-wang-et-al-double-fetch.pdf | Wang, Krinke, Lu, Li, Dodier-Lazaro. USENIX Security 2017 | double fetch: verify and use one private copy (step 9) | docs/13 |
| 2017-ronjom-bardeh-helleseth-yoyo-tricks-with-aes.pdf | Rønjom, Bardeh, Helleseth. ASIACRYPT 2017, [ePrint 2017/980](https://eprint.iacr.org/2017/980) | the yoyo game: Theorem 2, Algorithms 2 and 3 | docs/08, 14 |
| 2018-cid-huang-peyrin-sasaki-song-boomerang-connectivity-table.pdf | Cid et al. EUROCRYPT 2018, [ePrint 2018/161](https://eprint.iacr.org/2018/161) | the BCT | docs/11 |
| 2018-zhang-et-al-persistent-fault-analysis.pdf | Zhang et al. TCHES 2018(3), [tches.iacr.org](https://tches.iacr.org/index.php/TCHES/article/view/7272) | persistent faults | docs/11 |
| 2019-ferguson-windows-10-rng-infrastructure.pdf | Ferguson. The Windows 10 random number generation infrastructure. Microsoft 2019, [download.microsoft.com](https://download.microsoft.com/download/1/c/9/1c9813b8-089c-4fef-b2ad-ad80e79403ba/Whitepaper%20-%20The%20Windows%2010%20random%20number%20generation%20infrastructure.pdf) | ProcessPrng's design; the copy measured outside it | random.rs, docs/13 |
| 2019-kocher-et-al-spectre.pdf | Kocher et al. IEEE S&P 2019 | speculative reads of secrets | docs/13 |
| 2020-kwong-et-al-rambleed.pdf | Kwong, Genkin, Gruss, Yarom. IEEE S&P 2020 | Rowhammer as a read channel | shield.rs, docs/13 |
| 2020-murdock-et-al-plundervolt.pdf | Murdock et al. IEEE S&P 2020 | software fault injection, AES-NI keys | docs/11 |
| 2021-lipp-et-al-platypus.pdf | Lipp et al. IEEE S&P 2021 | software power analysis (RAPL) | docs/11 |
| 2022-beullens-breaking-rainbow.pdf | Beullens. CRYPTO 2022, [ePrint 2022/214](https://eprint.iacr.org/2022/214) | post-quantum history | docs/02, 08 |
| 2022-castryck-decru-sidh-key-recovery.pdf | Castryck, Decru. [ePrint 2022/975](https://eprint.iacr.org/2022/975) | SIKE broken | docs/02, 08 |
| 2022-wang-et-al-hertzbleed.pdf | Wang, Paccagnella, He, Shacham, Fletcher, Kohlbrenner. USENIX Security 2022 | power turned into remote timing (DVFS) | docs/13 |
| 2024-barbosa-et-al-x-wing-hybrid-kem.pdf | Barbosa et al. IACR CiC 2024, [ePrint 2024/039](https://eprint.iacr.org/2024/039) | X-Wing hybrid KEM (step 9) | docs/02, 03 |
| 2025-schneider-et-al-breaking-bad-compilers-constant-time.pdf | Schneider et al. ASIA CCS 2025, [arXiv 2410.13489](https://arxiv.org/abs/2410.13489) | compilers breaking constant time | docs/11 |
| li-li-su-sun-misty-structure-with-spn-round-function.pdf | Li, Li, Su, Sun. MISTY structure with SPN round function | background for the key-schedule Feistel (not cited) | — |
| nist-cshake-kmac-example-values.pdf | NIST example values for SP 800-185 | cSHAKE256 test vectors, self-test | xof.rs, selftest.rs |
| nist-fips-197-upd1-aes.pdf | FIPS 197 (update 1), [nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) | AES reference: MixColumns vectors, key expansion | docs/06, 12 |
| nist-sp800-185-sha3-derived-functions.pdf | NIST SP 800-185 | cSHAKE256 for every derivation | docs/07, 08 |
| nist-sp800-22r1a-statistical-test-suite.pdf (and .txt) | NIST SP 800-22 rev. 1a | the statistical battery | docs/10 |
| openssh-8.1-release-notes.txt | OpenSSH 8.1 release notes, 2019-10-09, [openssh.com](https://www.openssh.com/txt/release-8.1) | key shielding with a 16 KB prekey | shield.rs, docs/13 |
| yap-khoo-poschmann-parallelizing-camellia-sms4-cites-kanda.pdf | Yap, Khoo, Poschmann. Parallelizing Camellia and SMS4 | Kanda's theorem as restated (rB + ⌊r/2⌋ per 4r rounds) | docs/07, 08 |

## Sources not archived (not freely available)

We checked these through their abstracts or through papers that restate
them. Get them from the publisher when you need them:

- Jakobsen, Knudsen. The Interpolation Attack on Block Ciphers. FSE 1997.
- Wagner. The Boomerang Attack. FSE 1999.
- Biryukov, Wagner. Slide Attacks. FSE 1999.
- Piret, Quisquater. DFA against SPN structures. CHES 2003.
- Brier, Clavier, Olivier. Correlation Power Analysis. CHES 2004.
- Eisenbarth et al. KeeLoq power analysis. CRYPTO 2008.
- Indesteege et al. A Practical Attack on KeeLoq. EUROCRYPT 2008.
- Oswald, Paar. Mifare DESFire MF3ICD40. CHES 2011.
- Leander et al. PRINTcipher and the invariant subspace attack. CRYPTO 2011.
- Ferguson, Schroeppel, Whiting. A Simple Algebraic Representation of
  Rijndael. SAC 2001.
- Murphy, Robshaw. Essential Algebraic Structure within the AES. CRYPTO 2002.
- Langford, Hellman. Differential-Linear Cryptanalysis. CRYPTO 1994.
- Biham, Dunkelman, Keller. Enhancing Differential-Linear Cryptanalysis.
  ASIACRYPT 2002.
- Biryukov, De Cannière, Braeken, Preneel. Linear and Affine Equivalence
  Algorithms. EUROCRYPT 2003.
- Kanda. Feistel ciphers with SPN round function. SAC 2000.
- Bogdanov, Khovratovich, Rechberger. Biclique Cryptanalysis of the Full AES.
  ASIACRYPT 2011.
- Wang, Peyrin. Boomerang Switch in Multiple Rounds. ToSC 2019(1), open access
  at [tosc.iacr.org](https://tosc.iacr.org/index.php/ToSC/article/view/7400).
- Barreto, Rijmen. The Anubis and Khazad block ciphers. NESSIE 2000. The
  matrix was checked in the Linux kernel's `crypto/anubis.c`.
- Daemen, Rijmen. The Design of Rijndael (book).
- Ishai, Sahai, Wagner. Private Circuits: Securing Hardware against Probing
  Attacks. CRYPTO 2003 (restated in Rivain-Prouff 2010, section 2).
- Linux man pages madvise(2), mlock(2) and proc_pid_smaps(5), quoted from
  [man7.org](https://man7.org/linux/man-pages/); libgcrypt's source, read on
  [github.com/gpg/libgcrypt](https://github.com/gpg/libgcrypt).
