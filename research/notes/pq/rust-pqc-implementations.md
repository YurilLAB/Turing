# Existing ML-KEM / FrodoKEM / X25519 implementations: oracles, bugs and proofs

Status: IN PROGRESS (second run, 2026-09-27; sections marked "pending" are still being researched).

This file surveys existing implementations of ML-KEM (FIPS 203), FrodoKEM and X25519 in Rust and C,
to choose a differential-testing oracle for a from-scratch Turing lattice layer, and to list the
bug classes that real implementations have shipped. Date checked: 2026-09-27.

## Key findings

(pending; draft points from run 1, each still to be re-checked against its source)

- RustCrypto `ml-kem` 0.3.2 (2026-05-10) targets final FIPS 203, is pure Rust, MSRV 1.85, dual Apache-2.0/MIT, and its README says it "has never been independently audited". Versions before 0.3.0 did not check encapsulation keys (FIPS 203 Sec. 7.2) or the decapsulation-key hash (Sec. 7.3); both were added as fixes in 0.3.0.
- libcrux-ml-kem 0.0.10 (2026-07-15) is "formally verified" only in parts: its own verification table (proofs/verification_status.md, last regenerated 2026-03-10) shows large parts unproven. Its full proof jobs are disabled in CI (issue #1529).
- Two independent libraries shipped an implicit-rejection failure: pqc_kyber's AVX2 backend (RUSTSEC-2026-0290) and the HQC reference code in liboqs/PQClean (CVE-2024-54137).
- `pqcrypto-mlkem` (PQClean bindings) and `pqc_kyber` are flagged unmaintained by RustSec; PQClean is archived.

## 1. What a test oracle is, and what it must be

(pending)

## 2. Rust crates

Metadata from the crates.io API (`research/scripts/pq/rpi_crates_meta.py`, `rpi_crate_versions.py`, `rpi_crate_deps.py`; cache in scratch `pq/rpi/crates/`). Table from run 1; being re-checked.

| crate | newest stable (date) | MSRV declared | licence | repository | notes |
|---|---|---|---|---|---|
| ml-kem | 0.3.2 (2026-05-10) | 1.85 | Apache-2.0 OR MIT | RustCrypto/KEMs | |
| libcrux-ml-kem | 0.0.10 (2026-07-15) | not declared | Apache-2.0 | cryspen/libcrux | |
| aws-lc-rs | 1.18.1 (2026-09-01) | 1.71.0 | ISC AND (Apache-2.0 OR ISC) | aws/aws-lc-rs | |
| pqcrypto-mlkem | 0.1.1 (2025-08-05) | not declared | MIT OR Apache-2.0 | rustpq/pqcrypto | |
| oqs | 0.11.0 (2025-05-01) | not declared | MIT OR Apache-2.0 | open-quantum-safe/liboqs-rust | |
| fips203 | 0.4.3 (2025-02-25) | 1.70 | MIT OR Apache-2.0 | integritychain/fips203 | |
| pqc_kyber | 0.7.1 (2023-08-23) | not declared | MIT/Apache-2.0 | Argyle-Software/kyber | |
| x25519-dalek | 3.0.0 (2026-07-06) | 1.85 | BSD-3-Clause | dalek-cryptography/curve25519-dalek | |
| x-wing | 0.1.0 (2026-07-09) | 1.85 | Apache-2.0 OR MIT | RustCrypto/KEMs | |
| frodo-kem | 0.1.0 (2026-04-28) | 1.85 | Apache-2.0 OR MIT | RustCrypto/KEMs | |
| frodo-kem-rs | 0.9.1 (2026-08-09) | not declared | Apache-2.0 OR MIT | mikelodder7/frodoKem | |
| pqcrypto-frodo | 0.4.11 (2022-04-14) | not declared | MIT OR Apache-2.0 | rustpq/pqcrypto | |

API facts read in the crate sources (cargo registry copies of the exact versions):

- `ml-kem` 0.3.2: `EncapsulationKey::new` decodes and validates the key and returns `InvalidKey` on failure; `encapsulate_deterministic(m)` exists for known-answer tests (documented only with the `hazmat` feature); decapsulation computes `Kbar = J(z || c)` and selects with `ct_select` on `ct_eq` (src/decapsulation_key.rs).
- `libcrux-ml-kem` 0.0.10: deterministic `generate_key_pair([u8; 64])` and `encapsulate(pk, [u8; 32])`; key checks are separate functions (`validate_public_key`, `validate_private_key`) that the caller must invoke; backends `portable`, `avx2` (feature `simd256`) and `neon` (feature `simd128`) are exposed as modules (src/mlkem768.rs lines 61-434).
- `fips203` 0.4.3: `KG::keygen_from_seed(d, z)`, `encaps_from_seed(m)`; the FIPS 203 input checks live in `EncapsKey::try_from_bytes` (modulus check) and `DecapsKey::try_from_bytes` (embedded ek and hash check) (src/lib.rs).
- `pqcrypto-mlkem` 0.1.1: builds PQClean's C; its build.rs compiles the AVX2 code only when the target is x86_64 and not Windows and not macOS, so on Windows only the portable `clean` C is used. PQClean's `crypto_kem_enc_derand` performs no encapsulation-key check and always returns 0 (pqclean/crypto_kem/ml-kem-768/clean/kem.c). The C also exports `*_keypair_derand` and `*_enc_derand`, which the Rust crate does not wrap.
- `frodo-kem` 0.1.0: implements FrodoKEM and eFrodoKEM, 640/976/1344, AES and SHAKE; README: "has never been independently audited". The README also says it was tested against liboqs, but CHANGELOG 0.1.0 lists "Removed `safe-oqs` equivalence tests (#166)".

## 3. C implementations and formal verification

### 3.1 What "formally verified" means, in three different projects

"Verified" is not one property. Each project proves a different subset of: (a) memory safety / absence of panics, (b) functional correctness against a specification of FIPS 203, (c) secret-independent timing ("constant time"), (d) IND-CCA security of the specification itself. None of the three below proves all four for the code a Rust user would link today.

**libcrux-ml-kem (Cryspen, Rust, hax + F\*).** The crate README says "The portable and AVX2 code for field arithmetic, NTT polynomial arithmetic, serialization, and the generic code for high-level algorithms is formally verified using hax and F\*" and points to `proofs/verification_status.md` for detail. That file (identical on 2026-09-27 to the copy on main; last changed 2026-03-10 by commit 6be97dd642f7, "used a script to update") calls itself "a rough guide" and lists, per module, how many functions are proved panic-free and correct:

| module group | panic-free | correct |
|---|---|---|
| generic `ind_cpa` | 0/21 | 0/21 |
| generic `sampling` | 0/5 | 0/5 |
| generic `matrix` | 1/5 | 0/5 |
| generic `serialize` | 16/20 | 2/20 |
| generic `ntt` / `invert_ntt` | 4/8 / 4/6 | 4/8 / 4/6 |
| generic `ind_cca` | 27/27 | 26/27 |
| portable backend (arithmetic, ntt, serialize, compress, sampling) | all | all |
| AVX2 backend | 42/47 | 41/47 |
| NEON backend | 1/40 | 1/40 |

So the README's "generic code for high-level algorithms is formally verified" is broader than the table supports: the IND-CPA layer, matrix generation and sampling have no correctness proofs. Issue #1529 "[CI/Proofs] Re-enable full proof jobs for ML-KEM and ML-DSA" (opened 2026-07-14) is still open: the full proof jobs are "temporarily disabled" in CI, so a release is not re-checked against the proofs automatically. Constant time is not part of the proofs; the README says constant-time operation is "best-effort, as there are no guarantees from the compiler" and is checked "via inspection of the generated assembly". The hax paper (Bhargavan et al., ePrint 2025/142, VSTTE 2025, p. 20) says ML-KEM in libcrux "was verified using hax and its F\* backend" and was adopted by OpenSSH and Mozilla NSS; p. 11-12 show what an F\* proof gives: panic freedom (every integer operation stays in range) and a functional post-condition, per function.

**mlkem-native (PQ Code Package, C90 + assembly, CBMC + HOL Light).** README: "All C code in mlkem/src/\* and mlkem/src/fips202/\* is proved memory-safe (no memory overflow) and type-safe (no integer overflow) using CBMC. All AArch64 and x86_64 assembly is proved to be functionally correct, memory-safe, and of secret-independent timing (constant-time), using HOL-Light." Its SOUNDNESS.md (current on 2026-09-27) states the limits plainly: the CBMC proofs "do not currently cover" functional correctness ("There is no machine-checked proof that the C code computes the right answer per FIPS 203") or constant-time execution of the C code; backends other than AArch64 and x86_64 (RISC-V RVV, Armv8.1-M MVE, PowerPC) "are not yet covered by specification"; there is "no automatic coverage check for CBMC or HOL Light", so "a function or configuration could slip through". Functional correctness of the C is tested, not proved (KAT, ACVP, Wycheproof, unit tests). Releases: v1.0.0 on 2025-06-04, latest v2.0.0 on 2026-08-07. Users named in its README: liboqs since 0.13.0 (default ML-KEM), AWS-LC since v1.50.0, rustls since 0.23.28 through AWS-LC. There is no Rust crate: `mlkem-native` and `mlkem-native-sys` do not exist on crates.io (HTTP 404, 2026-09-27); from Rust it is reached through aws-lc-rs or liboqs.

**Jasmin/EasyCrypt (Formosa Crypto, libjade).** Episode IV (Almeida et al., TCHES 2023, ePrint 2023/215) proved Jasmin Kyber-768 implementations functionally correct against an EasyCrypt specification. Episode V (Almeida et al., CRYPTO 2024, ePrint 2024/843) adds a machine-checked IND-CCA proof of the ML-KEM specification and "Two formally verified implementations of ML-KEM written in Jasmin that are provably constant-time, functionally equivalent to the ML-KEM specification" (p. 1). Its limits, from the paper: the concrete theorem is for "the ML-KEM draft standard, with parameters fixed for ML-KEM-768" (p. 2), i.e. FIPS 203 ipd, not the final standard (which changed key generation to G(d ‖ k), FIPS 203 App. C.2); the implementations "deliberately do not" do public-key validation, and the C ABI cannot check buffer lengths, so the authors skipped those test vectors (p. 22); the constant-time proof is Jasmin's type system: no secret branches, no secret memory addresses, and division/modulo only on public operands (p. 21). This is the strongest end-to-end result, but it is for the draft, one parameter set, and a Jasmin toolchain rather than Rust.

### 3.2 Other C code bases

- **PQClean**: archived (GitHub `archived: true` on 2026-09-27; last push 2026-08-04; issue #604 of 2026-01-08 announced archiving "in or after July 2026"). The Rust wrapper repository rustpq/pqcrypto is archived too (`archived: true`, last push 2026-09-16); RustSec lists `pqcrypto-mlkem` as unmaintained (RUSTSEC-2026-0161, 2026-06-04). The ML-KEM code in pqcrypto-mlkem 0.1.1 is pq-crystals/kyber commit 10b478fc via mkannwischer/package-pqclean (META.yml).
- **liboqs**: latest release 0.16.0 (2026-07-09). The Rust `oqs` crate is at 0.11.0 (2025-05-01), and its `oqs-sys` version string `0.11.0+liboqs-0.13.0` shows it bundles liboqs 0.13.0, three releases behind.
- **AWS-LC**: NIST CMVP certificates #5298 ("AWS-LC 3 Cryptographic Module (dynamic)", FIPS 140-3, Level 1, initial validation 6/3/2026, status Active) and #5314 ("(static)", 6/5/2026) list "ML-KEM KeyGen" and "ML-KEM EncapDecap" among the approved algorithms (cert pages fetched 2026-09-27). The aws-lc-rs README still says AWS-LC-FIPS 3.x "has been submitted to NIST for certification"; which aws-lc-fips-sys release is byte-for-byte the certified module is not settled here (Open questions).

## 4. Published bugs and audits, and which test would have caught each

Primary sources: GitHub security advisories of each repository (listed with `gh api repos/<repo>/security-advisories` on 2026-09-27), the RustSec advisory database files, and the issue trackers. Side-channel bugs (KyberSlash, Clangover and their detection) are covered in depth by the sibling topic side-channels-faults-and-ct-verification (its Sections 1 and 5); they appear here only to map each bug to the test that finds it.

| # | bug (source) | where | class | found by | test that catches it |
|---|---|---|---|---|---|
| B1 | pqc_kyber AVX2 `cmov` is a no-op, so implicit rejection never happens; "full secret key was recovered in 4,272 decapsulation queries" on ML-KEM-768 (RUSTSEC-2026-0290, 2026-08-16; no patched version) | Rust, one SIMD backend only | functional, CCA-breaking | external report (007bsd) | decapsulate a modified ciphertext and compare with J(z ‖ c'), on every backend (Sec. 5 `reject`); Wycheproof `MalleableCiphertext` group now carries such vectors (source "github.com/007bsd/mlkem-implicit-rejection") |
| B2 | HQC decapsulation indexing error: `sigma` read as part of the public key, so malformed ciphertexts are accepted and "returns shared secrets based on their decryptions" (liboqs GHSA-gpf4-vrrw-r8v7 / PQClean GHSA-753p-wrj5-g8fj, CVE-2024-54137, high; fixed liboqs 0.12.0) | reference C of another KEM | functional, CCA-breaking | Quarkslab (Glénaz, Goudarzi) | same J(z ‖ c') test; also a KAT that includes a rejected ciphertext |
| B3 | libcrux incremental encapsulation: AVX2 `from_bytes`/`to_bytes` byte order differs from portable and NEON; results are wrong when the two halves run on different backends (issue #1275, 2025-12-27, fixed 2026-01-06) | Rust SIMD backend, serialisation of internal state | functional, interop | user running split encapsulation (Signal SPQR use case) | cross-backend differential test of every serialised intermediate, not only final outputs |
| B4 | libcrux-ml-dsa wrong output on aarch64-unknown-linux-musl (issue #1220, 2025-11-02, fixed next day) | Rust intrinsics on one target | functional, platform | accumulated test vectors run on a second machine | accumulated hash on every CI target triple |
| B5 | libcrux-sha3 incremental SHAKE squeeze dropped the first block (RUSTSEC-2026-0074), mis-buffered multiple squeezes (-0207) and could panic in AVX2 SHAKE-256 (-0208); advisories say ML-KEM/ML-DSA use was not affected | Rust hash layer | functional / availability | project | differential test of the XOF against a second SHA-3 implementation for many output lengths and squeeze patterns |
| B6 | ml-kem < 0.3.0 did not check encapsulation keys or the expanded-key hash; fixed in 0.3.0 (2026-04-28): "Validate encryption/encapsulation keys (#179)", "Validate expanded decapsulation key hash (#207)" | Rust API | missing FIPS 203 Sec. 7.2/7.3 input checks | project (with Wycheproof validation, same release) | CCTV `modulus/`, Wycheproof `encaps_test` invalid keys, Wycheproof `semi_expanded_decaps_test` |
| B7 | libcrux `encapsulate` runs on keys that fail `validate_public_key`; PQClean has no check at all (measured in Sec. 5) | API design | input checks left to the caller | this note | same vectors, run through the API that applications actually call |
| B8 | KyberSlash: secret numerator divided by a public constant, compiled to a hardware `div` (TCHES 2025; RUSTSEC-2023-0079 for pqc_kyber, never patched there; ml-kem fixed in 0.1.1) | reference C and ports | timing | formal verification (secret-type discipline) and manual analysis | no functional test can; needs a machine-code scan or KyberSlash-patched Valgrind (sibling side-channels note, Sec. 1.2, 5.3) |
| B9 | Clangover: clang 15-18 turned `poly_frommsg` masking into a branch; ML-KEM-512 key leaked "in ~10 minutes" (liboqs GHSA-f2v9-5498-2vpp, CVE-2024-36405; fixed liboqs 0.10.1) | reference C under clang | timing | Antoon Purnal (PQShield) | ctgrind-style Valgrind run on each compiler/flag combination shipped (sibling note Sec. 1.3) |
| B10 | HQC reference: secret-dependent branches under clang above -O0 (liboqs GHSA-qq3m-rq9v-jfgm, CVE-2025-52473; fixed 0.14.0) | reference C | timing | Lai, Zhang (Melbourne, MPI-SP) | same |
| B11 | curve25519-dalek `Scalar29::sub`/`Scalar52::sub`: LLVM inserted a branch on a mask (RUSTSEC-2024-0344, CVE-2024-58262; fixed 4.1.3) | Rust scalar arithmetic | timing | DATA tool (Fraunhofer AISEC) | binary-level constant-time analysis (sibling note) |
| B12 | libcrux X25519: missing length/clamping checks on imported secrets (GHSA-435g-fcv3-8j26, 2026-02-12; libcrux-ecdh 0.0.6) | Rust API | input validation | project | Wycheproof x25519 edge cases plus explicit malformed-input tests |
| B13 | keccak `asm!` operands on ARMv8 declared `in` instead of `inout` (RUSTSEC-2026-0012; patched keccak 0.1.6, the version Turing pins) | Rust inline assembly | unsoundness | project | Miri cannot see inside asm; needs review plus tests on the target |

Audits. ml-kem's README: "The implementation contained in this crate has never been independently audited!" frodo-kem's README says the same. No public third-party audit report of libcrux-ml-kem, fips203, mlkem-native or liboqs ML-KEM was found in the repositories' security pages on 2026-09-27 (Open questions). Absence here means "not found in the primary places checked", not "none exists".

## 5. Differential tests run for this note

Probe: `research/scripts/pq/rpi_oracle_probe.rs` (+ `rpi_oracle_probe.Cargo.toml`, runner `rpi_oracle_probe_run.sh`), built in scratch `pq/rpi/oracle-probe/` with Rust 1.95.0, target x86_64-pc-windows-gnu, on an AMD Ryzen 5 5600X (AVX2). Implementations: ml-kem 0.3.2, libcrux-ml-kem 0.0.10 portable and AVX2 backends, fips203 0.4.3, PQClean `clean` C via pqcrypto-mlkem 0.1.1 (called through its `*_derand` C entry points), x25519-dalek 3.0.0. Vector files are the scratch copies checked byte-identical to upstream by the sibling topic testing-ci-cd (its Sec. 1).

Build finding: pqcrypto-mlkem 0.1.1 does not build on x86_64-pc-windows-gnu with MinGW-w64 GCC out of the box. PQClean's `common/compat.h` includes the glibc header `<features.h>` for every GCC that is not clang, and MinGW-w64 has no such header ("fatal error: features.h: No such file or directory"). A two-line shim header defining `__GNUC_PREREQ` fixes it (scratch `rpi/shim/features.h`, used by the runner).

Results (run 2026-09-27; raw output in scratch `rpi/probe-*.out`):

| test | ml-kem 0.3.2 | libcrux portable | libcrux AVX2 | fips203 0.4.3 | PQClean clean |
|---|---|---|---|---|---|
| Go TestAccumulated ML-KEM-768, n = 100 (`1114b1b6...4415`) | PASS | PASS | PASS | PASS | PASS |
| accumulated ML-KEM-512 / 1024, n = 100: all five agree | `86b1b470...9a59` / `800018fe...ac00` | same | same | same | same |
| Wycheproof + CCTV strcmp positive vectors (512 / 768 / 1024) | 397 / 398 / 399 pass, 0 fail | same | same | same | same |
| Wycheproof invalid ek of correct length (108 / 112 / 116) | all rejected | all rejected by `validate_public_key` | same | all rejected | no check exists |
| CCTV modulus keys (775 / 780 / 1040) | all rejected; encapsulation refused | all rejected by `validate_public_key`, but `encapsulate` still runs on every one | same | all rejected; encapsulation refused | no check; encapsulation runs on every one |
| Wycheproof invalid dk (bad hash, bad embedded ek), 2 per set | rejected | rejected by `validate_private_key_only` | same | rejected | no check exists |
| implicit rejection, 300 modified ciphertexts per set: output = J(z ‖ c') and != K | 300/300 | 300/300 | 300/300 | 300/300 | 300/300 |
| negative controls: mutant with wrong z; mutant that returns the real key | both detected in 300/300 trials | | | | |

X25519 (x25519-dalek 3.0.0): all 518 Wycheproof `x25519_test.json` cases match; 31 of them give an all-zero shared secret (all flagged `LowOrderPublic` and `ZeroSharedSecret`), which `x25519()` returns without error. RFC 7748 Sec. 5.2 (two vectors, iterated 1, 1,000 and 1,000,000 times) and Sec. 6.1 (Alice/Bob) all pass, with every expected value parsed from the RFC text rather than typed in.

What this shows: the five implementations are byte-for-byte interchangeable on valid inputs and on implicit rejection, so any one of them is a usable oracle for standard ML-KEM. They differ on invalid inputs: only ml-kem and fips203 enforce the FIPS 203 Sec. 7.2 encapsulation-key check by construction; libcrux leaves it to the caller; PQClean has none.

**Volume.** Go's 1,000,000-test ML-KEM-768 value `424bf8f0...d0f0` was reproduced by all five implementations (ml-kem 204 s, libcrux portable 158 s, libcrux AVX2 87 s, fips203 259 s, PQClean clean 245 s, Windows GNU build). At n = 10,000 all five give `e0112db3...c14c` for ML-KEM-512 and `f1a3925c...cb6a` for ML-KEM-1024; there is no published value for these two, so they are cross-implementation agreements, not external checks (1,000,000-test values for 512 and 1024: see Sec. 5.1 when the run finishes).

**Platforms.** The same probe was built three ways and gave identical results:

| build | how | result |
|---|---|---|
| x86_64-pc-windows-gnu (MinGW-w64 GCC 15, Rust 1.95.0) | needs the `features.h` shim for pqcrypto-mlkem; all pure-Rust crates build unmodified | all tests above |
| x86_64-pc-windows-msvc (VS Build Tools, `cargo +stable-x86_64-pc-windows-msvc`) | no shim needed (PQClean's compat.h has an `_MSC_VER` branch) | accumulated n = 10,000 ML-KEM-768 = Go value for all five; `VECTORS`/`X25519` lines byte-identical to the GNU run; RFC 7748 no failures; FrodoKEM-976-SHAKE KAT 100/100; interop 500/500 |
| x86_64-unknown-linux-gnu, run in WSL2 Ubuntu (gcc 15.2.0) | Windows rustc + WSL gcc as C compiler, archiver and linker (`rpi_wsl_tool.py`); WSL has no Rust installed | same results, plus a sixth implementation: PQClean's AVX2 C, which pqcrypto-mlkem compiles only on Linux. It matches Go at n = 10,000, passes all positive vectors (397/398/399), implicit rejection 300/300 per set, and interop 1200/1200 |

**aws-lc-rs 1.18.1 (AWS-LC C, which uses mlkem-native for ML-KEM).** It builds on x86_64-pc-windows-gnu without cmake (its build log says "Building with: CC"). Its API has no deterministic key generation or encapsulation, so it cannot run the accumulated test; it was tested by interoperation instead: for 100 random key pairs per parameter set, every other implementation decapsulated aws-lc-rs ciphertexts (from the exported expanded key), aws-lc-rs decapsulated every other implementation's ciphertexts, and aws-lc-rs decapsulation of a modified ciphertext gave J(z ‖ c') computed independently: 1,500/1,500 per parameter set. Input checks: `EncapsulationKey::new` accepted all 775 / 780 / 1,040 CCTV modulus keys, but `encapsulate()` then returned an error for every one of them. So aws-lc-rs does perform the FIPS 203 Sec. 7.2 check, at encapsulation rather than at key construction; a test that only calls the constructor would wrongly conclude there is no check.

**X-Wing (RustCrypto x-wing 0.1.0).** Its README says it "matches the draft RFC version 06"; it nevertheless reproduces all 3 test vectors of draft-connolly-cfrg-xwing-kem-11 Appendix C (seed → sk, pk; eseed → ct, ss; decapsulation → ss), parsed from the draft text. (This is the combiner that docs/02 planned; the hybrid-combiners sibling covers its design.)

**FrodoKEM (frodo-kem 0.1.0).** With the NIST AES-256 CTR_DRBG reimplemented in the probe (the `rng.c` used by NIST KAT generators), the crate reproduces the official KAT files of microsoft/PQCrypto-LWEKE (commit e1edeb3af1fa; each file's git blob hash equal to the GitHub API `sha`): 100/100 records (pk, sk, ct, ss) for FrodoKEM-640/976/1344-SHAKE, FrodoKEM-640/976/1344-AES, eFrodoKEM-640/976/1344-SHAKE (976-AES and 1344-SHAKE also under Linux). Sizes seen: FrodoKEM-976 pk 15,632, sk 31,296, ct 15,792 bytes; FrodoKEM-1344 pk 21,520, sk 43,088, ct 21,696; eFrodoKEM-976 ct 15,744 and eFrodoKEM-1344 ct 21,632. The DRBG call pattern also shows how randomness is drawn: FrodoKEM-976 takes 88 bytes at key generation and 72 at encapsulation (μ plus salt), eFrodoKEM-976 takes 64 and 24 (no salt).

**An API hazard in frodo-kem 0.1.0.** `Algorithm::decapsulate` returns `(SharedSecret, Vec<u8>)`; the vector is μ', the IND-CPA decryption of the ciphertext, documented as "message generated during encapsulation". It is returned even when the FO re-encryption check fails. The probe flipped the lowest bit of the first ciphertext byte in 200 encapsulations per variant: for FrodoKEM-640/976/1344-SHAKE and eFrodoKEM-976-SHAKE, all 200 modified ciphertexts were rejected (shared secret differs) and all 200 returned μ' equal to the original μ. So the second return value is exactly the "decryption of an invalid ciphertext" that implicit rejection exists to hide. An application that logs it, returns it, or branches on it hands an attacker a plaintext-checking oracle, the same oracle that gave full key recovery in RUSTSEC-2026-0290. The crate itself does not leak it; the risk is in the API shape. A Turing KEM API should return only the shared secret from decapsulation.

## 6. Performance near 1000 dimensions

"About 1000 dimensions" covers two very different designs. ML-KEM-1024 is a module lattice of rank 4 over a ring of degree 256 (total dimension 1024) and uses the NTT, so a multiplication costs about n log n. FrodoKEM-976 and -1344 use plain LWE with an unstructured n × n matrix that must be regenerated from a seed each time, so cost grows with n²; that is why FrodoKEM is 30 to 250 times slower. (Background: sibling topic lattice-foundations.)

**Published reference numbers (cycles; medians unless stated).**

| scheme | source, machine | keygen | encaps | decaps |
|---|---|---|---|---|
| mlkem1024 | eBACS, Zen 3 (Ryzen 5 PRO 5650G, "cezanne"), supercop-20260831, page 2026-09-25 | 54,854 | 55,785 | 57,953 |
| mlkem1024 | eBACS, Zen 2 (EPYC 7742, "rome0"), supercop-20260831 | 61,847 | 62,324 | 64,836 |
| mlkem1024 | eBACS, Raptor Cove (Core 5 210H), supercop-20260627 | 47,930 | 47,432 | 49,592 |
| mlkem1024 | eBACS, Cortex-A76 (Raspberry Pi 5), supercop-20251222 | 173,074 | 239,289 | 346,551 |
| Kyber1024 ref C | Kyber round-3 spec, Table 2, p. 17, Haswell i7-4770K | 307,148 | 346,648 | 396,584 |
| Kyber1024 AVX2 | same table | 73,544 | 97,324 | 79,128 |
| frodokem976aes | eBACS, Zen 3 (cezanne) | 1,852,546 | 2,515,644 | 2,312,744 |
| frodokem976shake | eBACS, Zen 3 | 8,098,751 | 8,458,874 | 8,444,665 |
| frodokem1344aes | eBACS, Zen 3 | 3,075,391 | 4,205,314 | 4,003,130 |
| frodokem1344shake | eBACS, Zen 3 | 14,375,087 | 14,802,869 | 14,695,967 |
| FrodoKEM-976-AES | FrodoKEM CiC paper, Table 8, p. 29, Coffee Lake i7-8700, AES-NI (×10³) | 2,017 | 2,105 | 1,983 |
| FrodoKEM-1344-AES | same | 3,353 | 3,597 | 3,326 |
| FrodoKEM-976-SHAKE | same, 4-way AVX2 SHAKE (×10³) | 6,026 | 6,096 | 5,994 |
| FrodoKEM-1344-SHAKE | same | 10,725 | 10,643 | 10,497 |

eBACS marks every FrodoKEM row "T:", which its legend defines as: "the SUPERCOP database at the time of benchmarking did not list constant time as a goal for this implementation". The ML-KEM rows carry no flag.

**Measured here (Rust crates, Windows 11, x86_64-pc-windows-gnu, Ryzen 5 5600X).** Pending a clean re-run without a concurrent background job; see Sec. 6.1 when filled.

## 7. Recommended oracles and the bug-class test list

(pending)

## What this means for Turing

(pending)

## Sources

(pending)

## Claim ledger

(pending; rows being collected)

## Open questions

(pending)
