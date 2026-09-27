# How a lattice layer would plug into Turing: constraints from the existing design and code

This file reads the Turing repository as the primary source and lists every
constraint a lattice (post-quantum) layer would have to respect: how keys
enter the cipher, the label conventions of the `xof` module, the
requirements already collected for the deferred file-encryption step, the
dependency policy as practised, the `analysis`-feature boundary, the
self-test and fault-checked APIs, Bombe's validation conventions, and where
new code could live without colliding with the cipher work. It also
maps FIPS 203's implementation requirements onto the library's existing
machinery. Everything was checked on 2026-09-27 against commit 2071a07
(HEAD, "Raise Turing to 24 rounds and make keys leave nothing behind"). The
only uncommitted change outside `research/` on 2026-09-27 is a
two-line `.gitignore` addition (`/research/workfiles/`), which this
file does not depend on. Line numbers are at HEAD (`git show HEAD:<path>`);
`research/scripts/pq/tic_line_check.py` re-checks 104 of them against the
text they describe. Sections 9-11 cover where lattice code could live, which
Bombe tools could test it, and how the owner's "about 1000 dimensions" goal
meets the recorded X-Wing plan.

## Key findings

1. **A KEM secret already has Turing's key shape.** FIPS 203's shared
   secret is always 256 bits (PDF p.25); `Turing::new` takes `&[u8; 32]`
   and whitens it with cSHAKE256 under "Turing v2 key" (`cipher.rs` line 55;
   `keyschedule.rs` lines 28, 172-183). No cipher change is needed. How the
   file key is derived and what it binds is a file-format decision (section
   2; hybrid-combiners note).
2. **Step 9 (file encryption) has no design document; its requirements are
   scattered.** Twenty are collected in section 4 from docs 02, 03, 08, 11,
   12 and 13. One is stale: docs/02 and docs/03 cite X-Wing draft version 10;
   the current draft is -11 of 23 September 2026.
3. **"About 1000 dimensions" collides with the recorded plan.** X-Wing is
   fixed to ML-KEM-768 (768 secret coefficients) by design (draft-11 section
   1.2). The only specified ML-KEM-1024 hybrid is MLKEM1024-P384
   (draft-irtf-cfrg-concrete-hybrid-kems-04, section 4.3); there is no
   specified ML-KEM-1024 + X25519. Every route to ~1000 dimensions changes
   R2 or the "We do not hand-build the combiner" rule (docs/03 lines 16-17).
   The owner has to decide which (section 11).
4. **Turing's labelled-cSHAKE256 rule stops at the standard's boundary.**
   ML-KEM's hashes are fixed (SHA3-256, SHA3-512, SHAKE128, SHAKE256; FIPS
   203 PDF p.27-29). Changing them makes a new scheme with no test vectors.
   Turing's labels apply only to what is derived from the KEM's output
   (section 3).
5. **FIPS 203's implementation rules map onto machinery Turing already
   has:** the `analysis` feature for the derandomised internal functions
   (PDF p.25), checksum-and-compare for the key hash check and pair-wise
   consistency (PDF p.45-46), and `SecretBox` + `burn_stack` + `memscan` for
   "only the designated output can be retained in memory" (PDF p.25-26)
   (sections 6-7).
6. **Four memory-hygiene pieces must be extended before a KEM can "leave
   nothing behind":** wiping SHA3-256/SHA3-512/SHAKE256 wrappers (new
   `unsafe`, as in `cshake256_secret`); `Zeroable` has no 16-bit impls
   (`memory.rs` lines 33-35); `BURN_BYTES` (32 KB) was sized for the cipher,
   while one FrodoKEM-1344 matrix is 21,504 bytes; `ShieldedKey` holds
   exactly 32 bytes, while ML-KEM's storable seed (d, z) is 64 (sections 9.2,
   9.4).
7. **Seeds d, z and m should follow `new_key`'s pattern** because
   ProcessPrng leaves output residue (docs/13 lines 152-184). Whether
   cSHAKE256 post-processing still meets FIPS 203's "approved RBG" wording is
   unsettled: SP 800-90C has no SHAKE, XOF or KMAC construction (section
   9.5).
8. **A separate crate is the least-colliding placement.** Everything it
   needs from `turing` is public (`SecretBox`, `Zeroable`, `burn_stack`,
   `random`, `xof`). It collides with the cipher work only in the root
   `Cargo.toml` line 2 (members listed by name) and `Cargo.lock`
   (section 9).
9. **Bombe can already test part of a lattice layer:** `memscan` for
   high-entropy secrets, `stack_depth` for burn sizing, `dudect` through its
   closure, `asm_branches.py`, `rng`, the `refcipher` pattern, `mutate.py`
   and `wsl_linux.py` (section 10.1).
10. **Bombe's gaps for lattice code are concrete.** `asm_branches.py` has no
   division scan (KyberSlash). `memscan`'s 8-byte fragments hold only about
   8.1 bits of an ML-KEM secret, and about 3.8 fragments of each ML-KEM-768
   s are all zero (COMPUTED). The SP 800-22 battery rejects ML-KEM
   encapsulation keys by construction: the expected monobit statistic is
   52.65 on 2^20 bits (COMPUTED). Also missing: KEM fault hooks, lattice
   leakage models, KAT and malformed-input runners, an attack-cost
   reproduction and an exact decryption-failure computation (section 10.2).
11. **Validation must follow Bombe's conventions:** published values first,
   negative controls caught, and a planted-bug set in `tools/mutate.py`.
   Section 10.3 proposes 11 lattice-specific planted bugs.
12. **Flagged risks.** These add unanalysed structure: changing ML-KEM's
   internals; a three-component hybrid combined by a home-made rule;
   building lattice hashes or PRFs from Turing, which contradicts docs/08
   line 71; parameters without a reproduced attack-cost and
   failure-probability estimate.

## 1. What Turing is at HEAD

- Two crates in one Cargo workspace: `crates/turing` (the cipher library)
  and `crates/bombe` (the cryptanalysis workbench). `Cargo.toml` lines 1-3.
  The test profile is optimised (`opt-level = 2`, `Cargo.toml` lines 5-7).
- `turing` is version 0.1.0, edition 2021, `publish = false`
  (`crates/turing/Cargo.toml` lines 1-6). Its description: "an experimental
  128-bit block cipher with a 256-bit key".
- The library's modules (`crates/turing/src/lib.rs` lines 6-17): `cipher`,
  `gf`, `keyschedule`, `linear`, `masked`, `memory`, `random`, `sbox`,
  `selftest`, `shield`, `structure`, `xof`. Re-exports (lines 19-23):
  `Block`, `FaultDetected`, `Turing`, `MaskedTuring`, `RandomnessError`,
  `ShieldedKey`, `self_test`, `SelfTestError`.
- A compile-time assertion that every key-holding type is `Send + Sync`
  (`lib.rs` lines 25-33).
- The cipher is version 2: 24 rounds, 25 round keys
  (`structure.rs` lines 26-28); 24 is the stated ceiling, enforced by a
  const assertion (line 29).
- There is no public-key code, no file format and no AEAD in the tree.
  The file-encryption step (step 9) is parked: docs/12 line 12-13 says "Step
  9 (file encryption) is parked until this is done", and the docs index
  runs 01-13 with no step-9 document.

## 2. Keys: size, entry and the key schedule

- **Key size.** 256 bits, taken as `&[u8; 32]` by `Turing::new`
  (`cipher.rs` line 55), `MaskedTuring::new` (`masked.rs` line 240),
  `ShieldedKey::new` (`shield.rs` line 40) and `keyschedule::expand`
  (`keyschedule.rs` line 172). The reason given is Grover: "A 256-bit key
  keeps ~128-bit security" (docs/02 lines 32-33; docs/03 line 9).
- **How a key enters.** `Turing::new` runs the key schedule through a
  non-inlined `expanded` and then calls `memory::burn_stack()`
  (`cipher.rs` lines 55-67). The library never stores the caller's key
  (docs/13 line 91-92: "`Turing::new` reads it once, through the key
  schedule").
- **Whitening.** K' = cSHAKE256(X = K, S = "Turing v2 key"), computed with
  `xof::cshake256_secret` into a 32-byte stack array that is zeroized after
  being split into halves (`keyschedule.rs` lines 172-183; label at line
  28).
- **Feistel expansion.** (L, R) -> (R XOR F_j(L), L) with
  F_j(x) = MixState(S(x XOR C_j)); constants C_j are read from
  cSHAKE256(X = "", S = "Turing v2 key schedule constants") (line 29, line
  196); 13 warm-up rounds, then a round-key pair every 8 rounds (lines
  31-33, 197-213).
- **Feed-forward.** Each round key is a Feistel half XOR the matching half
  of K' (lines 209-211). Consequence stated in docs/11 lines 64-71: a
  recovered round key gives neither K' nor the other round keys.
- **Storage.** The 25 round keys and a checksum
  Σ x^i · RK_i in GF(2^128) (GCM polynomial; `keyschedule.rs` lines 73-85)
  live together in one `SecretBox<KeyMaterial<N>>` (lines 87-111), allocated
  zeroed and filled in place (lines 200-216).
- **The schedule is prefix-consistent**: a shorter expansion is a prefix of a
  longer one (test at lines 253-260). Version 2 changed its labels for
  exactly this reason (docs/13 lines 70-76; `keyschedule.rs` lines 24-29).
  Lesson for any new layer: a label must change whenever the function
  behind it changes, or old and new outputs are related.
- **Equivalent keys.** docs/11 lines 73-77: hashing 256 bits to 256 bits
  reaches about 63% of outputs (~2^255.3 distinct K'), and "Every key
  derivation that hashes a key does the same." This applies unchanged if a
  32-byte KEM shared secret becomes a Turing key.

What this means for a KEM: a 32-byte shared secret (ML-KEM's K is
"always 256-bit values", FIPS 203 PDF p.25, section 3.3) has exactly the
shape of a Turing key. The key schedule already whitens its input with a
labelled cSHAKE256, so a KEM output can be passed to `Turing::new` without
changing the cipher. Whether it should be passed directly, or through a
key-derivation step that binds the file header, is a design decision that
belongs to the file format (section 4) and to the hybrid-combiners and
cca-transforms-and-binding notes.

## 3. The xof module and label conventions

- **API.** Two functions (`crates/turing/src/xof.rs`):
  - `cshake256(label: &str, input: &[u8]) -> CShake256Reader` (lines
    24-29): cSHAKE256 with N = "" and S = label. "For public data only: the
    digest crate's internal buffers are not wiped when dropped" (lines
    22-23).
  - `cshake256_secret(label: &str, input: &[u8], out: &mut [u8])` (lines
    39-58): the same function for secret input and output. Full blocks are
    absorbed straight from the caller's slice, the partial block goes into a
    buffer that is wiped with `zeroize::zeroize_flat_type` (the module's
    one `unsafe` block, line 52), each output block is wiped after copying, and
    the Keccak state is wiped on drop by the sha3 crate's `zeroize` feature.
  - Both refuse an empty label (`assert!`, lines 25 and 40), because with N
    and S both empty cSHAKE256 is plain SHAKE256 (SP 800-185, PDF p.13:
    "When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent
    to SHAKE").
- **Tests** (lines 60-127): NIST SP 800-185 cSHAKE256 samples #3 and #4
  (published values), domain separation between labels, the empty-label
  refusal, and equality of the two paths for every input length 0-409 plus
  16,384, and output lengths across the 136-byte rate boundary.
- **Label convention.** docs/03 lines 20-30: "an ASCII label of the form
  `"Turing v1 <purpose>"` as the customization string S"; version 2 renamed
  the key-schedule labels to "Turing v2 ...", while the S-box and matrices
  keep the v1 labels they were generated with.
- **Every label in use at HEAD** (found by grepping all tracked files for
  string literals starting "Turing v"; script `tic_repo_facts.py`):

  | Label | Where | Input X | Purpose |
  |---|---|---|---|
  | "Turing v1 S-box" | `bombe/src/gen.rs` line 19; `turing/src/sbox_constants.rs` line 4 | counter (u32 big-endian) | S-box affine layers (public) |
  | "Turing v1 MixColumns" | `bombe/src/gen.rs` line 118 | counter | Cauchy points (public) |
  | "Turing v1 MixState" | `bombe/src/gen.rs` line 119 | counter | Cauchy points (public) |
  | "Turing v2 key" | `turing/src/keyschedule.rs` line 28 | the 32-byte key | whitening K' (secret) |
  | "Turing v2 key schedule constants" | `keyschedule.rs` line 29 | empty | Feistel constants (public) |
  | "Turing v2 key generation" | `turing/src/random.rs` line 67 | 64-byte OS seed | `new_key` (secret) |
  | "Turing v2 masks" | `random.rs` line 63 | 64-byte OS seed | mask stream (secret) |
  | "Turing v2 key shield" | `turing/src/shield.rs` line 24 | 16 KB prekey | shield mask (secret) |
  | "Turing v2 known-answer vectors" | `bombe/src/refcipher.rs` line 185 | empty | vector inputs (public) |

  Test-only labels: "Turing v1 test", "Turing v1 a", "Turing v1 ab",
  "Turing v1 key" and "Turing v1 key schedule constants" (`xof.rs` lines
  98-120; line 98 checks that moving bytes between label and input changes
  the output). With these and the two placeholder strings "Turing v1 ..."
  and "Turing v2 ..." in the module comment (`xof.rs` line 5), the script
  counts 16 distinct "Turing v..." literals.
- **A hard-coded label-length limit.** The mask stream implements cSHAKE's
  prefix by hand and asserts `STREAM_LABEL.len() < 32` because the label's
  bit length must fit `left_encode`'s one-byte form (`random.rs` line 68).
  Any new label fed through that hand-written path has the same limit;
  labels through `xof::cshake256*` do not.

**Constraint for lattice code.** FIPS 203 fixes ML-KEM's hash functions:
"Each function shall be instantiated by means of an approved hash function
or an approved eXtendable-Output Function (XOF), as prescribed below"
(PDF p.27, section 4.1): PRF_η(s, b) := SHAKE256(s‖b, 8·64·η),
H(s) := SHA3-256(s), J(s) := SHAKE256(s, 8·32) (PDF p.27),
G(c) := SHA3-512(c) and XOF = SHAKE128 (PDF p.28-29). So Turing's rule "every
derivation is cSHAKE256 with a Turing label" cannot reach inside a standard
KEM: replacing SHAKE256 with cSHAKE256 there would make a different,
non-interoperable scheme that no longer matches the standard's test vectors.
The rule can still apply at the boundary: everything Turing derives from a
KEM output (file keys, key-encryption keys, header MACs) can use new
"Turing v2 ..." (or "Turing v3 ...") labels. The same sha3 crate (0.10.9)
already provides SHA3-256, SHA3-512, SHAKE128 and SHAKE256, so ML-KEM's
hashes need no new hash dependency.

**A memory-hygiene gap that lattice code would reopen.** docs/11 lines
44 (item 1) records that the digest crate's input buffer holds absorbed key
bytes and is never wiped; that is why `cshake256_secret` exists. ML-KEM
hashes secrets at several points (the seed d, the message m, the implicit-
rejection value z, PRF(σ, N)). Through the high-level sha3/digest API those
secrets would stay in unwiped buffers exactly as K' once did. A Turing
lattice layer therefore needs secret-input variants of SHA3-256, SHA3-512
and SHAKE256 in the style of `cshake256_secret`, or a vetted KEM crate whose
hashing leaves nothing behind, and in either case Bombe's `memscan` has to
confirm it (section 10). FIPS 203 makes this a conformance requirement, not
only a hardening wish: "implementers shall ensure that intermediate data is
destroyed as soon as it is no longer needed ... only the designated output
can be retained in memory after the algorithm terminates" (PDF p.25-26,
section 3.3, "Destruction of intermediate values").

## 4. The deferred file-encryption step and its collected requirements

Step 9 has no document yet. Its requirements are spread over docs 02, 03,
08, 11, 12 and 13. Collected here, each with its source:

| # | Requirement | Source (HEAD) |
|---|---|---|
| R1 | Hybrid public-key encryption from the start, on vetted post-quantum primitives; "Only the data cipher is ours." | docs/03 lines 11-12 |
| R2 | Hybrid KEM X-Wing (X25519 + ML-KEM-768, SHA3-256 combiner); "We do not hand-build the combiner." | docs/03 lines 13-17 |
| R3 | "the implementation must track the draft version it follows" (X-Wing is an Internet-Draft, not an RFC) | docs/02 lines 60-64 |
| R4 | Sender signatures (ML-DSA) later; the file format reserves space (versioned header) | docs/03 lines 18-19 |
| R5 | A fresh random 256-bit file key per file from `turing::random::new_key` | docs/03 lines 73-75; docs/13 line 387 |
| R6 | Chunked STREAM construction: nonce encodes chunk counter and a last-chunk flag; header authenticated | docs/03 lines 79-83 |
| R7 | AEAD construction (e.g. CTR + MAC) decided in step 9 | docs/03 line 84 |
| R8 | Read each ciphertext chunk into private memory once, verify its tag on that copy, decrypt that same copy (double-fetch) | docs/03 lines 76-78; docs/13 lines 388-391 |
| R9 | Release no plaintext before its tag verifies | docs/13 lines 392-395 |
| R10 | Header stanzas: recipient stanza (hybrid KEM; the combiner binds ciphertexts and public keys) and password stanza (Argon2id, random salt, stored parameters) | docs/03 lines 86-95 |
| R11 | The file key is wrapped under each stanza's key-encryption key with the Turing AEAD | docs/03 lines 96-97 |
| R12 | Crates to be version-checked in step 9: an X-Wing implementation (or `ml-kem` + `x25519-dalek` combined exactly per the X-Wing spec), `argon2`, `sha3`, `getrandom` | docs/03 lines 99-101 |
| R13 | A random key per file and a mode that limits data per key well below the 2^64-block birthday bound | docs/08 lines 98-102 |
| R14 | Misuse-resistant (SIV-style) construction recommended as defence in depth | docs/08 lines 104-109 |
| R15 | Lock the pages holding the key and round keys (VirtualLock / mlock) | docs/11 lines 81-83 (now done in the library by `SecretBox`, docs/13 section 3) |
| R16 | Passphrases and derived keys must be wiped by the tool, and never logged | docs/11 line 88 |
| R17 | Call `self_test()` at start-up | docs/12 lines 211-213 |
| R18 | Use the checked calls wherever faults are part of the threat model | docs/12 lines 211-213 |
| R19 | Make ciphers after forking; hibernation needs full-disk encryption | docs/13 line 396 |
| R20 | Turing is used only for encryption, never as a hash building block; hashing uses SHA-3 | docs/08 lines 69-71 |

Three of these need updating or a decision before the lattice work builds
on them (the third is R2 against the "about 1000 dimensions" goal, section
11):

- **R3 is already stale.** docs/02 line 63 and docs/03 line 15 name
  "version 10, March 2026". The draft on file is
  draft-connolly-cfrg-xwing-kem-11, dated 23 September 2026, expiring 27
  March 2027, intended status Informational
  (`research/papers/ietf-draft-connolly-cfrg-xwing-kem-11.txt`, header). Its
  sizes: decapsulation key 32 bytes, encapsulation key 1216 bytes,
  ciphertext 1120 bytes, shared secret 32 bytes (section 5.1). The
  hybrid-combiners note covers what changed between -10 and -11.
- **R20 constrains any "lattice inside the symmetric layer" idea.** docs/08
  rules out using Turing as a hash building block; a design that feeds
  Turing into a lattice hash, or builds a PRF from Turing for a KEM's
  internals, would contradict a standing rule and needs an explicit design
  decision (see the lattices-inside-symmetric-primitives note).

## 5. Dependency policy in practice

Written policy: only "vetted implementations" for the public-key layer
(docs/02 line 60; docs/03 lines 11-12, 92). There is no written rule on
crate count, audits or features. The practice at HEAD:

- `turing` depends on `getrandom` 0.4.3, `keccak` 0.1.6, `sha3` 0.10 with
  the `zeroize` feature, `zeroize` 1.9.0; `windows-sys` 0.61.2 (features
  `Win32_System_Memory`, `Win32_Foundation`) on Windows and `libc` 0.2.189
  on Unix (`crates/turing/Cargo.toml` lines 8-23).
- `bombe` depends on `turing` with the `analysis` feature, `sha3` 0.10,
  `zeroize` 1.9.0, and platform crates for memory scanning
  (`crates/bombe/Cargo.toml` lines 8-17).
- `Cargo.lock` at HEAD resolves 18 packages in total, including the two
  workspace crates (sha3 resolves to 0.10.9, digest 0.10.7, block-buffer
  0.10.4, keccak 0.1.6).
- Features are chosen for memory hygiene: sha3's `zeroize` feature was
  added because the Keccak state was not wiped without it (docs/11 line 44).
  Dependency source was read to decide what must be wiped by hand
  ("digest 0.10.7 and block-buffer 0.10.4 have no wiping of their own
  (checked in their source)", docs/12 lines 206-209).
- `unsafe` code is justified in writing. docs/12 (a version-1 document)
  speaks of "The one `unsafe` block", the wipe in `cshake256_secret`, kept
  only because the dependency offers no alternative (docs/12 lines
  205-209). Version 2 added more: at HEAD the word `unsafe` occurs 24 times
  in `memory.rs` (OS allocation, locking, the volatile stack burn), 6 in
  `random.rs`, 3 in `keyschedule.rs`, 2 in `cipher.rs` and 1 each in
  `masked.rs` and `xof.rs` (a text count over `git show HEAD:` that
  includes comments and `unsafe impl`/`unsafe fn` declarations, not a count
  of blocks). So "one unsafe block" no longer describes the crate. The
  habit of justification holds: the text `unsafe {` occurs 23 times in
  those six files and a `SAFETY` comment 26 times, and in each file the
  comments are at least as many as the blocks (text count, same method).

Implications: an ML-KEM or X-Wing crate would be the largest
security-critical addition to a tree that today holds 16 third-party
packages (18 minus the two workspace crates); its own dependency count is
the rust-pqc-implementations note's to establish. The practice so far implies
that any new crate must (a) be read for what it leaves in memory, (b) be
pinned in `Cargo.lock` with the exact version recorded in the docs (R12),
and (c) pass Bombe's memory scan and timing tests before use. Which crates
qualify is the rust-pqc-implementations note's topic.

## 6. The analysis-feature boundary

- `crates/turing/Cargo.toml` lines 14-17: feature `analysis`, "Reduced-round
  encryption and round-key access, for the Bombe analysis workbench only. A
  normal build of the cipher cannot expose round keys." Only Bombe enables
  it (`crates/bombe/Cargo.toml` line 9).
- Behind `#[cfg(feature = "analysis")]` at HEAD: `Turing::new_without_stack_burn`,
  `encrypt_block_checked_with`, `flip_round_key_bit_in_use`,
  `flip_round_key_bit`, `encrypt_rounds`, `decrypt_rounds`, `round_key`
  (`cipher.rs` lines 71-181); `RoundKeys::get`, `all`,
  `keyschedule::expand_whitened` (`keyschedule.rs` lines 135-191);
  `MaskedTuring::with_mask_seed`, `encrypt_block_checked_with`,
  `encrypt_probed`, `encrypt_recorded` (`masked.rs` lines 249-398). Behind
  `any(test, feature = "analysis")`: fault-injection hooks and
  `MaskStream::from_seed` (`random.rs` lines 115-127).
- The boundary is itself tested: a probe crate showed the calls fail to
  compile without the feature (E0599/E0425) (docs/11 line 46), and a
  compile-time guard fails the build if `Turing` or `RoundKeys` implements
  `Debug` (`cipher.rs` lines 214-227; docs/11 line 47).

**FIPS 203 asks for the same boundary.** "The interfaces for these
functions should not be made available to applications other than for
testing purposes. In particular, the sampling of random values required for
key generation ... and encapsulation ... shall be performed by the
cryptographic module." (PDF p.25, section 3.3, "Controlled access to internal
functions".) The derandomised `KeyGen_internal(d, z)` and
`Encaps_internal(ek, m)` are exactly what known-answer tests and Bombe need,
and exactly what the `analysis` feature exists to hide. A lattice layer
should put them behind the same feature (or a new, equally guarded one),
with the same probe-crate test that they do not compile without it. X-Wing
also offers `GenerateKeyPairDerand` (section 5.2.1) and `EncapsulateDerand` (section 5.4.1), each introduced "For testing"
(draft-11, lines 399 and 475 of the .txt).

## 7. Self-test and fault-checked APIs

- `turing::self_test()` (`selftest.rs` lines 50-71) checks NIST's cSHAKE256
  sample #3 through both XOF paths, then two known-answer vectors (vectors 0
  and 2 of `vectors/turing-v2.txt`) through encryption and decryption. It
  returns `SelfTestError::{Xof, Encrypt, Decrypt}`. It does not exercise
  `MaskedTuring`, `ShieldedKey`, `random` or the checked calls.
- `encrypt_block_checked` / `decrypt_block_checked` (`cipher.rs` lines
  92-125): verify the round-key checksum, compute, run the inverse and
  compare without branching on data, verify the checksum again; on any
  mismatch the block is wiped and `Err(FaultDetected)` returned. Masked twins
  exist (`masked.rs` lines 337-342).

**How these map onto a KEM** (FIPS 203 section 7):

| Turing mechanism | FIPS 203 analogue | Source |
|---|---|---|
| `self_test()` at start-up with KAT vectors | Known-answer vectors for KeyGen/Encaps/Decaps through the derandomised internal functions | FIPS 203 PDF p.25 (internal functions "for testing purposes") |
| Round-key checksum checked before and after use | Decapsulation-key "Hash check": H(ek) stored inside dk is recomputed and compared | FIPS 203 PDF p.46, section 7.3, eq. (7.2) |
| Decrypt-and-compare | "Pair-wise consistency": encapsulate to ek, decapsulate with dk, reject unless K == K' | FIPS 203 PDF p.45, section 7.1 |
| Refusing bad lengths (types) | Ciphertext and key "type checks" and the encapsulation-key "modulus check" | FIPS 203 PDF p.45-46, sections 7.2-7.3 |

Differences that matter: FIPS 203 requires ciphertext checking "with every
execution of ML-KEM.Decaps" (PDF p.46), and forbids running Encaps on an
unchecked encapsulation key (PDF p.45-46), while the key checks themselves
"need not be performed by the ... party, nor with every execution" if
assurance comes "through other means (see SP 800-227)" (PDF p.46). Unlike
a block cipher, a KEM's decapsulation cannot be checked by running it
backwards; the FO transform's re-encryption already compares, and fault
attacks that skip that comparison are a separate topic
(side-channels-faults-and-ct-verification note).

## 8. Bombe's validation conventions

Stated in docs/04 lines 3-6: "Every tool is validated against AES, whose
values are published, and against deliberately broken controls, before its
verdict on our own components counts." In practice four conventions recur:

1. **Published values first.** Each tool reproduces a published result
   before it judges Turing: AES S-box values (docs/04 table), NIST SP 800-22
   reference results for 10^6 bits of e (docs/10 lines 114-119), Park et
   al. and Keliher-Sui bounds (docs/12 lines 51-54), Midori-64 invariant
   factors (docs/11 lines 190-195), cSHAKE256 samples (`xof.rs` lines
   69-87). Where the published value is itself wrong, the error is
   documented with a primary source (NIST's spectral examples, docs/10
   lines 120-125).
2. **Negative controls must be caught.** Every attack has a deliberately
   broken target it must break: identity and affine S-boxes (docs/04 lines
   35-36), the plain counter in the NIST battery and an early-exit S-box in
   dudect (docs/10 lines 111-113), a planted key in the heap and in a dead
   stack frame for `memscan` (docs/13 lines 141-149), unmasked values and
   repeated masks for TVLA (docs/13 lines 232-241).
3. **Predictions matched by measurement.** For example the 2-round
   boomerang rate, 32 expected returns (docs/11 lines 132-133) and 33 of
   262,144 quartets measured (docs/11 line 127).
4. **Planted bugs (mutation testing).** `tools/mutate.py` holds named sets
   (default, `--step8`, `--step9`, `--round3`, `--round4`) of (name, file,
   exact old text, new text, cargo test arguments). Each pattern must match
   exactly once; the file is always restored and the restore verified; a
   test run over 580 s counts as caught and the process tree is killed
   (`tools/mutate.py` lines 1-21, 283-348). `--check` verifies patterns
   without running tests. Arguments starting `--wsl` run the tests in WSL
   through `tools/wsl_linux.py` (lines 12-13, 294-297). The sets at HEAD:
   default 8, step8 13, step9 16, round3 14, round4 25 mutations, 76 in
   all (counted by `tic_repo_facts.py`). The set names follow the order in
   which the sets were written, not the step list of docs/03: `--step9`
   plants bugs in the key-handling code of docs/11 (for example "xof: secret
   cSHAKE drops its label", `tools/mutate.py` line 70), not in the parked
   file-encryption step 9.

A new lattice layer should arrive with the same three kinds of evidence:
published values reproduced (NIST ACVP / FIPS 203 vectors, the X-Wing
draft's vectors), controls caught, and its own planted-bug set in
`tools/mutate.py`.

## 9. Where lattice code would fit

### 9.1 The shared files every placement touches

Some files are edited by whatever placement is chosen. They are also the
files the cipher work edits, so they are the collision points:

| File (HEAD) | Why a lattice layer touches it |
|---|---|
| `Cargo.toml` line 2 | Workspace members are listed by name (`["crates/bombe", "crates/turing"]`), not by a glob, so a new crate needs this line changed; `Cargo.lock` then changes too. |
| `crates/turing/src/lib.rs` lines 6-17 | A new module inside `turing` needs a `pub mod` line here. |
| `crates/turing/src/selftest.rs` lines 17-24, 50-71 | A KEM known-answer check at start-up needs a new `SelfTestError` variant and more work in `self_test()`. |
| `crates/bombe/src/lib.rs`, `main.rs` lines 343-350, `campaign.rs` | New Bombe modules, a subcommand and a campaign section. |
| `tools/mutate.py` | A new planted-bug set (sets are Python lists at lines 25, 69, 121, 167, 196 and a flag table in `main()`). |
| `vectors/` | Known-answer files for the KEM. |
| `docs/` | The next design document would be docs/14. |

### 9.2 What the existing library already lets a separate crate reuse

Everything a KEM crate needs from `turing` is already public, so a separate
crate can reuse it without editing `turing`'s sources:

- `memory::SecretBox<T>`, `memory::Zeroable` (a `pub unsafe trait`) and
  `memory::burn_stack` are public (`memory.rs` lines 32, 38, 51-60, 131).
- `random::os_random` and `random::new_key` are public (`random.rs` lines
  40, 48).
- `xof::cshake256` and `xof::cshake256_secret` are public (`xof.rs` lines
  24, 39).

One gap needs care. `Zeroable` is implemented only for `u8`, `u64` and
arrays of `Zeroable` types (`memory.rs` lines 33-35). Lattice code works on
arrays of 16-bit (ML-KEM, FrodoKEM) or 32-bit coefficients. Rust's orphan
rule lets a downstream crate implement a foreign trait only for its own
types, so a KEM crate cannot add `Zeroable for i16`. It can define its own
coefficient or polynomial type (for example a newtype around `[i16; 256]`
that implements `Zeroize`) and implement `Zeroable` for that, which the
trait's safety contract allows ("Plain data for which all-zero bytes are a
valid value ... and which contains no pointers", lines 27-31). Adding
`i16`/`u16`/`i32` impls to `memory.rs` itself would be the simpler route but
edits a shared file.

Two parts would need new code wherever the KEM lives:

- **Secret-input SHA-3 functions.** `cshake256_secret` covers only cSHAKE256
  with a non-empty label. ML-KEM hashes secrets with SHA3-256, SHA3-512 and
  SHAKE256 (section 3). Wiping versions of these need the same technique as
  `cshake256_secret`, including its `unsafe` wipe of the digest crate's
  buffer (`xof.rs` line 52), because digest 0.10.7 and block-buffer 0.10.4
  do not wipe (docs/12 lines 206-209). That is new `unsafe` code in the
  most sensitive path, and it needs the same written justification and
  memory-scan evidence as the existing sites (section 5).
- **Key shielding for a KEM key.** `ShieldedKey` holds exactly a
  `[u8; 32]` (`shield.rs` lines 32-35). FIPS 203 allows the 64-byte seed
  (d, z) to be stored instead of the decapsulation key, with "the same
  safeguards as a decapsulation key" (PDF p.26). A shielded 64-byte seed,
  expanded with `KeyGen_internal` only when decapsulating, would reuse the
  OpenSSH-style design unchanged in principle, but needs either a generic
  `ShieldedKey<N>` (shared-file edit) or its own type in the new crate.

### 9.3 The placement options

| Option | What it is | For | Against |
|---|---|---|---|
| A. Module in `turing` (`turing::kem`) | KEM code beside the cipher | Private access to internals; one `analysis` feature | Edits `lib.rs`; mixes a standards-based public-key layer into the "experimental 128-bit block cipher" crate (`crates/turing/Cargo.toml` line 5); every KEM change rebuilds and re-tests the cipher crate |
| B. New crate, e.g. `crates/turing-kem`, depending on `turing` | Separate crate reusing `SecretBox`, `burn_stack`, `random`, `xof` through their public APIs | No edit to `turing`'s sources (section 9.2); its own `analysis` feature can forward `turing/analysis`; clear boundary for review and dependency vetting | One-line edit to `Cargo.toml` line 2 plus `Cargo.lock`; needs its own coefficient types and secret-hash wrappers |
| C. Wrapper crate around a vetted external KEM | As B, but the lattice arithmetic comes from an external crate | Follows the written policy (docs/02 line 60; docs/03 lines 11-12) | The external crate's internal buffers are outside `SecretBox` and `burn_stack`; its memory behaviour must be read in its source and measured with `memscan` (section 5; rust-pqc-implementations note) |
| D. Separate repository | Independent of the workspace | No collisions at all | Loses Bombe's in-process tools (memscan, dudect) unless they are made a library other crates can use |

On the evidence in this file, option B (or C inside B's crate) fits the
existing code best: it collides with the cipher work in one line of the root
manifest and nowhere in the cipher. The design phase should still decide it
with the owner, and the root-manifest edit should be made when the cipher
work is not mid-change (a `git status` check first).

### 9.4 Sizes against the memory machinery

Computed by `tic_sizes.py` from FIPS 203 Tables 2-3 and the FrodoKEM
proposal's Tables A.1, A.2, A.4, A.5 (every derived size matches the source's
printed size):

| Secret | Bytes | 4096-byte pages in one `SecretBox` |
|---|---|---|
| Turing round keys + checksum | 416 | 1 |
| ML-KEM seed (d, z) or X-Wing decapsulation key | 64 / 32 | 1 |
| ML-KEM-768 decapsulation key | 2,400 | 1 |
| ML-KEM-1024 decapsulation key | 3,168 | 1 |
| FrodoKEM-976 secret key | 31,296 | 8 |
| FrodoKEM-1344 secret key | 43,088 | 11 |

Page locking can be refused (Windows allows about the minimum working set;
Unix enforces RLIMIT_MEMLOCK), in which case the value lives in ordinary
memory and `locked()` reports it (`memory.rs` lines 10-12). An 8- or
11-page FrodoKEM key is larger than any single secret Turing locks today
(the largest is `ShieldedKey`'s 16 KB prekey, 4 pages; `shield.rs` line
23). Whether the default limits allow it beside Turing's own pages on the
target systems is not measured (open question 3).

The stack burn is sized for the cipher: `BURN_BYTES` is 32 KB, "several
times the deepest key setup (Turing::new peaks at a few kilobytes in a release
build)" (`memory.rs` lines 122-124). One FrodoKEM-1344 n x n-bar matrix of
16-bit entries is 21,504 bytes, 0.66 of `BURN_BYTES`; FrodoKEM-976's is
15,616 bytes (0.48). ML-KEM-768's whole matrix A-hat is 4,608 bytes. If an
implementation keeps two or more such matrices on the stack, a 32 KB burn no
longer covers it. Bombe already has the measuring tool,
`memscan::stack_depth` (paints 256 KB below the caller and finds the deepest
changed word; `memscan.rs` lines 193-217). The burn size for a KEM should
come from that measurement, not from the cipher's figure.

### 9.5 Randomness and key derivation at the boundary

- **Seeds d, z and m.** docs/13 lines 152-184 measured that Windows'
  `ProcessPrng` often leaves up to the last 16 bytes of its output readable
  elsewhere in the process: of 8 keys taken straight from it, 2 to 4 left
  fragments in each run; of 8 from `new_key`, none. `new_key` therefore
  hashes a 64-byte OS seed with cSHAKE256 (`random.rs` lines 10-17, 44-61).
  ML-KEM's seeds d, z (KeyGen) and m (Encaps) are 32 bytes each and are
  exactly such secrets, so the same pattern applies. FIPS 203 requires them
  to come from "an approved RBG, as prescribed in SP 800-90A, SP 800-90B, and
  SP 800-90C" with at least 192 bits of strength for ML-KEM-768 (PDF p.25;
  Table 2, PDF p.48). SP 800-90C's constructions do not mention SHAKE, XOFs
  or KMAC at all (`tic_source_checks.py`: 0 occurrences each). Whether
  cSHAKE256 post-processing of an approved RBG's output still counts as
  "generated using an approved RBG" is therefore not settled by the text
  (open question 1). It is a conformance question, not a strength question:
  hashing 512 OS bits to 256 loses no meaningful entropy.
- **From the KEM secret to a Turing key.** FIPS 203: "If further key
  derivation is needed, the final symmetric keys shall be derived from this
  256-bit shared secret key in an approved manner, as specified in SP 800-108
  and SP 800-56C" (PDF p.25). Turing's key schedule itself starts with a
  cSHAKE256 whitening (section 2), and Turing is not an approved cipher, so
  the file tool as a whole cannot claim FIPS conformance whatever KDF it
  uses. The KEM component can still be conformant on its own. The
  hybrid-combiners note covers what the derivation must bind (ciphertexts,
  public keys, a label).
- **Labels.** New derivations should get new labels in the house style
  (`"Turing v2 <purpose>"`, docs/03 lines 20-30), and a label must change
  whenever the function behind it changes (the version-2 lesson, docs/13
  lines 70-76). A label fed through the hand-written stream prefix must be
  shorter than 32 bytes (`random.rs` line 68); labels through
  `xof::cshake256*` have no such limit.

## 10. Bombe tools that could test a lattice layer, and new tools it needs

`bombe attack` runs 21 sections at HEAD (`campaign.rs` lines 157-887, from
"1. Correctness" to "21. Time of check to time of use, and concurrency").
Bombe has 38 modules and 15 integration-test files (`tic_repo_facts.py`,
section 7). Each existing tool is listed below with what it would do for a
lattice layer as it stands, and what it lacks.

### 10.1 Existing tools

| Tool (HEAD) | What it does now | Use for a lattice layer | Gap |
|---|---|---|---|
| `memscan` (`memscan.rs`) + `residue` | Reads every readable page of the process and reports every aligned 8-byte fragment of the named secrets; needles are stored XORed with a random pad (lines 41-90); `run_parked` pauses a worker thread after each step so its dead stack can be scanned (lines 151-189) | Works unchanged for high-entropy secrets: the seeds d, z, m, the shared secret K, the encoded decapsulation key (s-hat packed as 12-bit values), an X25519 scalar. Any byte string whose length is a multiple of 8 can be a needle (`Needles::add`, line 63) | Small-coefficient secrets in the normal domain are a problem. As 16-bit integers, one 8-byte fragment of ML-KEM's s holds four coefficients and about 8.1 bits of entropy (CBD with eta = 2: 2.031 bits per coefficient); P(fragment all zero) = 0.0198, so an ML-KEM-768 s (192 fragments) is expected to contain 3.8 all-zero fragments that match any zeroed memory. 64 bits of entropy need 32 such coefficients, 64 bytes (COMPUTED, `tic_sizes.py` section 6). Needed: a needle mode that reports only runs of consecutive fragments, or skips low-entropy fragments, with a control that shows it still finds a planted copy. |
| `memscan::stack_depth` (lines 193-217) | Measures the stack a function uses below its caller | Sizes `burn_stack` for KeyGen, Encaps and Decaps (section 9.4) | None; it paints 256 KB, enough for the sizes in section 9.4 unless an implementation keeps a whole FrodoKEM matrix A (1.9 MB) on the stack |
| `timing::dudect` (`timing.rs` lines 57-98) | Welch's t between two input classes, all-zero bytes against random bytes, with cropping; `leaks()` is max \|t\| > 4.5 (lines 50-52) | The closure receives the class's input bytes, so a KEM test can map them to its own classes: for example a fixed valid ciphertext for class 0 and a freshly tampered ciphertext for class 1, to time the implicit-rejection path of Decaps | The classes are hard-wired to zeros against random (lines 57-66); a valid-against-invalid ciphertext test needs the mapping written into each closure, or a class generator parameter. dudect measures this machine's timing, not power, so by docs/13 lines 345-348 it cannot rule out Hertzbleed-style power-to-timing effects |
| `tools/asm_branches.py` | Lists conditional jumps, or with `--loads` indexed memory accesses, in chosen functions of an x86-64 assembly file (lines 1-27) | Directly usable on KEM functions: NTT, CBD sampling, Compress, the FO comparison and the final key selection | It does not look for division instructions (no `div` pattern anywhere in the script). KyberSlash was a compiler-emitted division on secret data: "gcc 14.1.0 from May 2024 produces division instructions even when it is optimizing for speed" (2025-bernstein-et-al-kyberslash.pdf, PDF p.2). A `--divs` mode is the smallest useful addition (side-channels note, finding 1). |
| `nist` + `battery` (`battery.rs`) | NIST SP 800-22 tests on 2^20-bit keystreams | Meaningful only for outputs that are meant to be uniform bits: the 32-byte shared secret K and keystreams derived from it | Not for public KEM data. ML-KEM's encapsulation key encodes values mod 3329 in 12 bits, so its bits are biased by construction: mean bit 0.47429, top bit 0.38480; the expected monobit statistic on 2^20 bits is 52.65 (P about 0), a certain rejection that says nothing about security. Compressed ciphertext parts pass the monobit test, but their values are not uniform (Compress_10 gives each 10-bit value 3 or 4 preimages); a chi-square test against uniform values would reject after about 5,915 coefficients, far fewer than one 2^20-bit sequence holds (104,857). FrodoKEM's values mod 2^D are exactly unbiased. (COMPUTED, `tic_encoding_bias.py`.) Public KEM outputs need distribution tests against their exact law, not SP 800-22. |
| `fault` + `toctou` | DFA on the last rounds (`fault.rs`); flipping a key bit inside the check-to-use window through an `analysis` hook and confirming the second checksum catches it (`toctou.rs` lines 1-17) | The pattern transfers: a hook that skips or flips the FO re-encryption comparison, or corrupts the stored H(ek) or ciphertext between check and use, and a test that the default is rejection | New hooks in the KEM code; the side-channels note records that one skipped instruction bypassed the FO check in pqm4's Kyber, Saber and NTRU (its finding 9) |
| `leakage` + `power` | CPA and TVLA on Hamming-weight leaks of S-box values and masked shares | TVLA's fixed-against-random design is generic | The leakage models are the S-box's. Lattice decapsulation leaks through NTT butterflies, CBD sampling and message decoding, with arithmetic (mod q) rather than Boolean masking; new models are needed (side-channels note, findings 7-8) |
| `keycheck` (`keycheck.rs`) | Suspicious keys, zero or repeated round keys, equivalent keys for Turing's schedule | The idea maps to FIPS 203's input checks: the encapsulation-key modulus check and the decapsulation-key hash check (PDF p.45-46) | New tests with malformed keys and ciphertexts; published malformed-input sets (Wycheproof, ACVP) are covered in the testing-ci-cd note |
| `refcipher` (`refcipher.rs` lines 1-8) | An independent, deliberately different implementation of Turing; the known-answer vectors are generated from it | The same pattern for a KEM: a second, independent implementation (in Bombe or as a Python oracle) that generates or cross-checks the vectors | For a standard KEM, NIST's and others' published vectors come first; for a custom variant no external oracle exists (testing-ci-cd note, finding 3) |
| `rng` (`rng.rs`) | A labelled cSHAKE256 stream for reproducible experiments | Deterministic Monte-Carlo runs (for example decryption-failure sampling) and reproducible test inputs | None |
| `tools/mutate.py` | Named sets of planted bugs, each pattern matching once, file restored and verified (section 8) | A new `--lattice` (or similar) set | New set; see 10.3 |
| `tools/wsl_linux.py` | Builds with Windows rustc, links with WSL's gcc, runs tests in WSL (lines 1-17) | Runs the Linux paths of any KEM memory code (mlock, MADV_DONTDUMP, MADV_WIPEONFORK) | The WSL distro's state is covered in the testing-ci-cd note (its finding 6) |

### 10.2 New tools the lattice work needs

Each should follow Bombe's rule: reproduce a published value first, catch a
negative control, then judge Turing's parameters.

1. **Known-answer and malformed-input runner.** FIPS 203 vectors through
   the derandomised internal functions (kept behind the `analysis` boundary,
   section 6), NIST ACVP sets, Wycheproof, and for X-Wing the draft's own
   vectors. The testing-ci-cd note found and ran these sets against
   independent oracles.
2. **Attack-cost reproduction.** A Bombe (or research-script) reproduction
   of the lattice attack-cost model, validated on a published parameter set
   before it is applied to any Turing parameter set. The model and which
   published figures to reproduce are the attack-cost-estimation note's
   topic.
3. **Exact decryption-failure computation.** A convolution of the error
   distributions that reproduces a published failure probability before it
   is trusted for new parameters (decryption-failures note).
4. **Constant-time checks for lattice code.** A division scan
   (`asm_branches.py --divs` or a separate tool), dudect with valid and
   invalid ciphertext classes, and Valgrind-style secret poisoning in WSL
   (side-channels note, section 6).
5. **A memscan needle mode for low-entropy secrets** (10.1).
6. **Distribution tests for public KEM data**: decode the coefficients and
   test them against their exact law (uniform mod q for t-hat and u before
   compression, the Compress_d law after it), instead of SP 800-22 (10.1).
7. **Fault hooks for the FO comparison and the key checks** (10.1).

### 10.3 Planted bugs a lattice layer's tests should catch

Proposed, not yet written. Each is a known way lattice KEM code has gone
wrong or a check FIPS 203 requires, so a test suite that misses one has a
real gap:

| Planted bug | What should catch it |
|---|---|
| Encapsulation-key modulus check removed | malformed-key vectors (FIPS 203 PDF p.45-46) |
| Decapsulation-key hash check removed | a corrupted H(ek) in dk (PDF p.46) |
| Implicit rejection returns the decrypted key instead of J(z ‖ c) | tampered-ciphertext vectors; the rust-pqc-implementations note lists two libraries that shipped an implicit-rejection failure (a draft point there on 2026-09-27, still to be re-checked by that note) |
| Ciphertext comparison stops at the first differing byte | dudect with valid against tampered ciphertexts |
| Compress rounds down instead of to nearest | known-answer vectors |
| One NTT twiddle factor wrong | known-answer vectors; decryption-failure rate measured on random keys |
| CBD eta off by one | known-answer vectors; coefficient-distribution test |
| Secret seed d, m or z taken as raw OS output | memscan with the ProcessPrng residue control (docs/13 lines 152-184) |
| Seed or decapsulation key freed without wiping | memscan / residue |
| KDF or combiner label dropped, or a ciphertext left out of the combiner hash | domain-separation tests; the hybrid-combiners note's one-query break |
| Derandomised internal functions compiled without the `analysis` feature | a probe crate that must fail to compile (the docs/11 line 46 pattern) |

## 11. The "about 1000 dimensions" goal against the recorded plan

The recorded plan (R2) is X-Wing, whose lattice part is ML-KEM-768. In
FIPS 203 every ML-KEM polynomial has n = 256 coefficients and the module
rank k is 2, 3 or 4 (Table 2, PDF p.48), so the secret has k x n = 512, 768
or 1024 integer coefficients. "About 1000 dimensions" in that sense is
ML-KEM-1024 (k = 4) or, among unstructured schemes, FrodoKEM-976 (n = 976,
proposal Table A.1). The lattice-foundations and attack-cost-estimation
notes explain why the attack cost depends on more than this one number.

X-Wing is fixed to ML-KEM-768. Its authors write: "We aim for "128 bits"
security (NIST PQC level 1)" and "feel ML-KEM-768 provides a comfortable
margin" (draft-11, section 1.2, lines 183-186 of the .txt). The CFRG's list
of concrete hybrids, draft-irtf-cfrg-concrete-hybrid-kems-04 (6 July 2026,
expires 7 January 2027), defines exactly three: MLKEM768-P256,
MLKEM768-X25519 ("identical to the X-Wing construction") and MLKEM1024-P384
(table of contents, sections 4.1-4.3). There is no specified ML-KEM-1024 +
X25519 hybrid in either document. (Protocol standards define their own
ML-KEM-1024 hybrids with protocol-specific combiners, for example
SecP384r1MLKEM1024 in TLS and ML-KEM-1024 + X448 in OpenPGP; the
hybrid-combiners note lists them.) So the goal and the recorded rule "We do
not hand-build the combiner" (docs/03 lines 16-17) collide, and one of
these has to give:

| Route | Lattice dimension | Specified by | Cost to the plan |
|---|---|---|---|
| Keep X-Wing | 768 | draft-11 | Does not meet "about 1000" |
| MLKEM1024-P384 | 1024 | concrete-hybrid-kems-04, section 4.3 | Replaces X25519 with P-384 (a new crate family); still an Internet-Draft, so R3's "track the draft version" applies |
| ML-KEM-1024 + X25519 through the generic framework | 1024 | draft-irtf-cfrg-hybrid-kems-12 (a framework, not a concrete instance; hybrid-combiners note) | Turing would instantiate the framework itself: a combiner choice the project has so far said it would not make |
| ML-KEM-1024 + X448 as in OpenPGP (RFC 9980) | 1024 | RFC 9980, per the hybrid-combiners note (its section on OpenPGP; not re-read for this file) | A published, file-format precedent with an X-Wing-style combiner, but a different curve (X448) and a combiner defined for OpenPGP's packet format; adopting it means following another format's spec |
| X-Wing plus a third, unstructured component (FrodoKEM-976 or -1344) | 768 and 976 or 1344 | No IETF construction for three components; theory covers it (hybrid-combiners note, findings 1 and 8) | Three-way combiner; header grows to 16,912 or 22,816 bytes of KEM ciphertext per recipient (COMPUTED, `tic_sizes.py` section 7) |

The per-recipient KEM ciphertext is 1,120 bytes for X-Wing and 1,665 bytes
for MLKEM1024-P384 (both recomputed from FIPS 203 Table 3 plus the group
element sizes of the concrete draft's section 3.1, and matching its
published Nct). Which route is "harder to break" is not a question this file
can answer; the hybrid-combiners, pq-families-for-diversity and
attack-cost-estimation notes hold that evidence. What this file adds is that
every route except "keep X-Wing" changes a recorded decision (R2 or its
"no hand-built combiner" rule), which the owner has to make explicitly.

## What this means for Turing

Concrete implications for the design phase, each with its evidence:

1. **A 32-byte KEM secret fits the cipher unchanged.** FIPS 203's K is
   always 256 bits (PDF p.25) and `Turing::new` takes `&[u8; 32]`
   (`cipher.rs` line 55) and whitens it with cSHAKE256 (`keyschedule.rs`
   lines 172-183). No cipher change is needed to take a key from a KEM. The
   file format still needs a derivation step that binds the header (R10;
   hybrid-combiners note).
2. **Turing's house rules stop at the standard's boundary.** Inside ML-KEM
   the hash functions are fixed (SHA3-256, SHA3-512, SHAKE128, SHAKE256;
   FIPS 203 PDF p.27-29). Replacing them with labelled cSHAKE256 would be a
   new, non-interoperable scheme without test vectors. "Every derivation is
   cSHAKE256 with a Turing label" applies only to what Turing derives from
   the KEM's output. A "twist" inside the KEM loses every external oracle
   (testing-ci-cd note, finding 3).
3. **FIPS 203's implementation rules match what Turing already does.** The
   `analysis` feature is the "controlled access to internal functions" the
   standard asks for (PDF p.25); the checksum-and-compare pattern maps to the
   decapsulation-key hash check and pair-wise consistency (PDF p.45-46);
   `SecretBox` plus `burn_stack` plus `memscan` answer "only the designated
   output can be retained in memory" (PDF p.25-26). The same machinery should
   be applied, and each piece re-measured, not assumed (sections 6, 7, 9).
4. **Memory hygiene gets harder, and the tools need extending first.** The
   SHA-3 functions ML-KEM uses do not wipe their buffers (docs/12 lines
   206-209), `BURN_BYTES` was sized for the cipher (`memory.rs` lines
   122-124), `Zeroable` has no 16-bit impls (lines 33-35) and `memscan`'s
   8-byte fragments are too short for small-coefficient secrets (COMPUTED:
   about 8.1 bits of entropy per fragment for ML-KEM's s). Each needs work
   before a "leaves nothing behind" claim can be made for a KEM (sections
   9.2, 9.4, 10.1).
5. **The placement with the least collision is a new crate.** It can reuse
   `SecretBox`, `burn_stack`, `random` and `xof` through their public APIs and
   needs one edit to the root `Cargo.toml` (section 9.3). This is a proposal
   for the owner to decide, not a finding from the literature.
6. **Seeds must not be raw OS output.** docs/13's measurement of
   ProcessPrng residue applies to d, z and m; the `new_key` pattern
   (cSHAKE256 of 64 OS bytes) answers it, with an unsettled FIPS
   conformance question (section 9.5; open question 1).
7. **The recorded X-Wing decision needs updating in two ways.** docs/02 and
   docs/03 cite draft version 10 while draft-11 (23 September 2026) is
   current (R3), and X-Wing's ML-KEM-768 does not meet an "about 1000
   dimensions" target; every route that does changes a recorded rule
   (section 11).
8. **Bombe can test much of a lattice layer today, but not all.** memscan,
   stack_depth, dudect, asm_branches, rng, mutate.py and wsl_linux.py are
   reusable (10.1). Missing: a division scan, a low-entropy needle mode,
   distribution tests for public KEM data (the SP 800-22 battery rejects
   ML-KEM encapsulation keys by construction: expected monobit statistic
   52.65 on 2^20 bits), KEM fault hooks, KAT/malformed-input runners, an
   attack-cost reproduction and an exact failure-probability computation
   (10.2).
9. **Risks to flag.** Each of these adds structure no one has analysed:
   changing ML-KEM's internal hashes or sampling; a home-made combiner for a
   three-component hybrid without the published rule (hybrid-combiners
   note); feeding Turing into lattice hashing or PRFs, which also contradicts
   docs/08 line 71 ("never as a hash building block"); and a parameter set
   without a reproduced attack-cost estimate and failure probability.

## Sources

| File | Reference | URL | Used for |
|---|---|---|---|
| repository | Turing repository at commit 2071a07 (HEAD, 2026-09-26) | local: D:/Dev/Turing | all code and doc citations |
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, August 2024 | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf | sections 3.3, 4.1, 7, Tables 2-3 |
| nist-sp800-185-sha3-derived-functions.pdf | NIST SP 800-185, SHA-3 Derived Functions | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf | cSHAKE definition |
| ietf-draft-connolly-cfrg-xwing-kem-11.txt | Connolly, Schwabe, Westerbaan, X-Wing, draft-connolly-cfrg-xwing-kem-11, 23 Sept 2026 | https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt | sizes, derandomised test API, design goal (section 1.2) |
| ietf-draft-irtf-cfrg-concrete-hybrid-kems-04.txt | Connolly, Barnes, Concrete Hybrid PQ/T Key Encapsulation Mechanisms, draft-irtf-cfrg-concrete-hybrid-kems-04, 6 July 2026 | https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.txt | the three concrete hybrids and their sizes (sections 3.1, 4.1-4.3) |
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | FrodoKEM: Learning With Errors Key Encapsulation, Preliminary Standardization Proposal, 2023-03-14, revision 2025-09-29 | https://frodokem.org/ (site; local copy used) | Tables A.1, A.2, A.4, A.5 (sizes, error table) |
| 2025-bernstein-et-al-kyberslash.pdf | Bernstein, Bhargavan, Bhasin, Chattopadhyay, Chia, Kannwischer, Kiefer, Paiva, Ravi, Tamvada, KyberSlash: Exploiting secret-dependent division timings in Kyber implementations | https://kyberslash.cr.yp.to/ | why a division scan is needed (PDF p.2) |
| nist-sp800-90c-rbg-constructions.pdf | Barker, Kelsey, McKay, Roginsky, Sönmez Turan, NIST SP 800-90C, Recommendation for Random Bit Generator (RBG) Constructions | https://doi.org/10.6028/NIST.SP.800-90C | absence of SHAKE/XOF/KMAC constructions |
| nist-sp800-227-kem-recommendations.pdf | NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms | https://doi.org/10.6028/NIST.SP.800-227 | referenced by FIPS 203 for key checks and combiners (details in the hybrid-combiners note) |
| nist-sp800-22r1a-statistical-test-suite.pdf | NIST SP 800-22 rev. 1a, A Statistical Test Suite for Random and Pseudorandom Number Generators | https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final (URL not re-checked; local copy used) | the monobit test used in `tic_encoding_bias.py` (as implemented in `crates/bombe/src/nist.rs` l.144-149) |

Scripts written for this file (all in `research/scripts/pq/`, each prints
what it checks and exits non-zero on a mismatch where it compares):
`tic_repo_facts.py` (repository counts, read from `git show HEAD:` only),
`tic_sizes.py` (sizes, pages, entropies, hybrid sizes),
`tic_source_checks.py` (page of every quoted phrase),
`tic_encoding_bias.py` (bit and value bias of ML-KEM encodings),
`tic_line_check.py` (104 line citations re-checked at HEAD, with three
negative controls that must fail). Commands, from the repository root:

```
timeout 120 python research/scripts/pq/tic_repo_facts.py
timeout 60  python research/scripts/pq/tic_sizes.py
timeout 300 python research/scripts/pq/tic_source_checks.py
timeout 60  python research/scripts/pq/tic_encoding_bias.py
timeout 120 python research/scripts/pq/tic_line_check.py
```

All five ran on 2026-09-27 with exit status 0 (37 of 37 source phrases
found; every size matches its source; 104 of 104 citations match and all
three controls are caught).

## Claim ledger

| # | Claim | Status | Source |
|---|---|---|---|
| 1 | HEAD is 2071a07 on 2026-09-27 | VERIFIED | `git log --oneline` |
| 2 | Turing key is 256 bits (`&[u8; 32]`) | VERIFIED | `cipher.rs` l.55; `keyschedule.rs` l.172 |
| 3 | 24 rounds, 25 round keys, 24 is the ceiling | VERIFIED | `structure.rs` l.26-29 |
| 4 | K' = cSHAKE256(K, S = "Turing v2 key"); constants from "Turing v2 key schedule constants"; 13 warm-up rounds; 8 rounds per pair | VERIFIED | `keyschedule.rs` l.28-33, 172-213 |
| 5 | Round keys and GF(2^128) checksum stored in one SecretBox | VERIFIED | `keyschedule.rs` l.73-111, 200-216 |
| 6 | `cshake256` and `cshake256_secret` signatures; empty label refused | VERIFIED | `xof.rs` l.24-58 |
| 7 | cSHAKE256 with N and S empty equals SHAKE256 | VERIFIED | nist-sp800-185 PDF p.13 (tic_source_checks.py) |
| 8 | Label table: 9 production labels; 16 distinct "Turing v..." literals in all (with 5 test labels and 2 comment placeholders) | VERIFIED | `timeout 120 python research/scripts/pq/tic_repo_facts.py`, section 1 (reads `git show HEAD:` only) |
| 9 | Mask-stream label length limited to < 32 bytes | VERIFIED | `random.rs` l.68 |
| 10 | FIPS 203 hash functions: PRF = SHAKE256, H = SHA3-256, J = SHAKE256, G = SHA3-512, XOF = SHAKE128 | VERIFIED | nist-fips-203 PDF p.27-29, section 4.1 |
| 10b | The sha3 crate version in Cargo.lock (0.10.9) exports Sha3_256, Sha3_512, Shake128 and Shake256 | VERIFIED | local registry source `sha3-0.10.9/src/lib.rs` l.125-166 (read, not built) |
| 11 | FIPS 203: randomness from an approved RBG (SP 800-90A/B/C), strength >= 192 bits for ML-KEM-768 | VERIFIED | nist-fips-203 PDF p.25, section 3.3 |
| 12 | FIPS 203: internal derandomised functions only for testing; sampling done by the module | VERIFIED | nist-fips-203 PDF p.25, section 3.3 |
| 13 | FIPS 203: only the designated output may remain in memory; seed (d, z) may be stored with dk safeguards | VERIFIED | nist-fips-203 PDF p.25-26, section 3.3 |
| 14 | FIPS 203: K is always 256 bits | VERIFIED | nist-fips-203 PDF p.25 |
| 15 | FIPS 203 key-pair check (seed consistency, ek check, dk check, pair-wise consistency) | VERIFIED | nist-fips-203 PDF p.45, section 7.1 |
| 16 | FIPS 203 dk hash check and ciphertext check on every Decaps | VERIFIED | nist-fips-203 PDF p.46, section 7.3 |
| 17 | ML-KEM-768: ek 1184, dk 2400, ciphertext 1088, shared secret 32 bytes | VERIFIED | nist-fips-203 PDF p.48, Table 3 |
| 18 | X-Wing draft-11: dk 32, ek 1216, ct 1120, ss 32 bytes; dated 23 Sept 2026 | VERIFIED | ietf-draft-connolly-cfrg-xwing-kem-11.txt header and section 5.1 |
| 19 | docs/02 and docs/03 cite X-Wing version 10 (March 2026) | VERIFIED | docs/02 l.62-63; docs/03 l.14-15 |
| 20 | turing's direct dependencies and versions | VERIFIED | `crates/turing/Cargo.toml` l.8-23 |
| 21 | Cargo.lock resolves 18 packages; sha3 0.10.9 | VERIFIED | `Cargo.lock` at HEAD |
| 22 | Mutation sets: default 8, step8 13, step9 16, round3 14, round4 25 (76 in all). An earlier draft of this file said step9 = 15; the re-run on 2026-09-27 counts 16 | COMPUTED | `timeout 120 python research/scripts/pq/tic_repo_facts.py`, section 2 |
| 1b | Only uncommitted change outside research/ on 2026-09-27: `.gitignore` gains `/research/workfiles/` | VERIFIED | `git status --short`, `git diff .gitignore` |
| 23 | Workspace members are listed by name, not by glob | VERIFIED | `Cargo.toml` l.2 |
| 24 | `turing` declares its 12 modules in `lib.rs` | VERIFIED | `crates/turing/src/lib.rs` l.6-17 |
| 25 | `SecretBox`, `Zeroable` (pub unsafe trait), `burn_stack` are public; `Zeroable` is implemented only for u8, u64 and arrays | VERIFIED | `memory.rs` l.32-35, 38, 131 |
| 26 | `ShieldedKey` holds a 32-byte shielded key and a 16 KB prekey | VERIFIED | `shield.rs` l.23, 32-35 |
| 27 | `BURN_BYTES` = 32 KB, sized as "several times the deepest key setup" | VERIFIED | `memory.rs` l.122-124 |
| 28 | `memscan::stack_depth` paints 256 KB and returns the deepest changed word | VERIFIED | `memscan.rs` l.193-217 |
| 29 | SecretBox pages: ML-KEM-768 dk 1 page, FrodoKEM-976 sk 8, FrodoKEM-1344 sk 11; FrodoKEM-1344 n x n-bar int16 matrix 21,504 bytes (0.66 x BURN_BYTES), FrodoKEM-976 15,616 (0.48), ML-KEM-768 A-hat 4,608 | COMPUTED | `timeout 60 python research/scripts/pq/tic_sizes.py`, sections 4-5 |
| 30 | ML-KEM and FrodoKEM key and ciphertext sizes recomputed from the formulas match FIPS 203 Table 3 and the FrodoKEM proposal's Table A.5 | COMPUTED | `tic_sizes.py` sections 1-3 (inputs: FIPS 203 PDF p.48 Tables 2-3; FrodoKEM proposal PDF p.15-16 Tables A.1, A.2, A.5) |
| 31 | Of 8 keys straight from ProcessPrng, 2 to 4 left fragments per run; of 8 from `new_key`, none | VERIFIED (as the repository's own measurement; not re-run here) | docs/13 l.152-184 |
| 32 | SP 800-90C contains no occurrence of "SHAKE", "XOF" or "KMAC" | COMPUTED | `timeout 300 python research/scripts/pq/tic_source_checks.py` (whole-document search of nist-sp800-90c-rbg-constructions.pdf) |
| 33 | FIPS 203: further symmetric keys "shall be derived ... in an approved manner, as specified in SP 800-108 and SP 800-56C" | VERIFIED | nist-fips-203 PDF p.25, section 3.3 |
| 34 | memscan searches aligned 8-byte fragments, stored XORed with a random pad | VERIFIED | `memscan.rs` l.8-11, 41-90 |
| 35 | CBD eta = 2: 2.031 bits per coefficient; P(8-byte int16 fragment all zero) = 0.0198; expected 3.80 zero fragments in ML-KEM-768 s; 64 bits of entropy need 32 coefficients (64 bytes) | COMPUTED | `tic_sizes.py` section 6 |
| 36 | dudect classes are all-zero against random inputs; leak threshold max \|t\| > 4.5 | VERIFIED | `timing.rs` l.50-52, 55-66 |
| 37 | `asm_branches.py` lists conditional jumps or indexed loads and has no division scan | VERIFIED | `tools/asm_branches.py` l.1-64 (whole script read) |
| 38 | KyberSlash: "gcc 14.1.0 from May 2024 produces division instructions even when it is optimizing for speed" | VERIFIED | 2025-bernstein-et-al-kyberslash.pdf PDF p.2 (tic_source_checks.py) |
| 39 | ByteEncode_12 of uniform values mod 3329: mean bit 0.47429, top bit 1281/3329 = 0.38480; expected monobit s_obs 52.65 on 2^20 bits (certain rejection) | COMPUTED | `timeout 60 python research/scripts/pq/tic_encoding_bias.py`, section 1 |
| 40 | Compress_10 of uniform values: each 10-bit value has 3 or 4 preimages; monobit expected to pass; a chi-square against uniform rejects after about 5,915 coefficients (normal approximation of the chi-square statistic, so approximate) | COMPUTED | `tic_encoding_bias.py`, sections 2 and 2b |
| 41 | Compress_d = round((2^d/q) x) mod 2^d, ties rounded up; ByteEncode writes LSB first | VERIFIED | nist-fips-203 PDF p.30 eq. (4.7); p.15 notation; p.31 Algorithm 5 |
| 42 | FIPS 203 Table 2: n = 256, q = 3329; k = 2/3/4; eta1 = 3/2/2; eta2 = 2; (du, dv) = (10,4)/(10,4)/(11,5); RBG strength 128/192/256 | VERIFIED | nist-fips-203 PDF p.48, Table 2 |
| 43 | `bombe attack` has 21 sections | VERIFIED | `campaign.rs` l.157-887 |
| 44 | Bombe has 38 modules and 15 integration-test files | COMPUTED | `tic_repo_facts.py` section 7 |
| 45 | X-Wing aims at "128 bits" (NIST PQC level 1) and uses ML-KEM-768 for margin | VERIFIED | ietf-draft-connolly-cfrg-xwing-kem-11.txt section 1.2, lines 183-186 |
| 46 | draft-irtf-cfrg-concrete-hybrid-kems-04 is dated 6 July 2026, expires 7 January 2027, and defines exactly MLKEM768-P256, MLKEM768-X25519 and MLKEM1024-P384 | VERIFIED | ietf-draft-irtf-cfrg-concrete-hybrid-kems-04.txt header lines 7-9, contents lines 94-96, sections 4.1-4.3 |
| 47 | Concrete hybrids: MLKEM768-P256 Nek 1249 / Nct 1153; MLKEM768-X25519 1216 / 1120; MLKEM1024-P384 1665 / 1665; Nelem P-256 65, P-384 97, Curve25519 32 | VERIFIED, and recomputed | concrete-hybrid-kems-04 sections 3.1, 4.1-4.3; `tic_sizes.py` section 7 |
| 48 | KEM ciphertext per recipient: X-Wing + FrodoKEM-976 16,912 bytes; X-Wing + FrodoKEM-1344 22,816 bytes | COMPUTED | `tic_sizes.py` section 7 |
| 49 | ML-KEM-1024 has k x n = 4 x 256 = 1024 secret coefficients; FrodoKEM-976 has n = 976 | VERIFIED (inputs), product COMPUTED | FIPS 203 PDF p.48 Table 2; FrodoKEM proposal Table A.1 |
| 50 | `mutate.py --step9` plants bugs in key-handling code (first entry "xof: secret cSHAKE drops its label") | VERIFIED | `tools/mutate.py` l.69-71 |
| 51 | docs/13 section 8 lists four requirements for the file tool | VERIFIED | docs/13 l.385-396 |
| 52 | `self_test` uses vectors 0 and 2 of `vectors/turing-v2.txt` and NIST cSHAKE256 sample #3 | VERIFIED | `selftest.rs` l.26-47, 50-71 |
| 53 | The checked calls check the key checksum, compute, run the inverse and compare, check again, and wipe the block on failure | VERIFIED | `cipher.rs` l.92-125 (`guarded`) |
| 54 | "We do not hand-build the combiner" is a recorded rule | VERIFIED | docs/03 l.16-17 |
| 55 | Turing is "never" to be used "as a hash building block" | VERIFIED | docs/08 l.70-71 |
| 55b | At HEAD `unsafe` occurs 24/6/3/2/1/1 times in memory/random/keyschedule/cipher/masked/xof.rs; `unsafe {` 23 times and `SAFETY` 26 times across them; docs/12's "one unsafe block" is a version-1 statement | COMPUTED | `timeout 120 python research/scripts/pq/tic_repo_facts.py`, section 8 (text counts, comments included) |
| 55c | X-Wing draft-11 offers `GenerateKeyPairDerand` (5.2.1) and `EncapsulateDerand` (5.4.1) "For testing" | VERIFIED | ietf-draft-connolly-cfrg-xwing-kem-11.txt lines 397-413, 473-493 |
| 55d | FIPS 203: Encaps "shall not be run" on an unchecked ek; Decaps not on an unchecked dk or ciphertext; key checks may be assured "through other means (see SP 800-227)"; ciphertext checking on every Decaps | VERIFIED | nist-fips-203 PDF p.45-46, sections 7.2-7.3 |
| 55e | OpenPGP RFC 9980 specifies ML-KEM-1024 + X448 with an X-Wing-style combiner; TLS (RFC 10024) specifies SecP384r1MLKEM1024 | UNVERIFIED here | taken from the hybrid-combiners note (lines ~396, 698, 802 of that file on 2026-09-27); settle by reading RFC 9980 section 4.2 and RFC 10024 directly |
| 56 | 104 line-number citations in this file point at the text they describe at HEAD; three shifted citations are rejected | COMPUTED | `timeout 120 python research/scripts/pq/tic_line_check.py` (exit 0) |

## Open questions

1. **Does cSHAKE256 post-processing of an approved RBG's output satisfy
   FIPS 203's "generated using an approved RBG"?** SP 800-90C has no XOF
   construction (ledger 32). Would settle it: NIST SP 800-133 (key
   generation, which discusses post-processing RBG output) or CMVP
   implementation guidance, neither read for this file. It only matters if
   the KEM component is meant to be conformant.
2. **Which route to "about 1000 dimensions"** (section 11): keep X-Wing,
   MLKEM1024-P384, ML-KEM-1024 + X25519 through the generic framework, or
   X-Wing plus FrodoKEM. The owner decides, with evidence from the
   hybrid-combiners, pq-families-for-diversity and attack-cost-estimation
   notes.
3. **Page-lock limits for large secrets.** Will Windows' default minimum
   working set and a typical Linux RLIMIT_MEMLOCK lock an 8- or 11-page
   FrodoKEM key beside Turing's own pages? Settle by measuring
   `SecretBox::locked()` on the target systems.
4. **Stack depth of a real KEM implementation.** Settle with
   `memscan::stack_depth` on KeyGen, Encaps and Decaps of the chosen code,
   then size the burn from it.
5. **Seed or full key at rest.** Storing the shielded 64-byte seed (d, z)
   and re-running `KeyGen_internal` on every decapsulation (FIPS 203 PDF p.26
   allows it) keeps less secret material in memory but costs a key
   generation each time. That cost is not measured.
6. **An external KEM crate's memory behaviour** (option C). Settle by
   reading its source for buffers and running `memscan` against it
   (rust-pqc-implementations note).
7. **Where KEM known-answer files should live.** `vectors/` is in the cipher
   work's area; the design phase should agree the path before adding files.
8. **Precision of the chi-square estimate** in ledger row 40. It uses a
   normal approximation. An exact noncentral chi-square computation or a
   seeded simulation would pin it down; the conclusion (a few thousand
   coefficients, far below one battery sequence) does not depend on it.
