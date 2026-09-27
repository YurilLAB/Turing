# Review: the crypto-sensitive code of the turing crate (HEAD 7aa052d)

Reviewer: independent reviewer, 2026-09-28. Read-only on the repository; this file is the
only thing written into it. Scope: every module of crates/turing/src (cipher, key schedules,
S-box and GF arithmetic, linear layers, masked cipher, memory, randomness, cSHAKE, key shield,
self-test, lwe, Turing-1026, ML-KEM), the Bombe code the claims rest on, docs/13, 15, 16, 17
and 18, tools/ct_check.py and the CI workflow. `crates/`, `docs/`, `vectors/` and the Cargo
files are identical at 749fde2 and 7aa052d (the history rewrite between them touched only the
README, research notes and the wording of tools/ci.py and tools/CI.md), so the line numbers
below hold for both.

The review was done twice, independently, with separate code, and the results compared. Each
finding says how it was established: "reproduced" means both reviews got the result, each with
its own program (kept in `research/workfiles/review-crypto/`, local and gitignored); findings
established once, or by reading, say so. Builds: rustc 1.94.1 x86_64-pc-windows-msvc, release
profile, with and without the `analysis` feature as stated. Baseline: `cargo test --release --workspace --locked`
passes at 7aa052d (turing 106 unit tests, bombe 76, every integration test; 3 long tests
ignored), and `cargo test -p turing --release` (no `analysis`) passes 106 + 3 doc tests.

## Summary

| # | Severity | Kind | Where | One line |
|---|---|---|---|---|
| R1 | major | bug | turing1026.rs:415-427 (`drop(x)` at 422), 380-389 | After `from_seed` / `generate` the pair-wise check's cSHAKE state, which absorbed the secret seed, is left whole in dead stack; one inverse Keccak-f gives the seed, i.e. the whole Turing-1026 private key |
| R2 | major | bug (fault model) | turing1026.rs:271-273, 500, 508, 526-533 | The release build merges the two "independent" re-encryption verdicts into one mask (one `sarq $63`, one select), so one fault accepts an invalid ciphertext |
| R3 | major, latent | bug | mlkem.rs:479-485, 498-520, 307-317, 323-328 | Every ML-KEM operation leaves secrets in dead stack (K and r after encapsulation, r' and the J(z ‖ c) state after decapsulation); no stack burn. Nothing in production calls ML-KEM yet |
| R4 | minor | bug | keyschedule.rs:97-100, 112-115, 170-175; cipher.rs:109-125; turing256.rs:118-134; masked.rs:299-305 | Checked calls leave the checksum's secret point H and the stored check in dead stack; with H an attacker can compute faults that pass the check |
| R5 | minor | unsupported claim | docs/16:324-326; turing1026.rs:374-379, 415-427 | "Every single-bit flip in bits 0-13 of S ... is caught" is false: about 2^-8 of them pass the one-ciphertext pair-wise check, and the escaped key fails almost every decapsulation |
| R6 | minor | unsupported claim | docs/16:347-349; docs/17:189-191; bombe fault1026.rs:20-22; lwe.rs:232 | A single skipped `+ q/4` in the decoder is a key-recovery oracle (Pessl-Prokop); the docs name the z-skip as the only single-fault hole |
| R7 | minor | missing check | tools/ct_check.py:33, 44 | The KyberSlash assembly check lists `mlkem` but builds the production library, which contains no ML-KEM code: it has never read ML-KEM |
| R8 | minor | unsupported claim (still open, earlier review F7) | random.rs:27-30, 166-170 | Process-ID fork detection fails under PID reuse where MADV_WIPEONFORK is absent: a descendant with the seeder's PID draws the seeder's masks (reproduced on Linux) |
| R9 | minor | missing test | selftest.rs:3-6, 149-182 | `self_test()` never runs `MaskedTuring` or `MaskStream`: a masked S-box computing x^9, or masks repeating every 136 bytes, pass it |
| R10 | informational | missing input validation (analysis API) | mlkem.rs:31-38, 469, 480, 499 | Public `Params` fields and `assert!` on lengths: invalid parameter sets panic or silently break (k = 0 sends m in the clear) |
| R11 | informational | unsupported claim | README.md:112-113; docs/16:38, 313-316; memory.rs:10-13 | Locking is best effort: under default Windows limits the third key, and a new workspace once two keys exist, are not locked; the workspace's status is never reported |
| R12 | documentation | unsupported claim (still open, earlier review F9) | masked.rs:1-3, 16-17, 262-271; docs/13:229-230, 438-440 | Masked key setup runs unmasked; "every value it handles is independent of the key" overstates |
| R13 | documentation | inconsistency | docs/16:36, 97; shield.rs:15-16; docs/15:44, 108; docs/13:349-352 | "nine" labels (there are ten); "stack buffer" (it is a SecretBox); Turing-256's bound is 50/2^127, not unchanged; core-dump exclusion is Linux only; the GF(2^8) bound 4 is attained (earlier review F2) |

## Findings

### R1 — major — bug: the Turing-1026 seed is recoverable from dead stack after key generation

Status: reproduced (both reviews, separate probes and separate inverse permutations).

Where: turing1026.rs:415-427 (`pair_consistent`), 380-389 (`from_seed`), 369-372
(`generate`); xof.rs:137-141 (`SecretXof`'s `Drop`); memory.rs:155-168 (`burn_stack`).

```rust
// turing1026.rs:418-422
let mut x = SecretXof::new(KEY_CHECK_LABEL);
x.absorb(&self.secret.seed);
x.squeeze(&mut w.mu);
x.squeeze(&mut salt);
drop(x);
```

`drop(x)` moves the XOF into `drop`'s argument, so the wipe runs on the moved copy. In the
production build `pair_consistent` is inlined into `from_seed`, so the original 200-byte state
stays in `from_seed`'s own frame, and `burn_stack()` (called from `from_seed`) only overwrites
the stack below its caller. The state is S2 = f(S1 xor seed xor pad) with S1 the public
cSHAKE prefix state of "Turing-1026 v1 key check"; the squeezes read 96 < 136 bytes, so S2 is
final. Keccak-f[1600] is a permutation, so seed = (f^-1(S2) xor S1)[..32]: the single-seed key
design makes the seed the whole private key.

Evidence (`seedres/`, production build, no `analysis`): after `from_seed` for 10 of 10 seeds,
and after `generate()`, the whole S2 is found in the dead stack (a different seed's S2: 0 hits;
a planted copy is found). An inverse Keccak-f written from FIPS 202 section 3.2 (checked:
forward equals `keccak::f1600` and f^-1(f(s)) = s on 200 random states), run blind over every
8-aligned 200-byte window, returns exactly one candidate, the seed, and a key rebuilt from it
has the same public key. The second reviewer found the same from the release assembly:
`memcpy(376(%rbp) <- -88(%rbp), 216)`, only the copy zeroed, then `callq burn_stack`.

This contradicts docs/16:38 ("no residue"), docs/16:313-323 ("even with the stack burn turned
off"), turing1026.rs:379 and xof.rs:74-76. Bombe misses it because its needles are raw secret
bytes, not sponge states, and because the `analysis` build does not inline `pair_consistent`.
The stack is not locked memory, so the state can also reach the page file.

The same `drop(<SecretXof>)` pattern is at turing1026.rs:407 (`noise`, absorbs the noise seed r)
and 521 (`h`, absorbs z). Both are wiped or burned in today's build (not found), but only
because the compiler elided the move or the frame lies below a burn.

Fix: drop sponges in place (let them fall out of a block scope, or give `SecretXof` a
`wipe(&mut self)`), mark `pair_consistent` `#[inline(never)]` so its frame is below the burn,
and add sponge-state needles (the state a known secret produces) to Bombe's scans, run on a
non-`analysis` build.

### R2 — major — bug (fault model): the two re-encryption verdicts are one mask in machine code

Status: reproduced (both reviews read the single `sarq` in their own builds); the skip emulation is the second review's.

Where: turing1026.rs:271-273 (`zero_mask`), 500, 508, 526-533 (selection); claims at
docs/16:343-346, docs/17:187-191, turing1026.rs:289-293, 467-478, bombe fault1026.rs:16-21.

```rust
// turing1026.rs:530-531
let tmp = *out ^ ((*out ^ k) & accept_bytes);
*out ^= (*out ^ tmp) & accept_coeffs;
```

Algebraically this is `out ^= (out ^ k) & (accept_bytes & accept_coeffs)`, and LLVM compiles it
that way. In the production assembly of `decapsulated_faulted` (`asm/`) the byte verdict is
`decq %rsi` after the barrier (spilled to 728(%rbp)), the two coefficient verdicts are `decq
%rdi; decq %rbx; andq %rdi, %rbx`, and the three meet in `andq 728(%rbp), %rbx; sarq $63, %rbx`: the function's only
`sar`, followed by one `xorb/andb %bl/xorb` select per key byte. One fault on that `sar`, on
bit 63 of `%rbx` or on `%bl` installs K' for an invalid ciphertext. The second reviewer's
emulation: with C[0] xor 0x80 (same decoded message) and the `sarq` skipped, the mask is 0x7f and
224 of the 256 output bits are K'. The two re-encryptions do survive (two `call reencrypt`).

The fault map does not see this because it runs the `Faults` monomorphisation, whose opaque
hooks keep the verdicts apart; the production `NoFault` code is a different compilation.

Fix: pass each verdict, and `tmp`, through `opaque` (a value barrier) so the selections cannot
be fused (checked in isolation: two `sarq $63`, two selects, still branch-free), and add a CI
assembly check for it, or run the fault simulator of
research/notes/pq/side-channels-faults-and-ct-verification.md section 4.5 on the real function.

### R3 — major, latent — bug: ML-KEM leaves its secrets in dead stack

Status: reproduced for K and r; the recovery of m, K and z is the second review's.

Where: mlkem.rs:479-485 (`encaps_inner`), 498-520 (`decaps_inner`), 297-305, 307-317, 323-328.
`encaps_inner` never wipes `k` or the (K, r) pair `g` returns; `Digest`/`finalize_xof` move
the sha3 hashers (their buffers are not wiped; the crate's `zeroize` feature only wipes the
state on drop); nothing burns the stack, unlike turing1026.rs.

Evidence (`mlres/`, ML-KEM-1024 through the `analysis` API): after `encaps_internal` the dead
stack holds K twice and r three times; after `decaps_internal` r' twice; with `burn_stack` after
each call, nothing; a control call that never computes K leaves nothing. The second reviewer
(`mlkem/`) found the same counts for all three parameter sets, recovered m and K from r and the
public (ek, c), and recovered z (the implicit-rejection secret) by running a whole
J(z ‖ c) state back through the public ciphertext blocks. FIPS 203 section 3.3 (pp. 16-17):
"All other data shall be destroyed prior to the algorithm terminating."

Latent: production builds contain no ML-KEM code. It must be fixed before the hybrid calls it:
the turing1026 pattern (`#[inline(never)]` worker, `burn_stack()` in the caller), `k` zeroized,
and an ML-KEM case in bombe tests/memory.rs.

### R4 — minor — bug: checked calls leave the checksum's point H and the stored check behind

Status: reproduced for H and the check; the crafted passing fault is the second review's.

Where: keyschedule.rs:97-100 (`checksum`), 112-115 (`sealed_check`), 170-175 (`intact`, whose
`now` is never wiped), run twice per checked call from cipher.rs:109-125, turing256.rs:118-134,
masked.rs:299-305 and 361-387. Only key setup is followed by a burn.

keyschedule.rs:91-93 and 118 say the point must stay secret ("at a public point the attacker can
solve for faults that cancel"; "As secret as the key"). Evidence (`residue/`): after
`encrypt_block_checked` and after `decrypt_block_checked`, both 8-byte halves of H and the whole
stored check are in dead stack, for 20 of 20 random keys; `burn_stack` afterwards leaves none;
plain `encrypt_block` and `Turing::new` leave none. The second reviewer used a leaked H to build
a fault (one bit of RK_23 plus the 69 bits of H^24 x^5 in the stored check) that passes the
checked call and releases a one-byte-wrong ciphertext (a last-round DFA pair). Minor, because
docs/11:84-87 already concedes that encryption states stay on the stack, and exploiting H needs
a stack read and a precise multi-bit fault.

Fix: zeroize `now` (and `a`, `b` in `MaskedTuring::intact`), keep the checksum in a non-inlined
function and burn the stack after each checked call; add H and the check to Bombe's needles.

### R5 — minor — unsupported claim: the pair-wise check misses about 2^-8 of single-bit faults in S

Status: reproduced (random sampling here, full sweeps in the second review).

docs/16:324-326: "Every single-bit flip in bits 0-13 of S between expansion and the pair-wise
check is caught". One check ciphertext decides it: a flip of S[k][j] moves column j of C - B'S
by B'[r][k] 2^b in each of the 8 rows, which flips each decoded bit with probability about 1/2,
so a flip escapes with probability about 2^-8. Bit 14 (q/2) behaves the same and is not
mentioned. Evidence (`pairwise/`, through `from_seed_with_fault`): 10 of 3,000 random flips in
bits 0-13 pass (0.33%), 3 of 1,000 flips of bit 14 pass; every escaped key keeps the published
public key and decapsulates 99-100 of 100 honest ciphertexts to the wrong key, the setting of
Fahr et al. ("When Frodo Flips"). The second reviewer measured 0.30-0.49% over four full sweeps
(459,648 flips each). The test (bombe tests/turing1026.rs:121-129) tries 4 positions.

Fix: a deterministic check, as Fahr et al. (CCS 2022, section 8.2) recommend for FrodoKEM:
recompute B from (seed_a, S, E) and compare, or check B - AS mod q in [-18, 18]; otherwise
correct the claim.

### R6 — minor — unsupported claim: the decoder is a single-fault oracle

Status: derived in both reviews; emulated in the second.

Where: lwe.rs:232; docs/16:347-349; docs/17:189-191; bombe fault1026.rs:20-22. With the `+ q/4`
of one coefficient skipped, the decoded bit is right exactly when that coefficient's noise e_j
is >= 0, for either message bit, so decapsulation of a valid ciphertext returns K' or the
rejection key according to the sign of e_j, a linear function of (S, E) with known
coefficients. That is Pessl and Prokop's effective/ineffective fault attack (TCHES 2021(2),
abstract and section 7.1), which "many forms of double execution" do not stop. The second
reviewer's emulation agreed in 512 of 512 trials. The project's own note already records it
(research/notes/pq/side-channels-faults-and-ct-verification.md, finding 9 and section 4.2,
line 162, and its recommendation at line 312); docs/16 still says the z-skip is the only single
fault hole.

Fix: list the decoder in the fault model's residual holes; shuffling the decode order or
decapsulating only authenticated ciphertexts are the literature's mitigations.

### R7 — minor — missing check: the constant-time assembly check has never read ML-KEM

Status: reproduced.

tools/ct_check.py:33 lists `mlkem`, but line 44 builds `cargo rustc -p turing --release --lib`
without `analysis`, where every ML-KEM function is unused: rustc warns "never used" 37 times,
the assembly has 0 `mlkem` symbols, and the check reports "28 lattice functions", all lwe and
turing1026. The ML-KEM commit message says the check covers ML-KEM. The property holds today:
an `analysis` build has 0 `div`/`idiv` in all 14 emitted ML-KEM functions, and its message
decode and Compress are multiply-and-shift; the second reviewer planted `v / black_box(Q)` in
Compress and ct_check still passed the production build. Fix: also check an `analysis` build,
and fail when a listed module contributes no function.

### R8 — minor — unsupported claim (earlier review F7, still open): PID reuse defeats fork detection

Status: by reading; reproduced on Linux twice, by two separate programs.

random.rs:166-170 compares only the process ID, while random.rs:29-30 says a stream used
directly is "fork-safe on every platform, whatever the kernel said to MADV_WIPEONFORK". Where
MADV_WIPEONFORK is missing (macOS, the BSDs, Linux before 4.14 or a kernel that refuses it), a
process A seeds a stream and forks B; A draws and exits; B never draws and forks C, which gets
A's PID; C's public `fill()` does not reseed and draws exactly the bytes A drew. Both programs
used the unmodified library in WSL2 (Linux 6.18) as PID 1 of a new PID namespace, `ns_last_pid`
to hand C A's PID, and a seccomp filter that returns EINVAL for MADV_WIPEONFORK, as a kernel
before 4.14 does. Each got C = A's masks in 3 of 3 runs; the controls differ (C with a fresh PID;
the same run with MADV_WIPEONFORK granted, where the wipe, not the PID check, saves it)
(`pid-reuse/`, `symmetric/pidreuse/`, `symmetric/pidreuse.out`). `MaskedTuring` uses the same
check. Fix: a fork-generation counter bumped by a `pthread_atfork` child handler, and
`minherit(INHERIT_ZERO)` on the BSDs; or narrow the claim.

### R9 — minor — missing test: no known answer for the masked cipher or the mask stream

Status: by reading; mutation-tested in the second review.

selftest.rs:3-6 says a miscompiled or corrupted build "fails here", but `self_test()`
(selftest.rs:149-182) runs only cSHAKE, `Turing`, `Turing256` and Turing-1026. `MaskedTuring`
has its own composition (`sec_mult`, `refresh`, `sec_exp254`, the affine maps on two shares) and
`MaskStream` its own Keccak loop, and neither is called. Mutants on a copy of the crate
(`symmetric/mut/mutants.out`): the masked S-box without its output constant, `sec_exp254`
computing x^9, and a mask stream that never permutes (masks repeating every 136 bytes) all leave
`self_test() = Ok(())`, although the first two make `MaskedTuring` disagree with `Turing` on 16
of 16 blocks; the controls (a cSHAKE, an S-box and a SecretXof mutant) give `Err(Xof)`,
`Err(Encrypt)`, `Err(Kem)`. Fix: one masked encryption and decryption of a vector, and a
fixed-seed `MaskStream` draw, in the self-test.

### R10 — informational — the analysis-only ML-KEM API does not validate its inputs

Status: the second review's harness; the k = 5 and eta1 = 4 panics also follow from reading (arrays of MAX_K = 4, a 192-byte buffer).

`Params` has public fields and the internal functions `assert!` lengths: k = 5 and eta1 = 4
panic, du = 12 and dv = 0 give the two sides different keys, and k = 0 sends m in the clear
(second reviewer's `harness panics`). Production exposes none of it; the hybrid should take a
closed parameter enum and return errors on wrong lengths (FIPS 203 section 7).

### R11 — informational — locking is best effort and the workspace's status is never reported

Status: reproduced.

`seedres/src/bin/locks.rs`, default Windows limits: `keys_locked()` is true for the first two
Turing-1026 keys and false from the third; with two keys alive a new Workspace-sized
`SecretBox` (message, coins, S', the re-encryption) is not locked, and no API reports it. The
second review (`symmetric/lockquota.out`) measured a 200 KB minimum working set, about 44
one-page locks per process, a key's secret taking 17 pages and a workspace 13, and found
`locked()` equal to the OS's Locked bit (QueryWorkingSetEx) every time: the flags tell the
truth; the docs do not. memory.rs:10-13 and docs/13 document best effort; README.md:112-113
("Keys live in locked memory") and docs/16:38 and 313-316 say it without the qualification.
Microsoft's VirtualLock remarks: "Applications that need to lock larger numbers of pages must
first call the SetProcessWorkingSetSize function", which the library never does. Fix: qualify
the claims, or raise the minimum working set once at start-up.

### R12 — documentation (earlier review F9, still open): masked key setup is unmasked

Status: by reading.

masked.rs:262-271 runs `keyschedule::expand` in the clear and XORs plain round keys with masks;
masked.rs:1-3 and 16-17 and docs/13:229-230 and 438-440 say every value is shared, the key never
sits in memory as itself, and every value handled is independent of the key. Say that masking
covers encryption, decryption and the integrity checks, not key setup.

### R13 — documentation

Status: by reading; the GF(2^8) roots recomputed in both reviews.

- docs/16:36 and 97 say "nine" labels; there are ten (turing1026.rs:68-76 and
  `lwe::MATRIX_LABEL`), all distinct.
- shield.rs:15-16 says the key is unshielded "into a stack buffer"; `with_key` uses a SecretBox.
- docs/15:44 says the fault check is "unchanged (docs/13)"; over 50 stored blocks the bound is
  50/2^127, not docs/13's 25/2^127.
- docs/15:108 says the round keys are "excluded from core dumps"; that is Linux and Android only.
- docs/13:349-352 ("no fault tried passed at more than 3 ... the bound is 4"): the bound is
  attained, e.g. E = (80, bd, bb, 55), e = 39 has the four odd roots 11, 79, 87, bf in
  GF(2^8)/0x11b (recomputed); the check is still not in the repository (earlier review F2).

## Checked and correct

- **ML-KEM against FIPS 203 Algorithms 3-18**, line by line: parameter sets, ByteEncode/Decode
  (mod q for d = 12), Compress/Decompress (exact, round half up), SampleNTT (rho ‖ j ‖ i, 12-bit
  rejection), SamplePolyCBD, NTT and inverse (both tables equal Appendix A, x 3303), BaseCaseMultiply
  gammas, K-PKE with G(d ‖ k) and the transpose of A, dk layout, (K, r) = G(m ‖ H(ek)), implicit
  rejection J(z ‖ c) with a masked select, the section 7.2/7.3 checks. vectors/ml-kem-fips203.txt
  is byte-identical to the upstream ACVP and CCTV files; Wycheproof 1,725 of 1,725 pass;
  planted comparison bugs (skipping the last 32 bytes, the last byte, comparing c1 only, a
  16-byte hash check) are all caught by the vector test.
- **Turing-1026 against docs/16 and FrodoKEM**: seed expansion, matrix rows, CBD(18) (popcount,
  no rejection, no bias), B = AS + E, sizes (static asserts), packing a bijection (every field
  used, so no bit to reject), the salted FO transform (whole ciphertext and k in K, H(pk) in the
  coins and in the rejection key), decapsulation re-deriving exactly as encapsulation, the byte
  and coefficient comparisons cover everything with no early exit (the Guo-Johansson-Nilsson
  `memcmp` flaw is absent), decode equals FrodoKEM's dc including ties, `refkem1026.rs` agrees.
- **Constant time in the release assembly**: no division in lwe, turing1026 or (analysis build)
  ML-KEM; every conditional jump in decryption, sampling, packing, decapsulation, `sub8`,
  `inv8`, the mixing layers, `mul128` and `sec_mult` tests a counter, length, bound, round, fault
  result or the XOF position; Encode is `bt; setb; shl; add` and ML-KEM's ByteDecode_1 branches
  only on its bit counter (no Clangover-style branch on a message bit); indexed loads use counters.
- **Ciphers**: an independent Python implementation re-derives every constant from its cSHAKE
  label and reproduces all 16 known-answer vectors, every round key and every round state; every
  path (plain, checked, masked, masked-checked, Turing-256) inverts on 300 keys x 8 blocks and at
  every round count; `mul128`, `mul8`, `inv8`, `sub8` match Python on 27,144 inputs; the GCM
  polynomial is irreducible.
- **Fault checks**: earlier review F1's reset faults (and 14 other reset, stuck-at-one and copy
  variants) are caught in the plain, Turing-256 and masked checks; 100 of 100 key flips between
  the two checks are caught; a detected fault wipes the block and its copies.
- **Masking**: matches Rivain-Prouff Algorithms 1, 3 and 4 (d = 1); constants in one share,
  fresh randomness per multiplication, linear layers share by share, recombined only for output.
- **cSHAKE**: SecretXof's bytepad, left_encode and 0x04 ... 0x80 padding; all three paths
  (`cshake256`, `cshake256_secret`, `SecretXof`) give NIST SP 800-185 samples #3 and #4, and
  agree with an independent Python Keccak (itself equal to hashlib's SHA3-256 and SHAKE256) on
  2,736 cases (19 labels up to 8,193 bytes, inputs and outputs across block boundaries, parts),
  with a planted mismatch reported (`symmetric/xofvec.out`, `symmetric/cshake_ref.py`).
- **Randomness**: getrandom 0.4.3's Windows back end returns an error unless ProcessPrng returns
  TRUE (read in the crate source), `os_random` maps every error to `RandomnessError`, and every
  constructor propagates it: nothing falls back to a fixed seed.
- **Key shield**: earlier review F6's fix is complete; no mask array is returned by value in
  `new`, `refresh` or `with_key` (assembly), and Bombe's `shield_mask_is_nowhere_in_memory` and a
  separate scan find no stray fragment.
- **Stack burns**: every public entry point that hashes a secret ends in `burn_stack` in both
  builds (`Turing::new`, `Turing256::new`, `MaskedTuring::new`, `ShieldedKey`, `new_key`,
  `DecapsulationKey::{from_seed, generate, decapsulate}`, `encapsulate`); a scan for whole Keccak
  states finds the secret hashes' output without the burn and nothing with it. R1 is the one
  place where the state sits in the caller's own frame, above the burn.
- **Dependencies**: RustSec lists no advisory for sha3, getrandom or zeroize; keccak's only one,
  RUSTSEC-2026-0012 (the opt-in ARMv8 `asm` feature), is fixed in the locked 0.1.6.
- **The `analysis` feature**: all 25 analysis-only items are unreachable without it.

## Method and evidence

research/workfiles/review-crypto/ (local):
- `seedres/`: production-build probe for R1 (dead-stack snapshot, S2 search, `invkeccak.rs`
  inverse Keccak-f and blind recovery) and R11 (`src/bin/locks.rs`).
- `asm/decapsulated_faulted.production.s`: R2.
- `mlres/`: R3. `mlkem/`: the second reviewer's harness, residue tables, `keccak_invert.py`,
  `recover_from_r.py`, vector and Wycheproof checks.
- `residue/`: R4. `pairwise/`: R5 (logs `run-0-13.log`, `run-14.log`).
- `t1026-logs/` and `t1026-src/`: the second reviewer's Turing-1026 logs and probes (residue,
  sar skip, decoder emulation, pair-wise sweeps, locking, the barrier fix checked in isolation).
- `pid-reuse/` and `symmetric/pidreuse/`: R8. `symmetric/mut/`: R9's mutants.
- `symmetric/`: cSHAKE cross-checks, residue and lock-quota probes. `cipher/`: the cipher
  probes (residue, crafted fault, fault resets) and the independent Python reference.
- `logs/baseline-release.log`: the release test suite at the start.

## Fixes

Every finding is fixed in the commit after this review. The major ones have several independent
defences, each enough on its own for the bug found; every defence has a test or a check, and a
planted bug that undoes it is caught (`tools/mutate.py --review2`, 17 planted bugs). The new
residue tests were also run on the unfixed code, where they fail for the reason found here.

| # | Fix | Evidence |
|---|---|---|
| R1 | (1) `SecretXof`'s state lives in its own locked allocation, never on the stack, so a move moves a pointer; (2) `wipe()` clears it in place and refuses reuse, and every `drop(<XOF>)` is gone; (3) `from_seed` runs its work (expansion and both checks) in an `#[inline(never)]` frame below the burn, `pair_consistent` is `#[inline(never)]`, `new_key` likewise; (4) `cshake256_secret` runs on `SecretXof`, so no secret path uses the sha3 crate's by-value states | `no_sponge_state_is_left_on_the_stack` records every secret sponge's final state and searches dead stack after `from_seed`, `generate`, `encapsulate`, `decapsulate` (valid and rejected), with a planted-copy control; on the unfixed code it fails ("from_seed: sponge state 1 of 10 is in dead stack"). `secret_xof_state_lives_off_the_stack`, `wipe_clears_the_state_in_place`, `secret_xof_refuses_use_after_wipe` |
| R2 | (1) the selections are separate `#[inline(never)]` functions (`select_into`), the mask behind a value barrier inside; (2) a third verdict (the second run packed and compared as bytes) binds the accepted key: `bind_to_verdict` makes it cSHAKE256(c ‖ k' ⊕ K̄) unless that verdict accepts; (3) `tools/ct_check.py` fails unless the release build derives three masks and calls `select_into` twice and `bind_to_verdict` once | production asm: three `sarq $63` in three registers feeding three calls; `ct_check.py` on the unfixed build: 3 failures. Fault map: forcing both selection verdicts now gives denial of service; a bypass takes two correlated faults on the data side or three verdicts. Planted bugs: binding removed, binding verdict forced, binding reading the first run (fault map); selections fused, `select_into` inlined (`ct_check.py`) |
| R3 | (1) G, J and PRF hash on `SecretXof`; (2) K and r are written straight into the caller's buffers and wiped; (3) `mlkem::keygen/encapsulate/decapsulate`, the entry points the hybrid will call, run below a stack burn, as do the analysis wrappers | `entry_points_leave_no_secret_on_the_stack` (K, r and every sponge state, all three parameter sets, with a control) |
| R4 | `intact()` wipes the recomputed check (and the masked `a`, `b`); every checked call (Turing, Turing-256, masked) runs `guarded` in an `#[inline(never)]` frame and burns the stack after it | `checked_calls_leave_no_checksum_point_behind` for all three ciphers, with a control; on the unfixed code it fails ("encrypt_block_checked left H or the check") |
| R5 | `lwe::check_key`: B − A·S must lie in [−η, η] everywhere (branch-free), run with the pair-wise check at every key generation | `check_key_catches_every_single_bit_fault_in_s` (exhaustive on a small set), `faults_the_pair_wise_check_missed_are_caught` (the 8 escapes found here: the pair-wise check alone passes them, both checks refuse them), 240 random flips in bits 0-14 in Bombe; cost 29 → 37 ms per key generation |
| R6 | docs/16, docs/17 and fault1026.rs list the decoder (Pessl-Prokop) as the second single-fault hole, with the literature's mitigations | documentation |
| R7 | `ct_check.py` reads ML-KEM in an `analysis` build and fails when a listed module has no function in its build | a division planted in Compress now fails in two functions (the old check passed it) |
| R8 | a fork generation, moved on in every child by a `pthread_atfork` handler, is compared with the process ID (and, on Linux, the MADV_WIPEONFORK pages) | `a_fork_child_reseeds_even_when_its_pid_matches`, `fork_generation_moves_on_only_in_the_child` (Linux, in WSL) |
| R9 | `self_test()` runs `MaskedTuring` on the known-answer vectors with OS masks, and a fixed-seed `MaskStream` draw against cSHAKE256 | the x^9, missing-constant and never-permuting mutants now fail `self_test` |
| R10 | `mlkem::Params` has private fields: only the three FIPS 203 sets exist; the entry points return `InputError` for wrong lengths, a key failing the modulus check, a key failing the hash check | `entry_points_refuse_bad_inputs` |
| R11 | a refused lock grows the limit once (Windows working set, Linux soft RLIMIT_MEMLOCK, at most 64 MB) and retries; `memory::unlocked_allocations()` counts what stayed unlocked; README and docs/16 qualified | `secrets_beyond_the_default_quota_are_locked_on_windows` (24 × 64 KB), `linux_raises_the_soft_memlock_limit` (with a hard-limit control) |
| R12, R13 | masked.rs and docs/13 say key setup is unmasked; ten labels; `with_key`'s SecretBox; docs/15's bound and core-dump note; docs/13's GF(2^8) bound, now reproduced by `research/scripts/gf8_checksum_bound.py` | documentation, the script |

CI: a `production` stage and workflow step test the library without `analysis` (the build users
get, where R1 lived), and `--review2` joins the planted-bug sets.

## Follow-up: the decoder and rejection-key faults closed

R6 and the z-skip fault docs/16 named were single faults that leak without any bypass. Both are
now closed in code, each by more than one defence, and each defence is shown to hold on its own.

| Fault | Defences | Evidence |
|---|---|---|
| Decoder (R6): skipping one coefficient's `+ q/4` told the sign of its noise (Pessl-Prokop) | (1) three decryption passes, each computing C − B'S afresh, and a bitwise majority (`decrypt_voted`, `majority`); (2) each pass decodes in its own random order, a Fisher-Yates shuffle with no secret-dependent branch or memory access (`shuffle_order`), drawn from cSHAKE256 of z, a per-key decapsulation count and 32 OS bytes (`randomness`), each source enough on its own; (3) `ct_check.py` fails unless the release build calls `decode_pass` three times, each pass `decrypt_values` and `shuffle_order`, and the vote | Fault map: 0 of 768 single skipped roundings and 0 of 768 single arithmetic faults (C − B'S shifted by −q/4 at one coefficient of one pass) change a valid ciphertext's result; its control (one pass in order, as before) changes exactly the 128 coefficients of 256 whose noise is negative. With the vote skipped, the outcomes follow the noise signs by index at chance level (128 of 256). The boundary, measured and asserted: two faults aimed at one coefficient's arithmetic in two passes leak its sign, since C − B'S runs in a fixed order (the check's cheapest bypass also takes two faults). Unit tests: `shuffled_orders_are_uniform_permutations` (chi-square and fixed points), `each_decapsulation_decodes_in_fresh_orders`, `each_source_of_the_orders_randomness_counts` (with a control), `voted_decryption_equals_plain_decryption` |
| Rejection key: skipping z in the hash made K̄ computable, a validity oracle | (1) K̄ computed twice, by separate non-inlined calls (`rejection_key`); (2) a disagreement XORs a fresh unpredictable value into it (`infect`, the verdict behind a value barrier); (3) `ct_check.py` fails unless the release build calls `rejection_key` twice and `infect` once | Fault map: z skipped in either computation gives denial of service, and forcing the agreement verdict alone does nothing; its control (one computation, as before) is a validity oracle; the cheapest validity oracle now takes two faults |

Cost: decapsulation 12.9 → 13.4 ms, medians of the release build on this machine.

Detectors for each class of bug the review found, so the next one of its kind fails a test
instead of waiting for a review:

- secrets in dead stack (R1, R3, R4): `crates/turing/src/residue_sweep.rs` runs all 30 public
  operations that handle a secret, in the analysis and the production build, and searches the
  stack each leaves for its keys, seeds, checksum points, shared keys and sponge states (two
  planted-copy controls);
- the optimiser merging a redundant computation (R2): `ct_check.py` checks every redundant
  computation the fault defences rely on, and the two key checks per direction of the checked
  calls, on Windows and on Linux-target assembly (where calls go through the GOT, a form the first
  version of the rules missed); `ct_check.py --self-test` runs each rule on synthetic assembly, one
  correct file and 12 broken ones, as a CI stage (`ct-self-test`);
- a check that never read its target (R7): one of those broken files leaves the lattice module
  out of the build;
- the self-test's coverage (R9): `self_test()` also runs ML-KEM-1024 against a vector from the
  independent Python reference;
- input handling (R10): `entry_points_never_panic_on_arbitrary_input`;
- locking (R11): `a_realistic_workload_stays_locked_on_windows`;
- the docs against the code (R13): `mathaudit.py` compares docs/16's label count and names with
  the labels the code defines (its negative control plants a wrong count).

`tools/mutate.py --review3` plants 28 bugs, each removing one of these defences or disarming one
of these detectors, and every one is caught by the test or check written for it: the fault map
for a lost pass, vote, fresh C − B'S or per-pass order, and for the rejection key computed once,
compared with itself, not infected or infected with zeros; the order tests for an unshuffled
order, each of the three sources of its randomness dropped, and Sattolo's off-by-one (which
usually passes the chi-square test; the fixed-point count catches it); `ct_check.py` for an inlined
pass, rejection key or infection; the residue sweep for the stack burn removed from `Turing::new`,
`new_key`, `ShieldedKey::refresh`, Turing-1026 encapsulation and ML-KEM decapsulation; the
self-test for an ML-KEM rejection bug; the entry-point tests for a skipped length check;
`mathaudit.py` for a stale label count; and the checker's self-test for its count rule and its
division pattern weakened. The voted decoder's own rounding is one of them, since round 7's
"decoding rounds down" now reaches only `lwe::decrypt`, which decapsulation no longer calls.
Round 7's two rejection-key bugs now plant into `rejection_key`, where the code moved.
