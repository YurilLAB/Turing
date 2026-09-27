# Review: Turing-256 (commit f0d771c)

Reviewer: independent reviewer, 2026-09-27.
Scope: commit f0d771c "Add Turing-256, the same design on a 256-bit block":
docs/15-turing-256.md, crates/turing/src/{turing256,keyschedule256,linear256,linear256_constants}.rs,
Turing-256 parts of structure.rs, lib.rs and selftest.rs, crates/bombe/src/{refcipher256,wide,attack256}.rs,
Turing-256 sections of campaign.rs, crates/bombe/tests/turing256.rs, vectors/turing-256-v1.txt.
All file:line references are to the files as of f0d771c (`git show f0d771c:<path>`). Later commits
(574a107, 023c205, 4c8f826) changed only campaign.rs, tests/turing256.rs, lib.rs and selftest.rs among
these files; the cipher, schedule, layers, constants, reference and vectors are unchanged at HEAD.

Status: COMPLETE (2026-09-27).

Severity: critical / major / minor / documentation. Kind: bug / wrong maths / unsupported claim / missing test / suggestion.

## Summary

No bug in the cipher, its constants or its key schedule was found. An independent Python implementation written
from docs/15 alone (with every constant rebuilt from its cSHAKE256 label) reproduces all 8 known-answer vectors,
all 25 round keys and all 24 intermediate states; the 32x32 MixState is exactly the Cauchy matrix it claims to
be and is MDS; every number in docs/15's analysis table recomputes. The findings are about tests and wording:

| # | Severity | Kind | Where | Problem |
|---|---|---|---|---|
| F1 | documentation | unsupported claim | docs/15:24, 27-29 | 2^(n/3) "quantum collision search on the block" presented as a limit of Turing's 128-bit block; the project's own notes say Q1 keeps 2^64 and 2^(n/3) applies only to Q2 MACs |
| F2 | minor | missing test | turing256.rs:53-67, 114-129 | second key check and decrypt-and-compare are never exercised; a mutant without both passes every Turing-256 test (run) |
| F3 | minor | missing test | campaign.rs:1337, residue.rs:36-39 | Turing-256 memory scan has no no-burn control and "clean" does not require finding the keys where they belong |
| F4 | documentation | unsupported claim | docs/15:63-64, derivations.md:294 | "46 structures" is 22 structures (44 comparisons) |
| F5 | documentation | unsupported claim | keyschedule256.rs:9-11, docs/15:44, 108, 130-131 | wrong command cited for the 67 bound; checksum bound is 50/2^127 not Turing's 25/2^127; core-dump exclusion is Linux-only; dudect 1.9 is one run; no ShieldedKey for Turing-256 |
| F6 | minor | missing test | wide.rs:296-308 and others | division ranges only sampled; no automated branch-free check; no spec-level checker; no domain-separation test |
| S1 | minor | suggestion | docs/15 analysis | Park et al. hull bounds for B = 33 (2^-198.0 / 2^-195.7, 5 rounds 2^-221.6 / 2^-211.8) not given; all above 2^-256 |

Process note: one of my experiments (the F2 mutant, built from a scratch copy of f0d771c in the shared
CARGO_TARGET_DIR=target/review) overwrote the repo's `turing` unit-test binary in that directory between about
17:12 and 17:17 local time; I cleaned the turing and bombe outputs there and rebuilt them from the repo. Details
under F2.

## Findings

### F1. The quantum-collision row and its conclusion contradict the project's own Q1/Q2 analysis
- Severity: documentation. Kind: unsupported claim.
- Where: docs/15-turing-256.md:24 (table row "Quantum collision search on the block (Brassard-Hoyer-Tapp,
  about 2^(n/3)) | about 2^43 | about 2^85") and :27-29 ("it removes the data limits that come from the block
  size, the part of a 128-bit design that quantum collision finding weakens most").
- Problem: presented without a query model, the row reads as a generic 2^43 limit on Turing's 128-bit block.
  The project's own research note (research/notes/pq/quantum-crypto-and-quantum-attacks.md, key finding 16 at
  :78-81 and section 5.7 at :574-593, sources L80 Saturnin spec and L81/L82) says the opposite for Turing's threat
  model: in Q1 (classical queries, NIST's model, key finding 5) the mode birthday bound stays at the classical
  2^(n/2) = 2^64 blocks; CTR keeps the classical birthday bound even in Q2; the 2^(n/3) figure applies only to
  feed-forward MACs/PRFs in Q2 (quantum PRP/PRF switching, Zhandry 2015), BHT needs 2^(n/3) quantum RAM, and once
  communication is costed no known quantum collision algorithm beats classical parallel rho (Bernstein, via
  Banegas-Bernstein). Key finding 6 also says Q2 "is a robustness margin, not Turing's threat model".
- Arithmetic is right (128/3 = 42.67, 256/3 = 85.33) and BHT is the right name for the 2^(n/3) collision
  algorithm; what is unsupported is its application to "the block" and the conclusion drawn from it.
- Fix: label the row Q2 (superposition queries to a feed-forward MAC/PRF built on the cipher) and add the Q1 row
  (2^64 vs 2^128, same as the birthday row), or drop it; rephrase :27-29 accordingly.
- Verified by: reading docs/15 against the cited note lines (quoted above) at f0d771c.

### F2. Turing-256's checked calls: two of the three fault defences are never exercised by any test
- Severity: minor. Kind: missing test.
- Where: crates/turing/src/turing256.rs:114-129 (`guarded`), :53-67 (`checked`); tests at turing256.rs:239-252,
  crates/bombe/tests/turing256.rs:72-84, campaign.rs section 24 "persistent key faults" (campaign.rs:1320-1329
  at f0d771c).
- Problem: every Turing-256 fault test flips a stored bit *before* the call, which the first `intact()` check
  already rejects. Nothing injects a fault after the first check (time-of-check/time-of-use) or corrupts the
  computation, so (a) deleting the second `intact()` check (line 124) and (b) replacing `checked(...)` by the bare
  forward call would both leave every Turing-256 test and campaign line passing. docs/15:147-150 already concedes
  that dropping the first check is invisible to the tests; the same holds for the other two. Turing has the
  missing tests: its `guarded` takes a `between` hook (cipher.rs:109), with
  `a_key_flip_between_check_and_use_is_caught` (cipher.rs:309-326: flips a round key after the first check,
  expects `Err` and a wiped block, and shows as a control that decrypt-and-compare alone releases a wrong
  ciphertext), `checked_calls_catch_faults` (cipher.rs:328-345: faulty forward and backward closures must give
  `Err` and a wiped block) and the analysis API `encrypt_block_checked_with` / `flip_round_key_bit_in_use`
  (cipher.rs:131, 144). Turing-256's `checked` is its own copy (turing256.rs:53-67), not Turing's, and its
  `guarded` has no hook, so docs/15's "the same fault ... protection" is implemented but only one third tested.
- Fix: give Turing256::guarded the same `between` hook and port the TOCTOU test (key flip after the first check
  must give Err + wiped block; control: `checked` alone passes it); add a test that corrupts one direction
  (e.g. a `forward` closure that flips an output bit) so decrypt-and-compare must fire; add "drop the second
  check" and "drop decrypt-and-compare" to tools/mutate.py --round6.
- Verified by: reading every call site of encrypt_block_checked / decrypt_block_checked for Turing256 at
  f0d771c (git grep: turing256.rs tests, tests/turing256.rs, campaign.rs section 24, residue.rs plain256) - all
  either use intact keys or flip stored bits before the call; and by a mutant run: on a scratch copy of
  f0d771c (`git archive`, outside the repo; scratch/mutate_scratch.py) with BOTH the second `intact()` check
  removed and `checked` reduced to the forward call (the diff is forced to 0), `cargo test --release -p turing
  --lib -- turing256 keyschedule256 linear256` passed 12/12 and `cargo test --release -p bombe --test turing256`
  passed 6/6 (including `stored_key_faults_are_caught` and `checked_calls_pass_clean_and_catch_faults`).
- Side effect to know about: that mutant build shared CARGO_TARGET_DIR=target/review (as the review rules
  require) and, because cargo hashes workspace members by their workspace-relative path, it overwrote the
  repo's `turing` unit-test binary (turing-d6f6fa2457349283.exe) with the f0d771c+mutant build at about
  17:12 local time; cargo then treated it as fresh for builds from D:\Dev\Turing. I ran
  `cargo clean --release -p turing -p bombe` on target/review at about 17:17 (it removed every turing
  artifact; one bombe test binary, memory-45da08b7deb0c7c7.exe, was locked by another reviewer's run and was
  left, built at 16:35, before the mutant) and rebuilt turing and the bombe turing256 test from the repo
  (checked: the new dep-info lists lwe.rs and turing1026.rs, which f0d771c lacks). Anyone who ran
  `cargo test -p turing --lib` in target/review between about 17:12 and 17:17 ran the f0d771c-based binary.

### F3. The Turing-256 memory scan has no control, and "clean" also passes a scan that finds nothing
- Severity: minor. Kind: missing test.
- Where: crates/bombe/src/campaign.rs:1337 at f0d771c (`for snap in residue::plain256(true)`), residue.rs:328-365
  (`plain256`), residue.rs:36-39 (`Snapshot::clean` = no stray hits).
- Problem: `residue::plain256(false)` (the no-burn control, with its own scenario names already written) is never
  called, at f0d771c or at HEAD (git grep). Section 20 does this for Turing (`residue::plain(false)`,
  "control: the same key schedule without the stack burn", and `round_keys_found_in_their_page`). Since
  `clean()` only checks for stray hits and `expected` (hits in the key page) is not asserted, a Turing-256
  needle list that never matched (for instance a wrong K' or Feistel-state computation in `secrets256`) would
  still report "clean". docs/15:108-110 says the scan "finds key material only in the caller's key buffer and the
  round keys' page"; the "finds ... in the round keys' page" half is never checked.
- Also: the needle list (residue.rs:367-395) holds the key, K', the Feistel halves at the 13 round-key pairs and
  the 25 round keys, but not the other 92 Feistel states (warm-up rounds 1-8 and the 7 rounds between pairs).
  Any two consecutive halves are equivalent to K' (the Feistel runs backwards with public constants), so their
  leftovers are exactly as sensitive and invisible to this scan. (Same design as Turing's `secrets()`; noted as a
  suggestion.)
- Today the scan does work: my quick and full campaign runs (HEAD build, 2026-09-27) print "104 key fragments
  where they belong, 0 anywhere else" (4 after drop), so this is about what the pass condition enforces, not a
  broken scan.
- Fix: log `plain256(false)` as a control expected to be caught, and require `expected > 0` (round keys found in
  their locked page) in the Turing-256 snapshots; optionally add the intermediate Feistel states as needles.
- Verified by: git grep of `plain256` at f0d771c and HEAD (only the `true` call), reading `Snapshot::clean`.

### F4. "46 structures" is 22 structures (44 comparisons)
- Severity: documentation. Kind: unsupported claim.
- Where: docs/15-turing-256.md:63-64 and research/notes/derivations.md:294 ("reproduces
  `division::balanced_until` on 46 structures from both starting layers").
- Problem: the test that backs it, wide.rs:275-285 (`division_matches_the_16_byte_engine`), checks 15 prefix
  structures (1..=15 bytes) plus 7 listed ones = 22 structures, from 2 starting layers = 44 comparisons. Neither
  number is 46.
- Verified by: counting the structures in wide.rs:277-278 at f0d771c.

### F5. Smaller documentation inaccuracies
- Severity: documentation. Kind: unsupported claim.
- crates/turing/src/keyschedule256.rs:9-11 attributes "8 Feistel rounds already force at least 67 active
  S-boxes" to `bombe key-schedule`. That command (main.rs:177-197 at f0d771c) prints only Turing's 16-byte
  Feistel table (`feistel_min_active(16)`) and Turing's round-key depths; nothing prints the 32-byte figures
  except campaign section 24 and tests/turing256.rs. (The numbers themselves are right, see below.)
- docs/15:44 says the fault check is Turing's checksum "unchanged (docs/13)". The construction is unchanged, but
  its proven bound is not: the escape probability is at most N/2^127 with N the number of stored blocks
  (research/notes/derivations.md:139-141, 162, 323-324 give 25/2^127 = 2^-122.4 for Turing). Turing-256 stores
  N = 50 blocks, so the bound is 50/2^127 = 2^-121.4. The second half of the argument (the d * k_0 term when the
  point itself is faulted) carries over with k_0 = the first 16 bytes of round key 0. The number should be
  stated for Turing-256.
- crates/turing/src/structure.rs:22 (not changed by this commit, but now shared): `Layer::MixState` is
  documented as "The 16x16 MixState over the whole state (branch 17)"; for Turing-256 the same variant means
  the 32x32 layer with branch 33.
- Verified by: reading the cited lines at f0d771c; 50/2^127 = 2^(log2 50 - 127) = 2^-121.36.
- docs/15:108 "Round keys in locked pages excluded from core dumps": the exclusion is Linux/Android only
  (MADV_DONTDUMP; cipher.rs documents that Windows full crash dumps include the keys). On this Windows machine
  campaign section 24 reports "locked: true, excluded from core dumps: false" (quick run, 2026-09-27).
- docs/15:130-131 "dudect measures |t| of at most 1.9 for Turing-256's encryption, decryption and key setup" is
  one run's maximum, not a bound. My full campaign run reproduced it (0.98 / 1.52 / 1.89 over 300,000 runs),
  but my quick run (80,000 runs) measured 1.25 / 3.49 / 0.94. All are below the 4.5 leak threshold, so no leak;
  the sentence should state the threshold rather than 1.9. (Nit.)
- Turing-256 has no key shielding: `ShieldedKey` (shield.rs:71-78) can build a `Turing` or a `MaskedTuring`
  but not a `Turing256`, and its `with_key` is private, so a Turing-256 user cannot keep the master key shielded
  between uses as docs/13 recommends. docs/15:4-7 ("the same fault and memory protection") and its "What is not
  done yet" list (only a masked Turing-256) do not mention this. Suggestion: `ShieldedKey::cipher256()`, or list
  it as not done.

### F6. Other test gaps: what a wrong implementation or analysis would get past
- Severity: minor. Kind: missing test.
- Division-property ranges: `wide::tests::turing_256_division_reach` (wide.rs:296-308) asserts only k = 1, 4,
  24, 25, 31 and "<= 6 for all k". docs/15's table claims whole ranges (k = 1-3 -> 3, 4-24 -> 4, 25-30 -> 5);
  a change that moved k = 2, 3 or 26-30 would pass. (The ranges are right today: division256.py computes all
  31 values.) Cheap fix: assert the full vector of 31 values.
- The central timing claim has no automated test. docs/15:128-131 rests on the release build of apply32,
  apply16 and apply_columns having a single conditional jump; `cargo test` never checks it, and dudect runs only
  inside `bombe attack` and is statistical (a quick run gave |t| 3.49, see F5). A compiler update that
  re-derived the branches would pass every test. Suggest a CI step (or an ignored test) that emits the
  assembly and runs tools/asm_branches.py on apply32 / apply16 / apply_columns expecting exactly one jump, with
  the documented negative control (`linear::mix_columns_with`, 21 jumps).
- Spec-level agreement: both Rust implementations were written by the same author from the same design, so an
  interpretation error shared by both (state layout, rotation direction, which half is fed forward) would pass
  `matches_the_independent_reference` and the vector test. My Python implementation from docs/15 alone agrees
  with them, so there is no such error now; committing a small spec-level checker like it (tools/ already
  holds Python) would keep it that way.
- No test pins the domain separation between the two ciphers (same key -> unrelated Turing and Turing-256
  round keys and checksum points). It holds by construction (distinct cSHAKE labels); a one-line test would
  catch a future label copy-paste.

### S1. The hull (clustering) bounds of docs/12 were not carried over, and they fall short of the codebook
- Severity: minor. Kind: suggestion (gap in the analysis, not an error).
- docs/15's table stops at trails; for Turing, docs/09 leans on docs/12 ("Clustering is bounded") for the
  factor-of-two margin. Recomputed with the docs/12 method (Park-Sung-Lee-Lim FSE 2003, Theorems 1-2, max row
  or column sum of DP^B / LP^B over Turing's S-box; script park_bound.py, which reproduces docs/12's B = 5 values
  2^-27.70 / 2^-26.48, B = 17 values 2^-102.00 / 2^-99.63 and 5-round values 2^-110.8 / 2^-105.9 exactly):
  for MixState256, B = 33, any 3 rounds (they contain S, MixState256, S) have MEDP <= 2^-198.00 and
  MELP <= 2^-195.68; the 5-round super-box bound uses the word-level branch number of MixState256, 9 (w active
  4-byte words give at least 33 - 4w active bytes out), so mu^8 = 2^-221.6 (DP) and 2^-211.8 (LP).
- All are above 2^-256, the Turing-256 codebook, and further from it than Turing's were from 2^-128 (44 bits
  short for LP against 22). So for Turing-256 "usable" rests on trails alone; the docs should say so and give
  these numbers, or list the hull bound under "What is not done yet".

## Checked and correct

- **MixState256 constants rebuilt from scratch.** A pure-Python Keccak/cSHAKE256 (validated against
  hashlib.shake_256 and NIST SP 800-185 cSHAKE256 samples #3 and #4, negative control with a changed label)
  reproduces cSHAKE256(X = 00000000, S = "Turing-256 v1 MixState"); its first 64 distinct bytes equal
  STATE256_X / STATE256_Y exactly (counter 0; counter 1 differs, as a control). The 64 points are all distinct,
  so x's distinct, y's distinct and x_i + y_j != 0: the Cauchy theorem applies and the matrix is MDS
  (branch number 33). M[i][j] = 1/(x_i + y_j) over GF(2^8) mod x^8+x^4+x^3+x+1 (0x11b, checked irreducible,
  0x11a as negative control) equals MIX_STATE_256 entry for entry; an independent Gauss-Jordan inverse equals
  MIX_STATE_256_INV; M*Minv = Minv*M = I. As an extra check independent of the theorem, 9,301 random square
  submatrices of M of all sizes 1..32 and 3,101 of Minv are nonsingular (rank computed in Python).
  Script: research/workfiles/review-turing256/mixstate256.py.
- **The specification in docs/15 matches the vectors.** A third implementation, written in Python from the
  docs/15 table alone (S-box A_out(x^254(A_in x)) with the affine maps re-drawn from cSHAKE256(counter 3,
  "Turing v1 S-box") and equal to IN_ROWS/OUT_ROWS/TABLE; MixColumns rebuilt from "Turing v1 MixColumns"
  counter 0; MixState256 as above; ShiftRows left by 0,1,3,4 on the 4x8 column-major state; key schedule
  cSHAKE256(K, "Turing-256 v1 key") -> 64 bytes, Feistel (L,R)->(R^F(L),L), F = MixState256(S(x^C)),
  constants from cSHAKE256("", "Turing-256 v1 key schedule constants"), 9 warm-up rounds, pairs every 8,
  feed-forward) reproduces all 8 ciphertexts of vectors/turing-256-v1.txt, all 8 decryptions, all 25
  ROUND_KEY lines and all 24 AFTER_ROUND lines. Negative controls: a reversed row-1 rotation or 8 warm-up
  rounds break vector 2. Script: research/workfiles/review-turing256/turing256_ref.py.
- Rijndael's ShiftRows offsets for Nb = 8 are C1 = 1, C2 = 3, C3 = 4 (Daemen-Rijmen, AES Proposal: Rijndael,
  amended version on csrc.nist.gov, Table 2 "Shift offsets for different block lengths": rows 4 1 2 3 / 6 1 2 3 /
  8 1 3 4; read 2026-09-27, not in research/papers): matches SHIFTS = [0, 1, 3, 4] and the left-rotation
  convention of linear256::shift_rows (out column c takes column c + C_r). Note that with strict alternation the
  offsets do not affect the trail bound at all (every ShiftMix starts from freely placed bytes); they matter only
  for windows that start on ShiftMix in the division analysis.
- **Trail bounds (docs/15 table row 1).** An independent count-level DP in Python (trail_bound.py; its own
  code, same abstraction) gives [1, 5, 34, 45, 67, 68, 100, 101] for 32 bytes and [1, 5, 18, 25, 35, 36, 52,
  53] for 16 bytes, both as docs/15 states. 45 x 6 = 270 > 256 and 34 x 6 = 204 <= 256, so "longest usable
  trail 3 rounds" holds under the 2^-6 maximum DP/LP of an inversion-based S-box. The exactness premise of the
  count abstraction (an MDS layer takes any input support A to any output support B with |A|+|B| >= n+1) was
  checked from the MDS weight-distribution formula: every support of size 33..64 of the [64,32,33] code over
  GF(256), and of size 5..8 of the [8,4,5] MixColumns code, carries codewords (count > 0; formula sanity-checked
  by summing to q^K). Whole 24-round cipher: at least 396 active S-boxes (count DP, MixState start).
- **Impossible differentials.** The count-level miss-in-the-middle (own code) finds one-byte-in/one-byte-out
  impossible differentials over 4 S-box layers only for ShiftMix, MixState, ShiftMix, and none over 5, for 16
  and 32 bytes. One active byte is the most restrictive input at count level (the forward sets are unions that
  grow with the input), so no other truncated pattern does better at this level.
- **Division property (docs/15 table row 4).** An independent Python re-implementation of the count-level
  word-level division property (division256.py; per-column minima by brute force over splits, column
  placement by its own DP) gives, for k active plaintext bytes: k = 1-3 -> 3, 4-24 -> 4, 25-30 -> 5, 31 -> 6,
  exactly the ranges in docs/15 (the repo's test only samples k = 1, 4, 24, 25, 31); and for Turing 1-3 -> 3,
  4-14 -> 4, 15 -> 5 as docs/09 says. Word-level sets larger than 2^248 (a byte with 7 or 6 active bits, 2^255
  and 2^254 texts) also stop at 6, so "2^248, balanced 5 rounds" is the word-level maximum.
- **Key-schedule bound (docs/15 row 5 and "7 force only 36").** A line-by-line Python replica of
  bombe::keyschedule::feistel_min_active_general and a second, differently written DP over (wt x_{i-1},
  wt x_i) both give, for 32-byte halves and branch 33: [0, 1, 2, 33, 34, 35, 36, 67, 68, 69, 70, 101] for
  1..12 rounds (and [.., 53] at 12 rounds for Turing's 16-byte halves, as docs/07). The 7-round minimum 36 is
  realised by the weight sequence x_0..x_8 = 32, 1, 0, 1, 32, 1, 0, 1, 32 (every 3-window around a non-zero
  middle sums to >= 33). round_key_depth gives 9 (L) and 8 (R), so every round key is behind >= 67 >= 43.
- Arithmetic in the prose: 24 / 9 = 2.67 ("2.7 times"), 24 / 7 = 3.4 ("over 3 times"), 43 x 6 = 258;
  quantum table: 2^(128/3) = 2^42.7, 2^(256/3) = 2^85.3, Grover on 256 bits about 2^128 (see F1 for the
  applicability of the 2^(n/3) row).
- "7 rounds on paper for about 2^251" is consistent: the 2^248 set is balanced at the input of S-box layer 6;
  round 6 is ShiftMix, so a byte there needs one column of RK7 plus one byte of InvMC(RK6) (2^40 guesses, as in
  docs/14's 7-round step), and about 6 structures of 2^248 (2^250.6 texts) filter the guesses; an 8th round
  would put MixState in the way and need all of RK8 (2^256). Not recomputed beyond this reconstruction.
- **Implementation matches docs/15** (turing256.rs, linear256.rs, keyschedule256.rs read line by line):
  round key 0 first, then S-box layer, MixState256 in odd rounds and ShiftRows + MixColumns on 8 columns in even
  rounds, no linear layer in the last round, round key r; decryption is the exact inverse
  (inv_shift_rows(inv_mix_columns(.)) for even rounds); `inv_shift_rows` inverts `shift_rows`; 25 round keys
  stored as 50 blocks, round key i = blocks 2i, 2i+1, used in that order by add_round_key; key schedule as
  specified (13 pairs, the last one's R half dropped).
- **The reference is genuinely independent in code**: refcipher256.rs uses the S-box table instead of the SWAR
  inversion, Bombe's generic `matrix::mat_vec` (its own GF(2^8) tables) instead of the precomputed masked
  columns, ShiftRows as row rotations (`rotate_left` / `rotate_right`) instead of index arithmetic, cSHAKE256
  straight from the sha3 crate with the labels typed again as literals, and its own round loop. It shares only
  public constants (S-box TABLE, MixColumns and MixState256 with their inverses), and each of those was rebuilt
  independently above. The known-answer vectors do come from it: tests/turing256.rs:44 requires the committed
  file to equal `refcipher256::render_vectors()` byte for byte, and my Python implementation reproduces them.
  The two self-test vectors (selftest.rs VECTORS_256) are exactly COUNT 0 and COUNT 2 of the file
  (selftest_vectors.py).
- **Key-schedule labels and independence**: "Turing-256 v1 key", "... key schedule constants", "... key
  check", "... MixState" are all distinct from Turing's "Turing v2 key", "Turing v2 key schedule constants",
  "Turing v2 key check", "Turing v1 MixState"; cSHAKE256 encodes S with its length, so the same 256-bit key
  gives Turing and Turing-256 unrelated K', round keys and checksum points. The cSHAKE whitening removes an
  attacker's control over K' differences (related-key trails would have to go through cSHAKE); the Feistel
  bound is defence in depth. The only shared parts (S-box, MixColumns) are public. The checksum point is
  derived from the 64-byte K' under its own label, unrelated to the round keys. Nothing secret is reused.
- **Constant time, checked in the release assembly** (HEAD build, stable x86_64-pc-windows-gnu,
  `cargo rustc -p turing --release --lib -- --emit asm` + tools/asm_branches.py): apply32 has 1 conditional
  jump (its loop counter) and 1 indexed load (the state byte x[j], indexed by the loop counter);
  apply_columns 1 jump (column counter), loads indexed by the column counter; shift_rows / inv_shift_rows 0;
  apply_layer / invert_layer 1 (the public layer enum); encrypt_block 1 and decrypt_block 3 (round counter);
  f 0; feistel_round 3 (the XOF reader's buffer position, public); guarded 5 (results of intact() and of the
  fault comparison, public fault status). No secret-dependent branch or index found. dudect in my full
  campaign run: |t| 0.98 / 1.52 / 1.89 (threshold 4.5).
- **Memory handling matches Turing's**: round keys in RoundKeys<50> (SecretBox, locked pages, keyed checksum),
  `burn_stack` after key setup, temporaries zeroized in the key schedule (whitened, k_left/k_right, l/r, F input,
  new_l, rk) and in `checked` (input, check); Turing-256's key-schedule stack depth is in `stack_depths`, which
  section 20 checks against BURN_BYTES.
- **Tests and campaign pass at HEAD**: turing lib tests for turing256/keyschedule256/linear256/linear/selftest
  18/18; bombe tests/turing256.rs 6/6; bombe lib wide:: and matrix:: 6/6; full `bombe attack --no-report`
  (HEAD, 2026-09-27): 206 findings, 0 failures, 209 s; section 24 matches docs/15 line for line (MDS, bounds,
  impossible differentials, division reach, key schedule 67, square attack 3 rounds broken / 4 not, avalanche
  within limits, NIST: 1 and 2 rounds fail at 64 sequences and 24 rounds pass, 400/400 stored faults caught).
  Note: in the quick run (16 sequences) 2-round Turing-256 passes all 11 statistics; the campaign logs that as
  PASS rather than a failure, which is fine, but docs/15's "1 and 2 rounds fail" holds only at full scale.

## Method and evidence

Scratch scripts: research/workfiles/review-turing256/
- keccak.py: independent Keccak-f[1600], SHAKE256, cSHAKE256.
- mixstate256.py: rebuild and check of the 32x32 MixState.
- turing256_ref.py: independent Turing-256 from docs/15, checked against the vector file.
- trail_bound.py: count-level trail bound, impossible differentials, MDS support-count premise.
- division256.py: count-level division property, independent code.
- feistel_bound.py, feistel_path.py: key-schedule Feistel bound (replica + independent DP + cheapest path).
- park_bound.py: Park-Sung-Lee-Lim 2-round and 5-round hull bounds for B = 5, 17, 33 from the S-box's DDT/LAT.
- selftest_vectors.py: turing::selftest::VECTORS_256 against the vector file.
- mutate_scratch.py + ws/ (a `git archive f0d771c` copy): the F2 mutant, applied and reverted in scratch only.
- attack-quick.txt, attack-full.txt: `bombe attack [--quick] --no-report` output at HEAD (no report written).
- Never run: tools/mutate.py (rewrites sources), `bombe attack --deep`. No repo file other than this report was
  created or edited; the only other write was to the shared build directory target/review (see F2).
