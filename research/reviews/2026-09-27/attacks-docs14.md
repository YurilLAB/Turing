# Review: fifth attack campaign (commit 7d3d174)

Reviewer: independent reviewer, 2026-09-27.
Scope: docs/14-attacks-from-the-aes-256-literature.md, crates/bombe/src/{keyedsquare,yoyo,mitm,fast,aes}.rs,
new sections of crates/bombe/src/campaign.rs, crates/bombe/tests/yoyo.rs, changes to
crates/bombe/tests/classic_attacks.rs, additions to research/notes/derivations.md and
research/notes/verified-facts.md.

The module files, the tests and docs/14 are unchanged between 7d3d174 and HEAD (4c8f826)
(`git diff --stat 7d3d174 HEAD` lists only campaign.rs, derivations.md and verified-facts.md, which
gained later sections), so the test runs below on HEAD apply to the commit.

Status: COMPLETE.

## Summary

| # | Severity | Kind | Where | Problem |
|---|---|---|---|---|
| F1 | major | unsupported claim (wrong conclusion) | docs/14 table and section 3; docs/09; campaign section 23 | Demirci-Selcuk with differential enumeration reaches 6 rounds (2^113 CP, ~2^189) and 7 rounds with RK0 guessed (~2^189, full codebook), not "5 at best" |
| F2 | major | bug (wrong check threshold) | campaign.rs section 23 | the enumerated table (2^176) is checked against 2^128, not the 2^256 key space, so a usable table reports PASS |
| F3 | minor | wrong maths | docs/14 section 4 | impossible differential with RK0 guessed costs ~2^134.5 (pair-first sieve), not "at least 2^188", and is not "more than every attack above" |
| F4 | documentation | unsupported claim (units) | docs/14 section 1, keyedsquare::costs | Turing's 2^173.8 (112 S-boxes per encryption) is set beside Ferguson's 2^172 (2^8 per encryption) for the same 2^180.6 S-box lookups |
| F5 | documentation | unsupported claim (unverifiable) | research/README.md, verified-facts.md | the three papers behind docs/14 are indexed but absent from research/papers; their quoted values are unverified |
| F6 | minor | unsupported claim | docs/14 section 1, verified-facts.md | wrong-guess results at 2^32 texts and first-structure counts are not produced by any committed code |
| F7 | minor | missing test (weak control) | campaign.rs section 3 control | the random-RK0 control checks right-byte survival (kept < 16), not the rejection rule the cost relies on |
| F8 | minor | missing test | keyedsquare.rs tests, yoyo.rs | table accumulation in structure() untested outside an #[ignore] test (demonstrated with two planted bugs); sampled partial-sum check; costs() untested; unbounded retry loops |

## Findings

### F1. Demirci-Selcuk with differential enumeration reaches 6 and 7 rounds, not "5 at best" (major, wrong conclusion)

Where: docs/14 results table ("5 rounds at best"), section 3 last paragraph ("The family that
reaches 9 of AES-256's 14 rounds reaches 5 of Turing's 24, two fewer than the square attack");
docs/09 ("Demirci-Selçuk sequences over 4 rounds need 36 parameters (AES 24), so that family stops
at 5 rounds"); campaign.rs section 23 "best attack from it".

docs/14 itself counts the enumerated 4-round table at 22 bytes (2^176), and mitm.rs's module doc
states the criterion "the attack needs the table smaller than the key space" (2^256): 176 < 256.
The only obstacle named is the right pair's probability 2^-120, which data pays for. Two attacks built
only from ingredients docs/14 already has (numbers from recount.py):

- **6 rounds, nothing guessed at the front, no full codebook.** Delta-set = a structure of 2^8
  plaintexts varying in one byte: as a multiset it is a delta-set after S-box layer 1 (Dunkelman-
  Keller-Shamir's multiset trick removes the ordering, so no RK0 byte is needed). 4-round property
  over linear layers 1-4 (MixState, SR+MC, MixState, SR+MC), output at the S-box layer 5 input.
  Enumeration for this alignment: 1 + 16 + 4 + 1 = 22 bytes, trail 2^-120 (my reimplementation of the
  counting rule; `mitm::enumerated(&schedule[..4], i, o)` is the same computation, the campaign only
  evaluates `schedule[1..5]`). A right pair needs 2^120 pairs: 2^105 structures, 2^113 chosen
  plaintexts. Rounds 5 (MixState) and 6 at the back: for each pair and each of the 255 values of the
  S-box-5 output difference at the output byte, the layer-6 input difference is MixState of it, and
  RK6 follows byte by byte from the DDT (Turing's S-box: mean 1.0039 solutions per nonzero
  (in, out) difference, P(0) = 0.502, measured), about 2^8 RK6 candidates per pair, 2^128 in all;
  one byte of MixState^-1(RK5) is guessed (2^8). Online 2^144.1 S-box lookups; offline table 2^176
  entries x 256 states x 36 S-boxes = 2^189.2; memory ~2^185 bits; a lookup matches a wrong
  multiset with probability 2^-330.
- **7 rounds with RK0 guessed (same model as the square attack's 7 rounds).** Delta-set after S-box
  layer 2, 4-round property to the layer 6 input (22 bytes, 2^-120), rounds 6 (SR+MC) and 7 at the
  back: one column of RK7 and one byte of e6 = SR^-1(MC^-1(RK6)). With the delta byte j and the
  output byte o fixed (one table), right pairs have a one-column ciphertext difference; 2^144 such
  pairs are needed (2^-24 back, 2^-96 middle, 2^-24 front), 2^161 exist in the codebook. Per pair:
  about 2^8 RK0 candidates (255 values of the one-byte layer-2 difference, one RK0 each from the
  DDT), 2^8 RK7-column candidates, 2^8 e6 guesses. Online 2^176.1, offline 2^189.2: the same order
  as the square attack's 2^180.6.

Consequences: the family reaches 7 rounds on paper, like the square attack; the round-count rule
(8) still holds and the 24-round margin is unaffected, but docs/14's comparison, the results table,
docs/09's "stops at 5 rounds" and the section 23 conclusion are wrong. 8 rounds stays out of reach
(the back key grows to all of RK8 + 4 bytes of e7 + a byte of e6).

Verified by: recount.py (own implementation of the DS dependency rules and the enumeration count,
Turing S-box DDT from sbox_constants.rs, the attack arithmetic). Standard DKS/DFJ assumptions
(about one S-box solution per difference pair; multisets as table keys).

### F2. Campaign section 23 checks the enumerated table against 2^128 instead of the key space (major, bug in the check)

campaign.rs section 23, "differential enumeration":
`pass_if(aes_table.free == 10 && 8 * turing_table.free > 128)`.
The 4-round check just above uses the key space (`pass_if(8 * four > 256)`), and mitm.rs says the
table must be smaller than the key space to be usable. 2^176 > 2^128 passes, but 2^176 < 2^256, so
the check that should have caught F1 reports PASS. No threshold of 128 appears anywhere in the
DS reasoning.

### F3. Impossible differential with RK0 guessed: ~2^134.5, not "at least 2^188" (minor, wrong maths)

docs/14 section 4: "A wrong guess only shows when a pair's ciphertexts differ in the one byte the
impossible differential names and nowhere else, 2^-120 per pair: at least 2^188 work, more than every
attack above." That counts guess-first (2^128 guesses x 2^60 texts per guess). The usual sieve is
pair-first: the impossible differential (one active byte at the S-box layer 2 input never gives one
active byte at the layer 5 input, whatever the positions, since MixState would map <= 4 active bytes
to <= 4) makes every one-byte ciphertext difference pair (chosen ciphertexts in one-byte structures,
decrypted) remove each RK0 that would give it a one-byte layer-2 difference: 16 x 255 targets,
about one RK0 each from the DDT, 2^12.08 keys per pair. 2^122.4 pairs (2^115.4 chosen ciphertexts)
leave only the right RK0: 2^134.5 eliminations, 2^128 bits of memory (impdiff.py). That is below the
Demirci-Selcuk 5-round figure (2^144) and uses far less data than the yoyo (full codebook), so "more
than every attack above" is false. Reach is unchanged: 6 rounds would sieve RK0 and RK6 together,
256 key bits, over 2^256.

### F4. 7-round cost compared with AES-256 in different units (documentation)

keyedsquare::costs: 2^128 x 6 x 2^50 = 2^180.585 S-box lookups, / 112 = 2^173.78 encryptions.
The figure docs/14 sets beside it, Ferguson et al.'s 2^172 for 7-round AES-256, is the same
2^128 x 6 x 2^50 S-box lookups converted at 2^8 per encryption (verified-facts.md records "2^52 S-box
lookups at 2^8 per encryption"). derivations.md says "whose cost ours matches"; docs/14 prints
2^173.8 vs 2^172, which reads as if Turing costs more. Use one conversion for both (2^172.6 and 2^172.6,
or 2^173.8 and 2^173.8). Also minor: step 1 of the partial sums does two table lookups per entry,
so a structure is 2^50.32 rather than 2^50 (0.3 bit).

### F5. The papers behind docs/14 are not in research/papers; their values are unverified (documentation)

research/README.md indexes 2000-ferguson-et-al-improved-cryptanalysis-of-rijndael.pdf,
2013-derbez-fouque-exhausting-demirci-selcuk-mitm.pdf and 2017-ronjom-bardeh-helleseth-yoyo-tricks-with-aes.pdf;
none is in research/papers (ls of its 343 files, find over the repo, no text copies in research/).
So the values quoted in verified-facts.md and docs/14 from these papers (2^50 S-box applications per
structure, 6 x 2^32 and 2^44, 21 x 2^32 and 2^172, 2^128 - 2^119 and 2^120, 2^204; Theorem 2,
Algorithms 2 and 3, 2^25.8; Property 5's 25/24 and "10 parameters") are UNVERIFIED in this review.
What could be checked without them: the yoyo properties the tests rely on hold mathematically for
Shape::Yoyo AES and for Turing's windows, and the DS counts follow from the stated counting rules
(see "Checked and correct"). docs/14's "Checked on AES first" for the partial sums is only an
equivalence test against the plain sum on random data; no AES partial-sum attack was run.

### F6. Reported wrong-guess results are not produced by any committed code (minor, unsupported claim)

docs/14 section 1 and verified-facts.md report, for 2^32-text structures: "diagonal, round key 0 one
byte wrong: 2, 3; at layer 6 no byte of the sum is zero"; "the right byte survived in 0 and 1 of 16
positions, and 6 of the 16 bytes kept no guess at all, which is what rejects a wrong guess"; for
7 rounds "Under either wrong guess of round key 0 the right value did not survive one structure";
and first-structure counts "65,147 to 65,413" and "10,370". The committed code: the --deep campaign
runs only a random RK0 guess and reports only balance depth and right-byte survival; the ignored
test only asserts `balanced_to(&off) < 6`; the one-byte-wrong guess runs only at 2^8/2^16 texts;
nothing counts bytes with no surviving guess; no partial sums run under a wrong RK0; `attack()`
reports candidate counts only after its last structure (grep of `is_empty`, `rk6_candidates`,
`parity6`, `.partial` over crates/bombe at 7d3d174). The expected values agree with theory (5.9 of
16 empty bytes expected; 2^16 x 0.632^4 = 10,466 column survivors), but the numbers cannot be
reproduced from the repository.

### F7. The random-guess control tests the wrong statistic (minor, weak test)

campaign.rs section 3: `caught_if(depth < predicted && kept < 16)`, where `kept` counts positions in
which the RIGHT RK6 byte survives. A wrong RK0 is rejected when some byte keeps no candidate at all
(the 2^-10.6 in the cost), and the attacker does not know the right RK6. `kept < 16` holds for almost
any code, including code that keeps every candidate in every byte. It should assert that at least one
byte has no candidate (and the ignored test likewise).

### F8. Test gaps (missing tests)

1. **structure()'s table accumulation is tested only by an #[ignore] test.** `parity6`
   (keyedsquare.rs:164-166) and the partial-sum table (168-172) are read only by `attack()`, which runs
   only in the ignored 20-minute test and `attack --deep`. The unit tests build their own tables
   (partial_sums_agree_with_the_plain_sum duplicates lines 168-172 at 517-523; zero_sum_structure
   builds parity6 by hand), and tools/mutate.py --round5 plants nothing there.
   **Demonstrated:** in a scratch copy of the workspace, with parity6 read from the 7-round
   ciphertexts and c2/c3 swapped in the partial table, all 6 existing keyedsquare unit tests pass.
   A proposed test (review_structure_tables_match_the_real_cipher: a 2^12 structure, parity6 and the
   partial table rebuilt from `Turing::encrypt_rounds` and compared) passes on the real code and fails
   on the mutant ("assertion failed: parity6"). Its code is in mutant_setup.py (NEW_TEST).
2. `partial_sums_agree_with_the_plain_sum` is sampled (every 97th hit, 3000 random guesses) though
   an exhaustive 2^24-guess comparison on ~50 texts costs ~2^32 lookups; e.g. losing one worker's
   results (`k % threads == w`) would stay inside the 50,000-80,000 window on 8+ threads and escape the
   3000-guess check with probability about 0.2 (8 threads) to 0.5 (16).
3. The full partial sum over 2^40 guesses (the k0, k1 step) is neither implemented nor tested, so the
   2^50-per-structure cost is never exercised; the run always gives k0, k1.
4. `keyedsquare::costs()` has no test: dropping log2(6), or 128 for 112, passes.
5. The wrong-RK0 rejection rule (a byte with no candidate; all 2^40 candidates dying after ~6
   structures) is never asserted (F6, F7).
6. `mitm::enumerated` is tested at (0, 0) for two windows only; nothing compares the table with the
   key space correctly (F2), and the delta-after-SB1 alignment (schedule[..4]) is never enumerated.
7. `yoyo::pair_game`/`single_game` retry forever while `simple_swap` returns None; a cipher bug that
   leaves ciphertexts differing in fewer than two words hangs instead of failing (mutate.py counts a
   timeout as caught, but `cargo test` would just hang).

## Checked and correct

- Round structure in all new code matches cipher.rs encrypt_n (RK0; S-box; layer(r) except the last
  round; RK r). fast.rs folds S-box + layer into tables; matches encrypt_rounds for every round count
  (test run).
- ShiftRows in turing::linear is AES's (out[4c+r] = in[4((c+r) mod 4)+r]), so DIAGONAL = [0,5,10,15],
  yoyo::diagonals, mitm::sources and Target::new (ShiftRows^-1: 4((c-r) mod 4)+r) are consistent;
  targets_read_the_layer_6_input checks Target against the real layer-6 input.
- plaintext_for: P = S^-1(MixState^-1(z)) xor g gives z xor RK1 at the layer-2 input iff g = RK0.
- 7-round target byte = S^-1(sum_i M^-1[row][i] S^-1(C[4col+i] xor RK7[4col+i]) xor e_j),
  e = SR^-1(MC^-1(RK6)) = equivalent_rk6: derived by hand, matches.
- partial_sums / column_candidates / rk6_candidates / balanced_to bookkeeping: table sizes (2^24,
  2^16, 2^8 bits), packing k<<2 | e>>6, AND over structures, stop rule of attack(): correct.
- Division property: diagonal at round 2 balanced to layer 6 not 7; 1-3 diagonal bytes to layer 4;
  2^32 at round 1 to layer 4; 15 bytes at round 3 to layer 7; 2^120 at round 2 to layer 6. Redone by
  hand with Todo's word-level rules; derivations.md's argument is right.
- Costs (recount.py): wrong-guess survival 0.6328^16 = 2^-10.56; 6 rounds 2^160; expected structures
  per wrong guess 5.64 ("about 6"); 2^128 x 6 x 2^50 = 2^180.585, /112 = 2^173.78; 6 rounds without
  RK0: ~15 stages of 2^144 per structure = 2^147.9, 17 structures = 2^151.99 with 2^124.09 CP; 8 rounds
  needs 296 key bits (> 2^256); the 15-byte set at round 3 needs 2^160 x 2^120 = 2^280.
- Yoyo: Theorem 2 (S o L o S, any swap of last-layer words keeps the first layer's zero pattern)
  proved by hand; Turing 2 rounds, 3 rounds (bytes in, columns out) and rounds 2-5 with RK0 (diagonals
  in, columns out) are S o L o S; 4 Turing rounds and 5 AES rounds are not. Shape::Yoyo AES 3 rounds
  has the one-new-ciphertext property (L sends a column difference to a diagonal, so replacing one
  super-box column keeps the difference in one plaintext column) and 4 rounds the pair property.
  5 rounds with RK0: 2^128 x 4 lookups = 2^130, false keep 2^-96. "Never" thresholds (2^-96, 2^-120
  per game) are sound.
- DS parameters (own implementation): AES 8/24/40; Turing 32/36/64 after SB1, 8/36/40 after SB2;
  AES enumeration 10 bytes with 2^-120; Turing 22 bytes with 2^-120 for both alignments; the 5-round
  attack with the 3-round property: 2^136 guesses x 2^8 = 2^144.
- Nothing in the headline costs is double-counted. Two small omissions, both negligible: the 6-round
  count is codebook lookups only (the per-text byte-parity updates add up to 16 per text, about 2.7
  with early abort on the first empty byte), and the 7-round count recovers RK0, one column of RK7
  and 4 bytes of e; with cSHAKE256 round keys a break means all 8 round keys, but once RK0 is known
  the rest peel off at far below 2^180 (docs/14 never says what "break" recovers).
- Statistical stop rules of attack() (unique after >= 2 structures, max 4) have negligible failure
  probability (about 2^-20 for RK6, 2^-16 for a wrong column).
- `cargo test -p bombe --release --lib -- keyedsquare yoyo mitm fast aes`: 21 passed.

## Method and scratch scripts

Scratch directory: research/workfiles/review-attacks/
- recount.py: parses Turing's S-box from sbox_constants.rs (DDT: uniformity 4, mean 1.0039, P(0) 0.502),
  recomputes every square/yoyo cost, reimplements the DS dependency and enumeration rules, and prices
  the 6- and 7-round DS attacks of F1.
- impdiff.py: the pair-first impossible-differential sieve of F3.
- mutant_setup.py: copies Cargo.toml, Cargo.lock and crates/ to ws/, adds the proposed test, and
  (mode "mutant") plants the two bugs of F8.1 inside structure() only.

Note for other reviewers of the shared target dir: cargo names workspace-member artifacts by a
path-independent hash, so my first scratch build (release profile, real code + the proposed test)
replaced target/review/release/deps/bombe-ea97b13a62a8603e.exe for a few minutes. I rebuilt it from
a byte-identical copy of the repo's keyedsquare.rs and confirmed from the repo that the lib tests are
the original 61 (6 in keyedsquare). The mutant was built only under a separate profile, so its
artifacts are in target/review/review-mut/ (safe to delete); no mutated code ever reached the
release artifacts. Nothing in the repo other than this report was written.
