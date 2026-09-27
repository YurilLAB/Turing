# 04 — Bombe, the analysis suite

Bombe is named after the machine Turing designed to break Enigma. It exists to
break Turing. Every tool is validated against AES, whose values are published,
and against deliberately broken controls, before its verdict on our own
components counts.

## Built: S-box lab (step 3)

```
cargo run --release -p bombe -- sbox <turing | aes | aes-inv | identity | random:SEED | file> [--html out.html]
cargo run --release -p bombe -- gen-sbox [--rust out.rs] [--html out.html]
```

Exit status 0 = meets the Turing v1 criteria, 1 = rejected, 2 = error.

| Measurement | Attack it models | AES (published) | Bombe on AES |
|---|---|---|---|
| Differential uniformity (DDT) | Differential cryptanalysis | 4 | 4 |
| Linearity / nonlinearity (Walsh) | Linear cryptanalysis | 32 / 112 | 32 / 112 |
| Boomerang uniformity (BCT) | Boomerang attacks | 6 (Cid et al. 2018) | 6 |
| Component degree | Higher-order differential, algebraic | 7 | 7 |
| Quadratic / bi-affine implicit equations | Algebraic attacks (XSL) | 39 / 23 (Courtois & Pieprzyk 2002) | 39 / 23 |
| Cycle structure | Structural weakness | 87 81 59 27 2 | 87 81 59 27 2 |
| Fixed / opposite fixed points | Structural weakness | 0 / 0 | 0 / 0 |
| Differential / linear branch number | Input to trail bounds | 2 / 2 | 2 / 2 |

The HTML worksheet draws the full DDT and LAT as heatmaps. A good S-box looks
like even static; any line, block or bright spot is exploitable structure.

**How the tools are verified** (`crates/bombe/tests/reference.rs`):

- AES values above are pinned to the literature, not to our own output.
- Negative controls must be rejected: identity, an affine map, a
  non-bijective table, and AES with one swapped pair.
- Invariants that hold for every S-box: DDT rows sum to 256 with even entries;
  Parseval (squared Walsh coefficients sum to 2^16 per column); cycles cover all
  256 points; inverse of the inverse is the original.
- Mutation check: planting a bug in the BCT or the Möbius transform makes the
  suite fail (done by hand on 2026-09-26).

## Built since

**Linear layer lab (step 5): `bombe gen-linear`**
- MDS check: every square submatrix invertible (exhaustive or sampled by size).
- Branch number measured directly on inputs with 1–3 active bytes.
- Rounds to full diffusion: how many rounds until every output byte depends on
  every input byte.

**Key-schedule prover (step 6): `bombe key-schedule`**
- Minimum active S-boxes through the key-schedule Feistel, and the bound
  behind every individual round key. Validated against Kanda's theorem.

**Trail bounder and impossible-differential search (step 7): `bombe rounds`**
- Exact minimum active S-boxes over any window of rounds, for any mix of
  ShiftRows + MixColumns and MixState layers (dynamic programming over the
  2^16 byte-activity patterns). Reproduces the published AES table for 1–14
  rounds exactly.
- Miss-in-the-middle impossible-differential search. Finds AES's 4-round
  impossible differentials and none over 5 rounds, matching the proof of
  Sun et al. Every result is rechecked by exhaustive trail enumeration.
- Compares candidate layer schedules side by side (docs/09).

**Round tracer (step 8): `bombe trace`**
- The state after every operation of every round, for any key, plaintext and
  round count; with a second input (a flipped plaintext or key bit, or any
  other plaintext or key), the XOR of the two runs and how many bits and
  bytes differ.

**Attack bench (step 8): `bombe attack`**, see docs/10
- Correctness against an independent reference implementation and the
  known-answer vectors (`bombe vectors`).
- Square attack: balanced-sum distinguisher and real key recovery on
  reduced rounds.
- Differential and linear: measured branch numbers, 1-round differential
  probability and linear correlation against the DDT and LAT, truncated
  differentials by round.
- Avalanche (strict avalanche criterion) on plaintext and key bits.
- NIST SP 800-22 (nine tests, eleven statistics) on counter-mode keystreams,
  validated against NIST's reference results for e.
- Key checks: suspicious keys, equivalent keys among neighbours.
- Timing side channel, dudect-style, with a leaky control.

**Classic attacks and key handling (step 10, second campaign)**, see docs/11
- Word-level division property engine (`bombe::division`), validated on
  AES's integral distinguishers, and square attacks with 2^16–2^32
  plaintext structures on all CPU threads (`attack --deep` runs 2^32).
- Boomerang quartets against the S-box's BCT; 16-dimensional cube testers.
- Related-key round-key and output differences, with and without cSHAKE.
- Differential fault analysis of the last round key, and the
  decrypt-and-compare countermeasure.
- The S-box as a polynomial over GF(2^8) (interpolation attack), validated on
  the published 9-term AES polynomial.
- Invariant attacks: W_L(D) and invariant-factor profiles of the linear
  layers (Beierle et al. 2017), validated on Midori-64.
- Correlation power analysis on simulated Hamming-weight leakage.
- `tools/asm_branches.py`: conditional jumps in the release assembly, for
  the constant-time review.

**Attacks by someone who knows everything (step 10, third campaign)**, see
docs/12
- Provable MEDP/MELP bounds (Park et al.), validated on AES's published
  values, and Keliher and Sui's exact best-differential search (53/2^34 for
  AES reproduced; Turing 57/2^35).
- Symmetry search over byte permutations and S-box scalings, and the
  reflection test, each with a control that must be caught.
- Linear relations in the key schedule (AES-128's 1,088 as the control).
- Differential-linear distinguishers with an exact 2-round prediction.
- `tools/mutate.py`: the planted-bug harness, now in the repository.

**Version 2 and the library (step 10, fourth campaign)**, see docs/13
- `memscan` and `residue`: a memory-dump attacker that reads every readable
  page of the process for key fragments, with planted-key controls.
- `leakage`: CPA on single shares and second-order CPA, and TVLA with
  Goodwill et al.'s two-group rule on every share and on every value the
  masked S-box computes.
- `toctou`: key faults injected between the checksum check and use;
  concurrency and fork(2) tests.
- `tools/asm_branches.py --loads`: indexed memory accesses (table lookups)
  in the release assembly.
- `tools/wsl_linux.py`: builds for Linux on Windows and runs the tests in WSL.

**After the outside review (review 6 in docs/08)**, see docs/13 §5
- `fault::two_bit_key_faults`: every two-bit fault in the stored round keys
  that cancels in version 2's first, public checksum (35,800 pairs), flipped
  in a real cipher and run through the checked call, with the public
  checksum recomputed as the control; `fault::point_faults` for every one-
  and two-bit fault that moves the checksum's secret point (434,240), and
  `fault::multi_bit_key_faults` for random faults of 2 to 16 bits anywhere
  the check reads.
- `tools/mutate.py --round4`: 35 planted bugs in this round's code.

**Attacks from the AES-256 literature (step 10, fifth campaign)**, see
docs/14
- `fast`: table-driven rounds for 2^32-text experiments, checked block for
  block against the real cipher.
- `keyedsquare`: the square attack with round key 0 guessed, placing a
  2^32 structure at round 2 (balanced to S-box layer 6, run on two
  structures), the 6-round last step and Ferguson et al.'s partial sums
  for 7 rounds, with wrong-guess controls; `attack --deep` runs it.
- `yoyo` and `aes`: the yoyo game, validated on AES-128 (3 and 4 rounds
  always, 5 never; FIPS-197 vector for the AES code).
- `mitm`: Demirci-Selçuk parameter counts and differential enumeration,
  reproducing Derbez-Fouque's 25/24 and Derbez-Fouque-Jean's 10 for AES.
- `tools/mutate.py --round5`: 14 planted bugs in the new tools.

**Turing-256 (step 11)**, see docs/15
- `gen-linear --turing-256`: the 32x32 Cauchy MixState from cSHAKE256,
  checked for MDS with sampled submatrices of every size and the branch
  number measured.
- `wide`: trail bounds, the division property and one-byte impossible
  differentials counted in active bytes, exact for alternating layers on
  any number of columns; they reproduce Turing's 16-byte pattern-level
  results before giving Turing-256's.
- `refcipher256` and `vectors --turing-256`: an independent reference and
  its known-answer vectors; `attack256`: the square attack on reduced
  Turing-256; avalanche, the NIST battery, dudect, faults and the memory
  scan for 32-byte blocks (campaign section 24).
- `tools/mutate.py --round6`: 13 planted bugs.

## Planned

- Keliher and Sui's upper-bound search, to pin Turing's exact 2-round MEDP
  between 57/2^35 and 79/2^34.
- Bit-level division property (MILP or SAT) to check the word-level results,
  in particular that nothing stays balanced past S-box layer 6.
- Bit independence criterion.
