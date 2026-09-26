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

## Planned, in the order they become useful

**Watch: the round tracer (step 8)**
- Encrypt with any key and plaintext and print or render the state after every
  sub-step (S-box, mixing, round key) of every round, plus the round keys.
- Controls: run reduced-round variants, flip chosen plaintext or key bits,
  swap in an alternative S-box or linear layer.
- Differential view: encrypt two inputs side by side and show, round by round,
  which bytes differ. This makes diffusion visible.

**Cipher-level statistics (steps 8 and 10)**
- Avalanche matrix (strict avalanche criterion): for each input bit, the
  probability each output bit flips. Target 0.5 everywhere, with a statistical
  test for deviation.
- Bit independence criterion.
- Key avalanche: the same test with key bits flipped (key schedule quality).
- Randomness battery on ciphertext streams (counter mode): monobit, runs,
  serial, chi-square, and a subset of the NIST SP 800-22 tests.

**Attack bench (step 10)**
- Integral distinguishers via the division property: the one structural
  attack family the step 7 tools do not model yet (docs/09).
- Reduced-round distinguishers: differential, linear, integral (square) and
  boomerang. The number of rounds each one breaks, measured against the full
  round count, is the security margin.
- Slide and related-key probes against the key schedule.
- Weak-key scan: sample keys for short cycles or fixed points of the full
  cipher.
- Timing test (dudect-style Welch t-test) to confirm the implementation is
  constant-time.
