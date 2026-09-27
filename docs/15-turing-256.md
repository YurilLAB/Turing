# 15 — Turing-256: the same design on a 256-bit block (step 11)

The owner asked for a direct upgrade of Turing to a 256-bit block, keeping
the 256-bit key. Turing-256 is Turing's design on a 32-byte state: the same
S-box, the same alternation of a whole-state MDS layer with ShiftRows +
MixColumns, the same kind of key schedule and the same fault and memory
protection. Everything below was computed or measured by Bombe, each tool
first checked against what it already reproduced for Turing.

```
cargo run --release -p bombe -- attack             # section 24 attacks Turing-256 (179 findings, 0 failures)
cargo run --release -p bombe -- gen-linear --turing-256   # regenerates its MixState
cargo run --release -p bombe -- vectors --turing-256      # its known-answer vectors
cargo test --release -p bombe --test turing256     # against the independent reference
python tools/mutate.py --round6                    # the planted bugs of this round
```

## Why a wider block

| | Turing (128-bit block) | Turing-256 |
|---|---|---|
| Key search, classical / Grover | 2^256 / about 2^128 | the same: the key is still 256 bits (NIST's highest category, like AES-256) |
| Birthday bound of any mode (blocks under one key before collisions) | 2^64 | 2^128 |
| Quantum collision search on the block (Brassard-Høyer-Tapp, about 2^(n/3)) | about 2^43 | about 2^85 |
| A 32-byte key or hash fits in one block | no | yes |

The wider block does not make key search harder; it removes the data
limits that come from the block size, the part of a 128-bit design that
quantum collision finding weakens most.

## Specification

| Parameter | Turing-256 | Reason |
|---|---|---|
| Block, key | 256 bits, 256 bits | the request; key search as Turing's |
| State | 4 rows x 8 columns, byte 4c + r at row r, column c | Turing's layout, twice as wide |
| Rounds | 24, round keys 25 x 32 bytes | the analysis below; Turing's ceiling |
| Round r | S-box layer (all 32 bytes), linear layer, round key r | Turing's round |
| S-box | Turing's (A_out ∘ x^254 ∘ A_in, docs/05), constant-time | unchanged |
| Odd rounds | MixState256: 32 x 32 Cauchy matrix, branch number 33 | one byte changes all 32 |
| Even rounds | ShiftRows (rows rotate left by 0, 1, 3, 4) + Turing's 4 x 4 MixColumns on all 8 columns | Rijndael's offsets for 8 columns: each column's bytes go to four different columns |
| Last round | no linear layer | as Turing |
| Key schedule | cSHAKE256(K, "Turing-256 v1 key") to 64 bytes; Feistel on 32-byte halves with F(x) = MixState256(S(x ⊕ C_j)); 9 warm-up rounds, then a pair of round keys every 8 rounds; feed-forward | Turing's schedule (docs/07) on wider halves |
| Fault check | Turing's keyed checksum over the 50 stored 16-byte blocks, point from "Turing-256 v1 key check" | docs/13's construction; over 50 blocks the bound is 50/2^127, twice Turing's 25/2^127 |

MixState256 comes from cSHAKE256(X = counter, S = "Turing-256 v1
MixState"): the first 64 distinct bytes are the points x_0..x_31, y_0..y_31
of M[i][j] = 1/(x_i + y_j). Counter 0 was accepted, as the Cauchy theorem
predicts. Bombe checks it independently (`bombe gen-linear --turing-256`):
Cauchy structure over 64 distinct points, submatrices of every size (all of
them for sizes 1, 31 and 32, 20,000 sampled for the others), branch number
33 measured on all 8,160 one-byte inputs and on 200,000 each with two and
three, and M x M^-1 = I.

## Analysis behind the round count

Turing's tools work on 16 bytes (2^16 activity patterns). For 32 bytes
(2^32 patterns) Bombe uses `bombe::wide`: when MixState and ShiftRows +
MixColumns alternate, only the number of active bytes matters after each
MixState, because an MDS layer can put a given number of active bytes
anywhere. The count-level trail bound reproduces Turing's exact 16-byte
pattern bound for every window from both starting layers, and the
count-level division property reproduces Turing's word-level engine on all
46 structures it was validated on (tests in `wide.rs`).

| Property | Turing-256 | Turing |
|---|---|---|
| Fewest active S-boxes, 1 to 8 rounds | 1, 5, 34, 45, 67, 68, 100, 101 | 1, 5, 18, 25, 35, 36, 52, 53 (docs/09) |
| Longest usable trail (probability above 1 / codebook) | 3 rounds (4 rounds: 45 active, ≤ 2^-270 < 2^-256) | 3 rounds (4 rounds: 25 active, ≤ 2^-150 < 2^-128) |
| Longest impossible differential (one byte in, one out) | 4 rounds (ShiftMix, MixState, ShiftMix) | 4 rounds |
| Division property, plaintext sets | 2^8-2^24: 3; 2^32-2^192: 4; 2^200-2^240: 5; 2^248: 6 | 2^8-2^24: 3; 2^32-2^112: 4; 2^120: 5 |
| Every round key behind (key schedule) | 67 active S-boxes | 53 |

The one change: the largest structures a 256-bit block allows (2^248 of
its 2^256 plaintexts) stay balanced for five rounds, one more than
Turing's 2^120 set, so docs/09's rule gives max(3, 4, 5) + 4 = 9 against
Turing's 8. With partial sums at the end (docs/14) that distinguisher
reaches 7 rounds on paper for about 2^251. Guessing a whole round key costs
2^256 here, so the extension that took Turing's square attack to 7 rounds
(docs/14) is gone. 24 rounds is 2.7 times the rule's 9 and over 3 times the
longest attack; 24 is also Turing's ceiling, so Turing-256 keeps it.

The key schedule needs fewer warm-up rounds than Turing's (9 against 13):
with 32-byte halves and branch number 33, 8 Feistel rounds already force 67
active S-boxes, and 7 force only 36, below the target of 43 (2^-258). So 9
warm-up rounds is the smallest number that puts every round key, including
the first R half (one round behind), behind the target.

## What was run

Section 24 of `bombe attack` (and `tests/turing256.rs`):

- **Correctness.** The constant-time implementation matches an independent
  reference (`refcipher256`: table S-box, generic matrix products, its own
  ShiftRows and key schedule) on every round count and every round key, and
  reproduces the 8 known-answer vectors in `vectors/turing-256-v1.txt`,
  which the reference generated. `turing::self_test()` checks two of them.
- **Square attack.** One active byte, 2^8 texts: the input of S-box layer
  3 is balanced in all 32 bytes and layer 4's is not (known key), as the
  division property says; round key 3 of 3-round Turing-256 comes out byte
  by byte from two structures; 4 rounds with 2^16 texts fail, as predicted.
- **Avalanche** on the full cipher over 256 x 256 cells, plaintext and key
  bits: every cell within the Bonferroni limit.
- **NIST SP 800-22** on Turing-256 in counter mode: 1 and 2 rounds fail it,
  the full cipher passes all 11 statistics.
- **Faults.** Random bit flips anywhere in the stored round keys, checksum
  and point: every one caught by the checked calls, block wiped.
- **Memory.** Round keys in locked pages (excluded from core dumps on Linux
  and Android; Windows has no such call); the
  memory-dump scan finds key material only in the caller's key buffer and
  the round keys' page, after key setup, after encryptions and after drop.
- **Timing.** dudect on encryption, decryption and key setup.

## A timing leak found and fixed

The first timing run failed: encryption |t| = 2,524, decryption 4,108, key
setup 109 (a leak is |t| > 4.5). The source of MixState256 is the same
branch-free pattern as Turing's MixState (XOR each precomputed column AND a
mask made from one bit of the state), but the release build of the 32-byte
version turned it back into "if the bit is set, XOR the column":
`tools/asm_branches.py` listed 16 conditional jumps testing single bits of
every state byte. The same optimisation did not happen for Turing's 16-byte
layer, only because of the optimiser's cost model, the risk docs/11 cites
from Schneider et al. (2025).

The masks now pass through a value barrier (`linear::bit_masks`, via
`linear::opaque`: an empty inline-assembly block that keeps each mask in a
register and emits no instruction), so the optimiser cannot tell they are
all zeros or all ones. After the change every mixing function of both
ciphers has one conditional jump, its loop counter, every indexed load is
indexed by a loop counter, and dudect measures |t| of at most 1.9 for
Turing-256's encryption, decryption and key setup. Turing's own layers got
the same barrier: they were branch-free, but nothing guaranteed they would
stay so under another compiler version. Their output is unchanged (the
known-answer vectors pass), and they cost about 15% more (6.3 to 7.3 µs per
block here). A first version used `core::hint::black_box`, which sends the
masks through memory and cost Turing 45%. Turing-256 got faster, 21.9 to
14.6 µs per block, since the jumps were mispredicting.

## Planted bugs

`tools/mutate.py --round6` plants 13 bugs: the wrong ShiftRows offsets, the
inverse MixState, one warm-up round fewer, no feed-forward, no S-box in the
key schedule, a linear layer in the last round, decryption's forward layer,
wrong bit masks in Turing's layers, a count-level ShiftMix transition one
byte short, a unit vector from five bytes in one column, a broken subset
enumeration, the reference's ShiftRows rotating the wrong way, and square-
attack guesses judged on one structure. The tests catch all 13. (A 14th,
dropping the first key check of the checked calls, was taken out as
equivalent: the second check still catches every persistent fault, so no
output changes.)

## What is not done yet

- A masked Turing-256 (Turing has `MaskedTuring`, docs/13).
- The 2^32-text square attack on 4 rounds, predicted to work: with the
  constant-time cipher it would take about 1.6 hours on 4 threads, so it
  needs a table-driven version first, as `fast` is for Turing.
- Bit-level division property, for both ciphers (docs/04).
- A mode of operation and file format (step 9, docs/03).
