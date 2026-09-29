# 15. Turing-256: the same design on a 256-bit block (step 11)

The owner asked for a direct upgrade of Turing to a 256-bit block, keeping
the 256-bit key. Turing-256 is Turing's design on a 32-byte state. It has the
same S-box, the same alternation of a whole-state MDS layer with ShiftRows +
MixColumns, the same kind of key schedule and the same fault and memory
protection. Bombe computed or measured everything below, and each of its
tools was first checked against what it already reproduced for Turing.

```
cargo run --release -p bombe -- attack             # section 24 attacks Turing-256 (179 findings, 0 failures)
cargo run --release -p bombe -- gen-linear --turing-256   # regenerates its MixState
cargo run --release -p bombe -- gen-constants --turing-256  # regenerates its round constants (v2)
cargo run --release -p bombe -- vectors --turing-256      # its known-answer vectors
cargo test --release -p bombe --test turing256     # against the independent reference
python research/scripts/turing256_py.py            # against a third implementation, in Python
python tools/mutate.py --round6                    # the planted bugs of this round
```

## Why a wider block

| | Turing (128-bit block) | Turing-256 |
|---|---|---|
| Key search, classical / Grover | 2^256 / about 2^128 | the same: the key is still 256 bits (NIST's highest category, like AES-256) |
| Birthday bound of any mode (blocks under one key before collisions) | 2^64 | 2^128 |
| Quantum collision search on the block (Brassard-Høyer-Tapp, about 2^(n/3)) | about 2^43 | about 2^85 |
| A 32-byte key or hash fits in one block | no | yes |

A wider block doesn't make key search harder. What it removes are the data
limits that come from the block size, which is the part of a 128-bit design
that quantum collision finding weakens most.

## Specification

| Parameter | Turing-256 | Reason |
|---|---|---|
| Block, key | 256 bits, 256 bits | the request; key search as Turing's |
| State | 4 rows x 8 columns, byte 4c + r at row r, column c | Turing's layout, twice as wide |
| Rounds | 24, round keys 25 x 32 bytes | the analysis below; Turing's ceiling |
| Round r | S-box layer (all 32 bytes), linear layer, round constant r, round key r | Turing's round, plus the constant (version 2, below) |
| Round constants | 24 x 32 bytes, read in order from cSHAKE256("", S = "Turing-256 v2 round constants") | every round and every column different |
| S-box | Turing's (A_out ∘ x^254 ∘ A_in, docs/05), constant-time | unchanged |
| Odd rounds | MixState256: 32 x 32 Cauchy matrix, branch number 33 | one byte changes all 32 |
| Even rounds | ShiftRows (rows rotate left by 0, 1, 3, 4) + Turing's 4 x 4 MixColumns on all 8 columns | Rijndael's offsets for 8 columns: each column's bytes go to four different columns |
| Last round | no linear layer | as Turing |
| Key schedule | cSHAKE256(K, "Turing-256 v2 key") to 64 bytes; Feistel on 32-byte halves with F(x) = MixState256(S(x ⊕ C_j)), C_j from "Turing-256 v2 key schedule constants"; 9 warm-up rounds, then a pair of round keys every 8 rounds; feed-forward | Turing's schedule (docs/07) on wider halves |
| Fault check | Turing's keyed checksum over the 50 stored 16-byte blocks, point from "Turing-256 v2 key check" | docs/13's construction; over 50 blocks the bound is 50/2^127, twice Turing's 25/2^127 |

MixState256 comes from cSHAKE256(X = counter, S = "Turing-256 v1
MixState"). The first 64 distinct bytes are the points x_0..x_31,
y_0..y_31 of M[i][j] = 1/(x_i + y_j). Counter 0 was accepted, as the Cauchy
theorem predicts. Bombe checks the matrix independently
(`bombe gen-linear --turing-256`): the Cauchy structure over 64 distinct
points, submatrices of every size (all of them for sizes 1, 31 and 32,
20,000 sampled for the others), branch number 33 measured on all 8,160
one-byte inputs and on 200,000 each with two and three, and
M x M^-1 = I.

## Analysis behind the round count

Turing's tools work on 16 bytes, which means 2^16 activity patterns. For 32
bytes (2^32 patterns) Bombe uses `bombe::wide`. When MixState and ShiftRows
+ MixColumns alternate, only the number of active bytes matters after each
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

The one change is in the largest structures a 256-bit block allows (2^248
of its 2^256 plaintexts): they stay balanced for five rounds, one more
than Turing's 2^120 set, so docs/09's rule gives max(3, 4, 5) + 4 = 9
against Turing's 8. With partial sums at the end (docs/14), that
distinguisher reaches 7 rounds on paper for about 2^251. Guessing a whole
round key costs 2^256 here, so the extension that took Turing's square
attack to 7 rounds (docs/14) is gone. 24 rounds is 2.7 times the rule's 9
and over 3 times the longest attack. 24 is also Turing's ceiling, so
Turing-256 keeps it.

The key schedule needs fewer warm-up rounds than Turing's (9 against 13).
With 32-byte halves and branch number 33, 8 Feistel rounds already force 67
active S-boxes, while 7 force only 36, below the target of 43 (2^-258). So
9 warm-up rounds is the smallest number that puts every round key,
including the first R half (one round behind), behind the target.

## What was run

Section 24 of `bombe attack` (and `tests/turing256.rs`):

- The constant-time implementation matches an independent reference
  (`refcipher256`: table S-box, generic matrix products, its own ShiftRows
  and key schedule) on every round count and every round key, and
  reproduces the 8 known-answer vectors in `vectors/turing-256-v2.txt`,
  which the reference generated. `turing::self_test()` checks two of them.
  A third implementation, `research/scripts/turing256_py.py` (Python, its
  own Keccak, CI stage `turing256-py`), shares no code or constant with
  either. It derives the S-box, both matrices and the round constants from
  their labels and reproduces all 89 values of the vector file
  (ciphertexts, decryptions, round constants, round keys and every
  reduced-round output). Each of three planted mistakes in it (ShiftRows
  rotating right, 8 warm-up rounds, no round constants) makes it fail.
- For the square attack, one active byte (2^8 texts) leaves the input of
  S-box layer 3 balanced in all 32 bytes and layer 4's not (known key), as
  the division property says. Round key 3 of 3-round Turing-256 comes out
  byte by byte from two structures, and 4 rounds with 2^16 texts fail, as
  predicted.
- Avalanche on the full cipher over 256 x 256 cells, plaintext and key
  bits: every cell is within the Bonferroni limit.
- NIST SP 800-22 on Turing-256 in counter mode: 1 and 2 rounds fail it, and
  the full cipher passes all 11 statistics.
- Random bit flips anywhere in the stored round keys, checksum and point:
  every one is caught by the checked calls, and the block is wiped.
- Round keys sit in locked pages (excluded from core dumps on Linux and
  Android; Windows has no such call). After key setup, after encryptions
  and after drop, the memory-dump scan finds key material only in the
  caller's key buffer and the round keys' page.
- dudect timing tests on encryption, decryption and key setup.

## A timing leak found and fixed

The first timing run failed: |t| came out at 2,524 for encryption, 4,108
for decryption and 109 for key setup (a leak is |t| > 4.5). The source of
MixState256 uses the same branch-free pattern as Turing's MixState (XOR
each precomputed column AND a mask made from one bit of the state), but
the release build of the 32-byte version turned it back into "if the bit
is set, XOR the column". `tools/asm_branches.py` listed 16 conditional
jumps testing single bits of every state byte. The same optimisation did
not hit Turing's 16-byte layer, but only because of the optimiser's cost
model. That is the risk docs/11 cites from Schneider et al. (2025).

The masks now pass through a value barrier (`linear::bit_masks`, via
`linear::opaque`: an empty inline-assembly block that keeps each mask in a
register and emits no instruction), so the optimiser can't tell they are
all zeros or all ones. After the change every mixing function of both
ciphers has one conditional jump, its loop counter, every indexed load is
indexed by a loop counter, and dudect measures |t| of at most 1.9 for
Turing-256's encryption, decryption and key setup. Turing's own layers got
the same barrier. They were branch-free, but nothing guaranteed they would
stay so under another compiler version. Their output is unchanged (the
known-answer vectors pass), and they cost about 15% more (6.3 to 7.3 µs
per block here). A first version used `core::hint::black_box`, which sends
the masks through memory and cost Turing 45%. Turing-256 got faster, 21.9
to 14.6 µs per block, since the jumps were mispredicting.

## Version 2 round constants (2026-09-29)

Version 1 added nothing to the state except the round keys, as Turing does,
so its rounds differ from each other only because its round keys do. Two
attack families work on rounds that are alike. A slide attack needs the
same round function at two positions. An invariant-subspace attack (the
kind that broke PRINTcipher and Midori-64 for weak keys) needs a set of
states that every round maps to itself, such as the states fixed by a
symmetry of the round (ShiftRows + MixColumns commute with rotating the
columns), when the round keys share that symmetry. Version 1 is protected
from both by its key schedule, which makes every round key pseudorandom.
Version 2 makes the protection hold whatever the round keys are, the way
SKINNY and Midori use their round constants: round r XORs a public 32-byte
constant RC_r into the state together with round key r.

The constants RC_1..RC_24 are the first 768 bytes of cSHAKE256("",
S = "Turing-256 v2 round constants"), in order, with no search
(`bombe gen-constants --turing-256`; a test regenerates
`crates/turing/src/round_constants256.rs` and requires an exact match).
They are pairwise different, and none is fixed by rotating the columns (by
1 to 7) or the rows within every column (by 1 to 3), so no round equals
another and no such rotation commutes with any round's addition, even when
the round keys are symmetric. A test checks both against controls built
with each symmetry.

Every key-schedule label moved from "v1" to "v2". With v1's labels, one key
used in both versions would give round keys that differ by exactly the
public constants: a related-key pair the attacker knows. The MixState label
stays "v1", because the matrix did not change.

We measured what the constants buy. Beierle, Canteaut, Leander and Rotella
(CRYPTO 2017) give the criterion docs/11 applied to Turing's round keys:
the differences between what two rounds with the same linear layer L add
are linear structures of any invariant. So once W_L(D), the smallest
L-invariant space holding those differences, is the whole state, an
invariant can only be affine, and that would need an S-box with a linear
component; Turing's has none. `bombe::invariant::wide` computes it on 256
bits. From the round constants alone (the case where every round key is
equal, in which version 1 has W = {0}), W = 256 of 256 for the MixState
rounds, for the ShiftRows + MixColumns rounds, and for both layers
together. One difference already reaches all 256 dimensions for either
layer, as for Turing's (docs/11). The controls give 0: no constants, and
constants that differ only between the two kinds of round.

A constant XORed into every text alike cancels in every difference and
keeps every balanced sum balanced, so the trail bounds, the impossible
differentials, the division property and the square attack above are
exactly as before (the 3-round square attack now recovers round key
3 ⊕ RC_3, which gives round key 3 at once). Key search is still 2^256. The
cost is one 32-byte XOR per round. The constants sit in read-only memory
beside the S-box and matrix constants; a persistent fault there changes
both directions alike, so the checked calls do not see it, exactly as for
those constants.

The constant-time implementation, the reference (its own cSHAKE256 from the
sha3 crate) and the Python implementation (its own Keccak) derive the
constants independently and agree on all 24 and on the new vectors,
`vectors/turing-256-v2.txt`, which lists them.

## Planted bugs

`tools/mutate.py --round6` plants 20 bugs. Seven are version 2's:
encryption leaving out the round constants, the same constant in every
round, decryption taking them in reverse order, the key-schedule labels
left at v1, the reference without constants, the 256-bit invariant closure
never applying the layers, and the square attack's target missing the
constant. The other 13 are version 1's: the wrong ShiftRows offsets, the
inverse MixState, one warm-up round fewer, no feed-forward, no S-box in the
key schedule, a linear layer in the last round, decryption's forward layer,
wrong bit masks in Turing's layers, a count-level ShiftMix transition one
byte short, a unit vector from five bytes in one column, a broken subset
enumeration, the reference's ShiftRows rotating the wrong way, and
square-attack guesses judged on one structure. The tests catch all 20.
(One more, dropping the first key check of the checked calls, was taken out
as equivalent: the second check still catches every persistent fault, so no
output changes.)

## What is not done yet

- A masked Turing-256 (Turing has `MaskedTuring`, docs/13).
- The 2^32-text square attack on 4 rounds, predicted to work: with the
  constant-time cipher it would take about 1.6 hours on 4 threads, so it
  needs a table-driven version first, as `fast` is for Turing.
- Bit-level division property, for both ciphers (docs/04).
- A mode of operation and file format (step 9, docs/03).
