# 09 — Round structure and round count (step 7; version 2 in step 10)

## The round

Encryption adds round key 0, then runs 24 rounds (version 2; version 1
had 16). Each round is:

1. the S-box layer (16 S-boxes),
2. a linear layer, **MixState in odd rounds (1, 3, …, 23)** and
   **ShiftRows + MixColumns in even rounds (2, 4, …, 22)**, none in round 24,
3. the round key.

That makes 25 round keys and 12 MixState layers. It is defined in
`crates/turing/src/structure.rs`, which also fixes 24 as the maximum.

The last round has no linear layer for the same reason AES drops its last
MixColumns: a public linear map after the final key addition can be undone by
anyone, so it adds no security.

## The tools behind the choice

### Trail bounder (differential and linear)

`crates/bombe/src/trail.rs` tracks which of the 16 bytes carry a difference
(a 16-bit *activity pattern*). S-box layers keep the pattern and cost one
active S-box per active byte. An MDS layer with n inputs allows a transition
from pattern X to pattern Y exactly when both are zero or wt(X) + wt(Y) ≥ n + 1
(every support of that size is taken by some codeword of an MDS code, so this
is exact at the byte level). A dynamic program over all 2^16 patterns gives
the minimum number of active S-boxes over any number of rounds, for any mix
of layers.

Linear trails give the same numbers. Masks move through ShiftRows in the same
direction as differences, and through the transposed inverse of an MDS
matrix, which is also MDS with the same branch number.

**Validation:**

- AES (ShiftRows + MixColumns in every round) reproduces the published table
  for 1–14 rounds exactly: 1, 5, 9, 25, 26, 30, 34, 50, 51, 55, 59, 75, 76, 80
  (Mouha, Wang, Gu, Preneel, Inscrypt 2011, Table 4).
- MixState in every round gives 1, 17, 18, 34, 35, …, the two-round
  propagation theorem met exactly.
- The column-by-column shortcut agrees with brute-force enumeration of every
  allowed pattern pair, on all 14 mixed schedules with 1–3 linear layers.
- Every pair of rounds meets its layer's branch number (5 or 17) in all 64
  mixed schedules of 6 layers.

### Impossible-differential search

`crates/bombe/src/impossible.rs` is the miss-in-the-middle method. Each byte
is certainly zero, certainly non-zero, or unknown. What is certain is pushed
forward from the input pattern and backward from the output pattern, and any
contradiction (a byte zero on one side and non-zero on the other, or a linear
layer whose two sides cannot fit its branch number) proves the pair of
patterns impossible for every key. The rules only claim what must hold, so
everything found is real.

**Validation:**

- For AES it finds the classic 4-round impossible differential (Biham and
  Keller) and none over 5 rounds. Sun, Liu, Guo, Rijmen and Li (EUROCRYPT
  2016) proved that impossible differentials not using S-box details cover at
  most 4 AES rounds. Wang and Jin (DCC 2019) showed no concrete impossible
  differential longer than 4 rounds exists for AES.
- Every impossible differential it reports is rechecked by exhaustively
  enumerating all byte-level trails between the two patterns.

## Comparing structures

`cargo run --release -p bombe -- rounds 16` compares candidate layer
schedules for a 16-round cipher. Figures are the weakest window of r
consecutive rounds anywhere in the cipher:

| Structure | r2 | r3 | r4 | r5 | r6 | r7 | r8 | to 22 | to 43 | Imp. diff. | Cost |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AES-like (no MixState) | 5 | 9 | 25 | 26 | 30 | 34 | 50 | 4 | 8 | 4 | 5312 |
| MixState every round | 17 | 18 | 34 | 35 | 51 | 52 | 68 | 4 | 6 | 2 | 8192 |
| **MixState every 2nd round (Turing)** | **5** | **18** | **25** | **35** | **36** | **52** | **53** | **4** | **7** | **4** | **6848** |
| MixState every 3rd round | 5 | 9 | 22 | 26 | 30 | 43 | 47 | 4 | 7 | 4 | 6272 |
| MixState every 4th round | 5 | 9 | 22 | 26 | 30 | 34 | 47 | 4 | 8 | 4 | 5888–6080 |
| MixColumns every 3rd, MixState otherwise | 5 | 18 | 22 | 23 | 39 | 40 | 44 | 4 | 8 | 3 | 7232 |
| MixColumns every 4th, MixState otherwise | 5 | 18 | 22 | 35 | 36 | 52 | 53 | 4 | 7 | 3 | 7424–7616 |

"to 22" and "to 43" are the rounds after which every window has at least 22
active S-boxes (probability ≤ 2^-132) or 43 (≤ 2^-258). Cost counts field
multiplications in the constant-time code. For version 2's 24 rounds
(`rounds` with no argument) the window figures are the same and every cost
grows by half: Turing 10304 against 8000 for the AES-like structure.

What the table shows:

- **Strict alternation gives the best trail bounds for its cost.** Any 3
  rounds have 18 active S-boxes (AES: 9), any 5 have 35 (AES: 26), any 7 have
  52 (AES: 34).
- **MixState every 4th or 5th round buys nothing** at 7–8 rounds compared with
  AES. The step-6 review rule "MixState at least every 4 rounds" was too weak
  and is replaced by alternation.
- **Alternation does not shorten impossible differentials: they still reach
  4 rounds.** The tool shows why. One active byte becomes 4 through
  MixColumns, and from a one-byte output the same happens backwards. A
  MixState in between would need 4 + 4 ≥ 17, a contradiction.
- Mixes heavier in MixState cut impossible differentials to 3 rounds, but
  they are weaker on trails at 4–8 rounds and cost more.
- MixState in every round is best on every measure but is not a mix, and it
  costs 20% more. It remains an option.

### Why MixState in the odd rounds

Odd-round and even-round alternation have identical bounds. Odd rounds put
MixState in round 1 and in the last linear layer (round 15 in version 1,
23 in version 2). An attack extended
by a round at either end then has to guess a whole 16-byte round key to
follow one active byte, instead of one 4-byte column. It costs one more
MixState layer.

## Turing's numbers

| Rounds (any window) | Min active S-boxes | Trail probability |
|---|---|---|
| 1 | 1 | ≤ 2^-6 |
| 2 | 5 | ≤ 2^-30 |
| 3 | 18 | ≤ 2^-108 |
| 4 | 25 | ≤ 2^-150 |
| 5 | 35 | ≤ 2^-210 |
| 6 | 36 | ≤ 2^-216 |
| 7 | 52 | ≤ 2^-312 |
| 8 | 53 | ≤ 2^-318 |
| 16 (version 1's whole cipher) | 136 | ≤ 2^-816 |
| 16 (weakest window of version 2) | 121 | ≤ 2^-726 |
| 24 (version 2's whole cipher) | 204 | ≤ 2^-1224 |

For the whole cipher, the 24 rounds split into 12 pairs, each around one
MixState, so the two-round theorem gives 12 × 17 = 204. The bounder confirms
that is the exact minimum. Differential and linear bounds are the same.

- Longest impossible differential: 4 rounds.
- Full diffusion: every output byte depends on every input byte after 3
  rounds (2 starting from a MixState round).

## Round count: 16, then 24

Version 1 chose 16 by the rule below. Version 2 raised it to 24 (docs/13):
the published ways to make the S-box less algebraic weakened it on every
other count, so the extra strength comes from rounds, with 24 fixed as the
maximum. The rule:

1. A differential or linear distinguisher is usable only if its trail
   probability is above 2^-128, since the attacker cannot get more than the
   2^128 possible blocks. Every 4-round window already has at least 22 active
   S-boxes (≤ 2^-132), so usable trails cover at most **3 rounds**.
2. The longest impossible differential covers **4 rounds**.
3. Attacks add rounds around a distinguisher by guessing key material. The
   best impossible-differential attacks on AES add 3 rounds to a 4-round
   distinguisher. We allow **4** (2 at each end), even though MixState at
   both ends makes each of those rounds cost a full 16-byte key guess.
   That allowance was needed: against a 256-bit key the 2^128 guess is
   affordable on paper, and the square attack spends one such round at
   the front and two at the back, 4 + 3 = 7 rounds (docs/14).
4. So the longest attack these techniques can build is max(3, 4) + 4 =
   **8 rounds**.
5. Version 1 had **twice that: 16 rounds**, more than AES-256's 14.
   Version 2 has **three times that: 24 rounds**.

Cross-check: even trails that a 2^256 budget could not use (≥ 43 active
S-boxes) run out after 7 rounds, and 7 + 4 = 11 is well below 16, let alone 24.

For comparison, the best single-key attacks on AES-256 reach 9 of its 14
rounds with practical-model meet-in-the-middle techniques, and 10 rounds with
more exotic ones.

### What the margin is for

These tools cover differential, linear and impossible-differential
cryptanalysis at the byte level. They do not model:

- **differentials and linear hulls** (many trails adding up), the usual gap
  between trail bounds and real probabilities,
- **meet-in-the-middle** attacks (the best known attacks on AES-256),
- **integral / division-property** distinguishers,
- **algebraic** attacks.

Step 10 has since measured three of these. **Clustering is bounded**
(docs/12). Park et al.'s theorem counts every trail at once, under
independent round keys. Any 3 consecutive rounds contain S-box layer,
MixState, S-box layer, so every differential over them has probability at
most 2^-102.0 and every linear hull at most 2^-99.6 (the same argument gives
AES only 2^-28.3). Any 5 rounds: 2^-110.8 and 2^-105.9. The integral
part (docs/11): the word-level division
property keeps a 2^120-plaintext set balanced through 4 rounds, and a 4-round
key recovery with 2^32 plaintexts was run and works: max(3, 4, 4) + 4 = 8,
so the rule above is unchanged. Cube testers stop at 2 rounds, and the
interpolation attack finds no sparse polynomial to start from. The fifth
campaign (docs/14) measured meet-in-the-middle: Demirci-Selçuk sequences
over 4 rounds need 36 parameters (AES 24), but differential enumeration
brings the table to 22 bytes (2^176), below the 2^256 keys, so that family
reaches 6 rounds, and 7 with round key 0 guessed, on paper (corrected
after the review of 2026-09-27; docs/14, section 3). The yoyo game stops
at 5 rounds, and the square attack with round key 0 guessed reaches 7
rounds on paper (the full codebook, about 2^174 encryptions): both 7-round
attacks are within the rule's 8. Hulls and bit-level models remain, and
the factor-of-two margin is there for them.

## Cost

In the constant-time code (field multiplications, each 8 steps), a 24-round
Turing encryption costs 10304 units against 8000 for an AES-like 24-round
structure (16 rounds: 6848 against 5312): 29% more for 50–100% more active
S-boxes in 3–7 round windows.

## Sources

- Mouha, Wang, Gu, Preneel. Differential and Linear Cryptanalysis Using
  Mixed-Integer Linear Programming. Inscrypt 2011.
  https://mouha.be/wp-content/uploads/milp.pdf
- Daemen, Rijmen. The Design of Rijndael (wide trail strategy, two- and
  four-round propagation theorems).
- Biham, Keller. Cryptanalysis of Reduced Variants of Rijndael (the 4-round
  impossible differential).
- Sun, Liu, Guo, Rijmen, Li. Provable Security Evaluation of Structures
  Against Impossible Differential and Zero Correlation Linear Cryptanalysis.
  EUROCRYPT 2016.
- Wang, Jin. More accurate results on the provable security of AES against
  impossible differential cryptanalysis. Designs, Codes and Cryptography, 2019.
- Derbez, Fouque, Jean. Improved Key Recovery Attacks on Reduced-Round AES in
  the Single-Key Setting. EUROCRYPT 2013. Li, Jia, Wang. Improved Single-Key
  Attacks on 9-Round AES-192/256. FSE 2014. Meet-in-the-middle attacks on
  10-round AES-256. Designs, Codes and Cryptography, 2016.
- Rijmen, Daemen, Preneel, Bosselaers, De Win. The Cipher SHARK. FSE 1996
  (an SPN with a whole-state MDS layer in every round, the precedent for
  MixState).
