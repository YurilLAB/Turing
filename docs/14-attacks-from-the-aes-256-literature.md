# 14 — The attacks that go furthest against AES-256, tried on Turing (step 10, fifth campaign)

The question for this round: can the attacks that reach furthest into
AES-256 reach further into Turing than the 4 rounds broken so far? Three
families were added to Bombe, each first checked against its published AES
results:

- the square attack extended by guessing a whole round key, with
  Ferguson et al.'s partial sums (FSE 2000);
- the yoyo game (Rønjom, Bardeh, Helleseth, ASIACRYPT 2017);
- Demirci-Selçuk meet-in-the-middle, with Dunkelman, Keller and Shamir's
  differential enumeration (FSE 2008, ASIACRYPT 2010; counted as Derbez,
  Fouque and Jean count it), the family behind the best single-key attacks
  on AES-256.

```
cargo run --release -p bombe -- attack          # 23 sections, 154 findings, 0 failures (22-23 and part of 3 are new)
cargo run --release -p bombe -- attack --deep   # adds the 2^32-text structures of section 3: 160 findings, 0 failures, 64 min on 4 threads
cargo test --release -- --ignored               # includes the same structures as a test
python tools/mutate.py --round5                 # the planted bugs of this round
```

## Results

| Attack | Checked on AES first | Turing | Cost of the full attack |
|---|---|---|---|
| Square attack, round key 0 guessed | division property reproduces AES's integral distinguishers (docs/11); partial sums equal the plain sum on every guess tested | **7 rounds** (6 with a simpler last step) | 7 rounds: 2^180.6 S-box lookups (2^173.8 encryptions), the full codebook |
| Yoyo game | 3 and 4 rounds always return the pattern, 5 never, as published | 3 rounds from the plaintext; 5 with round key 0 guessed | 5 rounds: about 2^130, the full codebook |
| Demirci-Selçuk | 4 rounds: 25 parameters (24 for differences); enumeration: 10 bytes | 4-round sequences need 36 parameters (2^288), but enumeration brings the table to 22 bytes (2^176), below the key space: **6 rounds**, and **7** with round key 0 guessed (on paper; corrected 2026-09-27, section 3) | 6 rounds: about 2^144 online and 2^189 to build the table, 2^113 chosen plaintexts; 7 rounds: about 2^176 online and 2^189 offline, the full codebook |

The longest attack on Turing is now 7 of its 24 rounds, on paper: it needs
every one of the 2^128 plaintext-ciphertext pairs and about 2^174
seven-round encryptions, far beyond anyone and far below the 2^256 of
trying every key. What was run is the step each guess of round key 0 must
pass, with the right guess and with wrong ones (section 1). The 4 rounds
broken in practice (docs/11) stay the longest attack anyone can run.

## 1. The square attack with round key 0 guessed

Turing starts with MixState so that an attack extended by a round at the
front must guess all 16 bytes of round key 0, not one 4-byte column
(`structure.rs`, docs/09). With a 256-bit key that guess, 2^128, is
affordable on paper. With round key 0 guessed, any set of states can be put
at round 2's S-box input: the plaintext for a target z is
S^-1(MixState^-1(z)) ⊕ RK0, and round 2 then starts from z ⊕ RK1.

Round 2 mixes with ShiftRows + MixColumns, like AES, so a diagonal taking
all 2^32 values there fills a column after one round, as in Ferguson et
al.'s AES attacks. The division property (`bombe::division`, validated on
AES in docs/11) then gives:

| Set at round 2's S-box input | Balanced up to the input of S-box layer |
|---|---|
| 1 to 3 bytes of the diagonal (2^8 to 2^24) | 4 |
| the diagonal (2^32) | **6** |

A set of 2^32 plaintexts chosen at round 1 stays balanced to layer 4
(docs/11), so the guess buys two S-box layers. The hand derivation is in
`research/notes/derivations.md`. No set at round 1 or at round 2 stays
balanced past layer 6 by this analysis. One round later, a set with 15
active bytes at round 3's S-box input would stay balanced to layer 7, but
placing it needs round key 0 and four bytes of round key 1 (2^160 guesses),
each summed over 2^120 texts: more than 2^256.

**Run on the real key schedule** (`keyedsquare::structure`, table-driven
rounds `bombe::fast` checked against `Turing::encrypt_rounds`, 4,096 blocks
per structure rechecked by the real cipher, no mismatch):

| Structure | Balanced at the inputs of S-box layers |
|---|---|
| diagonal, 2^32 texts, round key 0 right (two structures, and two more under each of two other keys in the test and `attack --deep`) | 2, 3, 4, 5, 6 (all 16 bytes); layer 7: 0 of 16 bytes |
| 3 diagonal bytes, 2^24 texts, right | 2, 3, 4 |
| diagonal, round key 0 one byte wrong | 2, 3; at layer 6 no byte of the sum is zero |
| diagonal, round key 0 random | 2 only; at layer 6 one byte of 16 is zero (chance) |

**6 rounds.** Round 6 is the last, so each byte of RK6 is guessed on its
own: S^-1(c ⊕ k) must sum to zero. The first
structure left 1 to 3 guesses per byte, always including the right one;
two left exactly one per byte, all 16 right. Under the one-byte-wrong and
the random guess of round key 0 the right byte survived in 0 and 1 of 16
positions, and 6 of the 16 bytes kept no guess at all, which is what
rejects a wrong guess.

**7 rounds.** Round 6 now has ShiftRows + MixColumns. A byte of the layer 6
input is S^-1(Σ_i M^-1[r][i] · S^-1(C[4c + i] ⊕ RK7[4c + i]) ⊕ e), with
e = ShiftRows^-1(MixColumns^-1(RK6)): four bytes of a column of RK7 and one
of e, 2^40 guesses. Ferguson et al.'s partial sums fold the ciphertexts
into parities of (x, c2, c3), then (x, c3), then x, one key byte at a time,
about 2^50 S-box lookups per structure instead of 2^72; the tests check
that they give exactly the guesses the plain sum gives. Run with two of the
column's bytes given (2^24 guesses per byte of the layer 6 input, the four
bytes that share the column checked together): one structure
leaves about 2^16 of the 2^24 guesses for each of the four bytes (65,147
to 65,413), always including the right one, and 10,370 of the 2^16 values
of the column's other two bytes; two structures leave exactly one, the
right one, with the right byte of e for all four. Under either wrong guess
of round key 0 the right value did not survive one structure.

**What the full attacks cost.** Each guess of round key 0 asks for its own
plaintexts, so over all guesses the attacker needs the whole codebook,
2^128 pairs stored (2^132 bytes).

| Rounds | Work | Why |
|---|---|---|
| 6 | 2^160 codebook lookups | one structure per guess; a wrong guess keeps a candidate in all 16 bytes with probability 2^-10.6 |
| 7 | 2^180.6 S-box lookups = 2^173.8 seven-round encryptions | about 6 structures of 2^50 per guess before a wrong one dies |
| 6, without guessing round key 0 | about 2^152 S-box lookups, 2^124 chosen plaintexts | docs/11's 2^120 set, balanced at layer 5; one byte there needs all of RK6 and one byte of MixState^-1(RK5); partial sums over 16 bytes |
| 8 | more than 2^256 | a byte of layer 6 through rounds 6-8 needs all of RK8 on top of RK0 |

Ferguson et al.'s 7-round attack on AES-256 also guesses a whole 16-byte
round key, the last one, and costs about 2^172 with 21 · 2^32 chosen
plaintexts. On Turing the guessed key has to be the first, behind MixState,
which is why the attack here needs the full codebook.

**Against the round-count rule.** docs/09 allowed 4 rounds of key guessing
around the longest distinguisher (4 rounds), including a full 16-byte key
at each end: 8. This attack uses 3 of them (one at the front for 2^128, two
at the back) around a 4-round distinguisher: 7 ≤ 8. The rule holds, and
the cipher has 24.

## 2. The yoyo game

For E = S ∘ L ∘ S with S layers of independent word permutations and L
linear, swapping words between two ciphertexts and decrypting returns two
plaintexts whose difference is zero in exactly the words where the first
pair's was (their Theorem 2). The words at the two ends need not be the
same size: the swap uses the last S layer's words, the pattern the
first's. Two AES rounds are one layer of super-boxes, so 4 AES rounds (their
Algorithm 3) and 3 (Algorithm 2) return the pattern every time.

`bombe::yoyo` plays it; `bombe::aes` is AES-128 with any number of rounds,
checked against FIPS-197:

| Cipher and rounds | Pattern returned |
|---|---|
| AES, 3 rounds (one new ciphertext) | always |
| AES, 4 rounds | always |
| AES, 5 rounds (control) | never |
| Turing, 2 rounds (bytes) | always |
| Turing, 3 rounds (bytes at the plaintext, columns at the ciphertext) | always |
| Turing, 4 rounds (any words) | never |
| Turing, 5 rounds, round key 0 guessed right (diagonals at round 2, columns) | always |
| the same, one bit of round key 0 wrong / 6 rounds | never |

Rounds 1-3 are S ∘ MixState ∘ super-boxes, because round 2's MixColumns
joins the S-box layers of rounds 2 and 3. From round 1, four rounds put
MixState on both sides of a super-box layer and the game stops. Rounds 2-5
are super-box, ShiftRows ∘ MixState, super-box: a 4-round yoyo, but behind
round 1, so it needs round key 0 guessed. Over every guess that is about
2^130 work with the full codebook for 5 rounds, more than the square
attack's 5 rounds (two structures of 2^120 chosen plaintexts, docs/11).

## 3. Demirci-Selçuk meet-in-the-middle

Take a δ-set (256 states differing in one byte, which takes every value)
after an S-box layer; the sequence of values one output byte takes a few
rounds later is fixed by the bytes of each S-box layer in between that are
both active and needed for that output byte. The attacker tabulates every
possible sequence offline, then guesses outer round keys online and looks
sequences up; the table must stay smaller than the key space.
`bombe::mitm` counts the parameters and reproduces Derbez and Fouque's
Property 5 (FSE 2013): 4 AES rounds, 4 + 16 + 4 = 24 for differences, 25
for values. Dunkelman et al.'s differential enumeration keeps only δ-sets
holding a pair that follows a sparse trail, which leaves AES's table 10
bytes (2^80, the count Derbez, Fouque and Jean give); `mitm::enumerated`
reproduces the 10.

| Rounds | AES | Turing, δ-set after round 1's S-boxes | after round 2's |
|---|---|---|---|
| 3 | 8 | 32 | 8 |
| 4 | 24 | 36 | 36 |
| 5 | 40 | 64 | 40 |

MixState makes every S-box layer next to it count in full: a 4-round
sequence has 2^288 possible values, more than the 2^256 keys. Enumeration
brings it to 22 bytes (2^176), with a pair that must go from 16 active
bytes to 1 through MixState, probability 2^-120. The 3-round property after
round 2's S-boxes has 8 parameters, but its δ-set sits behind round 1 and
needs round key 0: with a byte of RK5 for the output, 5 rounds at about
2^144 S-box lookups.

**Correction (review of 2026-09-27).** An earlier version of this section
ended "the family ... reaches 5 of Turing's 24, two fewer than the square
attack". That does not follow from its own numbers: the enumerated table,
2^176, is smaller than the 2^256 key space, which is the usability rule
`mitm.rs` states, and the 2^-120 pair probability is paid with data. The
review (research/reviews/2026-09-27/attacks-docs14.md, F1) builds two
attacks from the ingredients above, on paper, under the usual
Dunkelman-Keller-Shamir and Derbez-Fouque-Jean assumptions (about one
S-box solution per difference pair, multisets as table keys):

- 6 rounds with nothing guessed at the front: 2^105 structures of 2^8
  plaintexts (2^113 chosen plaintexts, not the full codebook) for a right
  pair, about 2^144 S-box lookups online, and about 2^189 to build the
  table (2^176 entries of 256 states, 36 S-boxes each);
- 7 rounds with round key 0 guessed, the square attack's model: about
  2^176 online and the same 2^189 offline, the full codebook.

So Demirci-Selçuk reaches 7 rounds on paper, like the square attack, not
two fewer. Neither attack was run. The round-count rule (8) and the
24-round margin are unaffected: at 8 rounds the key material behind the
property grows to all of round key 8 and more. Campaign section 23 now
checks the table against the key space; it compared it with 2^128
before, which is why it did not flag this.

## 4. Considered, not built

- Impossible differentials with round key 0 guessed: Turing's 4-round
  impossible differentials start at an even round's S-box layer and end
  three rounds later (`impossible::find` finds them over ShiftRows +
  MixColumns, MixState, ShiftRows + MixColumns only; docs/09), so the
  earliest runs from round 2 to round 5, and with round key 0 guessed they
  reach 5 rounds. A wrong guess only shows when a pair's ciphertexts
  differ in the one byte the impossible differential names and nowhere
  else, 2^-120 per pair. An earlier version priced this by looping over the
  2^128 guesses ("at least 2^188 work, more than every attack above"). The
  review of 2026-09-27 (F3) prices it pair by pair instead: each right-shaped
  pair rules out about 2^12 guesses, for about 2^134.5 work with 2^115.4
  chosen ciphertexts, cheaper than the Demirci-Selçuk attacks but still
  5 rounds (on paper, not run).
- Biclique attacks cover the full cipher only as a small speed-up of
  trying every key; they do not reduce the rounds a cipher keeps.
- Related-key attacks: blocked by the cSHAKE256 key schedule (docs/07, 11).

## 5. Planted bugs

`tools/mutate.py --round5` plants 14 bugs in the new tools (table-driven
rounds built from the inverse S-box, a plaintext without its inverse S-box,
ShiftRows undone the wrong way, partial sums that skip a key byte, a yoyo
swap of an equal word, AES's first ShiftRows kept, the wrong diagonal in
the meet-in-the-middle dependencies, and others); the tests catch every
one. The first run missed one: a yoyo swap that takes the first word
instead of the first word that differs, which only matters when the pair
agrees in its first word, and the test had only pairs that differ
everywhere. A test for such a pair now catches it.

## Sources

- Ferguson, Kelsey, Lucks, Schneier, Stay, Wagner, Whiting. Improved
  Cryptanalysis of Rijndael. FSE 2000.
  https://www.schneier.com/wp-content/uploads/2016/02/paper-rijndael.pdf
- Rønjom, Bardeh, Helleseth. Yoyo Tricks with AES. ASIACRYPT 2017.
  https://eprint.iacr.org/2017/980
- Derbez, Fouque. Exhausting Demirci-Selçuk Meet-in-the-Middle Attacks
  against Reduced-Round AES. FSE 2013.
  https://www.di.ens.fr/~fouque/pub/fse13b.pdf
- Demirci, Selçuk. A Meet-in-the-Middle Attack on 8-Round AES. FSE 2008
  (through Derbez-Fouque).
- Dunkelman, Keller, Shamir. Improved Single-Key Attacks on 8-Round AES-192
  and AES-256. ASIACRYPT 2010 (through Derbez-Fouque).
- Derbez, Fouque, Jean. Improved Key Recovery Attacks on Reduced-Round AES
  in the Single-Key Setting. EUROCRYPT 2013 (the 10-byte table, through
  Derbez-Fouque).
- Todo. Structural Evaluation by Generalized Integral Property.
  EUROCRYPT 2015 (docs/11).
