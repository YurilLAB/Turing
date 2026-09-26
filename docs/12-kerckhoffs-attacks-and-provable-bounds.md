# 12 — Attacks by someone who knows everything (step 10, third campaign)

Kerckhoffs's principle (doc 01): a cipher must stay secure when the
attacker knows everything except the key. That means the source code,
every constant, how the S-box was derived and why the matrices look the way
they do. This round attacks Turing from exactly that position. The attacker
uses the real S-box, the real matrices and the real key schedule, and looks
for anything special about them. It also hardens the library itself. Step 9
(file encryption) is parked until this is done.

```
cargo run --release -p bombe -- attack          # 93 findings, about 60 s
cargo run --release -p bombe -- attack --deep   # adds the long runs below
cargo test --release -- --include-ignored       # every test, including the slow one
python tools/mutate.py --round3                 # the planted bugs of this round
```

## Results

| Question an attacker who knows everything asks | Answer | Section |
|---|---|---|
| Can many differential trails add up to something usable? | No. Any 3 consecutive rounds: every differential ≤ 2^-102.0 and every linear hull ≤ 2^-99.6 (the same argument gives AES only 2^-28.3). Any 5 rounds: ≤ 2^-110.8 / 2^-105.9 | 15 |
| What is the best real 2-round differential? | 57/2^35 = 2^-29.17 through ShiftRows+MixColumns, found by exact search (AES: 53/2^34 = 2^-28.27) | 15 |
| Does the round commute with some shuffle of the bytes? | Only the identity, once both layers are counted (AES's round has 4 such shuffles); no pair of shuffles crosses MixState either | 16 |
| Does it have a hidden scaling symmetry? | No: only the identity passes the S-box (the bare inverse function has 255) | 16 |
| Is decryption secretly encryption (reflection)? | No: nearest at rank 124 of 128 (an involutional control scores 0) | 16 |
| Do round keys obey linear equations? | No: 0 relations among 2,432 key and round-key bits, with or without cSHAKE (AES-128: 1,088) | 17 |
| Differential-linear? | Breaks 2 rounds, exactly as predicted from the S-box; nothing from 3 | 18 |

## Provable bounds: counting every trail

Earlier steps counted active S-boxes along the single best trail. The
standard objection is that many trails can share the same input and output
difference and add up (clustering, or linear hulls). The answer
designers give is a *provable* bound on the expected probability of every
differential and every linear hull. It holds under the usual model in which
the round keys are independent and uniformly random (a Markov cipher).

**The theorem.** Park, Sung, Lee and Lim (FSE 2003, Theorem 1) prove that
for two rounds, an S-box layer, a linear layer with branch number B and
another S-box layer, every differential has probability at most the largest
sum over one row (or column) of the S-box's difference table of DP^B. Their
Theorem 2 gives the same for linear hulls with LP = correlation². Turing's
S-box is affine-equivalent to x^-1, like AES's, so every row has the same
values: one entry 2^-6, 126 entries 2^-7, and the rest zero.

**Checked against the literature first.** Bombe's implementation
(`bombe::provable`) reproduces both AES bounds exactly: 79/2^34 and
192,773,764/2^54, the values Keliher and Sui (ePrint 2005/321) quote as the
earlier upper bounds.

**What it gives Turing.**

- *Two rounds through ShiftRows+MixColumns (B = 5):* the same bounds as AES,
  2^-27.70 and 2^-26.48.
- *Two rounds through MixState (B = 17):* 2^-102.00 for differentials and
  2^-99.63 for linear hulls.
- *Any 3 consecutive rounds:* with independent keys, extra rounds never help
  an attacker. Summing over the differences before and after a window, the
  other rounds contribute factors that add up to 1: the rows of a
  permutation's difference table, or Parseval for correlations. Every 3
  consecutive rounds contain S-box layer, MixState, S-box layer, so the B = 17
  bound holds for all of them. The same argument gives AES only its 2-round
  value for 3 rounds, 2^-28.27.
- *Any 5 consecutive rounds, and so the full cipher:* 4 rounds that start
  with ShiftRows+MixColumns are four 32-bit super-boxes, then MixState, then
  four more super-boxes. MixState has branch number 5 counted in 32-bit
  words: a active bytes in give at least 17 − a out. Applying the theorem to
  the super-boxes gives μ⁴, where μ bounds one super-box. This is the argument
  Park et al. and Keliher and Sui use for AES. With μ ≤ 79/2^34 it gives
  2^-110.8 for differentials and 2^-105.9 for linear hulls. Every window of 5
  rounds contains such a 4-round block. For comparison, Park et al.'s bounds
  for 4 rounds of AES are 1.144 × 2^-111 and 1.075 × 2^-106. Those are
  essentially the same numbers; their case analysis trims the product
  slightly.

**The exact best differential.** Keliher and Sui's Theorem 1 gives a lower
bound on μ. It is the largest exact probability of a differential whose
activity pattern has the minimal 5 active S-boxes, summed over all 255
characteristics that share its input and output differences. Bombe runs
that search with pruning, over all 56 patterns and all 255^5 choices of outer
differences:

- AES: **53/2^34** exactly, the value Keliher and Sui prove is AES's true
  2-round MEDP. A second, brute-force implementation agrees with the pruned
  search on restricted ranges.
- Turing: **57/2^35 = 2^-29.17**, for a differential with 2 active input
  bytes and 3 active output bytes. That is about half of AES's best
  (106/2^35).

So Turing's μ lies between 57/2^35 and 79/2^34. Pinning it exactly would
need Keliher and Sui's full upper-bound search over about 2^24 larger lists,
which is not done here. If μ equals the lower bound, the 5-round bound
improves to (57/2^35)^4 = 2^-116.7, against 2^-113.1 for AES.

**Limits.** These are expected probabilities with independent round keys.
Real keys come from the key schedule; that gap is the same for every
provably bounded cipher. They say nothing about attacks that are neither
differential nor linear.

## Symmetries

A symmetry is a map φ with Round(φ(x)) = φ′(Round(x)) for the keyless round.
With keys it becomes a related-key property. With a key schedule that
repeats itself, it becomes a weak-key class or a slide attack. Only two
families of maps can get through an S-box layer:

- *Byte permutations.* The S-box layer applies one S-box to every byte, so it
  commutes with any shuffle of the bytes.
- *Bytewise affine maps* built from the S-box's self-equivalences
  S(A x) = B S(x).

**Permutations.** Bombe searches all 16! shuffles with pruning (`bombe::symmetry`):

| Layer | Shuffles it commutes with |
|---|---|
| AES round (control) | 4: the column rotations, AES's known symmetry |
| Turing's ShiftRows+MixColumns round | 4: the same column rotations |
| MixState | 1: only the identity |
| Both of Turing's layers | **1: only the identity** |

AES removes its column symmetry only through the round constants in its
key schedule. Turing removes it structurally every other round, because
MixState does not commute with any shuffle.

A symmetry could also shuffle differently before and after a layer
(π_out L = L π_in) and chain those pairs from round to round. MixState admits
only the identity pair. Its entries 1/(x_i + y_j) would need both sets of
Cauchy points to be closed under a common shift. A control built on GF(16)
and a coset of it shows the 16 pairs that structure creates. So every chain
dies at the first MixState.

**Bytewise maps.** Suppose the linear layer carries B, applied to every
byte, to some A′ applied to every byte. Then each non-zero entry m_ij of the
matrix gives m_ij B_j = A′_i m_ij. Two rows and two columns combine into B_j
commuting with the cross-ratio (m_ij m_i′k)/(m_ik m_i′j). If that element lies
outside GF(16), it generates all of GF(2^8). The only 8×8 bit matrices that
commute with a generator of the field are the field multiplications, so B_j
must be multiplication by some β. The condition was checked for both
matrices. A symmetry therefore needs x ↦ S⁻¹(β·S(x) ⊕ b) to be affine for
some (β, b) ≠ (1, 0). Bombe checks all 65,280 pairs:

- the bare inverse function passes for all 255 values of β (the control:
  x^-1 has exactly the scaling symmetry that affine layers exist to break);
- AES's S-box and Turing's S-box pass only for (1, 0), the identity.

**Reflection.** Any S-box of the form A_out(A_in(x)^-1) satisfies
S⁻¹ = T S T with T = A_in⁻¹ A_out⁻¹ (checked on all 256 inputs). So Turing's
decryption can be rewritten as an SPN with the same S-box and linear layers
T L⁻¹ T. If those equalled the encryption layers, decryption would be
encryption under other keys. Involutional ciphers such as Khazad and Anubis
are built that way on purpose, and reflection attacks exploit it. Bombe
measures the distance as the rank of T L⁻¹ T ⊕ L over GF(2). An involutional
control scores 0: x^-1 with the Hadamard matrix of first row (1, 2, 4, 6),
Anubis's matrix, applied here over the AES field. Turing's closest pair
scores 124 of 128.

## Linear relations in the key schedule

If some XOR of key and round-key bits were the same for every key, an
attacker who learned some round-key bits (through a side channel or a fault)
would get others for free. The test samples random keys. The columns are
all key and round-key bits plus a constant, and relations = columns − rank.
Enough extra samples are drawn that a missed relation has probability
below 2^-100.

- **AES-128 (control): 1,088 relations** among 1,536 bits. The rank is 449 =
  128 key bits + 320 S-box outputs + 1, exactly what its mostly-linear
  schedule predicts (FIPS-197 §5.2). The expansion is checked against FIPS-197
  Appendix A.1.
- **Turing: 0 relations** among 2,432 bits, and 0 for the Feistel stage alone
  (K′ in, cSHAKE removed).

## Differential-linear (Langford–Hellman 1994)

Encrypt pairs with a fixed input difference and look for a biased parity in
the output difference. For 2 rounds the correlation can be predicted
exactly. The first S-box sends α to γ with probability DDT/256. MixState
sends γ to m_j γ in byte j. The last S-box then gives the parity with
correlation AC_λ(m_j γ)/256, where AC is the autocorrelation of the component
λ·S. Summing over γ gives the prediction. The measurement matches: 0.0175
against 0.0173 predicted at the same byte and mask, and the largest predicted
value is 2^-5.81. With 2^22 pairs the noise limit is 0.0029. At 3 and 4 rounds
the largest correlation is 0.0018, below it.

## Hardening the library

- **`turing::self_test()`** runs known-answer vectors through encryption and
  decryption, plus NIST's cSHAKE256 example value through both XOF paths. It
  is the cryptographic algorithm self-test that FIPS 140 validation expects
  before a module uses an algorithm. It catches a broken build, a compiler
  that rewrites the bit-sliced code, or a corrupted binary before any real
  key is used. The vectors are checked against the independent reference
  implementation in Bombe's tests.
- **`encrypt_block_checked` / `decrypt_block_checked`** implement the
  decrypt-and-compare countermeasure from doc 11 as real API calls. The
  comparison does not branch on the data, a faulty result is wiped instead of
  returned, and the internal copies are wiped either way. Tests inject faults
  into each direction at every byte. The limits are those from doc 11: twice
  the cost, and no protection against a persistent fault in the stored round
  keys.
- **The one `unsafe` block stays.** It wipes the digest crate's input buffer
  in `cshake256_secret`. digest 0.10.7 and block-buffer 0.10.4 have no wiping
  of their own (checked in their source), so there is nothing to replace it
  with yet.

For step 9, the file tool must call `self_test()` at start-up. It must also
use the checked calls wherever faults are part of the threat model, and lock
its key pages (doc 11).

## Long runs (`--deep`)

- The fast implementation against the reference on 100,000 more random keys.
- The NIST battery at NIST's own scale: 1,000 sequences of 2^20 bits, full
  cipher and zero key, with the uniformity-of-P-values criterion.
- Turing's exact best minimal differential (57/2^35), about 70 s.
- The 2^33-encryption square attack from doc 11.

## Checking the checkers

- **Published values reproduced exactly:**
  - Park et al.'s two AES bounds;
  - Keliher and Sui's 53/2^34;
  - the 56 patterns and distinct inner values of their Lemma 1;
  - FIPS-197's key expansion.
- **Controls caught:**
  - AES's column rotations;
  - the 16 shuffle pairs of a structured Cauchy matrix;
  - the inverse function's 255 scalings;
  - an involutional SPN's reflection;
  - AES-128's 1,088 key-schedule relations.
- **Predictions matched:** the 2-round differential-linear correlation, like
  the 2-round boomerang rate in doc 11.
- **Planted bugs:** 14 in this round's code, run with
  `tools/mutate.py --round3`. One of them made the pruned search run forever
  rather than fail. The harness now counts a timed-out test as caught, since
  it did not pass, and kills the whole process tree. `--check` confirms every
  older mutation still matches today's code; two had gone stale and were
  updated.

## What this does not show

- The provable bounds assume independent round keys (the Markov model), like
  every such bound for AES.
- The exact 2-round MEDP of Turing's column round lies between 57/2^35 and
  79/2^34 but is not pinned down.
- The symmetry search covers byte permutations and bytewise affine maps.
  Those are what can pass an S-box layer, but maps on other word sizes (bit
  permutations, nibbles) were not searched.
- Meet-in-the-middle attacks and bit-level integral models are still open
  (docs/11).

## Sources

- Park, Sung, Lee, Lim. Improving the Upper Bound on the Maximum Differential
  and the Maximum Linear Hull Probability for SPN Structures and AES. FSE
  2003.
- Keliher, Sui. Exact Maximum Expected Differential and Linear Probability for
  2-Round Advanced Encryption Standard (AES). ePrint 2005/321; IET
  Information Security 1(2), 2007.
- Daemen, Rijmen. Understanding Two-Round Differentials in AES. SCN 2006,
  ePrint 2006/039.
- Langford, Hellman. Differential-Linear Cryptanalysis. CRYPTO 1994.
  Biham, Dunkelman, Keller. Enhancing Differential-Linear Cryptanalysis.
  ASIACRYPT 2002.
- Biryukov, De Cannière, Braeken, Preneel. A Toolbox for Cryptanalysis:
  Linear and Affine Equivalence Algorithms. EUROCRYPT 2003 (self-equivalences
  and equivalent representations of ciphers).
- Barreto, Rijmen. The Khazad and Anubis block ciphers (NESSIE submissions,
  2000): involutional SPNs.
- FIPS 197, Advanced Encryption Standard (key expansion, §5.2 and
  Appendix A.1).
