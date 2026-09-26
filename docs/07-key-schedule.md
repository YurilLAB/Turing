# 07 — The key schedule

## What went wrong with AES-256

Biryukov and Khovratovich (ASIACRYPT 2009, "Related-key Cryptanalysis of
the Full AES-192 and AES-256") broke full AES-256 in the related-key model
with 2^99.5 time and data. Two properties of the AES key schedule made it
possible:

- **Local collisions.** A difference in the key is injected into the state,
  then cancelled by the next round key's difference. The paper describes
  the idea as injecting "a difference into the internal state, causing a
  disturbance, and then to correct it with the next injections".
- **An almost linear schedule.** AES-256 key expansion is mostly XOR, with
  only 8 S-box lookups per 32 bytes of expanded key (4 per round key,
  against 16 in every cipher round). The authors conclude that "optimal
  key-schedule trails should be based on low-weight codewords in the key
  schedule", meaning key differences that stay cheap because they rarely
  meet an S-box.

A related-key attack assumes the attacker can get encryptions under keys
with a chosen relationship. That rarely happens in practice, and the authors
call their attacks "mainly of theoretical interest". For file encryption,
where every file key is random and independent, it matters even less. It is
still a weakness in the design, and Turing is built to not have it.

## Turing's schedule: a mix of SHAKE256 and Turing's own rounds

1. **Whitening (cSHAKE256).** K' = cSHAKE256(X = K, S = "Turing v1 key").
   A chosen key difference becomes a pseudorandom difference the attacker
   cannot predict.
2. **Feistel expansion (Turing's round function).** Split K' = (L, R) and
   run (L, R) -> (R XOR F_j(L), L) with F_j(x) = MixState(S(x XOR C_j)).
   The constants C_j are read from cSHAKE256(X = "", S = "Turing v1 key
   schedule constants"). After 13 warm-up rounds the first round-key pair
   (L, R) is taken, then one pair every 8 rounds. This is the same shape as
   Kuznyechik's schedule (8 Feistel rounds per pair of round keys, RFC 7801),
   with Turing's S-box and whole-state MixState inside.
3. **Feed-forward.** Round key = Feistel half XOR the matching half of K'.

Round keys are wiped from memory (`zeroize`) when dropped.

### Proof: every round key is expensive to reach

Bombe computes, by dynamic programming, the minimum number of active
S-boxes any non-zero key difference must cross (`bombe key-schedule`).
Because MixState is MDS over the whole 16 bytes, only the number of active
bytes per half matters, which makes the computation exact over a 17 × 17
state space:

| Feistel rounds | Min active S-boxes | Trail probability |
|---|---|---|
| 4 | 17 | ≤ 2^-102 |
| 8 | 35 | ≤ 2^-210 |
| 11 | 38 | ≤ 2^-228 |
| 12 | 53 | ≤ 2^-318 |
| 13 | 54 | ≤ 2^-324 |

Each round key depends on a certain number of Feistel rounds. An L half is
taken after the rounds run so far, but an R half equals the L half of *one
round earlier*, so it lags by one. With 13 warm-up rounds the first pair
depends on 13 and 12 rounds, and later pairs on 8 more each. The weakest
round key is therefore behind 12 rounds, at least **53 active S-boxes**.

Target: every round key individually behind at least 43 active S-boxes
(2^-258, beyond the 2^256 key space). 13 is the smallest warm-up that meets
it.

**This bound holds even if cSHAKE256 were broken** and an attacker could
choose the difference in K' directly. The two layers are independent
defences.

The prover respects Kanda's theorem (SAC 2000, as stated in ePrint
2010/426): a Feistel cipher with an SP round function of branch number B has
at least rB + ⌊r/2⌋ active S-boxes in every 4r rounds. This is tested for
halves of 4, 8 and 16 bytes, and for 4 and 8 rounds the prover gives exactly
Kanda's values (B and 2B + 1). The bound counts differential *trails*
(characteristics). Clustering of many trails into one differential is the
usual caveat, and the margin (2^-318 against a 2^-256 target) is there for
it.

### Correction made in the step 7 review

The first version of this schedule used 12 warm-up rounds and claimed 53
active S-boxes "before the first round keys", plus a target of 22 active
S-boxes "between pairs". Both claims overlooked the one-round lag of the R
half. Round key 1 depended on only 11 rounds (38 active S-boxes, 2^-228), and
the R half of each later pair on 7 fresh rounds, not 8. The fix is one more
warm-up round, and the target is now stated per round key, which is what an
attacker actually needs to predict. The between-pairs target, which did not
correspond to a real attack model, is gone.

### Why the feed-forward

Without it, the Feistel is invertible: any two consecutive round keys give
back K', and each round key is a simple function of the previous one. That
redundancy is what cold-boot attacks used to repair decayed AES key
schedules read out of RAM (Halderman et al., USENIX Security 2008: most
128-bit keys recovered in seconds at 10% bit decay). With the feed-forward,
relating neighbouring round keys means solving
RK_{i+1} XOR K' = Feistel^8(RK_i XOR K') for the unknown K', which has no
known shortcut.

## Verification

- The cipher's schedule matches an independent reference model (table
  S-box, Bombe's arithmetic, published labels) on 40 keys.
- Every one of 256 key bits, on 4 keys, flips 42–58% of all 2048
  round-key bits (a window over 7 standard deviations wide).
- The Feistel stage is not affine: E(a) ⊕ E(b) ⊕ E(c) ⊕ E(a ⊕ b ⊕ c) ≠ 0
  for every round key in 20 trials.
- Planted bugs, all caught: dropping the feed-forward, one fewer warm-up
  round, and removing the S-boxes from F.

The last one is worth remembering. **With the S-boxes removed, the schedule
still passed the avalanche test**, because cSHAKE256 and MixState spread bits
around even when the schedule is linear. Avalanche does not detect linearity,
and linearity is exactly what the 2009 attacks used. The non-affinity test
was added because of this.
