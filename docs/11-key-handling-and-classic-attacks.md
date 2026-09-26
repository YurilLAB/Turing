# 11 — Key handling, and the attacks that broke other ciphers (step 10, second campaign)

Two questions for this round. How safely does the implementation handle keys?
And does Turing survive the attacks that broke real ciphers: MISTY1,
COCONUT98, Trivium variants, AES-256's key schedule, PRINTcipher, Midori-64,
SHARK variants, KeeLoq, smart cards? Everything below is measured by
`bombe attack` (sections 3 and 9–14) and checked by tests. Each tool was first
made to reproduce a published result.

```
cargo run --release -p bombe -- attack          # 71 findings, about 35 s (--quick: 13 s)
cargo run --release -p bombe -- attack --deep   # adds the 2^33-encryption attack, about 15 min
```

## Results

| Attack (what it broke) | Breaks Turing to | Full cipher | Evidence |
|---|---|---|---|
| Division property, Todo 2015 (first attack on full MISTY1) | integral key recovery on **4 rounds** with 2^32 chosen plaintexts | resists | predicted by the new engine, then run: 2^16 and 2^24 fail at 4 rounds, 2^32 recovers the whole round key (every byte unique after 2 sets, 867 s), and again under a second key in `attack --deep` |
| Boomerang, Wagner 1999 (COCONUT98) | 2 rounds (2^-13.0 per quartet) | resists | 1 round returns at 2^-5.4, the S-box's BCT value 6/256; 2 rounds at exactly the predicted 2^-13.0; 0 of 262,144 quartets return at 3 and 4 rounds |
| Cube testers, Dinur–Shamir / Aumasson et al. 2009 (767-round Trivium) | 2 rounds | resists | all 2,048 cube-sum bits zero at 1–2 rounds; 1,031 of 2,048 at 3 (random: half) |
| Related keys, Biryukov–Khovratovich 2009 (AES-256) | nothing | resists | one-bit key differences give round-key differences of mean 64.02 of 128 bits, lowest 42; even with cSHAKE removed, mean 63.94, lowest 40 |
| Interpolation, Jakobsen–Knudsen 1997 (SHARK variant) | nothing | resists | S-box polynomial has 254 of 256 terms, inverse 255 (AES S-box: 9) |
| Invariant subspace / nonlinear invariant, 2011 and 2016 (PRINTcipher, Midori-64, SCREAM) | nothing | resists | both linear layers have one invariant factor; real round keys give W_L(D) = 128 of 128 for every key tried |
| Differential fault analysis, Piret–Quisquater 2003 (AES; Plundervolt 2020 in SGX) | — | **exposed** without a countermeasure | 2 faulty ciphertexts give the last round key; decrypt-and-compare catches 20,000 of 20,000 faults |
| Correlation power analysis, Brier–Clavier–Olivier 2004 (KeeLoq, DESFire) | — | **exposed** without masking | round key 0 from 10 traces (no noise), 40 (SNR 1), 320 (SNR 0.1) |
| Slide attacks, Biryukov–Wagner 1999 (KeeLoq) | — | not applicable | see below |

The design-level attacks stop at 4 rounds of 16. The two implementation
attacks work against any unprotected cipher, AES included; the fixes are
engineering, not design (below).

## Key handling: what was found and fixed

The step-8 code (commit 9dc7358) was reviewed for where key material lives
and what can reach it.

| # | Problem in step 8 | Fix |
|---|---|---|
| 1 | Key whitening ran the 256-bit key through cSHAKE256 and dropped the hasher. With sha3's default features the Keccak state is not wiped on drop, and the digest crate's input block buffer, which holds the absorbed key bytes, is never wiped. | sha3 built with its `zeroize` feature (the Keccak state is wiped on drop; the call is visible in the assembly), and a new `xof::cshake256_secret` that also wipes the input buffer and the output block. A test proves it gives exactly the same output as the public version for every input length 0–135. |
| 2 | Round keys were stored inline in `RoundKeys`, so every move of a `Turing` copied all 17 of them and left the old copy unwiped. The zeroize crate documents this limitation of moves. | Round keys live in a heap `Box`, written in place and wiped on drop; moving a `Turing` moves one pointer. |
| 3 | `round_key`, `RoundKeys::get`/`all`, `encrypt_rounds` and `decrypt_rounds` were public in every build, so any program could read the round keys. | Compiled only with the `analysis` feature, which only Bombe enables. A probe crate proves it: the calls fail to compile without the feature (E0599/E0425) and compile with it. |
| 4 | Nothing stopped a future `#[derive(Debug)]` from printing round keys into logs. | A compile-time guard: if `Turing` or `RoundKeys` ever implements `Debug`, the crate's tests stop compiling. Checked by adding such an impl: error E0283. |
| 5 | The reference `linear::mat_vec` claimed to be constant-time. In the release build the compiler turns `gf::mul`'s masks into a conditional jump on each bit of the state (21 jumps in `mix_columns_with`). Nothing in the cipher calls it, so nothing leaked. | Docs corrected. `mat_vec` and `mix_columns_with` are compiled only for tests and analysis builds, and a normal build cannot call them (the same probe). |

**The assembly review.** Branch-free source is not branch-free machine code;
Schneider et al. ("Breaking Bad", ASIA CCS 2025) measured compilers breaking
constant-time code across many libraries, and item 5 is that effect here.
`tools/asm_branches.py` lists every conditional jump in chosen functions of
the release build with the instructions before it. In `encrypt_block`,
`decrypt_block`, `Turing::new`, the Feistel round, `cshake256_secret`,
`inv8`, `sub8`, the Affine8 maps, `apply16` and `apply_columns`, every
conditional jump tests a round counter, a loop bound, the public layer choice,
the read position in the public constant stream, a length or an allocation
result. None tests key or state data. The constant-time claim covers exactly
these functions, in this build, with this compiler (rustc 1.95.0 on x86-64
Windows, checked 2026-09-26). It has to be rechecked when the compiler
changes.

**Round keys are independent.** DFA and CPA recover *round* keys. In AES-128
one round key gives the master key, and in AES-256 two consecutive round keys
do, because the key schedule runs backwards. Turing's round keys are
Feistel states XORed with K' (feed-forward), and K' comes from cSHAKE256, so
a recovered round key gives neither K' nor the other round keys. An attacker
has to extract each of the 17 round keys separately, one round deeper each
time. That makes these attacks harder work, not impossible: 17 round keys
decrypt as well as the master key does.

**Equivalent keys exist but cannot be found.** Hashing 256 bits to 256 bits
hits about 1 − 1/e ≈ 63% of the outputs, so about 2^255.3 distinct K' values
are reachable and some keys collide. Finding a pair means finding a cSHAKE256
collision (about 2^128 work), and brute force still needs about 2^255 trials.
Every key derivation that hashes a key does the same.

**What the cipher cannot fix** (requirements for the file tool, step 9):

- Keys in use are in memory. Lock the pages holding the key and round keys
  (`VirtualLock` on Windows, `mlock` elsewhere) so they never reach swap or
  the hibernation file (Halderman et al. 2008 recovered keys from RAM).
- Intermediate states such as p ⊕ RK0 stay on the stack after encryption,
  and Rust gives no guarantee against compiler-made copies. With known
  plaintext, p ⊕ RK0 gives RK0. The practical defence is the same as for the
  round keys: keep the process's memory private and short-lived.
- Passphrases and derived keys must be wiped by the tool, and never logged.

## The attacks

### Division property (Todo 2015): the attack that broke full MISTY1

The word-level division property tracks, through each layer, which products
of input bits still sum to zero over a chosen-plaintext set. Bombe's engine
(`bombe::division`) reproduces the known AES results: one active byte stays
balanced to the input of the 4th S-box layer, a diagonal to the 5th. For
Turing:

| Active bytes (plaintexts) | Balanced up to the input of S-box layer |
|---|---|
| 1–3 (2^8–2^24) | 3 |
| 4–14 (2^32–2^112) | 4 |
| 15 (2^120) | 5 |

So the square attack reaches **4 rounds** once it uses 2^32 plaintexts per
set, one more than the 2^8 structure of step 8. That prediction was then
run. With 2^16 and 2^24 per set, no key guess survives at 4 rounds. With
2^32 (4 active bytes, 2 sets, 2^33 encryptions on 12 threads), every byte of
the 4th round key came out unique and correct, in 867 s; `attack --deep`
repeats it under another key (the whole campaign then takes 906 s). The attack stops after two
sets once every byte is unique; otherwise it takes more. A wrong guess
survives a set with probability 2^-8, so two sets leave a false survivor
about 6% of the time.

The 2^120 structure keeps the set balanced for four full rounds, so its
key recovery would reach 5 rounds, with more chosen plaintexts than any
attacker could collect. The rule behind the round count (docs/09) was
max(3, 4) + 4 = 8. Counting this 4-round integral distinguisher it is
max(3, 4, 4) + 4 = 8: unchanged, and still half of 16.

### Boomerang (Wagner 1999): broke COCONUT98

Two short differentials, one from each end, can beat one long one. The
return rate for one round matches the S-box's Boomerang Connectivity Table
entry exactly: best pair 6/256 = 2^-5.4, measured 2^-5.4. Two rounds still
return at 2^-13.0 (33 of 262,144 quartets). Both pairs cross MixState with
the same 16-byte difference, so only S-box events count. The pairs must be
shifted alike through the last S-box. On the way back both pairs are also
shifted by the same value, which puts the first S-box through a second,
correlated switch (the multi-round switch of Wang and Peyrin, ToSC 2019).
Counting over both S-box inputs gives exactly 8/65,536 = 2^-13.00, or 32
expected returns. Treating the two S-boxes as independent predicts 2^-15.2,
four times too few. From three rounds nothing comes back in 262,144
quartets. A random permutation returns with probability 2^-128.

### Cube testers (Dinur–Shamir 2009; Aumasson et al. 2009)

Summing the output over all 2^16 values of 16 plaintext bits gives zero
whenever the output's degree in those bits is below 16. The cube attack
recovered keys of Trivium with 767 of its 1152 initialisation rounds. For
Turing the sums vanish at 1–2 rounds and look random from 3. After one round
each output bit depends on a single byte, so its degree is at most 8. After
two, each output bit is the last S-box (degree 7) applied to a sum of
functions of single bytes. So every term involves at most 7 first-round
bytes, and its degree is at most the number of cube bits in those 7 bytes.
Sixteen random bits spread over more than 7 bytes 99.65% of the time (10.7
on average), which keeps the degree below 16.

### Related keys (Biryukov–Khovratovich 2009): broke AES-256's key schedule

The attack needs round-key differences it can predict. Flipping each of the
256 key bits of 16 random keys, the 69,632 round-key differences average
64.02 of 128 bits with the lowest at 42. The same holds with the cSHAKE256
layer removed (mean 63.94, lowest 40), so the Feistel stage defends on its
own. Encrypting one plaintext under related keys gives output differences of
mean 64.13 bits after one round and 64.00 after 16.

### Interpolation (Jakobsen–Knudsen 1997): broke a SHARK variant

Write the cipher as a polynomial over GF(2^8) and solve for its
coefficients; it works when the polynomial is sparse. Every function on
GF(2^8) is exactly one polynomial of degree below 256 (Lagrange). Bombe
computes it and reproduces the published AES S-box polynomial: 9 terms,
05·x^254 + 09·x^253 + F9·x^251 + 25·x^247 + F4·x^239 + x^223 + B5·x^191 +
8F·x^127 + 63 (Rosenthal 2003, eq. 2.3). The sparsity comes from AES feeding
its input straight into x^-1. It is what the algebraic descriptions of AES
build on (Ferguson–Schroeppel–Whiting 2001, Murphy–Robshaw 2002), though no
attack on AES has come of it. Turing puts an affine map in front of the
inversion: its S-box has **254 terms** and its inverse 255, as dense as a
random permutation (about 254).

### Invariant attacks (Leander et al. 2011; Todo–Leander–Sasaki 2016)

These find a property of the state that every round preserves, so it
survives any number of rounds. They broke PRINTcipher, Midori-64, iSCREAM,
SCREAM, NORX v2.0, Simpira v1 and Haraka v.0 (list from BCLR). All of them
use the same round key in every round up to simple round constants (the
permutations among them use round constants alone).

Beierle, Canteaut, Leander and Rotella (CRYPTO 2017) turned this into a
criterion. If two rounds share the linear layer L, the difference of their
round keys is a linear structure of any such invariant, and the linear
structures form an L-invariant subspace. So they contain W_L(D), the
smallest L-invariant subspace holding all those differences. If W_L(D) is
the whole state, only affine invariants remain, and those would need an
S-box with a linear component. Turing's has none: every component has
degree 7.

`bombe::invariant` computes W_L(D). It was checked against the paper first.
For Midori-64's linear layer it reproduces the published invariant factors
(eight (X+1)^6 and eight (X+1)^2): the dimensions reached with 1, 2, … 16
differences are 6, 12, … 48, 50, … 64. It also confirms that Midori's
constants, which are non-zero only in the lowest bit of each cell, stay
inside a 16-dimensional space.

| Linear layer | Invariant factors | Differences needed for the full space |
|---|---|---|
| Turing MixState | 1 (minimal polynomial of degree 128) | 1 |
| Turing ShiftRows + MixColumns | 1 (degree 128) | 1 |
| AES MixColumns ∘ ShiftRows | 16, all of degree 8 | 16 |
| Midori-64 | 16 (degrees 6 and 2) | 16 |

For Turing's real round keys (7 differences between MixState rounds, 6
between the others), W_L(D) = 128 for each layer and for both together, for
all 64 random keys tried. A cipher using the same round key in every round
gives W_L(D) = 0 and is flagged. By the paper's Theorem 1, AES's 9 MixColumns
rounds (AES-128) can reach at most 64 dimensions whatever the round keys,
so this proof cannot cover AES at all. For Turing one difference is enough.

Limit: the criterion covers invariants that are the same in every round.
Invariants that alternate between rounds are not excluded by it.

### Differential fault analysis (Piret–Quisquater 2003)

A glitch corrupts one state byte near the end of an encryption, and the
correct and faulty ciphertexts pin down the last round key. For AES-128, two
faulty ciphertexts suffice. This is not only a smart-card problem.
Plundervolt (Murdock et al., IEEE S&P 2020) undervolted Intel CPUs from
software and extracted AES-NI keys from SGX enclaves this way.

For Turing a byte fault before round 15's S-box layer passes one S-box, then
MixState spreads it to all 16 bytes as β times one matrix column. Guessing
the position and β (16 × 255 hypotheses) and solving each key byte
separately leaves 65,536 candidates after one fault and **1 after two**, the
right one. Decrypting the output and comparing it with the input catches
every one of 20,000 single faults at random rounds, bytes and values.

Two limits of that countermeasure. It doubles the cost. It also cannot catch
a *persistent* fault in the round-key memory, since encryption and
decryption would both use the corrupted key. Persistent fault analysis
(Zhang et al., TCHES 2018) usually targets S-box tables in memory. Turing
has none; its S-box is computed.

### Correlation power analysis (Brier–Clavier–Olivier 2004)

A chip's power draw follows the Hamming weight of the values it handles.
Guess one key byte, predict HW(S(p ⊕ k)) for each trace, and keep the guess
that correlates best. This broke KeeLoq car remotes (Eisenbarth et al.,
CRYPTO 2008) and the Mifare DESFire MF3ICD40 card (Oswald–Paar, CHES 2011).
PLATYPUS (Lipp et al., IEEE S&P 2021) did it without an oscilloscope: it read
Intel's RAPL energy counters from unprivileged software and leaked AES-NI
keys from SGX and the Linux kernel.

Simulated on Turing's real first-round S-box outputs, CPA recovers all 16
bytes of round key 0 from 10 traces without noise, 40 at a signal-to-noise
ratio of 1 and 320 at 0.1. Every unmasked cipher falls this way; the
countermeasure is **masking**. Turing's S-box computes x^254 with exactly the
addition chain Rivain and Prouff mask at any order (CHES 2010, Algorithm 2:
x^2, x^3, x^12, x^15, x^240, x^252, x^254, with 4 multiplications, which
they note is the minimum). Squaring is linear in characteristic 2, and the
affine layers cost nothing to mask. Turing does not implement masking. On a
desktop the attacker needs physical access or a leaky interface such as the
RAPL counters PLATYPUS read, so masking belongs with hardware or
shared-machine threat models.

### Slide attacks (Biryukov–Wagner 1999): not applicable

Slide attacks need the cipher to be the same keyed function repeated,
F^r. KeeLoq fell to one because its 64-bit key is reused cyclically
(Indesteege et al., EUROCRYPT 2008). Turing alternates two different linear
layers, and its round keys are distinct pseudorandom values: the key checks
found no repeated round key among 266 suspicious keys and 65,536 neighbours.
The key-schedule Feistel reads a fresh constant every round, so it has no
self-similarity to slide either.

## Checking the checkers

- **Published and predicted results reproduced:** the AES S-box polynomial
  (9 terms, all coefficients), BCLR's Midori-64 invariant factors, the AES
  integral distinguishers (division engine), the S-box's BCT value in the
  1-round boomerang rate, and the exact 2-round rate (32 returns expected,
  33 measured).
- **Controls caught:** identical round keys (W_L(D) = 0), CPA with too few
  traces for the noise fails, a `Debug` impl breaks the build, the reference
  `mix_columns_with` shows its 21 bit-testing jumps to the assembly tool.
- **16 planted bugs, all caught by the test meant for them:** secret cSHAKE
  without its label, K' right half copied from the left, a `Debug` impl on
  `Turing`, an unsound division rule, the forward S-box in the structured
  attack, a boomerang with one ciphertext shifted, a cube missing one point
  per thread, a related-key weight counting one byte, the DFA using a row
  instead of a column, the fault injected a round late, polynomial
  coefficients reversed, a closure that forgets images, the wrong Turing
  layer map, round-key differences mixed across layers, a CPA model adding
  instead of XORing, and the exact boomerang rate using MixState instead of
  its inverse.

## What this does not show

- Meet-in-the-middle attacks (the best known on AES-256) and bicliques are
  still not modelled; the factor-of-two margin covers them.
- The division engine works on words, not bits. Bit-level models (MILP,
  SAT) can find longer integral distinguishers; for AES-like ciphers the gain
  is usually small, but it has not been checked here.
- The boomerang test uses the single best BCT pair on one byte, and the cube
  test random 16-bit cubes. Other choices could do better on 2–3 rounds.
- Power and fault attacks were simulated with textbook leakage and fault
  models, not measured on hardware.
- As before: this is Bombe attacking Bombe's author's cipher.

## Sources

- Todo. Structural Evaluation by Generalized Integral Property. EUROCRYPT
  2015. Todo. Integral Cryptanalysis on Full MISTY1. CRYPTO 2015.
- Wagner. The Boomerang Attack. FSE 1999. Cid, Huang, Peyrin, Sasaki, Song.
  Boomerang Connectivity Table. EUROCRYPT 2018. Wang, Peyrin. Boomerang
  Switch in Multiple Rounds. ToSC 2019(1).
- Dinur, Shamir. Cube Attacks on Tweakable Black Box Polynomials. EUROCRYPT
  2009. Aumasson, Dinur, Meier, Shamir. Cube Testers and Key Recovery Attacks
  on Reduced-Round MD6 and Trivium. FSE 2009.
- Biryukov, Khovratovich. Related-key Cryptanalysis of the Full AES-192 and
  AES-256. ASIACRYPT 2009.
- Jakobsen, Knudsen. The Interpolation Attack on Block Ciphers. FSE 1997.
- Rosenthal. A Polynomial Description of the Rijndael Advanced Encryption
  Standard. J. Algebra Appl. 2003, arXiv cs/0205002.
- Ferguson, Schroeppel, Whiting. A Simple Algebraic Representation of
  Rijndael. SAC 2001. Murphy, Robshaw. Essential Algebraic Structure within
  the AES. CRYPTO 2002.
- Leander, Abdelraheem, AlKhzaimi, Zenner. A Cryptanalysis of PRINTcipher:
  The Invariant Subspace Attack. CRYPTO 2011.
- Todo, Leander, Sasaki. Nonlinear Invariant Attack: Practical Attack on Full
  SCREAM, iSCREAM, and Midori64. ASIACRYPT 2016, ePrint 2016/732.
- Beierle, Canteaut, Leander, Rotella. Proving Resistance Against Invariant
  Attacks: How to Choose the Round Constants. CRYPTO 2017, ePrint 2017/463.
- Banik et al. Midori: A Block Cipher for Low Energy. ASIACRYPT 2015, ePrint
  2015/1142.
- Piret, Quisquater. A Differential Fault Attack Technique against SPN
  Structures, with Application to the AES and KHAZAD. CHES 2003.
- Murdock, Oswald, Garcia, Van Bulck, Gruss, Piessens. Plundervolt:
  Software-based Fault Injection Attacks against Intel SGX. IEEE S&P 2020.
- Zhang et al. Persistent Fault Analysis on Block Ciphers. TCHES 2018(3).
- Brier, Clavier, Olivier. Correlation Power Analysis with a Leakage Model.
  CHES 2004.
- Eisenbarth, Kasper, Moradi, Paar, Salmasizadeh, Shalmani. On the Power of
  Power Analysis in the Real World: A Complete Break of the KeeLoq Code
  Hopping Scheme. CRYPTO 2008.
- Oswald, Paar. Breaking Mifare DESFire MF3ICD40: Power Analysis and
  Templates in the Real World. CHES 2011.
- Lipp, Kogler, Oswald, Schwarz, Easdon, Canella, Gruss. PLATYPUS:
  Software-based Power Side-Channel Attacks on x86. IEEE S&P 2021.
- Rivain, Prouff. Provably Secure Higher-Order Masking of AES. CHES 2010,
  ePrint 2010/441.
- Biryukov, Wagner. Slide Attacks. FSE 1999. Indesteege, Keller, Dunkelman,
  Biham, Preneel. A Practical Attack on KeeLoq. EUROCRYPT 2008.
- Schneider, Lain, Puddu, Dutly, Capkun. Breaking Bad: How Compilers Break
  Constant-Time Implementations. ASIA CCS 2025, arXiv 2410.13489.
- Halderman et al. Lest We Remember: Cold Boot Attacks on Encryption Keys.
  USENIX Security 2008.
- The zeroize crate documentation (limits of wiping values that move).
