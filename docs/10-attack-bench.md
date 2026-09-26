# 10 — Does it work, and does it hold up? (step 8 and the attack bench)

> Numbers in this document are for version 1 (16 rounds, 17 round keys).
> Version 2 has 24 rounds and 25 round keys (docs/13); the attacks and tools
> are unchanged, and `bombe attack` reports the version 2 figures.

Until this step Turing's parts were designed and proven one by one, but no
block had been encrypted end to end. This step builds the cipher, checks it
is right, lets you watch it run, and attacks it.

```
cargo run --release -p bombe -- attack            # everything, about 35 s
cargo run --release -p bombe -- attack --quick    # about 13 s
cargo run --release -p bombe -- trace --flip-plaintext-bit 0
cargo run --release -p bombe -- vectors
```

## Turing encrypts

`turing::Turing` encrypts and decrypts 128-bit blocks under a 256-bit key
in 16 rounds (`crates/turing/src/cipher.rs`). On this machine: **3.0 µs per
block (5.2 MB/s), 20 µs per key setup**, all constant-time.

Speed comes from working on eight bytes per 64-bit operation. Field
multiplication runs in all byte lanes at once. Squaring is done as the
linear map it is. x^254 uses an 11-step addition chain (7 squarings, 4
multiplications). The mixing layers XOR public column vectors selected by
masks built from the secret bits. There are no secret-dependent branches and
no lookups indexed by secret data.

Every fast routine is proven equal to the straightforward version:

- **8-lane multiply:** all 65,536 input pairs, with different values in
  every lane so any leak between lanes shows.
- **S-box layer:** every value at every byte position.
- **Mixing layers:** all 128 single-bit inputs. The layers are linear, so
  this proves equality on every input.

## It is right

- **Independent reference implementation** (`bombe::refcipher`), written
  differently on purpose: table S-box, generic matrix arithmetic, its own
  ShiftRows, key schedule, round loop and layer rule. It agrees with the
  real cipher on 300 keys × all 16 round counts in both directions, and on
  2000 random cases in the campaign.
- **Known-answer vectors** in `vectors/turing-v1.txt`: 8 vectors, plus every
  round key and the state after each round for one of them, so another
  implementation can find exactly where it diverges.
- Decryption inverts encryption at every round count; 65,536 consecutive
  counters encrypt to 65,536 different blocks.

## Watching it: the round tracer

`bombe trace` prints the state after every operation. Given a second input
(`--flip-plaintext-bit`, `--flip-key-bit`, `--plaintext2`, `--key2`), it shows
the XOR of the two runs:

```
step                        A xor B (.. = same byte)           bits  bytes
input                       01..............................      1      1
R1  S-box                   9c..............................      4      1
R1  MixState                2ff9520e95bfc819adc5065fdd1442f7     68     16
R2  S-box                   cdaa8c1ab9253bb976c3d2a6e361a61e     66     16
```

One flipped bit becomes 4 after the first S-box and 68, spread over all 16
bytes, after the first MixState. From there it stays near 64 of 128, which is
what random looks like.

## Attacking it: `bombe attack`

Every technique is run against reduced-round versions to find where it stops
working, and against the full cipher. Full run, 43 findings, **0 failures**:

| Technique | Breaks | Fails from | Evidence |
|---|---|---|---|
| Square / integral distinguisher | 1–2 rounds | 3 | 100% of output bytes balanced at 2 rounds; 0.2–0.8% (random: 0.4%) from 3 |
| **Square key recovery** | **3 rounds: last round key recovered from 512 chosen plaintexts** | 4 | at 4 rounds no key guess survives |
| Truncated differential | 1–2 rounds | 3 | at 2 rounds every output byte changes, with certainty |
| Best linear approximation | 1 round | 2 | measured \|correlation\| 0.1241 (predicted 0.125); 2 rounds at noise level |
| Avalanche (16,384 bit-pair cells) | 1 round | 2 | full cipher: mean 0.5001, worst cell within the 1% limit |
| NIST SP 800-22 (11 statistics, 64 × 2^20 bits) | 1–2 rounds | 3 | full cipher and all-zero key pass everything |
| Key checks | — | — | 266 suspicious keys and 65,536 neighbours: no zero or repeated round keys, no equivalent keys |
| Timing side channel (dudect) | — | — | encryption \|t\| 0.8–1.7 across runs, key setup 1.0–2.1; limit 4.5 |

The best attack here breaks **3 of Turing's 16 rounds**, and the statistical
tests stop seeing any structure after 2–3 rounds. (The second campaign,
docs/11, extends the square attack to 4 rounds with 2^32 chosen plaintexts,
as the division property predicts.)

Recovering round key 3 does not give up the master key: the key schedule is
one-way (cSHAKE256 and feed-forward). In AES-128, by contrast, the key
schedule can be run backwards, so the last round key gives the master key.

### Theory meets measurement

The same numbers the step 3–7 analysis predicted appear in real encryptions:

| Quantity | Predicted | Measured |
|---|---|---|
| MixState / MixColumns branch number | 17 / 5 | 17 / 5 (smallest over 200,000 differences) |
| Best 1-round differential | 4/256 = 0.01562 | 0.01534 ± 0.00024 |
| Best 1-round linear correlation | 32/256 = 0.125 | 0.1241 ± 0.0010 |
| Unchanged bytes after 2 rounds from a 1-byte difference | 0 (MixState is MDS) | 0 of 1,048,576 |
| Square property | holds to the round-3 S-box input | key recovery works at 3 rounds, not 4 |

## Checking the checkers

Every test has to show it can catch a bad cipher, or its pass means nothing:

- **Negative controls, all caught:** the plain counter fails all 11 NIST
  statistics; 1-round Turing fails all 11; a textbook early-exit S-box scores
  |t| above 10,000 in the timing test.
- **Bombe's NIST implementation** reproduces the document's worked examples,
  and NIST's reference results for 1,000,000 bits of e to six decimals
  (frequency, block frequency, both cusums, runs, longest run, rank,
  spectral, approximate entropy, serial). The e sequence is generated by
  `crates/bombe/tests/data/make_e.py` and matches NIST's own counts (500,029
  ones; 250,116 "00" pairs).
- **Two errors in NIST's document.** The spectral test's two small worked
  examples (2.6.4 and 2.6.8) do not follow from its own definition. A direct
  transform gives N1 = 5 and 48 peaks below the threshold, not the printed 4
  and 46. The test was corrected after those examples were written (Kim,
  Umeno, Hasegawa, ePrint 2004/018), and NIST's million-bit reference result
  matches Bombe exactly.
- **NIST's pass-proportion rule is built for about 1000 sequences.** With 8
  it demands all 88 P-values pass, which a perfect generator does only 41%
  of the time. Bombe uses an exact binomial bound with a 0.1% false-alarm
  rate across all 11 statistics. NIST's own rule is kept, tested against its
  worked example (981 of 1000).
- **13 planted bugs, all caught:** carries leaking between lanes, a wrong
  inverse exponent, swapped output halves, round keys off by one, decryption
  using the forward layer, the reference using the wrong layer rule, the
  attack using the forward S-box, a wrong spectral threshold, a class
  probability typo, the serial test without wrap-around, the timing control
  made constant-time, a 100× looser false-alarm budget, and the truncated
  test counting the wrong bytes.

## What this does not show

- Passing statistical tests is necessary, not sufficient. The best attacks
  on real ciphers are structural, and these tools cover integral,
  differential, linear and impossible-differential attacks, not
  meet-in-the-middle, division-property or algebraic ones. (Docs/11 adds the
  division property, boomerangs, cube testers, related keys, interpolation,
  invariant attacks, and fault and power analysis.)
- The timing test ran on one machine with one compiler. It shows no
  data-dependent timing there; it does not prove constant time everywhere,
  and cache or power side channels are not measured. (Docs/11 reads the
  release assembly and simulates power analysis.)
- Everything here is Bombe attacking a cipher Bombe's author designed. Real
  confidence only comes from other people trying to break it.

## Sources

- NIST SP 800-22 rev. 1a, A Statistical Test Suite for Random and
  Pseudorandom Number Generators for Cryptographic Applications (2010).
- Kim, Umeno, Hasegawa. Corrections of the NIST Statistical Test Suite for
  Randomness. ePrint 2004/018.
- Reparaz, Balasch, Verbauwhede. Dude, is my code constant time? DATE 2017,
  ePrint 2016/1123.
- Daemen, Knudsen, Rijmen. The Block Cipher Square. FSE 1997.
- Webster, Tavares. On the Design of S-Boxes. CRYPTO 1985 (the strict
  avalanche criterion).
