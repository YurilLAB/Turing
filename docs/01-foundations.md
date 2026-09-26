# 01 — What makes a cipher hard to break

Turing is an experimental cipher. It is designed the way real ciphers are
designed (security measured, not assumed), but a new algorithm is only trusted
after years of public cryptanalysis, so it must not protect real secrets.

## 1. The key is the only secret (Kerckhoffs's principle)

Assume the attacker has the full algorithm and source code. All security must
come from the key. Anything that relies on the design staying hidden is broken.

## 2. The goal: indistinguishable from random

A secure block cipher is a *pseudorandom permutation*: without the key, nobody
can tell its output apart from a random shuffle of all 2^128 blocks. If that
holds, the best attack is brute force over the key space. With a 256-bit key
that is 2^256 trials. Any attack faster than brute force means the cipher is
broken, even if that attack is still impractical.

## 3. Confusion and diffusion (Shannon, 1949)

- **Confusion**: the relationship between key and ciphertext is complex and
  non-linear.
- **Diffusion**: flipping one input bit flips about half of all output bits
  (the *avalanche effect*). We will measure this, not assume it.

## 4. Linear means broken

If a cipher were only XOR, shifts and bit permutations, every output bit would
be a linear equation in the input and key bits. Gaussian elimination solves
those in seconds. Every cipher therefore needs a non-linear component, usually
an **S-box**: a small lookup table (for example 8 bits in, 8 bits out) that no
simple equation describes.

## 5. The two big attacks, and the metrics they give us

- **Differential cryptanalysis** (Biham and Shamir): feed in input pairs with a
  chosen XOR difference, look for output differences that occur more often than
  chance. An S-box's weakness is measured by its **Difference Distribution
  Table (DDT)**. The largest entry is its *differential uniformity*; AES's
  S-box reaches 4 out of 256, close to optimal for 8 bits.
- **Linear cryptanalysis** (Matsui): look for XOR relations between input and
  output bits that hold with probability away from 1/2. Measured by the
  **Linear Approximation Table (LAT)**.

Neither attack has to work on one round; it has to survive through all rounds.

**Wide-trail strategy.** The linear layer is chosen so that any differential or
linear trail must pass through many *active S-boxes*. AES guarantees at least 25
active S-boxes over any 4 rounds. At probability at most 2^-6 each, the best
4-round trail has probability at most 2^-150. This turns "secure" into a proven
bound, and it is how Turing's round count will be chosen.

## 6. Flaws designers build in by accident

| Flaw | Consequence | Mitigation |
|---|---|---|
| All rounds identical | Slide attacks | Distinct round constants per round |
| Weak key schedule | Related-key attacks, weak keys | Non-linear key expansion |
| 64-bit block | Birthday bound: repeats after ~32 GB | 128-bit block |
| Too few rounds | An attack on r-1 rounds breaks it | Proven bound plus safety margin |
| Table lookups in memory | Cache-timing side channels leak the key | Constant-time implementation |
| Cipher used raw (ECB) | Equal blocks give equal ciphertext; tampering undetected | Proper mode, authentication, unique nonce |

## 7. The Turing connection

Enigma was broken by a combination of things, not a single flaw. Marian
Rejewski of the Polish Cipher Bureau first broke it in December 1932 with
permutation-group mathematics and intelligence material, and the Poles
handed their methods to Britain and France in 1939. At Bletchley Park,
Turing's Bombe searched for rotor settings consistent with a guessed piece of
plaintext (a "crib"). Gordon Welchman's diagonal board, which used the
reciprocity of the plugboard, cut the false settings sharply. Structural
properties and operator habits made this possible. Enigma could never
encrypt a letter to itself, which showed where a crib could not sit, and
operators kept sending predictable phrases. The lesson for this project: any
detectable pattern, however small, is a way in.

## Roadmap

1. Math foundations (this document) — done
2. Design spec: block size, key size, structure — done (03)
3. Analysis tools in Rust: DDT, LAT, avalanche tests — done (04)
4. Design and measure the S-box — done (05)
5. Design the linear layer and prove its branch number — done (06)
6. Design the key schedule — done (07), reviewed (08)
7. Set the round count from proven bounds — done (09)
8. Implement the cipher with test vectors — done (10), with the round tracer
9. File encryption: mode, authentication, key derivation, file format —
   parked until the cipher is hardened and validated (requirements collected
   in docs/11 and 12)
10. Attack it ourselves — first campaign done (10): square, differential,
    linear, avalanche, NIST battery, key checks, timing. Second campaign done
    (11): division property, boomerang, cube testers, related keys,
    interpolation, invariant attacks, fault and power analysis, and a
    key-handling review. Third campaign done (12): provable bounds that count
    every trail, symmetries, reflection, key-schedule relations,
    differential-linear, and a self-test plus fault-checked calls in the
    library. Meet-in-the-middle still to add

Source for the Enigma history: "Cryptanalysis of the Enigma" (Wikipedia
overview) and J. Wilcox, "Solving the Enigma: History of the Cryptanalytic
Bombe" (NSA Center for Cryptologic History).
