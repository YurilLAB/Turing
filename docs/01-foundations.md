# 01. What makes a cipher hard to break

Turing is an experimental cipher. We design it the way real ciphers are
designed, measuring security instead of assuming it. But a new algorithm is
only trusted after years of public cryptanalysis, so it must not protect real
secrets.

## 1. The key is the only secret (Kerckhoffs's principle)

Assume the attacker has the full algorithm and the source code. Then all the
security has to come from the key, and anything that relies on the design
staying hidden is already broken.

## 2. Indistinguishable from random

A secure block cipher is a pseudorandom permutation: without the key, nobody
can tell its output from a random shuffle of all 2^128 blocks. If that holds,
the best attack is brute force over the key space, which with a 256-bit key is
2^256 trials. Any attack faster than brute force means the cipher is broken,
even if that attack is still impractical.

## 3. Confusion and diffusion (Shannon, 1949)

Confusion means the relationship between key and ciphertext is complex and
non-linear. Diffusion means that flipping one input bit flips about half of
all output bits, which is called the avalanche effect. We will measure this
rather than assume it.

## 4. Linear means broken

If a cipher were built only from XOR, shifts and bit permutations, every
output bit would be a linear equation in the input and key bits, and Gaussian
elimination solves those in seconds. So every cipher needs a non-linear
component, usually an S-box: a small lookup table (for example 8 bits in,
8 bits out) that no simple equation describes.

## 5. The two big attacks and their metrics

Differential cryptanalysis (Biham and Shamir) feeds in pairs of inputs with
a chosen XOR difference and looks for output differences that turn up more
often than chance. You measure an S-box's weakness with its difference
distribution table (DDT). The largest entry is the differential
uniformity, and AES's S-box reaches 4 out of 256, about as good as an 8-bit
S-box gets.

Linear cryptanalysis (Matsui) looks for XOR relations between input and
output bits that hold with a probability away from 1/2. The metric here is
the linear approximation table (LAT).

Neither attack has to work on one round; it has to survive through all the
rounds.

The wide-trail strategy works on the linear layer: it is chosen so that any
differential or linear trail has to pass through many active S-boxes. AES
guarantees at least 25 active S-boxes over any 4 rounds. At probability at
most 2^-6 each, the best 4-round trail has probability at most 2^-150. That
turns "secure" into a proven bound, and it is how we will pick Turing's round
count.

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

No single flaw broke Enigma; it fell to a combination of things. Marian
Rejewski of the Polish Cipher Bureau first broke it in December 1932, using
permutation-group mathematics and intelligence material, and in 1939 the
Poles handed their methods to Britain and France. At Bletchley Park, Turing's
Bombe searched for rotor settings consistent with a guessed piece of
plaintext (a "crib"), and Gordon Welchman's diagonal board, which used the
reciprocity of the plugboard, cut the false settings sharply. Two things made
this possible: structural properties of the machine and operator habits.
Enigma could never encrypt a letter to itself, which showed where a crib
could not sit, and operators kept sending predictable phrases. The lesson for
this project is that any detectable pattern, however small, is a way in.

## Roadmap

1. Math foundations (this document): done
2. Design spec (block size, key size, structure): done (03)
3. Analysis tools in Rust (DDT, LAT, avalanche tests): done (04)
4. Design and measure the S-box: done (05)
5. Design the linear layer and prove its branch number: done (06)
6. Design the key schedule: done (07), reviewed (08)
7. Set the round count from proven bounds: done (09)
8. Implement the cipher with test vectors: done (10), with the round tracer
9. File encryption (mode, authentication, key derivation, file format):
   parked until the cipher is hardened and validated (requirements collected
   in docs/11 and 12)
10. Attack it ourselves. First campaign done (10): square, differential,
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
