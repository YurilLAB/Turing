# 08 — Security review

A living review of every component against published attacks on AES-like
ciphers, first written after step 6 and revisited in step 7. Each item says
what the literature shows, whether Turing is exposed, and what, if anything,
changes. The second review's findings about Turing's *own* earlier work are
at the end.

## Related-key attacks (Biryukov–Khovratovich 2009)

Fixed in step 6 and corrected in step 7; see 07-key-schedule.md. Every round
key now sits behind at least 53 active S-boxes from any key difference.

## Biclique attacks (Bogdanov, Khovratovich, Rechberger, ASIACRYPT 2011)

Full AES-256 in about 2^254.4 operations: barely faster than brute force,
but a break on paper. Bicliques build groups of keys whose differences touch
only part of the cipher for a few rounds, which AES's slow key schedule
permits. In Turing every round key depends on every key bit through at least
53 S-boxes, so that partial-key structure is absent. Status: expected to be
mitigated; to be tested in step 10.

## Hidden S-box structure (Kuznyechik)

Biryukov, Perrin and Udovenko reverse-engineered a hidden structure in the
S-box shared by Russia's Kuznyechik and Streebog, whose design process was
never published. Asked about it, the designers said it was picked at random
and that the generation algorithm had been lost (Perrin, 2019). Nobody has
shown the structure to be a backdoor, but it undermined trust because no
public derivation existed. Turing's S-box, matrices and constants all come
from published cSHAKE256 labels, and each takes the first acceptable
candidate, so anyone can check nothing was chosen. Status: already handled.

## Invariant subspace and nonlinear invariant attacks

Beierle, Canteaut, Leander and Rotella (CRYPTO 2017) show these attacks
target ciphers whose round keys differ only by round constants (Midori,
PRINTcipher and others), and give criteria for choosing those constants.
Turing's round keys are nonlinear pseudorandom outputs of the key schedule,
not "key + constant", so the precondition does not hold. Status: not exposed.

## Subspace trails, multiple-of-8, mixture and yoyo attacks

Grassi, Rechberger and Rønjom (ToSC 2016, EUROCRYPT 2017) and follow-up
work (Rønjom et al. 2017; Bar-On et al.) give the best distinguishers on
5–6 round AES. They use the fact that AES's ShiftRows + MixColumns maps
column and diagonal subspaces onto each other, independent of the key.

MixState breaks this structure. Every entry of the 16×16 matrix is non-zero
(every 1×1 submatrix is invertible, verified). So for any set of active
input bytes, each output byte is non-zero for some input in that set: no
byte-aligned subspace smaller than the whole state survives one MixState.

**Outcome in step 7:** the proposed rule, "MixState at least every 4
rounds", was measured with the trail bounder and found too weak. Placing
MixState every 4th or 5th round gives no more active S-boxes than AES over 7–8
rounds. Turing now alternates the two layers, so no two ShiftRows +
MixColumns rounds are ever adjacent (docs/09).

## Chosen-key and known-key settings

The same 2009 work showed AES-256 is not an "ideal cipher" when an attacker
can choose keys, which matters when a block cipher is used to build a hash
function (e.g. Davies–Meyer). Turing's schedule removes the specific
weakness, but Turing makes no ideal-cipher claim. **Rule:** Turing is used
only for encryption, never as a hash building block. Hashing uses SHA-3.

## Cold-boot memory attacks (Halderman et al. 2008)

Handled in step 6: the feed-forward removes simple relations between round
keys, and round keys are wiped when dropped. Wiping cannot protect keys
while they are in use, and copies made by the compiler or OS (swap,
hibernation) are outside the cipher's control.

## Timing side channels

Everything is written branch-free with no secret-indexed tables, and
cSHAKE256 (Keccak) uses no tables. The compiler could still introduce
branches, so this is a claim to measure, not assume. **Planned:** a
dudect-style timing test in step 10.

## Block size and data limits

With a 128-bit block, ciphertext blocks start to collide after about 2^64
blocks under one key (the birthday bound). **Planned for step 9:** a random
key per file, and a mode that limits data per key well below that.

## Nonce misuse

If a nonce is ever reused, CTR-style modes leak the XOR of two plaintexts.
Each file already gets a fresh random key, which makes reuse very unlikely.
**Recommendation for step 9:** a misuse-resistant construction (SIV-style,
where the nonce is derived from the message) as defence in depth.

## Review 2 (step 7): problems found in Turing's own earlier work

Every earlier step was re-read and its claims re-checked against primary
sources. Found and fixed:

| # | Where | Problem | Severity | Fix |
|---|---|---|---|---|
| 1 | Key schedule (step 6) | The R half of each round-key pair lags one Feistel round. Round key 1 depended on 11 rounds (38 active S-boxes, 2^-228), not the claimed 12 (53). The "22 between pairs" target was also off by the same lag and did not match a real attack model. | Real, not exploitable (2^-228 is still far out of reach) | 13 warm-up rounds; target stated per round key; test checks every round key's depth |
| 2 | All derivations (steps 4–6) | SHAKE256(label ‖ input) with raw concatenation. Safe only because every label/input combination had a different length, so a future label could collide. | Latent | Everything now uses cSHAKE256 (NIST SP 800-185), label as the customization string. Constants regenerated: new S-box (candidate 3) and new matrix points; all checks pass as before |
| 3 | Rule from review 1 | "MixState at least every 4 rounds" gives no gain over AES at 7–8 rounds | Design | Alternating layers (docs/09) |
| 4 | Doc 02 | SIKE fell in about 10 minutes (the paper's figure), not an hour; SIKE was a round-4 candidate, not a finalist | Accuracy | Corrected |
| 5 | Doc 03 | X-Wing is an IETF Internet-Draft, not a published standard | Accuracy | Status and version recorded |
| 6 | Docs 03, 05 | Called the inverse S-box "optimal"; it is the best *known* (8-bit APN permutations are an open problem) | Accuracy | Reworded |
| 7 | Doc 01 | "Enigma fell to one structural bias" oversimplified the history | Accuracy | Rewritten with the Polish work, the Bombe and the diagonal board |
| 8 | Test from step 6 | Asserted "B + 2 active S-boxes in 6 Feistel rounds", a figure taken from a search summary, not from Kanda | Test quality | Test now asserts Kanda's verified theorem (rB + ⌊r/2⌋ per 4r rounds) as a lower bound |
| 9 | Mutation script | The first run labelled every caught bug "compile error" because `cargo test -q` hides per-test lines | Tooling | Parser fixed; rerun shows which test catches each bug |

Checked and found correct: the AES validation values (differential 4,
nonlinearity 112, boomerang 6, 39/23 equations, cycles), Cauchy MDS proofs,
the FIPS-197 round vectors, the 2009 attack quotes, the Halderman and
Beierle et al. citations, the biclique complexity (2^254.4).

## Sources

- Biryukov, Khovratovich. Related-key Cryptanalysis of the Full AES-192 and
  AES-256. ASIACRYPT 2009. https://eprint.iacr.org/2009/317
- NIST SP 800-185, SHA-3 Derived Functions (cSHAKE), with its published
  example values. https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
- Castryck, Decru. An Efficient Key Recovery Attack on SIDH.
  https://eprint.iacr.org/2022/975
- Beullens. Breaking Rainbow Takes a Weekend on a Laptop. CRYPTO 2022.
  https://eprint.iacr.org/2022/214
- Perrin. Partitions in the S-Box of Streebog and Kuznyechik. ToSC 2019.
- draft-connolly-cfrg-xwing-kem (X-Wing), IETF datatracker.
- Bogdanov, Khovratovich, Rechberger. Biclique Cryptanalysis of the Full AES.
  ASIACRYPT 2011.
- Biryukov, Perrin, Udovenko. Reverse-Engineering the S-Box of Streebog,
  Kuznyechik and STRIBOBr1. EUROCRYPT 2016.
- Beierle, Canteaut, Leander, Rotella. Proving Resistance against Invariant
  Attacks: How to Choose the Round Constants. CRYPTO 2017.
  https://eprint.iacr.org/2017/463
- Grassi, Rechberger, Rønjom. Subspace Trail Cryptanalysis and its
  Applications to AES. ToSC 2016(2).
- Halderman et al. Lest We Remember: Cold Boot Attacks on Encryption Keys.
  USENIX Security 2008.
- Kanda. Practical Security Evaluation against Differential and Linear
  Cryptanalyses for Feistel Ciphers with SPN Round Function. SAC 2000.
- RFC 7801. GOST R 34.12-2015: Block Cipher "Kuznyechik".
