# 08 — Security review after step 6

A review of every component built so far against published attacks on
AES-like ciphers. Each item says what the literature shows, whether Turing
is exposed, and what, if anything, changes.

## Related-key attacks (Biryukov–Khovratovich 2009)

Fixed in step 6; see 07-key-schedule.md. Every key difference now crosses
at least 53 active S-boxes before the first round key.

## Biclique attacks (Bogdanov, Khovratovich, Rechberger, ASIACRYPT 2011)

Full AES-256 in about 2^254.4 operations: barely faster than brute force,
but a break on paper. Bicliques build groups of keys whose differences touch
only part of the cipher for a few rounds, which AES's slow key schedule
permits. In Turing every round key depends on every key bit through at least
53 S-boxes, so that partial-key structure is absent. Status: expected to be
mitigated; to be tested in step 10.

## Hidden S-box structure (Kuznyechik)

Biryukov, Perrin and Udovenko reverse-engineered a hidden structure in the
S-box of Russia's Kuznyechik and Streebog, which were presented as random.
Nobody has shown it to be a backdoor, but it undermined trust because no
public derivation existed. Turing's S-box, matrices and constants all come
from published SHAKE256 labels, and each takes the first acceptable
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

**Change for step 7:** add a design rule, then confirm it with the trail
bounder. No run of consecutive ShiftRows + MixColumns rounds may be long
enough for the AES-structure distinguishers (5 rounds or more), so MixState
must appear at least every 4 rounds.

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
SHAKE256 (Keccak) uses no tables. The compiler could still introduce
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

## Sources

- Biryukov, Khovratovich. Related-key Cryptanalysis of the Full AES-192 and
  AES-256. ASIACRYPT 2009. https://eprint.iacr.org/2009/317
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
