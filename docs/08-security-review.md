# 08 — Security review

A living review of every component against published attacks on AES-like
ciphers, first written after step 6 and revisited in steps 7 and 10 (three
times). Each
item says what the literature shows, whether Turing is exposed, and what, if
anything, changes. The reviews of Turing's *own* earlier work are at the
end.

## Related-key attacks (Biryukov–Khovratovich 2009)

Fixed in step 6 and corrected in step 7; see 07-key-schedule.md. Every round
key now sits behind at least 53 active S-boxes from any key difference.

## Biclique attacks (Bogdanov, Khovratovich, Rechberger, ASIACRYPT 2011)

Full AES-256 in about 2^254.4 operations: barely faster than brute force,
but a break on paper. Bicliques build groups of keys whose differences touch
only part of the cipher for a few rounds, which AES's slow key schedule
permits. In Turing every round key depends on every key bit through at least
53 S-boxes, so that partial-key structure is absent. Status: expected to be
mitigated; not modelled by Bombe yet (docs/11).

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
not "key + constant", so the precondition does not hold. **Measured in step
10 (docs/11):** both linear layers have a single invariant factor, and the
real round-key differences span all 128 dimensions (W_L(D) = 128) for every
key tried, so the paper's criterion leaves no invariant. Status: not
exposed.

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
keys, and round keys are wiped when dropped. Step 10 closed three gaps
(review 3 below): key bytes left in the cSHAKE state, round keys copied
when the cipher value moved, and round keys readable through the public API.
The fourth campaign (review 5) locks the key pages out of swap and core
dumps, burns the stack after key setup, and checks the whole process with a
memory-dump attacker (docs/13). Hibernation and registers remain outside the
cipher's control.

## Timing side channels

Everything is written branch-free with no secret-indexed tables, and
cSHAKE256 (Keccak) uses no tables. The compiler could still introduce
branches, so this is a claim to measure, not assume. **Measured:** the
dudect-style test finds no data-dependent timing (step 8, docs/10), and in
step 10 the release build's assembly was read: no conditional jump in the
cipher's secret paths depends on data. The compiler *did* turn the masks of
the reference `mat_vec` into branches on state bits, which is why it is now
compiled for tests only (docs/11). The fourth campaign extends both checks:
dudect covers decryption, the checked calls, the masked cipher and key
shielding too, and the assembly is also read for indexed memory accesses,
none of which depends on secret data (docs/13).

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

## Review 3 (step 10, second campaign): key handling and earlier claims

| # | Where | Problem | Severity | Fix |
|---|---|---|---|---|
| 1 | Key whitening (steps 6, 8) | The key went through cSHAKE256 and the hasher was dropped unwiped: sha3 without its `zeroize` feature leaves the Keccak state in memory, and the digest crate never wipes its input buffer | Real, needs a memory disclosure to exploit | sha3 `zeroize` feature; `xof::cshake256_secret` wipes the buffer and output block; a test proves identical output for every input length 0–135 |
| 2 | `RoundKeys` (step 6) | Round keys stored inline, so every move of a `Turing` copied them and left the old copy unwiped | Real, same condition | Round keys on the heap, filled in place |
| 3 | Cipher API (step 8) | `round_key`, `get`, `all` and the reduced-round functions were public in every build | Real: any program could read the round keys | `analysis` feature, used only by Bombe; a probe crate shows the calls fail to compile without it |
| 4 | `linear::mat_vec` (step 5) | Documented as constant-time, but the release build compiles it into 21 conditional jumps on state bits | Latent: the cipher never calls it | Docs corrected; compiled for tests and analysis only |
| 5 | This document | The timing test was still "planned" (done in step 8) and bicliques "to be tested in step 10" | Accuracy | Updated |
| 6 | Doc 10 | "The best attack breaks 3 rounds" and "division property not covered" | Accuracy | The division property predicts, and a 2^32-plaintext run confirms, a 4-round key recovery; doc 10 now points to doc 11 |
| 7 | New structured square attack | With two fixed sets, a correct attack is reported as failed about 6% of the time (a wrong key byte guess survives both sets with probability 2^-16) | Tooling | Adds sets until every byte is unique |

## Review 6 (after version 2): an outside review

Four problems around the cipher, each reproduced here before it was fixed.

| # | Where | Problem | Severity | Fix |
|---|---|---|---|---|
| 1 | Round-key checksum | Σ x^i · RK_i has two-bit blind spots: bit b of RK_i and bit b − 1 of RK_i+1 cancel. 38,700 two-bit faults in all (0.7%), 35,800 of them in the round keys, and the checked calls passed each one, releasing output under the wrong keys | Fault countermeasure bypassed | Keyed checksum Σ H^(i+1) · RK_i at a secret point (derived from the key for `Turing`, random for `MaskedTuring`): a fault arranged without the key escapes with probability at most 25/2^127, whatever its weight. All 35,800 pairs and random 2–16-bit faults caught (campaign 12); unit tests show no one- or two-bit fault goes unseen |
| 2 | `random::MaskStream` | Its public draws reseeded after fork(2) only if the state had been wiped, so outside Linux, or where the kernel refused MADV_WIPEONFORK, a child drawing directly repeated its parent's masks. `MaskedTuring` was safe: it checks the process ID at the start of every operation | Masking defeated for direct users | Every public draw checks the process ID first; the masked cipher keeps a crate-private path without the system call, behind its own check |
| 3 | `SecretBox` | The results of MADV_DONTDUMP and MADV_WIPEONFORK were discarded, so nothing reported whether a key's pages were kept out of core dumps | Protection not observable | `dump_excluded()` and `wiped_on_fork()` report the kernel's answers, passed on as `keys_dump_excluded()` and `ShieldedKey::dump_excluded()`; campaign 20 reports them |
| 4 | Doc 13, `shield.rs` | "Has to recover all 16,416 bytes without error": each unknown bit only doubles a search that a known plaintext can test, so a few errors are correctable | Accuracy | "With high accuracy", as OpenSSH says, with what each missing bit costs |
| 5 | Keyed checksum (fix 1) | Its bound was shown for faults in the round keys and the stored checksum; for a fault in the point H the docs only asserted it, and no test tried one beyond single bits | Proof gap (no bypass known) | Shown: moving H by d changes round key 0's term by exactly d · RK_0, so such a fault passes for one value of RK_0 only (2^-128 while the key is unknown). Every one- and two-bit fault that moves H is tried in the unit tests and in campaign 12 (434,240 caught) |

## Review 5 (step 10, fourth campaign): version 2 and the library

| # | Where | Problem | Severity | Fix |
|---|---|---|---|---|
| 1 | Key schedule | Prefix-consistent: with unchanged labels, version 2's first 17 round keys would equal version 1's | Cross-version relation | Labels "Turing v2 key", "Turing v2 key schedule constants" |
| 2 | Key setup | The release build left two 8-byte pieces of K' in dead stack, surviving encryptions and drop | Key residue | `burn_stack` after key setup; the memory scan finds nothing |
| 3 | Callers' keys | Windows' `ProcessPrng` leaves up to the last 16 bytes of its output in process memory | Key residue (platform) | `random::new_key`: cSHAKE256 of a 64-byte seed; nothing found |
| 4 | Checked calls | A key fault between the checksum check and use passed decrypt-and-compare and released output under a wrong key | Fault window (TOCTOU) | A second checksum check after the computation |
| 5 | Mask generator | A fork child would reuse the parent's masks | Masking defeated | MADV_WIPEONFORK state and a process-ID check; tested on Linux |
| 6 | `impossible::find` | Iterated `HashMap`s, so the witness it reported changed from run to run | Reproducibility | Ordered maps |
| 7 | Truncated propagation | The rule for one certain non-zero byte beside unknown ones had no test; a wrong version survived the planted-bug run | Test gap | Soundness test against real differences |
| 8 | Docs | Docs 10–12 give version 1's numbers | Accuracy | Marked as version 1; doc 13 has version 2's |

## Review 4 (step 10, third campaign): earlier claims and tooling

| # | Where | Problem | Severity | Fix |
|---|---|---|---|---|
| 1 | Docs 10, 11 | The planted-bug results they cite came from a script that lived outside the repository | Tooling: a cited checker must exist | `tools/mutate.py`, with the step-8, step-9 and round-3 sets |
| 2 | Doc 09 | "Differentials and linear hulls (many trails adding up)" listed as unmodelled | Gap | Provable bounds that count every trail (docs/12): any 3 rounds ≤ 2^-102.0 / 2^-99.6, any 5 ≤ 2^-110.8 / 2^-105.9 |
| 3 | Doc 11 | Todo's MISTY1 and division-property claims rested on memory: the local "MISTY" paper was a different one (Li et al.) | Accuracy (the claims were right) | Todo's two papers downloaded and checked |
| 4 | Library | Nothing checked at run time that the compiled cipher still computes Turing | Hardening | `turing::self_test()`; the vectors are cross-checked against the reference implementation |
| 5 | Library | The DFA countermeasure existed only as a Bombe simulation | Hardening | `encrypt_block_checked` / `decrypt_block_checked` |

Checked and found correct in review 4: Park et al.'s theorems and AES
values, Keliher and Sui's exact AES MEDP, and FIPS-197's key expansion (all
reproduced by Bombe). Also Anubis's matrix, checked in the Linux kernel's
tables.

Checked and found correct in review 3: Turing's inversion chain is exactly
Rivain–Prouff's Algorithm 2 (so masking applies unchanged), the BCLR
statements and Midori-64 figures (reproduced by Bombe), the AES S-box
polynomial (Rosenthal, reproduced), the Midori cell permutation (checked
against its published inverse), and the Trivium, Plundervolt and PLATYPUS
claims against the papers.

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
