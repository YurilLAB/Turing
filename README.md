# Turing

An experimental 128-bit block cipher with a 256-bit key, designed from scratch in
Rust and named after Alan Turing; Turing-256, the same design on a 256-bit
block (docs/15); and Turing-1026, a post-quantum key-encapsulation mechanism
on plain LWE in dimension 1026 whose shared keys are Turing keys (docs/16).
A file-encryption tool on top of them, with password unlock (Argon2id), is
planned (docs/03).

**Experimental. Do not use it to protect real data.** A new cipher is only
trusted after years of public cryptanalysis.

The design reasoning lives in [docs/](docs/), one document per step.

## How it works

Turing is a substitution-permutation network, the family AES belongs to:
24 rounds, each substituting every byte of the 128-bit block, mixing the
bytes together and adding a round key.

- **S-box**: the field inversion AES uses, x^254 in GF(2^8), between two
  affine maps of Turing's own. Nonlinearity 112, differential uniformity 4
  and degree 7, the best known for an 8-bit S-box. It is computed
  arithmetically, never looked up in a table.
- **Mixing**: odd rounds multiply the whole state by a 16×16 MDS matrix, so
  one changed byte changes all 16; even rounds use ShiftRows and a 4×4
  MixColumns, as AES does. Any differential or linear trail through the
  full cipher has at least 204 active S-boxes.
- **Key schedule**: the key is hashed with cSHAKE256, expanded by a Feistel
  network of S-box and mixing rounds, and fed forward, so round keys cannot
  be run back to the key and any key difference crosses at least 53 active
  S-boxes before it reaches one.
- **No hidden constants**: every constant comes from cSHAKE256 of a public
  label, and Bombe regenerates them all.
- **Constant time**: no branch or memory access depends on secret data, and
  the release build's assembly is checked for it.

**Turing-1026** is the post-quantum part: a sender makes a random 256-bit key
and a ciphertext only the recipient's secret key opens. Its hard problem is
learning with errors in its plainest form (no ring structure, as FrodoKEM
uses), the textbook Lindner-Peikert encryption on top, and a
Fujisaki-Okamoto transform against chosen ciphertexts. Its parameters
(dimension 1026, modulus 2^15, noise of standard deviation 3), hashing,
transform details and code are Turing's own. The best known lattice attack
costs 2^252.4 in the standard core-SVP count (ML-KEM-1024: 2^253.9 in the
same count) and about 2^269.5 in the lattice-estimator's model — run under
real SageMath and with its greedy dual-hybrid search corrected — and a
ciphertext fails to decrypt with probability 2^-266, computed exactly and
proven not to concentrate on unlucky keys.

## What has been tested

- `bombe attack` runs 25 sections of attacks against the real cipher:
  differential, linear, square and division-property, boomerang, cube,
  related-key, differential-linear, interpolation, invariant, symmetry,
  yoyo and meet-in-the-middle attacks, plus the implementation attacks
  below. The best of them break 4 of the 24 rounds in practice, and the
  longest impossible differential found by `bombe rounds` also spans 4. On
  paper, the square attack with all of round key 0 guessed reaches 7
  rounds, but needs every possible plaintext-ciphertext pair and about
  2^174 encryptions (docs/14). Counting every trail, any 3 rounds have
  differential probability at most 2^-102.0 and linear hulls at most
  2^-99.6, and from 3 rounds on the output passes the NIST SP 800-22
  statistical battery.
- Turing-1026 (section 25): its attack cost and failure rate come from
  tools that first reproduce FrodoKEM's and NewHope's published tables; the
  lattice-estimator is also run under real SageMath and audited for its two
  known optimiser flaws; the real code fails exactly as often as the computed
  law says, and the per-key failure spread is bounded and measured over
  100,000 keys; Bombe's own LLL and BKZ recover the secret from real keys
  with the dimension cut to 100, needing the block sizes the cost model
  predicts; chosen and adversarial ciphertexts, a decapsulation fault map,
  timing, faults and memory are checked as for the cipher.
- Each analysis tool is first checked against published results (AES,
  Midori-64, NIST's test data, FrodoKEM, NewHope) before it is trusted on
  Turing.
- The cipher, Turing-256 and Turing-1026 each match an independent
  reference implementation and the known-answer vectors in `vectors/`, and
  the library ships a self-test covering all three.
- Implementation attacks: timing (dudect on eight code paths, no leak),
  simulated power analysis (the masked variant shows no first-order
  leakage), injected faults (every one- and two-bit fault in the stored key
  material is caught) and a memory-dump attacker that scans the whole
  process (no key material left behind).
- `cargo test` runs over 200 tests, and `tools/mutate.py` plants bugs in the
  code to check that the tests catch them.
- An outside review of version 2 found problems around the cipher, not in
  it; all are fixed and logged in docs/08.

All of this is our own analysis, which is why Turing stays experimental.

## Crates

- `crates/turing`: the cipher, version 2. 24 rounds (the maximum),
  constant-time, about 4.5 µs per block; a first-order masked variant
  (`MaskedTuring`, about 20 µs), an OpenSSH-style shielded key
  (`ShieldedKey`) and key generation that leaves no copy behind
  (`random::new_key`). Keys live in locked pages, kept out of core dumps
  on Linux; `keys_locked()` and `keys_dump_excluded()` report what the
  operating system granted.
- `crates/turing` also holds **Turing-256** (`Turing256`): a 256-bit block
  with the same S-box, alternating 32x32 MixState and ShiftRows +
  MixColumns, the same kind of key schedule and the same locked,
  fault-checked round keys, 24 rounds. The wider block moves the birthday
  bound of any mode from 2^64 to 2^128 blocks (docs/15).
- `crates/turing` also holds **Turing-1026** (`turing1026`): the
  post-quantum KEM. Public key 61,592 bytes, ciphertext 15,934 bytes, secret
  key a 32-byte seed kept expanded in locked memory; about 13 ms to
  encapsulate or decapsulate (docs/16).
- `crates/bombe`: the cryptanalysis workbench, named after Turing's
  code-breaking machine. It exists to break Turing.

## Bombe commands

```
cargo run --release -p bombe -- attack             # attack the real cipher and KEM: 25 sections, 0 failures expected
cargo run --release -p bombe -- attack --deep      # adds the long runs (2^33-encryption square attack, 2^32 structures through 7 rounds, NIST at scale), about an hour on 4 threads
cargo run --release -p bombe -- trace --flip-plaintext-bit 0
cargo run --release -p bombe -- sbox turing --html sbox.html
cargo run --release -p bombe -- rounds             # compare round structures
cargo run --release -p bombe -- key-schedule
cargo run --release -p bombe -- vectors            # known-answer vectors (--turing-256, --turing-1026)
```

`cargo test` runs the whole suite: the cipher, Turing-256 and Turing-1026
against their independent reference implementations and the vectors in
`vectors/`, every analysis tool against published results (AES, Midori-64,
NIST, FrodoKEM, NewHope), each attack against the rounds it must break, and
the library's defences against a memory-dump attacker, simulated power
analysis and injected faults.
`python tools/wsl_linux.py test -p turing --lib` runs the Linux code paths
(mlock, MADV_DONTDUMP, MADV_WIPEONFORK, fork) from Windows, in WSL.

`cargo test --release -- --include-ignored` also runs the slow tests
(Turing's exact best 2-round differential, about a minute, and the 6- and
7-round square attack steps on 2^32-text structures, about 20 minutes on 4
threads). `python tools/mutate.py --round7` plants bugs in the latest code
(Turing-1026) and checks the tests catch each one (`--step8`, `--step9`,
`--round3` to `--round6` and the default set cover the earlier rounds).

The library runs a known-answer self-test (`turing::self_test()`, call it
at start-up) and offers fault-checked calls (`encrypt_block_checked`,
`decrypt_block_checked`) that check the round keys' keyed checksum before
and after computing. Round keys and reduced-round encryption are only
reachable through the `turing` crate's `analysis` feature, which only Bombe
turns on. For the constant-time review, `tools/asm_branches.py` lists every
conditional jump, with `--loads` every indexed memory access, and with
`--divs` every division instruction, in the release build's assembly
(docs/11, 13, 16).

`research/` holds the papers, verified facts and derivations behind the
docs (papers stay local; the index links to each one).
