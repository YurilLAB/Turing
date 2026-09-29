# Turing

[![CI](https://github.com/YurilLAB/Turing/actions/workflows/ci.yml/badge.svg)](https://github.com/YurilLAB/Turing/actions/workflows/ci.yml)

Turing is a block cipher and a post-quantum key exchange, designed from
scratch in Rust and named after Alan Turing. The repository also holds
Bombe, a workbench built to break them.

> [!WARNING]
> **Experimental. Do not use it to protect real data.** A new cipher is only
> trusted after years of public cryptanalysis, and all of the analysis here
> is our own.

## What's inside

| Part | What it is |
|---|---|
| Turing | 128-bit block, 256-bit key, 24 rounds, constant time, about 4.5 µs per block |
| Turing-256 | The same design on a 256-bit block, with round constants (v2) ([docs/15](docs/15-turing-256.md)) |
| Turing-1026 | A post-quantum key-encapsulation mechanism (KEM) on plain LWE in dimension 1026, whose shared keys are Turing keys ([docs/16](docs/16-turing-1026.md)) |
| ML-KEM | FIPS 203, all three parameter sets, checked against NIST's and C2SP's vectors: the standard half of the planned hybrid KEM ([docs/18](docs/18-hybrid-kem-design.md)) |
| Bombe | The cryptanalysis workbench, named after Turing's code-breaking machine |

A file-encryption tool on top of them, with password unlock (Argon2id), is
planned.

## Getting started

You need Rust through [rustup](https://rustup.rs), which reads the pinned
version (1.94.1) from `rust-toolchain.toml`. The checks in `tools/` also
need Python 3.12 with `numpy` and `mpmath`.

```sh
git clone https://github.com/YurilLAB/Turing.git
cd Turing
cargo build --release
cargo test --release                      # the whole suite, over 300 tests
cargo run --release -p bombe -- attack    # attack the real cipher and KEM
python tools/ci.py                        # every automated check (tools/CI.md)
```

## How it works

Turing is a substitution-permutation network, the family AES belongs to. Each
of its 24 rounds substitutes every byte of the block, mixes the bytes
together and adds a round key.

The S-box is AES's field inversion (x^254 in GF(2^8)) between two affine maps
of Turing's own. It has nonlinearity 112, differential uniformity 4 and
degree 7, the best known for an 8-bit S-box, and it is computed, never looked
up in a table.

For mixing, odd rounds multiply the whole state by a 16×16 MDS matrix, so one
changed byte changes all 16, and even rounds use AES's ShiftRows and
MixColumns. Any differential or linear trail through the full cipher has at
least 204 active S-boxes.

The key schedule starts with cSHAKE256 and then runs a Feistel network of
S-box and mixing rounds, fed forward. Round keys cannot be run back to the
key, and any key difference crosses at least 53 active S-boxes.

There are no hidden constants: every constant is cSHAKE256 of a public label,
and Bombe regenerates them all. The implementation is constant time, meaning
no branch or memory access depends on secret data, and the release build's
assembly is checked for it.

Turing-1026 gives a sender a random 256-bit key and a ciphertext that only
the recipient can open. It rests on learning with errors in its plainest form
(no ring structure, as in FrodoKEM), with a Fujisaki-Okamoto transform
against chosen ciphertexts. The best known attack costs 2^252.4 in the
standard core-SVP count (ML-KEM-1024: 2^253.9), and a ciphertext fails to
decrypt with probability 2^-266. The public key is 61,592 bytes and the
ciphertext 15,934 bytes; encapsulating takes about 13 ms and decapsulating
about 26 ms.

## What has been tested

- `bombe attack` runs 25 sections of attacks against the real code, from
  differential, linear and square attacks to boomerang, related-key,
  invariant, yoyo and meet-in-the-middle. The best of them break 4 of the 24
  rounds in practice. On paper, the square attack reaches 7 rounds, but it
  needs every possible plaintext-ciphertext pair and about 2^174 encryptions
  ([docs/14](docs/14-attacks-from-the-aes-256-literature.md)).
- Every analysis tool reproduces published results (AES, Midori-64, NIST,
  FrodoKEM, NewHope) before we trust it on Turing.
- Turing, Turing-256 and Turing-1026 each match an independent reference
  implementation and the known-answer vectors in `vectors/`. Turing-256 and
  Turing-1026 also match a third implementation in Python.
- For implementation attacks we looked at timing (dudect, no leak), simulated
  power analysis (the masked variant shows no first-order leakage), injected
  faults (every one- and two-bit fault in the stored key material is caught)
  and a memory-dump attacker (no key material left behind).
- The tests get tested too: `tools/mutate.py` plants bugs in the code and
  checks that a test catches each one, and `tools/ci.py` runs every check,
  putting the GPU and every CPU thread to work on the statistical ones.

## Bombe commands

Run each with `cargo run --release -p bombe -- <command>`.

| Command | What it does |
|---|---|
| `attack` | The attack campaign against the real cipher and KEM |
| `attack --deep` | Adds the long runs, about an hour on 4 threads |
| `trace --flip-plaintext-bit 0` | Follows a one-bit change through every round |
| `sbox turing --html sbox.html` | Measures the S-box, with DDT and LAT heatmaps |
| `rounds` | Compares round structures |
| `key-schedule` | Proves the key schedule's minimum active S-boxes |
| `vectors` | Known-answer vectors (`--turing-256`, `--turing-1026`) |

## Using the library

- Call `turing::self_test()` at start-up.
- `encrypt_block_checked` and `decrypt_block_checked` check the round keys'
  keyed checksum before and after computing, against injected faults.
- `MaskedTuring` is a first-order masked variant (about 21 µs per block),
  `ShieldedKey` an OpenSSH-style shielded key, and `random::new_key`
  generates keys without leaving a copy behind. Keys live in memory locked
  where the OS allows it (reported by `locked()` and
  `memory::unlocked_allocations()`), kept out of core dumps on Linux.
- Round keys and reduced-round encryption sit behind the `analysis` feature,
  which only Bombe turns on.

## Repository map

| Path | Contents |
|---|---|
| `crates/turing` | The ciphers, the KEMs and key handling |
| `crates/bombe` | The cryptanalysis workbench |
| `docs/` | The design, one document per step |
| `vectors/` | Known-answer test vectors |
| `tools/` | The CI runner, mutation testing, constant-time and WSL checks |
| `research/` | The papers index, notes and scripts behind the docs (the papers stay local) |

The docs are grouped by number. The cipher's design is
[01](docs/01-foundations.md)–[09](docs/09-round-structure.md), attacks and
hardening [10](docs/10-attack-bench.md)–[14](docs/14-attacks-from-the-aes-256-literature.md),
Turing-256 [15](docs/15-turing-256.md), Turing-1026
[16](docs/16-turing-1026.md)–[17](docs/17-turing-1026-security-argument.md)
and the hybrid KEM [18](docs/18-hybrid-kem-design.md).
