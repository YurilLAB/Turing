# Turing

An experimental 128-bit block cipher with a 256-bit key, designed from scratch in
Rust and named after Alan Turing, plus a file-encryption tool built on it with
post-quantum hybrid key wrapping (X-Wing) and password unlock (Argon2id).

**Experimental. Do not use it to protect real data.** A new cipher is only
trusted after years of public cryptanalysis.

The design reasoning lives in [docs/](docs/), one document per step.

## Crates

- `crates/turing`: the cipher. 16 rounds, constant-time, about 3 µs per block.
- `crates/bombe`: the cryptanalysis workbench, named after Turing's
  code-breaking machine. It exists to break Turing.

## Bombe commands

```
cargo run --release -p bombe -- attack             # attack the real cipher, 93 findings, about 60 s
cargo run --release -p bombe -- attack --deep      # adds the long runs (2^33-encryption square attack, NIST at scale), about 20 min
cargo run --release -p bombe -- trace --flip-plaintext-bit 0
cargo run --release -p bombe -- sbox turing --html sbox.html
cargo run --release -p bombe -- rounds             # compare round structures
cargo run --release -p bombe -- key-schedule
cargo run --release -p bombe -- vectors            # known-answer vectors
```

`cargo test` runs the whole suite: the cipher against an independent
reference implementation and the vectors in `vectors/turing-v1.txt`, every
analysis tool against published results (AES, Midori-64, NIST), and each
attack against the rounds it must break.

`cargo test --release -- --include-ignored` also runs the slow test (Turing's
exact best 2-round differential, about a minute). `python tools/mutate.py
--round3` plants bugs in the latest attack code and checks the tests catch
each one.

The library runs a known-answer self-test (`turing::self_test()`, call it
at start-up) and offers fault-checked calls (`encrypt_block_checked`,
`decrypt_block_checked`). Round keys and reduced-round encryption are only
reachable through the `turing` crate's `analysis` feature, which only Bombe
turns on. For the constant-time review, `tools/asm_branches.py` lists every
conditional jump in the release build's assembly (docs/11).

`research/` holds the papers, verified facts and derivations behind the
docs (papers stay local; the index links to each one).
