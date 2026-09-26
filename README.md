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
cargo run --release -p bombe -- attack             # attack the real cipher, about 30 s
cargo run --release -p bombe -- trace --flip-plaintext-bit 0
cargo run --release -p bombe -- sbox turing --html sbox.html
cargo run --release -p bombe -- rounds             # compare round structures
cargo run --release -p bombe -- key-schedule
cargo run --release -p bombe -- vectors            # known-answer vectors
```

`cargo test` runs the whole suite: the cipher against an independent
reference implementation and the vectors in `vectors/turing-v1.txt`, every
analysis tool against published AES results, and Bombe's NIST statistical
tests against NIST's own reference results.
