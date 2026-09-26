# Turing

An experimental 128-bit block cipher with a 256-bit key, designed from scratch in
Rust and named after Alan Turing, plus a file-encryption tool built on it with
post-quantum hybrid key wrapping (X-Wing) and password unlock (Argon2id).

**Experimental. Do not use it to protect real data.** A new cipher is only
trusted after years of public cryptanalysis.

The design reasoning lives in [docs/](docs/), one document per step.

## Crates

- `crates/turing`: the cipher, version 2. 24 rounds (the maximum),
  constant-time, about 4.5 µs per block; a first-order masked variant
  (`MaskedTuring`, about 20 µs), an OpenSSH-style shielded key
  (`ShieldedKey`) and key generation that leaves no copy behind
  (`random::new_key`). Keys live in locked pages, kept out of core dumps
  on Linux; `keys_locked()` and `keys_dump_excluded()` report what the
  operating system granted.
- `crates/bombe`: the cryptanalysis workbench, named after Turing's
  code-breaking machine. It exists to break Turing.

## Bombe commands

```
cargo run --release -p bombe -- attack             # attack the real cipher: 21 sections, 0 failures expected
cargo run --release -p bombe -- attack --deep      # adds the long runs (2^33-encryption square attack, NIST at scale), about 20 min
cargo run --release -p bombe -- trace --flip-plaintext-bit 0
cargo run --release -p bombe -- sbox turing --html sbox.html
cargo run --release -p bombe -- rounds             # compare round structures
cargo run --release -p bombe -- key-schedule
cargo run --release -p bombe -- vectors            # known-answer vectors
```

`cargo test` runs the whole suite: the cipher against an independent
reference implementation and the vectors in `vectors/turing-v2.txt`, every
analysis tool against published results (AES, Midori-64, NIST), each
attack against the rounds it must break, and the library's defences against
a memory-dump attacker, simulated power analysis and injected faults.
`python tools/wsl_linux.py test -p turing --lib` runs the Linux code paths
(mlock, MADV_DONTDUMP, MADV_WIPEONFORK, fork) from Windows, in WSL.

`cargo test --release -- --include-ignored` also runs the slow test (Turing's
exact best 2-round differential, about a minute). `python tools/mutate.py
--round4` plants bugs in the latest code and checks the tests catch each
one (`--step8`, `--step9`, `--round3` and the default set cover the earlier
rounds).

The library runs a known-answer self-test (`turing::self_test()`, call it
at start-up) and offers fault-checked calls (`encrypt_block_checked`,
`decrypt_block_checked`) that check the round keys' keyed checksum before
and after computing. Round keys and reduced-round encryption are only
reachable through the `turing` crate's `analysis` feature, which only Bombe
turns on. For the constant-time review, `tools/asm_branches.py` lists every
conditional jump, or with `--loads` every indexed memory access, in the
release build's assembly (docs/11, 13).

`research/` holds the papers, verified facts and derivations behind the
docs (papers stay local; the index links to each one).
