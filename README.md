# Turing

An experimental 128-bit block cipher with a 256-bit key, designed from scratch in
Rust and named after Alan Turing, plus a file-encryption tool built on it with
post-quantum hybrid key wrapping (X-Wing) and password unlock (Argon2id).

**Experimental. Do not use it to protect real data.** A new cipher is only
trusted after years of public cryptanalysis.

The design reasoning lives in [docs/](docs/), one document per step.
