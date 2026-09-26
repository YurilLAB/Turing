# 03 — Design spec

Status: architecture agreed. Component details (S-box, linear layer, key
schedule, round count, AEAD) are filled in by steps 4–9.

## Decided

- Symmetric cipher designed from scratch, written in Rust.
- 256-bit key (quantum margin: ~128-bit security against Grover).
- Substitution-permutation network (SPN).
- Hybrid public-key encryption from the start, built on vetted post-quantum
  primitives. Only the data cipher is ours.
- Hybrid KEM: **X-Wing** (X25519 + ML-KEM-768 with its published SHA3-256
  combiner). ML-KEM-768 is NIST category 3; X25519 guards against a future
  break of ML-KEM. We do not hand-build the combiner.
- Sender signatures (ML-DSA): **later**, after file encryption works end to
  end. The file format reserves space for them (versioned header).
- Constants: derived with **SHAKE256** (the SHA-3 extendable-output function)
  from ASCII labels of the form `"Turing v1 <purpose>"`, e.g.
  `"Turing v1 round constants"`. SHAKE256 produces any length, so one rule
  covers every constant, and anyone can reproduce them with a standard tool.

## Layer 1: the Turing block cipher

| Parameter | Proposal | Reason |
|---|---|---|
| Block size | 128 bits (4x4 bytes) | Avoids the 64-bit birthday bound |
| Key size | 256 bits | Quantum margin |
| Round | S-box layer → linear layer → add round key | Classic SPN, wide-trail analysable |
| S-box | Our own 8-bit bijective S-box | Designed and measured in step 4 |
| Linear layer | Our own, target branch number 5 (MDS) | Guarantees active S-boxes (step 5) |
| Key schedule | Non-linear, uses the S-box, per-round constants | Blocks slide and related-key attacks (step 6) |
| Rounds | Set from proven bounds + margin (step 7) | AES-256 uses 14; expect similar or more |
| Implementation | Constant-time, no secret-indexed table lookups | Cache-timing side channels |

### S-box acceptance criteria (checked by our step 3 tools)

- Bijective (every output appears exactly once).
- Differential uniformity ≤ 4 (max DDT entry, non-trivial rows).
- Max LAT absolute entry ≤ 16 (linear bias ≤ 2^-3).
- Algebraic degree 7 (maximal for a bijective 8-bit S-box).
- No fixed points: S(x) ≠ x and S(x) ≠ x XOR 0xFF.
- Has a small Boolean circuit, so it can be computed in constant time.

Note: forbidding S(x) = x in one component is fine. Enigma's flaw was that
the *whole* cipher could never map a letter to itself; our full cipher must
remain able to map any block to any block.

### Constants must be "nothing up my sleeve"

Every constant (S-box generation seed, round constants) is derived by a
published, reproducible rule, so anyone can check that none were chosen to
plant a weakness. Dual_EC_DRBG is the cautionary example: unexplained
constants that turned out to enable a backdoor.

## Layer 2: file encryption

- Each file gets a fresh random 256-bit **file key** from the OS CSPRNG.
- Data is split into chunks (e.g. 64 KiB). Each chunk is encrypted and
  authenticated with a Turing-based AEAD, using a nonce that encodes the chunk
  counter and a "last chunk" flag (STREAM construction). This prevents
  reordering, dropping, or truncating chunks.
- The header is authenticated as well, so it can't be tampered with.
- AEAD construction (e.g. CTR + MAC) is decided in step 9.

## Layer 3: hybrid key wrapping (how the file key reaches the reader)

The header carries one or more **stanzas**, each able to unlock the file key:

- **Recipient stanza**: post-quantum hybrid KEM (X25519 + ML-KEM). An attacker
  must break *both* to recover the key. The two shared secrets are combined
  by a vetted combiner that also binds the ciphertexts and public keys.
- **Password stanza**: Argon2id (memory-hard; slows GPU guessing) with a random
  salt and stored parameters.

The file key is wrapped under the stanza's key-encryption key with the Turing
AEAD.

Crates (versions verified in step 9): an X-Wing implementation (or `ml-kem`
+ `x25519-dalek` combined exactly per the X-Wing spec), `argon2`, `sha3`,
`getrandom`.
