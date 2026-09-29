# 03. Design spec

Status: architecture agreed. Component details (S-box, linear layer, key
schedule, round count, AEAD) are filled in by steps 4 to 9.

## Decided

- The symmetric cipher is designed from scratch and written in Rust.
- The key is 256 bits, for a quantum margin of about 128-bit security against
  Grover.
- The structure is a substitution-permutation network (SPN).
- Post-quantum public-key encryption is there from the start. In step 12 we
  changed the plan so that the KEM is our own, Turing-1026 (docs/16). It sits
  on the standard plain-LWE problem with our parameters, hashing, transform
  and implementation, and the data cipher is Turing or Turing-256. The earlier
  plan kept only the data cipher ours and used X-Wing (X25519 + ML-KEM-768
  with its SHA3-256 combiner, draft-connolly-cfrg-xwing-kem, not yet an RFC),
  where X25519 guards against a future break of the lattice part.
  Turing-1026 has no such second, non-lattice partner yet (docs/16, "What is
  not done").
- Sender signatures (ML-DSA) come later, after file encryption works end to
  end. The file format reserves space for them (versioned header).
- Constants and key-derived values all come from cSHAKE256 (NIST SP 800-185),
  with the input as X and an ASCII label of the form `"Turing v1 <purpose>"`
  as the customization string S (`crates/turing/src/xof.rs`). Version 2
  renamed the key-schedule labels to `"Turing v2 ..."` (docs/13), while the
  S-box and matrices keep the v1 labels they were generated with. cSHAKE
  encodes the label's length, so no two labels can ever produce the same hash
  input. Plain SHAKE256(label || input), which we used until step 7, only had
  that property because the lengths happened to differ. It produces any
  output length, so one rule covers everything, and standard tools reproduce
  it.

## Layer 1, the Turing block cipher

| Parameter | Proposal | Reason |
|---|---|---|
| Block size | 128 bits (4x4 bytes) | Avoids the 64-bit birthday bound |
| Key size | 256 bits | Quantum margin |
| Round | S-box layer → linear layer → add round key | Classic SPN, wide-trail analysable |
| S-box | A_out∘inv∘A_in over GF(2^8), affine layers from cSHAKE256 (docs/05) | Best known 8-bit strength, reproducible constants |
| Linear layer | 16×16 Cauchy MixState (branch 17) in odd rounds, ShiftRows + 4×4 Cauchy MixColumns (branch 5) in even rounds, none in the last (docs/06, 09) | Guarantees active S-boxes |
| Key schedule | cSHAKE256 whitening, then a Feistel of S-box + MixState rounds with feed-forward, 13 warm-up rounds (docs/07) | Every round key sits behind >= 53 active S-boxes; no local collisions |
| Rounds | 24 (version 2; docs/09, 13); 24 is the maximum | Three times the longest attack our tools can build (8 rounds); AES-256 uses 14 |
| Implementation | Constant-time, no secret-indexed table lookups (checked in the release assembly) | Cache-timing side channels |
| Keys in memory | Round keys in locked pages (on Linux also dump-excluded) with a keyed integrity checksum, checked before and after every checked call; stack burned after key setup (docs/13) | Cold boot, crash dumps, RAMBleed; Rowhammer faults |
| Masked variant | `MaskedTuring`: first-order Boolean masking, round-key shares re-randomised every call (docs/13) | Power, EM and frequency side channels |

### S-box acceptance criteria (checked by our step 3 tools)

- Bijective (every output appears exactly once).
- Differential uniformity ≤ 4 (max DDT entry, non-trivial rows).
- Linearity (max |Walsh coefficient|) ≤ 32: correlation ≤ 2^-3, that is, a
  linear approximation holds with probability at most 1/2 ± 2^-4.
  (Nonlinearity ≥ 112.)
- Boomerang uniformity ≤ 6.
- Algebraic degree 7 (maximal for a bijective 8-bit S-box).
- No fixed points: S(x) ≠ x and S(x) ≠ x XOR 0xFF.
- Shortest permutation cycle ≥ 16 (stricter than AES, which has a 2-cycle).
- Computable in constant time. Turing evaluates it arithmetically (two affine
  maps and x^254) with no table lookups; compact Boolean circuits for field
  inversion are also known if speed is needed later.

Forbidding S(x) = x in one component is fine. One of Enigma's weaknesses was
that the whole machine could never map a letter to itself. Our full cipher
must stay able to map any block to any block.

### Constants must be "nothing up my sleeve"

Every constant (S-box generation seed, round constants) is derived by a
published, reproducible rule, so anyone can check that none were chosen to
plant a weakness. Dual_EC_DRBG is the cautionary example: unexplained
constants that turned out to enable a backdoor.

## Layer 2, file encryption

- Each file gets a fresh random 256-bit file key from
  `turing::random::new_key`. That is cSHAKE256 of a 64-byte OS seed, because
  raw OS output can leave a copy in the generator's memory (docs/13).
- Each chunk is read into private memory once, its tag verified on that
  copy, and that same copy decrypted; no plaintext is released before its
  tag verifies (docs/13, section 8).
- Data is split into chunks (e.g. 64 KiB). Each chunk is encrypted and
  authenticated with a Turing-based AEAD, using a nonce that encodes the chunk
  counter and a "last chunk" flag (STREAM construction). This prevents
  reordering, dropping, or truncating chunks.
- The header is authenticated as well, so it can't be tampered with.
- The AEAD construction (e.g. CTR + MAC) is decided in step 9.

## Layer 3, hybrid key wrapping (how the file key reaches the reader)

The header carries one or more stanzas, each able to unlock the file key.

- A recipient stanza uses Turing-1026 (docs/16), whose shared key is derived
  from the whole ciphertext and, through its coins, the recipient's public
  key. (The earlier plan was a hybrid KEM, X25519 + ML-KEM, under a vetted
  combiner, so that an attacker had to break both; a second, non-lattice
  KEM beside Turing-1026 would restore that property.)
- A password stanza uses Argon2id (memory-hard; slows GPU guessing) with a
  random salt and stored parameters.

The file key is wrapped under the stanza's key-encryption key with the Turing
AEAD.

Crates (versions verified in step 9): `argon2`, `sha3`, `getrandom`; the
KEM is Turing-1026, in the turing crate.
