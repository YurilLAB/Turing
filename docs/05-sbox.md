# 05 — The Turing S-box

## Construction

S(x) = A_out( inv( A_in(x) ) ) over GF(2^8), with field polynomial
x^8 + x^4 + x^3 + x + 1.

- **inv** is the multiplicative inverse (inv(0) = 0). It reaches the best
  values known for an 8-bit permutation: differential uniformity 4 and
  nonlinearity 112. (Whether an 8-bit permutation with uniformity 2 exists is
  a famous open problem, so "best known", not "optimal". Other 4-uniform
  permutations with nonlinearity 112 exist too; the inverse is the
  best-studied.)
- **A_in, A_out** are invertible affine maps y = M·x ⊕ c over GF(2), read from
  cSHAKE256.

This is a mix of the two approaches considered in step 4: the well-studied
algebraic core, wrapped in layers produced by a public search.

## Why the search cannot weaken it, and what it can change

Differential uniformity, linearity, boomerang uniformity, algebraic degree
and the number of implicit quadratic equations are all **affine invariants**:
wrapping an S-box in invertible affine maps leaves them unchanged. So every
candidate scores exactly like the field inverse (4 / 32 / 6 / 7 / 39), which the
test `every_candidate_has_the_inverse_core` confirms.

What the affine layers *do* change are structural properties: fixed points and
the cycle structure. Those are what the search selects on. Turing requires a
shortest cycle of at least 16, which AES's S-box (with a 2-cycle) would fail.
No known attack uses short S-box cycles; the rule is cheap hygiene.

The polynomial choice does not matter. All fields with 256 elements are
isomorphic via a linear map on the bits, so a different polynomial would only
be another affine wrapper.

## Derivation (reproducible by anyone)

For counter n = 0, 1, 2, ...:

1. Stream = cSHAKE256(X = n as 4 bytes big-endian, S = "Turing v1 S-box").
2. A_in: read 8 bytes as matrix rows, redrawing while singular, then 1 byte
   as the constant. A_out: the same, continuing the stream.
3. Grade the candidate with Bombe. The **first** candidate passing every
   check is the S-box. Taking the first, not the best-looking, means nobody
   could have steered the result.

Result: candidates 0 to 2 failed (fixed points, opposite fixed points and
short cycles); **candidate 3** was accepted.

| Property | Turing | AES |
|---|---|---|
| Differential uniformity | 4 | 4 |
| Linearity / nonlinearity | 32 / 112 | 32 / 112 |
| Boomerang uniformity | 6 | 6 |
| Degree | 7 | 7 |
| Quadratic / bi-affine equations | 39 / 23 | 39 / 23 |
| Fixed / opposite fixed points | 0 / 0 | 0 / 0 |
| Cycles | 115 91 50 | 87 81 59 27 2 |

History: until step 7 the stream was plain SHAKE256("Turing v1 S-box" || n),
which picked candidate 34 (cycles 165 30 22 22 17). The review moved every
derivation to cSHAKE256 for proper domain separation (docs/08), which
changed the S-box. Both passed every check; the rule, not the result, is
what matters.

Reproduce it: `cargo run --release -p bombe -- gen-sbox`.

## Constant-time evaluation

The cipher never indexes a table with secret data. `turing::sbox::sub`
computes the affine maps with popcount parities and the inverse as x^254 using
a branch-free field multiply (fixed 8-iteration loops, masks instead of `if`).
The published `TABLE` exists for analysis and tests only. A timing test
(step 10) will check this empirically; x^254 by square-and-multiply is simple
but slow, and a faster tower-field circuit can replace it later without
changing any output.

## Guards

- `committed_constants_are_reproducible`: the committed
  `crates/turing/src/sbox_constants.rs` must equal the generator's output
  byte for byte. Changing one S-box byte by hand fails it (checked).
- `xof::tests::matches_nist_samples`: the cSHAKE256 helper every derivation
  goes through matches NIST SP 800-185 samples #3 and #4, so other cSHAKE256
  tools reproduce the same constants. `shake256_matches_fips202` checks the
  underlying SHAKE256 against FIPS 202.
- The arithmetic S-box, its inverse and the published table agree for all 256
  inputs.
