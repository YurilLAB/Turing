# Status of the post-quantum research (stopped 2026-09-27)

The owner stopped this research on 2026-09-27. The notes in this folder are research
drafts. Most were never independently fact-checked, so treat a claim here as
sourced but unreviewed unless the table below says a check passed.

## What finished

| Notes file | Research | Sources check | Reasoning check | Corrections applied |
|---|---|---|---|---|
| nist-pqc-standards.md | done | done: 78 claims, 1 minor issue | done: 50 claims, 1 major + 10 minor issues | none (see below) |
| hybrid-combiners.md | done | done: 68 claims, no issues | partial record only (`checks/`) | none needed from the sources check |
| lattice-foundations.md | done | partial record only | partial record only | none |
| lattices-inside-symmetric-primitives.md | done | partial record only | not run | none |
| cca-transforms-and-binding.md | done | not run | not run | none |
| decryption-failures.md | done | not run | not run | none |
| pq-families-for-diversity.md | done | not run | not run | none |
| quantum-crypto-and-quantum-attacks.md | done | not run | not run | none |
| testing-ci-cd.md | done | not run | not run | none |
| turing-integration-constraints.md | done | not run | not run | none |
| attack-cost-estimation.md | cut off, but substantial | not run | not run | none |
| side-channels-faults-and-ct-verification.md | cut off, but substantial | not run | not run | none |
| rust-pqc-implementations.md | cut off early (short) | not run | not run | none |

The completeness review, the gap research and the synthesis (an index of
these notes) never ran. Check records, claim by claim, are in `checks/`.

## Issues found and not yet applied (nist-pqc-standards.md)

- **Major.** The notes quote Kyber's round-3 attack estimates as ML-KEM's
  current margins (8.5 / 8.1 / 15.3 bits over the category thresholds) and,
  elsewhere, IR 8413's remark that the sets "fall slightly below" their
  targets. Both are 2021-2022 views. NIST's FAQ on Kyber512 (December 2023)
  revisits them after Ducas-Pulles questioned the dual-sieve attacks: best
  estimate about 2^147 gates for ML-KEM-512 (2^145 with huge memories),
  window 2^135 to 2^158, against 2^143 for AES-128.
- The MAXDEPTH grid's 2^96 column is meaningless for AES-128 (G/MAXDEPTH
  only holds while one Grover run is deeper than MAXDEPTH; NIST's own
  footnote says so): used as a bar it would sit about 23 bits too low.
- `nist_pqc_check.py` section 10 has a check hard-coded to pass.
- FrodoKEM vs ML-KEM: plain LWE does hedge against attacks on ring/module
  structure; it does not hedge against a general advance in lattice
  reduction, and it is not the non-lattice diversity IR 8545 means.
- Use salted FrodoKEM, never eFrodoKEM, for a key that receives many
  encapsulations (eFrodoKEM is for about 2^8 ciphertexts per key).
- ML-DSA-44 drops from category 2 to 1 with an RBG under 192 bits (FIPS 204
  section 3.6.1).
- Smaller wording issues: the ISO FrodoKEM text is not known to equal the
  2025 public proposal; ANSSI's CatKDF claim assumes IND-CCA components; an
  IR 8545 remark on Classic McEliece reports public comments, not NIST's
  view; "constant term" misdescribes where ML-KEM puts the message bits; the
  reduction needed depends on n, q and sigma jointly, not on q/sigma alone.

## Used since by Turing-1026 (docs/16)

Turing-1026 (commit 574a107) cites
attack-cost-estimation.md, decryption-failures.md,
cca-transforms-and-binding.md, hybrid-combiners.md and the side-channels
notes, none of which were fact-checked. Its two headline numbers were
checked independently in a review on 2026-09-27
(`../../scripts/pq/review_t1026_bounds.py`, written from the published
formulas): primal block size 869 against docs/16's 868, and a proven
Chernoff bound on the failure rate of 2^-260.3 per ciphertext, 5.7 bits
above docs/16's exact 2^-266.06, the same gap as at the other widths. The
qualitative claims it takes from the notes (binding of the transform
ingredients, multi-target security, hybrid advice) remain unreviewed.
