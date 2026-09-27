# Fact-check audit (lens: mathematics and reasoning): lattice-foundations.md

Independent check of `research/notes/pq/lattice-foundations.md` (82 978 bytes, 385 lines,
mtime 2026-09-27 07:14). Lens: derivations, formulas, worked examples, the author's scripts,
security arguments and conclusions. Started 2026-09-27. This file is the audit trail
kept up to date as the check went. My own script:
`research/scripts/pq/check_lattice-foundations_reasoning.py`.

A sibling check with the "sources" lens is in `lattice-foundations.sources.md`; I do not repeat
its pure quote checks unless the reasoning depends on them.

## Method

1. Read the notes end to end; list every derivation, formula, worked example, computed number,
   security argument and conclusion.
2. Recompute each number with my own script (independent code), with a negative control.
3. Run the author's scripts (toy_lwe.py, lattice_basics.py, lf_*.py) with a timeout, read them,
   and check that their output supports what the notes say.
4. Go to the primary PDFs for any number a conclusion rests on.
5. Hunt for overclaims and confusions: reductions read as concrete guarantees, rank x degree vs
   dimension, classical vs quantum, core-SVP vs gates, per-ciphertext vs per-key failure.

## Row-by-row check record

| # | claim checked | OK / WRONG / UNVERIFIABLE | evidence |
|---|---|---|---|
| (filled in as checked) | | | |

## Issues found

(filled in as discovered)

## Confirmed highlights

(filled in as discovered)

## Status

IN PROGRESS
