# 06 — The mixing layers

The S-box scrambles bytes one at a time. The mixing layer spreads each byte
across the block so an attack cannot follow a few bytes through the cipher.
Turing uses a mix of two layers:

| Layer | What it does | Branch number | Rounds to full diffusion |
|---|---|---|---|
| ShiftRows + MixColumns | Row r rotates left by r; each 4-byte column × a 4×4 matrix | 5 per column | 2 |
| MixState | The whole 16-byte state × a 16×16 matrix | 17 | 1 |

ShiftRows + MixColumns is cheap and is the structure behind AES's proof of at
least 25 active S-boxes in any 4 rounds. MixState is expensive (256 field
multiplications) but changes all 16 bytes from any one byte in a single round.
**Which rounds use which layer is decided in step 7**, by computing the
guaranteed number of active S-boxes for each placement.

## Branch number and MDS

For a matrix M and non-zero input x, the branch number is the minimum of
(active bytes in x) + (active bytes in M·x). For an n×n matrix the best
possible is n + 1. A matrix reaching it is called **MDS** (maximum distance
separable), and M is MDS exactly when every square submatrix is invertible.
If a w×w submatrix were singular, some input with w active bytes would map to
an output with w zeros, giving a branch number of at most n.

## Construction: Cauchy matrices

M[i][j] = 1 / (x_i + y_j) over GF(2^8), with all 2n points distinct.

Every square submatrix of a Cauchy matrix is again a Cauchy matrix, and a
Cauchy determinant is a product of non-zero differences, so **every Cauchy
matrix is MDS**. That makes the construction a proof, not a hope. The points
are the first 2n distinct bytes of SHAKE256(label || counter):

- MixColumns: label "Turing v1 MixColumns", counter 0.
- MixState: label "Turing v1 MixState", counter 0.

Both were accepted on the first draw, as the theorem predicts. Reproduce with
`cargo run --release -p bombe -- gen-linear`.

## Independent verification

Bombe does not rely on the theorem alone:

| Check | MixColumns (4×4) | MixState (16×16) |
|---|---|---|
| Cauchy structure over published points | yes | yes |
| Every square submatrix invertible | all sizes, exhaustive | sizes 1–3 and 13–16 exhaustive; 4–12 sampled (400,000 each) |
| Branch number measured directly | 1–2 active bytes exhaustive, 3 sampled: 5 | 1 active byte exhaustive, 2–3 sampled: 17 |
| M × M⁻¹ = I | yes | yes |

The same checks run on AES MixColumns (published MDS, branch 5) as a positive
control, and must reject: AES's matrix with one entry changed (caught by both
the submatrix scan and the branch measurement), the all-ones matrix, a 16×16
matrix with one planted singular 2×2 block, and a Cauchy check with a
repeated point.

The cipher's ShiftRows and MixColumns reproduce the FIPS-197 Appendix B
round-1 vectors when run with the AES matrix, confirming the byte layout
(column-major, byte 4c + r) and shift direction.

## Constant time

All mixing is done with the branch-free field multiply from step 4 in
fixed-length loops. Bombe's fast table-based multiply is used only for
analysis, and a test confirms both produce the same results.
