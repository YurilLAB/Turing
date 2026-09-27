# Turing's automated checks

`python tools/ci.py` runs every automated check with a timeout each and
writes a report to `target/ci/<time>/` (a log per stage, `summary.md`,
`summary.json`); it exits 1 if any stage fails or times out. A tool that
is missing counts as a failure, not a skip: a quietly skipped check is a
gap nobody sees.

| Profile | Stages | Time (this machine, warm build) |
|---|---|---|
| `quick` (default) | release, overflow, robustness, math-audit | about 2.5 min |
| `full` | quick + math-audit-negative, mutation-patterns, campaign, linux-wsl | tens of minutes |
| `deep` | full + campaign-deep and every planted-bug set of `tools/mutate.py` | hours |

`--only a,b` picks stages; `--list` lists them; `--commit REF` runs in a
throwaway git worktree of REF, so the result belongs to a known snapshot
and is not disturbed by files that other people are editing. The
planted-bug sets always run in a worktree, because `mutate.py` rewrites
source files while it runs.

## What each stage catches, and the evidence

**release** runs the whole test suite as the docs run it (`cargo test
--release`).

**overflow** runs the same suite without `--release`. The difference
matters: `--release` turns off Rust's integer-overflow checks and every
`debug_assert!`. Checked on 2026-09-27 with the workspace's own profile
settings (`[profile.test] opt-level = 2`): `cargo test` stops on a `u8`
overflow, `cargo test --release` silently returns the wrapped value (44 for
200 + 100). Until this stage, no documented command ran the suite with
overflow checks on. The first run found no overflow; the stage now keeps it
that way.

**robustness** (`crates/bombe/tests/robustness.rs`) checks the inputs that
random tests almost never draw, each against the independent reference
implementations: all-zero, all-one, single-bit and counting keys and
blocks for Turing, Turing-256 and the masked cipher; every round count from
1 to 24, and the out-of-range counts 0, 25 and `usize::MAX` refused; the
plain-LWE core across the whole parameter space `lwe::Params::validate`
accepts (q from 2^4 to 2^16, noise widths 1 to 32, nbar up to 64, a 1 x 1
matrix, fields that straddle three bytes), where the existing test covers
four sets; packing at every width and every length from 0 to 40; every
wrong length of a Turing-1026 key or ciphertext; and structured seeds,
messages and salts for Turing-1026. `TURING_CI_ITERS` scales the random
part (1, 5 or 25 by profile).

Evidence that it adds something: two plausible bugs were planted, in a
worktree, in the noise sampler of `lwe.rs`, a bit buffer narrowed from
`u128` to `u64` and a mask computed in `u32`. Both only break noise widths
of 29 and above, which no existing test uses. The whole existing suite
(the library's unit tests and the Turing, Turing-256 and Turing-1026
integration tests) passed with each bug in place; the robustness suite
failed on both.

**math-audit** (`tools/mathaudit.py`) recomputes documented numbers with
code that shares nothing with the code that produced them:

- `tools/coresvp_exhaustive.py` evaluates the primal and dual attacks of
  Alkim, Ducas, Poppelmann and Schwabe (2016) at every (m, b) pair, never
  with a greedy or early-abort search. It must first reproduce that paper's
  Table 1: BCNS, JarJar and NewHope match to within 3 in block size and 1
  bit (the NTRU row is excluded: NTRU is not plain LWE and the paper models
  it differently). The search is exhaustive because a greedy one can be
  badly wrong: lattice-estimator issue #219 (open since 2026-07-09) shows its
  dual-hybrid search stopping at a local rise and overstating FrodoKEM-976's
  cost by 7.98 bits.
- Every row of docs/16's parameter and comparison tables: noise width,
  sigma^2/q, primal and dual core-SVP, sizes, and each exact
  decryption-failure figure, which must lie below a proven Chernoff bound
  and within 8 bits of it (it lies 5.6 to 6.2 bits below, as a tight bound
  predicts). Plus the sizes in `turing1026.rs` against its parameters, and
  arithmetic stated in docs/14 and docs/15.
- A sensitivity control inside each check: the same computation with a
  plausible mistake (the noise one step narrower) must fall outside the
  tolerance, or the check is reported as too weak to catch it.
- A lint for checks that cannot fail: `check(..., True, ...)` or `assert
  True` in Python helpers, and Rust tests with no assertion (tests
  documented as measurements are allowed). Its first run found two real
  ones, both in the post-quantum research scripts, and both are fixed:
  `research/scripts/pq/nist_pqc_check.py` passed a check that compared
  nothing, and `hyb_factcheck_math.py` counted a printout as a passed check.

What it found in docs/16: nothing wrong. The primal figures agree to 0.2
bit. The dual figures are 0.3 to 0.7 bit above the exhaustive optimum of
the published formulas, because Bombe's port uses a lattice of dimension
n + m where the paper has n + m + 1 (primal) and delta^d where the paper
has delta^(d-1) (dual). Both differences favour the defender slightly;
Turing-1026's dual core-SVP by the paper's exact formulas is 252.0, not
252.4. One convention note, checked in the sources: the paper's text writes
the dual advantage as 4 exp(-2 pi^2 tau^2), while its own script and
pq-crystals' `MLWE_security.py` use exp(-2 pi^2 tau^2), and the published
tables come from the scripts; the audit follows the tables.

**math-audit-negative** plants a wrong claimed value into every comparison
of the audit and requires every one to be flagged: 38 of 38 are.

**mutation-patterns** checks that every planted bug of every set of
`tools/mutate.py` still matches the code it is meant to change (133 bugs
in 8 sets). `mutate.py --check` on its own checks only the default set,
and that hid a real problem: on 2026-09-27, 21 planted bugs in six sets
(among them six of Turing-1026's, such as "rejection key without z" and
"salt left out of the coins", and ten of the memory and masking ones)
could no longer be planted at all. The cause was line endings: this
repository has `core.autocrlf=true`, so files that git writes (a checkout,
a pull, a worktree) get `\r\n`, while the patterns are written with `\n`,
and every multi-line pattern stopped matching. `mutate.py` now matches in
the file's own line ending; after the fix all 133 match, and "rejection
key without z" planted in a fresh worktree is caught by three tests.

**campaign** runs `bombe attack`, which exits 1 when any finding fails. Its
timing tests are sensitive to load: run it on a quiet machine.

**linux-wsl** builds the library for Linux on Windows and runs its tests
inside WSL with `tools/wsl_linux.py`, which exercises the Linux-only code
(mlock, madvise, fork detection).

**campaign-deep** and **mutation-*** are the long runs: the deep campaign,
and every planted-bug set, each in its own worktree.

## Not covered yet, and why

- Coverage-guided fuzzing (cargo-fuzz): its Windows support is "basic" and
  untested here, and it needs `libfuzzer-sys` and `arbitrary` from
  crates.io; adding them is the owner's call. The robustness suite's
  structured and randomised inputs are the dependency-free part of that.
- Miri (undefined behaviour in `unsafe` code) needs the `miri` toolchain
  component, which is not installed; `memory.rs` would also need a
  `cfg(miri)` path, since Miri has no shim for `VirtualLock` or `mlock`.
- Generated-code audits across compilers and targets, and GitHub-hosted
  runs, are being handled separately.
