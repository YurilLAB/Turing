# Turing's automated checks

`python tools/ci.py` runs every automated check with a timeout each and
writes a report to `target/ci/<time>/` (a log per stage, `summary.md`,
`summary.json`); it exits 1 if any stage fails or times out. A tool that
is missing counts as a failure, not a skip: a quietly skipped check is a
gap nobody sees.

| Profile | Stages | Time (this machine, warm build) |
|---|---|---|
| `quick` (default) | release, overflow, production, robustness, math-audit, constant-time, ct-self-test, turing256-py, noise, simulate | about 5 min |
| `full` | quick + math-audit-negative, noise-negative, simulate-negative, mlkem-million, mutation-patterns, campaign, linux-wsl | tens of minutes |
| `deep` | full + campaign-deep, an hour's soak and every planted-bug set of `tools/mutate.py` | hours |

Two stages of every run use the whole machine: **simulate** samples on the
GPU (an AMD RX 9060 XT here, through PyTorch with ROCm) and **noise**
encrypts on every CPU thread. Both add their samples to accumulated
evidence in `research/workfiles/sim/` (local, not in git), so every run
strengthens the long-run check; the evidence restarts by itself when the
code that produces it changes. `tools/ci.py` runs simulate with the Python
named by `TURING_GPU_PYTHON`, else by `"gpu_python"` in
`tools/ci-local.json` (this machine's settings, not in git), else its own;
without a GPU, simulate samples on the CPU with NumPy.

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

**production** runs the library's own tests with `-p turing` alone. A
workspace build also compiles Bombe, which turns on the library's
`analysis` feature, and the optimiser inlines that build differently: the
review of 2026-09-28 found Turing-1026's seed left in dead stack only in the
build users get (R1), because there `pair_consistent` was inlined into
`from_seed`, above the stack burn. The residue tests (`no_sponge_state_is_
left_on_the_stack`, `checked_calls_leave_no_checksum_point_behind`, ML-KEM's
`entry_points_leave_no_secret_on_the_stack`) run here in that configuration;
each has a planted-copy control, and each fails on the unfixed code. The
review found those three leftovers one operation at a time, so the residue
sweep (`every_public_operation_leaves_no_secret_on_the_stack`,
`crates/turing/src/residue_sweep.rs`) now runs every public operation that
handles a secret (30 of them: key setup and the checked calls of all three
ciphers, the shielded key, `new_key`, Turing-1026 and ML-KEM end to end)
and searches the stack each leaves for its keys, seeds, checksum points,
shared keys and sponge states. Bombe's memory scans cover several of these
operations, but only in the analysis build, since Bombe turns the feature
on; the sweep also runs here, in the build where R1 showed. Removing the
stack burn from `Turing::new`, `new_key`, `ShieldedKey::refresh`,
Turing-1026 encapsulation or ML-KEM decapsulation fails it (`mutate.py
--review3`).

**constant-time** (`tools/ct_check.py`) reads the release build's machine
code. No division in the lattice code (the KyberSlash class): `lwe` and
`turing1026` in the production build, `mlkem` in the analysis build, the
only one that compiles it until the hybrid calls it; a module with no
function in the build it is read in fails the check (review of 2026-09-28,
R7: ML-KEM was listed but never read, and a division planted in Compress
passed; now it fails in two functions). And Turing-1026 decapsulation keeps
its verdicts apart: three masks derived separately, `select_into` called
twice and `bind_to_verdict` once, both real functions. The release build had
fused the two selections into one mask, a single-fault bypass (R2); run on
that build, the check reports all three failed. The same rule covers every
redundant computation the fault defences rely on, since each is one the
optimiser could merge: two re-encryptions, the rejection key computed twice
and `infect` called, three decryption passes each computing C - B'S and
drawing its own order, and the vote; and the checked calls of all three
ciphers keep their two key checks per direction. Inlining a decryption
pass, the rejection key or the infection fails it (`mutate.py --review3`).

**ct-self-test** (`ct_check.py --self-test`) runs the checker on synthetic
assembly, a correct file and one broken file per rule (12 of them: fused
selections, one verdict mask, the rejection key computed once, no
infection, two decryption passes, no vote, one order for all passes, one
C - B'S for all passes, a checked call's second key check merged away, a
division, a decryption pass inlined, and the lattice module missing from
the build as in R7). Each broken file must fail and the correct one must
pass, so a rule that can no longer fail is caught without building
anything. Weakening the count rule, or the division pattern to signed
divisions only, fails it. The rules were also run on Linux-target
assembly, which GitHub's audit job reads: Linux's position-independent
code calls a `pub` function through the GOT (`callq *sym@GOTPCREL(%rip)`),
which the first version of the call pattern missed, failing seven rules
there while all passed on Windows. The pattern takes both forms now, and
one synthetic file makes its call the Linux way.

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

**turing256-py** (`research/scripts/turing256_py.py`, under a second)
reproduces all 89 values of `vectors/turing-256-v2.txt` with a Python
implementation that shares no code or constant with the two Rust ones: its
own Keccak (checked against hashlib and NIST's cSHAKE256 sample), and the
S-box, both matrices and the round constants derived from their labels.
Three planted mistakes in it (ShiftRows rotating right, one warm-up round
fewer, no round constants) must each fail first; a hand-edited byte of the
vector file fails it too (checked).

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
- docs/16's count and list of Turing-1026's cSHAKE labels against the
  labels the code defines (R13 found "nine" where the code had ten; the
  decoder fix added an eleventh). The negative control plants a wrong count.
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
of the audit and requires every one to be flagged: 41 of 41 are.

**noise** (`bombe noise`, `crates/bombe/src/noise1026.rs`) measures the
decryption error of real Turing-1026 ciphertexts at the real parameters.
docs/16's failure rate rests on the law of that error, X = S'E - E'S + E'',
computed exactly by convolution (`dfr.rs`). The existing Monte Carlo check
runs the real code only at n = 64, because at n = 1026 a failure is a
2^-274 event and will never be seen. The error itself can be seen: every
coefficient of C - B'S - Encode(m) is one sample of the real code's X. Each
run makes 400 keys with 4 ciphertexts each (409,600 samples, about 3 s on
12 threads) and compares them with the exact law at 25 points of its
distribution function (from -6 to +6 standard deviations), its mean (0 by
symmetry: the most sensitive test of a shift) and its second moment
(166,221). Coefficients of one key share S and E, so standard errors come
from the spread of per-key averages over keys, as in `dfr::monte_carlo`; a
statistic is judged once it has 200 keys and, for a probability, 200
expected events, and the critical value is Bonferroni-corrected for a
nominal false alarm rate of 1e-6 per run. The same samples must reject two
wrong laws (CBD(17) noise; 1026 products instead of 2052), and the real
decryption must get a bit right exactly when its measured error lies in
[-q/4, q/4).

Results on 2026-09-27: a three-minute run of 30,000 keys (30.7 million
samples) agrees with docs/16's law at all 19 statistics it could judge
(largest |z| 1.09 against a critical 5.44); its mean is 0.017 +- 0.074 and
its second moment 166,247 +- 43. The wrong laws are rejected at 418 and
1,931 standard errors. There were no decryption failures and no
decryptions that disagreed with their measured error. An earlier, smaller
run had shown P(X < 0) at z = -2.8, which is within chance for 18
correlated statistics. The mean statistic was added to settle it directly,
and the larger run found no shift. This is why the evidence is allowed to
accumulate.

Evidence that it catches what other tests cannot: a spec-level change was
planted in a worktree. Drawing E' one step narrower in `lwe.rs` would be
shared by the reference implementation, and the known-answer vectors would
simply be regenerated for it, but it makes docs/16's figure wrong. It moves
the error's variance by only 2.8%, and the 3-second run failed on it at
12.3 standard errors.

**simulate** (`tools/simulate.py`) checks docs/16's law itself on the GPU.
Three methods share no code:

- `dfr.rs`'s numbers, printed by `bombe dfr-tail`, against an independent
  FFT convolution. They must agree within the FFT's measured rounding error,
  and they do, to between 7e-12 and 2e-5 relative. The FFT is itself
  checked against direct convolution, to 1.2e-16.
- Both against X sampled exactly, from table lookups of random bits with no
  floating point: 2.7e8 samples of a small law (2n = 128, CBD(2)) and
  1.7e7 of Turing-1026's own (2n = 2052, CBD(18)) per run, in about 45 s.
  The counts beyond 15 thresholds, from 2^-8 down to 2^-36, are compared by
  an exact Poisson test at 1e-6 per threshold.
- The same samples against wrong laws, which they must reject wherever the
  sample is large enough that rejection is certain. Every run also first
  tests the sampler: the full histogram of 4.2 million draws must fit the
  exact law (chi-square) and must reject the law with the wrong noise.

Counts accumulate in `research/workfiles/sim/failures-state.json` per
version of the sampler, so the deep thresholds fill in over time. Over n
looks at the accumulated counts, the chance of a false alarm is at most
n x 1e-6 per threshold. `--status` judges the evidence so far. Without a
GPU the same tool samples with NumPy for 15 s per law, which reaches about
2^-15; that is what GitHub's runners do.

Evidence: with the round-7 bug planted in `dfr.rs` (n products instead of
2n), the FFT check fails at all 15 thresholds. The samples reject the
buggy law at all 11 thresholds where any event was seen; at t = 1200, for
example, 54,931 events fell where the buggy law predicts 561.

**noise-negative** and **simulate-negative** are the two checks' negative
controls, and they run on data that is wrong by construction. noise
encrypts with CBD(17) noise, and docs/16's law must reject it (it does, at
about 55 standard errors, and the CBD(17) law then fits). simulate samples
CBD(eta - 1) in place of each law, and dfr.rs's law must be rejected
wherever that is certain (at 7 thresholds per run).

**mlkem-million** runs CCTV's accumulated ML-KEM test at its published
1,000,000-case size for all three parameter sets. That is three million
key generations, encapsulations and pairs of decapsulations, spread over
every thread, and it takes 2.5 minutes here. The parallel runner absorbs
each case's outputs in order, and it must first reproduce the sequential
10,000-case hashes, so a scheduling mistake cannot pass. All three
1,000,000-case hashes match CCTV's.

**mutation-patterns** checks that every planted bug of every set of
`tools/mutate.py` still matches the code it is meant to change (202 bugs
in 12 sets; `--review2` holds the 17 of the 2026-09-28 review's fixes,
three of them checked by `ct_check.py` instead of a test, and `--review3`
the 28 of the decoder and rejection-key fixes and of the detectors added
with them). `mutate.py --check` on its own checks only the default set,
and that hid a real problem: on 2026-09-27, 21 planted bugs in six sets
(among them six of Turing-1026's, such as "rejection key without z" and
"salt left out of the coins", and ten of the memory and masking ones)
could no longer be planted at all. The cause was line endings: this
repository has `core.autocrlf=true`, so files that git writes (a checkout,
a pull, a worktree) get `\r\n`, while the patterns are written with `\n`,
and every multi-line pattern stopped matching. `mutate.py` now matches in
the file's own line ending; after the fix all 133 match, and "rejection
key without z" planted in a fresh worktree is caught by three tests. A
name filter (`mutate.py --review3 NAME`) that matches no planted bug is an
error: it used to print "all mutations caught" having run nothing, which
hid a pattern that a mangled edit had never added.

**campaign** runs `bombe attack`, which exits 1 when any finding fails. Its
timing tests are sensitive to load: run it on a quiet machine. Its fault
map of Turing-1026 decapsulation (`crates/bombe/src/fault1026.rs`) injects
every fault of docs/16's model into the real decapsulation code, and each
countermeasure has a negative control that runs the code as it was before:
skipping z in the one rejection hash is a validity oracle, and in the real
code takes two faults; skipping one rounding, or faulting one pass's
arithmetic, leaks exactly the negative-noise coefficients in the one-pass
decoder, and changes none of 768 in the real one; with the vote skipped,
the random orders alone hide the coefficient. Its measured boundary, two
faults aimed at one coefficient's arithmetic in two passes, is asserted
too, so a change to it cannot pass unnoticed.

**linux-wsl** builds the library for Linux on Windows and runs its tests
inside WSL with `tools/wsl_linux.py`, which exercises the Linux-only code
(mlock, madvise, fork detection).

**campaign-deep** and **mutation-*** are the long runs: the deep campaign,
and every planted-bug set, each in its own worktree.

**soak** (`tools/soak.py --minutes 60`) runs simulate and noise side by
side for an hour: the GPU samples while every CPU thread encrypts. Both
save their evidence as they go, so stopping early keeps what was measured.
Run it on its own whenever the machine is idle:

    python tools/soak.py --minutes 60
    python tools/simulate.py --status

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
- docs/16's far tail. The per-coefficient failure probability is 2^-274,
  and no sampling reaches it. simulate shows that the exact computation is
  right down to 2^-36, including on the very law that gives the 2^-274. The
  far tail itself rests on the convolution, on its FrodoKEM
  reproduction, on the Chernoff bracket in math-audit, and on the
  independent FFT.
