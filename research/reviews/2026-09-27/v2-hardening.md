# Review: Turing v2 library hardening (2071a07, a6e746b, f20543b, 5597cd4)

Reviewer: independent reviewer, 2026-09-27. Read-only on the repository; this file is the
only thing written into it.

Scope: crates/turing/src/{memory,shield,masked,random,gf,cipher,keyschedule}.rs at HEAD
(4c8f826; since 5597cd4 only keyschedule.rs gained `RoundKeys::sealed`, lines 168-179, for
Turing-256, and memory.rs the `u16` impl; all line numbers below are HEAD's),
docs/13-version-2-and-hardening.md, research/notes/derivations.md, README.md
(as of 5597cd4 and as now), and the Bombe code the claims rest on (residue.rs, memscan.rs,
fault.rs, toctou.rs, tests/memory.rs).

Evidence is kept locally (gitignored) in
`research/workfiles/review-v2/`:
`gf_checks.py`, `compare_mul.py`, `gf8_example.py`, `quotes.py`, `mutants.py`,
`probe/` (a crate depending on the repository's turing + bombe, analysis feature),
`ws/` (a scratch copy of the workspace for mutants; verified byte-identical to the committed
files before use) and `probe_ws/` (a crate on that copy, which adds two analysis-only accessors).
Every cargo build used `CARGO_TARGET_DIR=D:/Dev/Turing/target/review`, release profile,
rustc 1.95.0 x86_64-pc-windows-gnu.

## Summary

| # | Severity | Kind | Where | One line |
|---|---|---|---|---|
| F1 | major | wrong maths / unsupported claim (+ missing check) | keyschedule.rs:95-98, 152-155; masked.rs:296-300; docs/13:322-325 | A reset fault zeroing the stored checksum and its point makes `intact()` pass for any keys; with RK_24 in the same line the checked call releases C' with C xor C' = RK_24 |
| F6 | major | bug + missing test | shield.rs:32-36, 46-57; residue.rs:61-81 | `ShieldedKey::new` leaves the whole 32-byte shielding mask in dead stack (mask xor shielded = key); Bombe never searches for it |
| F3 | minor | missing test | keyschedule.rs:154, masked.rs:299, cipher.rs:35, masked.rs:374, memory.rs:184 | Partial comparisons in the integrity and decrypt-and-compare checks, and a Windows "locked" flag that is never checked against the OS, survive the tests |
| F7 | minor | unsupported claim | random.rs:27-30, 166-170; docs/13:231-240 | Process-ID fork detection fails under PID reuse where MADV_WIPEONFORK is absent; "fork-safe on every platform" is too strong |
| F8 | minor | unsound unsafe (latent contract gap) | memory.rs:29-38, 139 | `Zeroable`'s contract allows padding, but `Drop` reads every byte of T as `&[u8]` |
| F9 | minor | unsupported claim | masked.rs:1-3, 16-20, 262-274; docs/13:219-221, 414-419 | Masked key setup is unmasked (plain round keys, plain checksum); "every value it handles is independent of the key" / "the key never sits in memory as itself" overstate |
| F2 | minor | unsupported claim (not reproducible) | docs/13:327-331; derivations.md:168-173 | The GF(2^8) brute-force check is not in the repository; its "no fault passed at more than 3" is sample luck, the bound 4 is attained |
| F4 | documentation | unsupported claim | docs/13:164-194; verified-facts.md:43 | ProcessPrng table has no code behind it; small requests leave the *last* 16 bytes, not a 16-byte-aligned block |
| F5 | documentation | stale claim | docs/13:124-131; docs/08:200; bombe tests/memory.rs; keyschedule.rs:266-267 | Without the burn the release build now leaves round keys 0-23 in dead stack (30 fragments survive even the drop), not "two pieces of K'" |
| F10 | documentation | inconsistency | docs/08:185 | "Four problems" above a five-row table |
| F11 | documentation | stale comment | bombe fault.rs:7, 104 | "round 15" / "round key 16" (v1) while the code uses rounds 23/24 |
| F12 | documentation | sourcing | docs/13:290-291, 511; shield.rs:6-8 | "with high accuracy" is from OpenSSH commit 4f7a56d5, not from the cited 8.1 release notes |

## Findings

### F1 — major — wrong maths / unsupported claim (+ missing check): a reset fault on the checksum and its point disables the integrity check

Where: keyschedule.rs:95-98 (`checksum`), 152-155 (`intact`), 113-117 (`KeyMaterial`);
masked.rs:65-69 (`Shares`), 296-300 (`intact`); docs/13 lines 322-325; derivations.md 161-162;
keyschedule.rs:86-89; docs/08:189.

Claim (docs/13): "a fault arranged without knowing the key escapes with probability at most
25/2^127 ≈ 2^-122.4, however many bits it flips and wherever they are, H included."

The proof models a fault as a key-independent XOR difference (E_i, e, d). A reset (stuck-at-0)
fault is arranged without the key too, but its XOR difference equals the stored value, so the
proof does not apply. Concretely:

```rust
// keyschedule.rs:95-98
pub(crate) fn checksum(keys: &[Block], point: &Block) -> Block {
    let h = u128::from_le_bytes(*point);
    keys.iter().rev().fold(0u128, |acc, k| gf::mul128(acc ^ u128::from_le_bytes(*k), h)).to_le_bytes()
}
// keyschedule.rs:152-155
pub(crate) fn intact(&self) -> bool {
    let now = checksum(&self.material.keys, &self.material.point);
    now.iter().zip(&self.material.check).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}
```
At point 0 the checksum is 0 for every key set, and `intact()` never re-checks that the point
is still odd (the `|= 1` exists only at creation, keyschedule.rs:109 and 176). Zeroing `check`
and `point` therefore makes every later round-key fault invisible. The masked cipher is the same:
point 0 and both check shares 0 give a = b = 0 at masked.rs:297-299.

Layout, read from the page (probe `layout`): RK_0 at page offset 0, RK_24 at 384, the stored
checksum at 400, the point at 416, i.e. RK_24, checksum and point share the 64-byte line 384-447.

Reproduced (probe `reset`; faults applied with the analysis build's `flip_stored_bit`, flipping
exactly the bits that are 1, which is what a reset does):
```
control: point zeroed only -> checked call = Err(FaultDetected)
point and checksum zeroed, keys intact -> Ok(()), ciphertext correct: true
RK24, checksum and point zeroed -> Ok(())
released ciphertext XOR correct ciphertext == RK24: true
reset + 5 round-key bit flips -> Ok(()), released wrong ciphertext: true
   decrypt_block_checked on it -> Ok(())
```
With RK_24 zeroed too, the checked call releases C' = S(x) (round 24 has no linear layer), so
C xor C' is the whole last round key, from one output of the call built to prevent last-round DFA
(docs/11, docs/13:354-357).

The 25/2^127 bound is right for additive faults whose pattern does not depend on stored data,
and the text should say that is the model. How practical the reset is depends on the attacker:
Rowhammer flips are data-dependent too (true cells only go 1 → 0), but clearing all ~128 set bits
of 32 bytes is far beyond it; stuck-at / bit-reset faults on a memory region (laser or EM on
SRAM or cache, a skipped or misdirected store) are the model where this bites. The severity is
for the categorical claim, the cheap fix and the size of the payoff. `RoundKeys::sealed`
(Turing-256) uses the same `checksum`/`intact` and inherits the gap. Cheap fixes: `intact()` also requires
`point[0] & 1 == 1` (constant-time), and the checksum gets a non-zero public constant term
(e.g. store and compare `C xor 1`; for the masked cipher in one share), so all-zero material
never verifies. Add a test that zeroes check+point (and check+point+keys) and expects
`FaultDetected`.

### F6 — major — bug + missing test: `ShieldedKey::new` leaves the 32-byte shielding mask in dead stack; mask xor shielded = key

Where: shield.rs:32-36 (`fn mask(..) -> [u8; 32]` returns by value), 46-57 (`new`);
residue.rs:61-81 (needles); docs/13 table row "`ShieldedKey::new` with the caller's copy wiped;
a cipher made from it; after refresh | nothing"; README "no key material left behind".

`mask()` is inlined into `new`; its local `out` (rsp+0x70..0x8f) receives the cSHAKE256 output
and is then moved by value into `m` (rsp+0x30..0x4f). `m.zeroize()` wipes only the copy at
rsp+0x30, and `burn_stack()`, called from inside `new`, only reaches frames below `new`, so the
original at rsp+0x70 stays in `new`'s dead frame. Release disassembly of
`turing::shield::ShieldedKey::new` (objdump, probe binary built from the repository crate):
```
14010ba19: movaps %xmm0,0x80(%rsp)        ; out = [0; 32]
14010ba21: movaps %xmm0,0x70(%rsp)
14010ba26: lea    0x70(%rsp),%rax
14010ba4e: call   turing::xof::cshake256_secret   ; mask -> rsp+0x70
14010ba53: movaps 0x70(%rsp),%xmm0         ; move into m ...
14010ba58: movaps 0x80(%rsp),%xmm1
14010ba60: movaps %xmm1,0x40(%rsp)
14010ba65: movaps %xmm0,0x30(%rsp)         ; ... m = rsp+0x30, wiped byte by byte at 14010bc8e-14010bdbf
14010bdc9: call   turing::memory::burn_stack      ; rsp+0x70 is never wiped
```
Reproduced by scanning (probe_ws `shield`: the scratch copy adds only an analysis accessor
`ShieldedKey::analysis_mask`; the disassembly of `ShieldedKey::new`, 300 lines, is identical
modulo addresses to the build from the repository crate; the needle is built in a helper thread
whose stack is gone before the scan):
```
after ShieldedKey::new: mask fragments found 4 (4 on the worker's stack)    3 of 3 runs
after cipher(): 0 | after encrypt + drop of the cipher: 0 | after refresh(): 0 | after masked(): 0
```
So straight after construction the whole mask sits in the setup thread's dead stack until later
calls happen to overwrite it (here the next `cipher()` did; a thread that goes on to wait or run
shallow code keeps it), while the shielded key sits in its locked page. A process-memory
reader gets the key; a RAMBleed-style reader needs 512 bits instead of the 131,328 the shield is
meant to force. Bombe misses it because its needles are the key, K', Feistel states and round
keys only (residue.rs:63-79). Mutant M7 (`with_key` keeps `m` and skips the burn) also SURVIVED
`shielded_key_is_nowhere_in_memory`.

Fix: `mask` writes into a caller buffer (or a `SecretBox`) and/or is `#[inline(never)]` so its
frame lies below the burn; add the current mask as a needle in `residue::shielded` (it needs an
analysis accessor). The same by-value pattern is worth checking in `refresh` and `with_key`,
which were clean in this build.

Checked with the same method and clean: `MaskedTuring::new` leaves no construction-time share,
share pair or round key outside its page (3 of 3 runs, probe_ws `masked`), and neither do its
checked calls, which run `checksum` over each share twice (the shares current after the call,
3 of 3 runs, probe_ws `maskedchecked`); the M6 mutant (no burn in `MaskedTuring::new`) is caught
by `masked_cipher_holds_no_round_key`.

### F3 — minor — missing test: partial comparisons and an unverified Windows lock survive the tests

Mutants on the scratch copy (`mutants.py`), `cargo test -p turing --lib` (the command
`tools/mutate.py --round4` uses for these files; 92 tests pass on each mutant):

| Mutant | turing --lib | Bombe release tests |
|---|---|---|
| M1 `RoundKeys::intact` compares 8 of 16 bytes (keyschedule.rs:154, `.take(8)`) | SURVIVED | of the three Bombe test files run (classic_attacks, toctou, turing256), only turing256's `stored_key_faults_are_caught` catches it: a later Turing-256 test whose 200 random stored-bit flips happen to hit the upper checksum half |
| M2 `MaskedTuring::intact` compares 8 bytes (masked.rs:299) | SURVIVED | toctou SURVIVED |
| M3 decrypt-and-compare ignores byte 15 (cipher.rs:35, `.take(15)`) | SURVIVED | classic_attacks + toctou SURVIVED |
| M4 masked decrypt-and-compare ignores byte 15 (masked.rs:374) | SURVIVED | not run |
| M5 Windows: `let locked = true;` instead of calling VirtualLock (memory.rs:184) | SURVIVED | nothing checks the OS's lock state |
| M8 first key check removed from `Turing::guarded` | SURVIVED | (near-equivalent: the second check catches persistent faults) |

Why: every fault test flips a round-key or point bit (which moves all 16 checksum bytes) or
injects faults at the end of the forward / start of the backward computation (which diffuse to
all 16 bytes after the other direction). None flips a bit in the upper half of the stored
checksum alone, and none faults the input copy or the first round-key XOR of the forward
computation (there a one-byte change survives decrypt-and-compare as a one-byte difference:
with M3 the encryption of a different plaintext is released). On Windows,
`small_secrets_are_locked_on_windows` only reads the flag the code set itself.

Missing tests: each of the 128 single-bit faults in the stored checksum through `intact()` (per
share for the masked cipher); a fault on the input side of the forward computation for both
checked calls; on Windows, QueryWorkingSetEx's `Locked` bit for a box that reports `locked()`.

### F7 — minor — unsupported claim: process-ID fork detection fails under PID reuse

random.rs:27-30 says "every public draw (`fill`, `u64`, `block`) runs it first, so a stream used
directly is fork-safe on every platform, whatever the kernel said to MADV_WIPEONFORK"; docs/13
lines 231-240 likewise. The check is
```rust
// random.rs:166-170
if self.state.seeded == 0 || self.state.pid != u64::from(std::process::id()) {
    self.reseed().expect(...);
}
```
Where the state is not wiped on fork (macOS, BSDs, old Linux), a process A seeds the stream,
forks B, B never draws, A exits, B forks C, and C receives A's recycled PID: C's check passes
without reseeding and C draws exactly the masks A drew after the fork. A process-ID comparison
cannot tell C from A; wipe-on-fork memory (MADV_WIPEONFORK, BSD `minherit(INHERIT_ZERO)`) or a
fork generation counter bumped by `pthread_atfork` can. Verified by reading; not reproduced
(needs a Unix without MADV_WIPEONFORK). On
Linux with MADV_WIPEONFORK granted it cannot happen (B's and C's copies are zero). Suggest
saying "fork-safe unless a descendant reuses the seeding process's ID", or adding a
`pthread_atfork` generation counter / `minherit(INHERIT_ZERO)` on the BSDs.

### F8 — minor — unsound unsafe (latent): `Zeroable`'s contract does not forbid padding

memory.rs:29-34: "Plain data for which all-zero bytes are a valid value, so fresh zeroed pages
can hold it, and which contains no pointers. # Safety Implement only for such types." But
`Drop` (memory.rs:139) does
`core::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), core::mem::size_of::<T>())` and
reads it in the `debug_assert`. For a type with padding those bytes are uninitialised after typed
writes, and making/reading a `&[u8]` over them is undefined behaviour. The contract also does
not require that `Zeroize::zeroize` writes every byte, which release builds rely on silently.
No current implementation has padding (u8/u16/u64 and arrays; `KeyMaterial` and `Shares` are
byte arrays; `StreamState` is 200 + 136 + 3x8 = 360 bytes, a multiple of its alignment 8, with no
possible gap in any field order), so there is no UB today, but the trait is `pub unsafe` and a
downstream implementor following its text could hit it. Add "no padding bytes and no interior
mutability; `zeroize` sets every byte to 0" to the safety section (as bytemuck's `NoUninit`).

### F9 — minor — unsupported claim: masked key setup is unmasked

masked.rs:1-3 ("Every secret value inside the cipher is split into two shares"), 16-17 ("so the
key never sits in memory as itself"); docs/13:219-221 (same) and 414-419 ("The masked cipher
answers [Hertzbleed] at first order: every value it handles is independent of the key, so its
average power is too"). `MaskedTuring::with_stream` runs the plain key schedule and holds the
plain round keys in a `SecretBox` while it builds the shares:
```rust
// masked.rs:262, 267, 271
let plain = keyschedule::expand::<ROUND_KEYS>(key);
shares.keys[1][round] = xor(plain.key(round), &mask);
let mut sum = checksum(plain.keys(), &shares.point);
```
So K', the Feistel states, every round key and the checksum are handled unmasked in `new`, and
`ShieldedKey::masked()` (shield.rs:76-78) repeats that for the same key on every call. The
leakage tests cover encryption only. Say that the masking covers encryption and decryption, and
that key setup is unmasked (and repeated by `ShieldedKey::masked`).

### F2 — minor — unsupported claim (not reproducible): the GF(2^8) brute-force check is not in the repository

docs/13 lines 327-331, derivations.md 168-173 and commit f20543b cite a brute-force check in
GF(2^8) with four round keys. No script, test or tool in the tree implements it (tools/,
research/scripts/, crates/; research/workfiles is gitignored and has none). My version
(`gf_checks.py`, `gf8_example.py`) confirms the substance: with d != 0 exactly one RK_0 of 256
passes, at every one of the 256 points; with d = 0 at most 4 odd points. But the bound 4 is
attained: 49 of 20,000 random faults pass at 4 of the 128 odd points (0.245 %), e.g.
E = (0x80, 0xbd, 0xbb, 0x55), e = 0x39, roots 0x11, 0x79, 0x87, 0xbf. "No fault passed at more
than 3" is a property of that sample (P(no 4 among 150 faults) ≈ 0.69), not of the check. Commit
the script, and say "at most 4 (attained)".

### F4 — documentation — ProcessPrng residue: table not reproducible; small requests leave the last 16 bytes

docs/13 lines 164-194; verified-facts.md line 43 attributes the table to
`residue::generator_copies`, which only draws 32-byte keys (residue.rs:161-179); nothing
committed measures the other request sizes. Re-measured (probe `prng`: 10 runs per size;
`prng1`: needles at every byte offset, so the exact extent is seen):

| Request | Runs with a copy | Bytes left (exact) |
|---|---|---|
| 8 / 16 | 2 of 10 / 2 of 10 | all 8 / all 16 |
| 24 | 3-4 of 10 | 8-23 (once 16-23) |
| 40 / 48 | 5 of 10 / 4 of 10 | 24-39 / 32-47 |
| 64 | 5-6 of 10 | 48-63 (once 56-63) |
| 100 | 8 of 10 | 84-99 (straddles the 16-byte boundary at 96) |
| 128 | 7-9 of 10 | 112-127 |
| 136 / 200 | 8-9 of 10 / 10 of 10 | 128-135 / 192-199 |
| 256, 1024, 4096 | 6-10 of 10 | the last 16 |

The conclusion that matters holds: never more than 16 bytes, so a 64-byte seed keeps at least
384 unknown bits (random.rs:10-17). The details differ from the table: 24-byte requests do leave
copies (table: 0 of 6, nothing), 16-byte requests both halves (table: the last 8), and below 128
bytes (Ferguson's buffered path) the copy is the *last 16 bytes of the output*, not the last
16-byte-aligned block; only at 128 bytes and above is it the final (partial) block, as the text
says. Commit the per-size measurement.

### F5 — documentation — the no-burn residue is stale; keys are not "written only into their own locked pages"

docs/13 lines 124-131, docs/08:200 and the comment above `key_schedule_without_the_stack_burn`
in crates/bombe/tests/memory.rs say the release build without the burn leaves "two 8-byte pieces
of K'". At HEAD (release, Windows) that test reports 47 stray fragments straight after
`Turing::new_without_stack_burn`: round keys 0-23 (both halves of each but RK_21), no K'; 30
of them (RK_8-RK_23) are still there after the later encryptions and checked calls, and still
there after the cipher is dropped (the scratch copy's `noburn.txt`). keyschedule.rs:266-267 says
"the keys are written only into their own locked pages"; the build writes a copy of 24 round keys
to the stack, and the burn is what removes it (with it every scan is clean: my probe `calls`
scans after `new`, each checked call, each plain call and drop, 3 runs, nothing stray). The
burn therefore protects every round key, not only K', and a caller of the public
`keyschedule::expand` gets no burn.

### F10 — documentation — docs/08 line 185 says "Four problems" above a five-row table (row 5, the proof gap, was not a reproduced problem).

### F11 — documentation — crates/bombe/src/fault.rs:7 ("a byte fault just before the S-box layer of round 15") and :104 ("Recovers round key 16 ... from byte faults in round 15") describe version 1; the code faults round `ROUNDS - 1` = 23 and recovers `round_key(ROUNDS)` = RK_24.

### F12 — documentation — docs/13:290-291 and shield.rs:6-8 quote "with high accuracy" "as OpenSSH puts it"; the cited source (docs/13:511, the 8.1 release notes, local copy in research/papers) does not contain it. It is from OpenSSH commit 4f7a56d5e02e3d04ab69eac1213817a7536d0562 (djm, 2019-06-21): "Attackers must recover the entire prekey with high accuracy before they can attempt to decrypt the shielded private key" (found with `gh search commits`). Cite the commit.

## Checked and correct

GF(2^128) and the checksum
- x^128 + x^7 + x^2 + x + 1 is irreducible (sympy) and x is primitive (order 2^128 - 1).
- `gf::mul128` equals an independent Python product (carry-less multiply + long division) on
  56,660 pairs: all 34x34 edge pairs (0, 1, x^121..x^127, all-ones, 0x87, holes patterns
  0x1111../0x8888.., halves, x^127+1), single-bit pairs, 50,000 random/sparse/dense pairs: 0
  mismatches (`compare_mul.py`). The ctmul64 argument in gf.rs:232-237 (≤ 15 terms per
  position, 16 only at bits 60-63 whose carry leaves the word), the bit-reversal high half and
  the two-step reduction (`over` has ≤ 7 bits) are right.
- Release machine code: `clmul64` and `mul128` have no conditional jump and no call;
  `checksum` jumps only on the empty-slice test and its loop counter; both `RoundKeys::intact`
  instances only on the loop counter (final compare by `pcmpeqb`), as docs/13 §6 says.
- `checksum` computes Σ H^(i+1)·RK_i (Horner over the reversed keys).
- Counts: 35,800 round-key pairs and 2,900 key/checksum pairs cancel in Σ x^i·RK_i (enumerated;
  the order of x is 2^128-1 and no divisor of 2^128-1 lies in 129..151, so no other two-bit
  coincidence exists); Σ_{d=1}^{24}(25-d)(128-d) = 35,800; Σ(128-i) = 2,900; C(3200,2) =
  5,118,400; C(3328,2) = 5,536,128; 0.699 %; 434,240 point faults (128 + 434,112 pairs, matching
  the unit test's count); log2(25/2^127) = -122.36.
- The proof for additive faults: d = 0 gives a non-zero polynomial of degree ≤ 25 in H (e alone
  is a non-zero constant; H odd so H ≠ 0), hence ≤ 25 roots among 2^127 odd points; d ≠ 0 gives
  d·RK_0 + Q with Q free of RK_0, one RK_0. The independence of RK_0 from H and RK_1..RK_24 is a
  model assumption (all 26 blocks are functions of the 256-bit K'); derivations.md states it.
  The point is secret where it must be: derived from K' under its own label for `Turing`, drawn
  from the OS-seeded stream for `MaskedTuring`; weights start at H^1 (so RK_0 and the checksum
  cannot cancel).

Masking
- ISW d = 1 (masked.rs:151-158), RefreshMasks (161-164) and SecExp254 (171-179) match
  Rivain-Prouff Algorithms 1, 4 and 3 (numbers and chain checked in the local PDF); affine
  constants go into share 0 only; per-lane randomness is a full u64 per call; the Coron et al.
  quote ("defeated by an attack of order ⌈d/2⌉ + 1") is verbatim.
- 200 random keys x 20 blocks: masked encrypt, decrypt and both checked calls equal the plain
  cipher, 0 mismatches (probe `masked`). Shares are refreshed with one mask per round key XORed
  into both shares at every operation; the masked `intact()` compares two masked values and never
  forms an unmasked one; outputs are recombined only for the (public) result block.

TOCTOU
- `Turing::guarded` (cipher.rs:109-125) and `MaskedTuring::guarded` (masked.rs:356-382) check
  the checksum, run `between`, compute forward and backward, compare without data-dependent
  branches, and check again; the block is wiped on any failure. This is what docs/13 §5 says.
  The analysis hook runs single-threaded inside `guarded` (toctou.rs:38), so the raw-pointer
  write in `flip_bit_raw` does not race. (Model note: a fault that holds for both computations
  and is gone by the second check, e.g. a corrupted cached copy refetched from DRAM, is outside
  the "persistent flip" model the docs state.)

Unsafe code in memory.rs
- Allocation: size rounded up to whole pages; `align_of::<T>() <= 4096` asserted and
  mmap/VirtualAlloc return page-aligned memory; fresh anonymous/committed pages are zero, and the
  fallback uses `alloc_zeroed`/`dealloc` with the same `Layout::new::<T>()`.
- Lock refused: `locked = false`, no unlock at release; the value still works and is wiped.
- Drop: wipe (zeroize's volatile writes + compiler fence, not elidable) before unlock and unmap;
  release happens once (no Clone, no other release path); `burn_stack` writes a
  `MaybeUninit` buffer with volatile stores. Send/Sync mirror `Box<T>`.
- `mlock` / `MADV_DONTDUMP` / `MADV_WIPEONFORK` results are reported, not assumed.
- xof.rs:52 `zeroize_flat_type(&mut buffer)`: block-buffer 0.10.4's `BlockBuffer` is a byte
  array, a `u8` position and a `PhantomData`, has no `Drop` impl, and position 0 is a valid
  empty Eager buffer, as the SAFETY comment says.

Randomness
- The hand-written cSHAKE256 prefix/padding in `MaskStream::start` matches SP 800-185 (and the
  existing test against the sha3 crate); `new_key`, the stream seed and the shield prekey only
  use OS output through cSHAKE256, so the ≤ 16-byte residue (F4) leaves ≥ 384 unknown bits.
- Ferguson's whitepaper (local PDF) says what random.rs and docs/13 quote: requests under 128
  bytes come from a 128-byte buffer whose bytes are "wiped (zeroed)" when given out, and "the
  buffered RNG state no longer has the data to reconstruct the output it provided".
- OpenSSH 8.1 release-note quotes (Spectre/Meltdown/Rambleed, 16KB prekey) are verbatim.

Residue after calls
- Probe `calls`: after `Turing::new`, `encrypt_block_checked`, `decrypt_block_checked`,
  `encrypt_block`, `decrypt_block` and drop, no round-key fragment outside the key page (Bombe's
  own scenario ends with a plain decryption before scanning; each call scanned separately here).

README and numbers
- At 5597cd4: 21 campaign sections (campaign.rs has sections 1-21); "over 200 tests": 213
  `#[test]` functions (205 run on Windows) plus 3 doc tests (297 `#[test]` at HEAD); "dudect on
  eight code paths" matches docs/13 §6; "every one- and two-bit fault in the stored key material
  is caught" holds (for additive faults; see F1); "no key material left behind" does not hold for
  `ShieldedKey::new` (F6).
- Timing on this machine (probe `bench`, 3 runs, another build running concurrently): plain
  4.8 µs, checked 2.53-2.57x plain, checksum ≈ 1.3 µs, masked 21.5 µs (4.4-4.5x); docs/13 says
  4.5 µs, 2.6x, 1.5 µs, 21 µs (4.6x), README "about 20 µs". Consistent.
