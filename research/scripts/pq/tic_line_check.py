"""Check that every line-number citation in
research/notes/pq/turing-integration-constraints.md still points at the text
it describes, at the commit the notes were checked against (HEAD).

Topic: turing-integration-constraints (prefix tic_). Each entry is
(path, first line, last line, substring that must occur in that range).
Files are read with `git show HEAD:<path>` only (read-only; the working tree
may hold someone else's uncommitted edits). Prints OK or MISMATCH for each
entry, then runs three negative controls (citations moved to wrong lines,
which must not match), and exits 1 on any mismatch or missed control.
Deterministic.

Usage (from the repository root):
    timeout 120 python research/scripts/pq/tic_line_check.py
"""
import pathlib
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
ROOT = pathlib.Path(__file__).resolve().parents[3]

CITES = [
    # Section 1-2: the cipher, keys and key schedule.
    ("Cargo.toml", 2, 2, 'members = ["crates/bombe", "crates/turing"]'),
    ("crates/turing/Cargo.toml", 5, 5, "experimental 128-bit block cipher with a 256-bit key"),
    ("crates/turing/Cargo.toml", 14, 17, "analysis = []"),
    ("crates/turing/src/lib.rs", 6, 17, "pub mod xof;"),
    ("crates/turing/src/lib.rs", 25, 33, "send_sync::<ShieldedKey>();"),
    ("crates/turing/src/structure.rs", 26, 28, "pub const ROUND_KEYS: usize = ROUNDS + 1;"),
    ("crates/turing/src/structure.rs", 29, 29, "assert"),
    ("crates/turing/src/cipher.rs", 55, 55, "pub fn new(key: &[u8; 32]) -> Turing"),
    ("crates/turing/src/cipher.rs", 55, 67, "burn_stack"),
    ("crates/turing/src/cipher.rs", 92, 125, "block.zeroize();"),
    ("crates/turing/src/cipher.rs", 214, 227, "Debug"),
    ("crates/turing/src/keyschedule.rs", 28, 29, 'pub const CONSTANTS_LABEL: &str = "Turing v2 key schedule constants";'),
    ("crates/turing/src/keyschedule.rs", 31, 33, "pub const ROUNDS_PER_PAIR: usize = 8;"),
    ("crates/turing/src/keyschedule.rs", 73, 85, "GF(2^128)"),
    ("crates/turing/src/keyschedule.rs", 87, 111, "SecretBox<KeyMaterial<N>>"),
    ("crates/turing/src/keyschedule.rs", 172, 183, "xof::cshake256_secret(KEY_LABEL, key, &mut whitened);"),
    ("crates/turing/src/keyschedule.rs", 253, 260, "prefix"),
    # Section 3: xof.
    ("crates/turing/src/xof.rs", 22, 23, "For public data only"),
    ("crates/turing/src/xof.rs", 24, 24, "pub fn cshake256(label: &str, input: &[u8]) -> CShake256Reader"),
    ("crates/turing/src/xof.rs", 25, 25, "assert!"),
    ("crates/turing/src/xof.rs", 39, 40, "pub fn cshake256_secret(label: &str, input: &[u8], out: &mut [u8])"),
    ("crates/turing/src/xof.rs", 52, 52, "unsafe"),
    ("crates/turing/src/xof.rs", 98, 98, '"Turing v1 key schedule constants"'),
    ("crates/turing/src/random.rs", 10, 17, "only ever used\n//! through cSHAKE256"),
    ("crates/turing/src/random.rs", 40, 40, "pub fn os_random(buf: &mut [u8])"),
    ("crates/turing/src/random.rs", 48, 48, "pub fn new_key()"),
    ("crates/turing/src/random.rs", 63, 63, '"Turing v2 masks"'),
    ("crates/turing/src/random.rs", 67, 68, "the label's bit length must fit left_encode's one-byte form"),
    ("crates/turing/src/random.rs", 115, 127, 'feature = "analysis"'),
    ("crates/turing/src/shield.rs", 23, 24, '"Turing v2 key shield"'),
    ("crates/turing/src/shield.rs", 32, 35, "shielded: SecretBox<[u8; 32]>,"),
    ("crates/bombe/src/gen.rs", 19, 19, '"Turing v1 S-box"'),
    ("crates/bombe/src/gen.rs", 118, 119, '"Turing v1 MixState"'),
    ("crates/bombe/src/refcipher.rs", 185, 185, '"Turing v2 known-answer vectors"'),
    # Section 6-7: analysis boundary, self-test.
    ("crates/turing/src/cipher.rs", 71, 72, "pub fn new_without_stack_burn"),
    ("crates/turing/src/masked.rs", 240, 240, "pub fn new(key: &[u8; 32])"),
    ("crates/turing/src/masked.rs", 249, 250, "pub fn with_mask_seed"),
    ("crates/turing/src/masked.rs", 337, 342, "decrypt_block_checked"),
    ("crates/turing/src/selftest.rs", 17, 24, "Decrypt,"),
    ("crates/turing/src/selftest.rs", 32, 33, "vectors 0 and 2 of `vectors/turing-v2.txt`"),
    ("crates/turing/src/selftest.rs", 50, 50, "pub fn self_test() -> Result<(), SelfTestError>"),
    # Section 9: memory machinery.
    ("crates/turing/src/memory.rs", 10, 12, "RLIMIT_MEMLOCK"),
    ("crates/turing/src/memory.rs", 27, 31, "contains no pointers"),
    ("crates/turing/src/memory.rs", 32, 35, "unsafe impl Zeroable for u64 {}"),
    ("crates/turing/src/memory.rs", 38, 38, "pub struct SecretBox<T: Zeroable>"),
    ("crates/turing/src/memory.rs", 122, 124, "pub const BURN_BYTES: usize = 32 * 1024;"),
    ("crates/turing/src/memory.rs", 122, 124, "several times the deepest key\n/// setup"),
    ("crates/turing/src/memory.rs", 131, 131, "pub fn burn_stack()"),
    # Section 10: Bombe.
    ("crates/bombe/src/memscan.rs", 8, 11, "aligned 8-byte fragments"),
    ("crates/bombe/src/memscan.rs", 63, 63, "pub fn add(&mut self, name: &str, secret: &[u8]) -> usize"),
    ("crates/bombe/src/memscan.rs", 151, 189, "pub fn run_parked"),
    ("crates/bombe/src/memscan.rs", 193, 217, "const PAINT_BYTES: usize = 256 * 1024;"),
    ("crates/bombe/src/timing.rs", 50, 52, "self.max_t > 4.5"),
    ("crates/bombe/src/timing.rs", 55, 66, "class 0 is all zeros"),
    ("crates/bombe/src/toctou.rs", 1, 17, "second check"),
    ("crates/bombe/src/refcipher.rs", 1, 8, "known-answer vectors come from here"),
    ("crates/bombe/src/nist.rs", 144, 148, "2.1 Frequency (monobit)"),
    ("crates/bombe/src/campaign.rs", 157, 157, '"1. Correctness"'),
    ("crates/bombe/src/campaign.rs", 887, 887, '"21. Time of check to time of use, and concurrency"'),
    ("crates/bombe/src/main.rs", 343, 350, 'Some("attack")'),
    ("tools/asm_branches.py", 1, 27, "--loads"),
    ("tools/wsl_linux.py", 1, 17, "binaries run inside WSL"),
    ("tools/mutate.py", 69, 70, "xof: secret cSHAKE drops its label"),
    ("tools/mutate.py", 1, 21, "TIMEOUT = 580"),
    # Docs.
    ("docs/02-public-key-and-quantum.md", 60, 64, "must track the draft version it follows"),
    ("docs/02-public-key-and-quantum.md", 62, 63, "version 10, March 2026"),
    ("docs/03-design-spec.md", 11, 12, "Only the data cipher is ours."),
    ("docs/03-design-spec.md", 13, 17, "We do not hand-build the"),
    ("docs/03-design-spec.md", 20, 30, '"Turing v1 <purpose>"'),
    ("docs/03-design-spec.md", 73, 75, "turing::random::new_key"),
    ("docs/03-design-spec.md", 79, 83, "STREAM construction"),
    ("docs/03-design-spec.md", 84, 84, "AEAD construction (e.g. CTR + MAC) is decided in step 9."),
    ("docs/03-design-spec.md", 86, 97, "Argon2id"),
    ("docs/03-design-spec.md", 99, 101, "`argon2`, `sha3`"),
    ("docs/04-bombe-analysis-suite.md", 3, 6, "deliberately broken controls"),
    ("docs/08-security-review.md", 70, 71, "never as a hash building block"),
    ("docs/08-security-review.md", 98, 102, "birthday bound"),
    ("docs/08-security-review.md", 104, 109, "SIV-style"),
    ("docs/11-key-handling-and-classic-attacks.md", 44, 44, "digest cr"),
    ("docs/11-key-handling-and-classic-attacks.md", 73, 77, "Every key derivation that hashes a key does the same."),
    ("docs/11-key-handling-and-classic-attacks.md", 81, 83, "VirtualLock"),
    ("docs/11-key-handling-and-classic-attacks.md", 88, 88, "Passphrases and derived keys must be wiped by the tool, and never logged."),
    ("docs/12-kerckhoffs-attacks-and-provable-bounds.md", 12, 13, "(file encryption) is parked"),
    ("docs/12-kerckhoffs-attacks-and-provable-bounds.md", 206, 209, "block-buffer 0.10.4 have no wiping"),
    ("docs/12-kerckhoffs-attacks-and-provable-bounds.md", 211, 213, "must call `self_test()` at start-up"),
    ("docs/13-version-2-and-hardening.md", 70, 76, "prefix-consistent"),
    ("docs/13-version-2-and-hardening.md", 91, 92, "reads it once"),
    ("docs/13-version-2-and-hardening.md", 152, 184, "of 8 from `new_key`, none"),
    ("docs/13-version-2-and-hardening.md", 345, 348, "cannot"),
    ("docs/13-version-2-and-hardening.md", 385, 396, "Make ciphers after forking"),
    ("docs/11-key-handling-and-classic-attacks.md", 127, 127, "33 of 262,144 quartets"),
    ("docs/11-key-handling-and-classic-attacks.md", 132, 133, "32\nexpected returns"),
    ("docs/11-key-handling-and-classic-attacks.md", 46, 47, "probe crate"),
    ("docs/04-bombe-analysis-suite.md", 35, 36, "AES with one swapped pair"),
    ("docs/12-kerckhoffs-attacks-and-provable-bounds.md", 51, 54, "Keliher and Sui"),
    ("docs/11-key-handling-and-classic-attacks.md", 190, 195, "Midori-64"),
    ("docs/13-version-2-and-hardening.md", 141, 149, "Control: a key planted in the heap"),
    ("docs/13-version-2-and-hardening.md", 232, 241, "Control: the same attack on the XOR of the shares"),
    ("tools/mutate.py", 294, 297, '"--wsl"'),
    ("crates/turing/src/keyschedule.rs", 196, 196, "xof::cshake256(CONSTANTS_LABEL, &[])"),
    ("crates/turing/src/keyschedule.rs", 209, 211, "xor(&r, k_right)"),
    ("docs/02-public-key-and-quantum.md", 32, 33, "~128-bit security"),
    ("docs/03-design-spec.md", 9, 9, "256-bit key"),
    ("docs/11-key-handling-and-classic-attacks.md", 64, 71, "Round keys are independent."),
]


# Negative controls: citations shifted to the wrong lines. Each must NOT
# match, or the checker cannot tell a right citation from a wrong one.
CONTROLS = [
    ("docs/03-design-spec.md", 1, 10, "We do not hand-build the"),
    ("crates/turing/src/memory.rs", 110, 121, "pub const BURN_BYTES: usize = 32 * 1024;"),
    ("tools/mutate.py", 25, 30, "xof: secret cSHAKE drops its label"),
]


def show(path, cache={}):
    if path not in cache:
        cache[path] = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=ROOT, capture_output=True, text=True,
                                     encoding="utf-8", timeout=60, check=True).stdout.splitlines()
    return cache[path]


def main():
    bad = 0
    for path, a, b, needle in CITES:
        lines = show(path)
        text = "\n".join(lines[a - 1:b])
        ok = needle in text
        bad += not ok
        print(f"{'OK      ' if ok else 'MISMATCH'} {path}:{a}-{b}  {needle[:70]!r}")
    print(f"{len(CITES) - bad} of {len(CITES)} citations match")
    for path, a, b, needle in CONTROLS:
        caught = needle not in "\n".join(show(path)[a - 1:b])
        bad += not caught
        print(f"{'CONTROL CAUGHT' if caught else 'CONTROL MISSED'} {path}:{a}-{b} (a wrong range must not match)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
