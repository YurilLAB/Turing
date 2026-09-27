//! The Turing block cipher, version 2: 128-bit block, 256-bit key, 24 rounds.
//!
//! Encryption: XOR round key 0, then for rounds r = 1..=24: the S-box layer,
//! the round's linear layer (none in the last round), and round key r.
//! Decryption runs the same steps backwards with the inverse layers.
//!
//! EXPERIMENTAL. Do not use this to protect real data.

use crate::keyschedule::{self, RoundKeys};
use crate::structure::{self, ROUNDS, ROUND_KEYS};
use crate::{linear, sbox};
use zeroize::Zeroize;

pub type Block = [u8; 16];

fn add_round_key(state: &mut Block, key: &Block) {
    for (s, k) in state.iter_mut().zip(key) {
        *s ^= k;
    }
}

/// A fault was detected: the result did not invert back to the input, so it
/// was wiped instead of returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultDetected;

/// Runs `forward`, runs `backward` on a copy of the result and compares it
/// with the input without branching on the data; on a mismatch the output
/// is wiped. The copies of the input and the check are wiped either way.
fn checked(block: &mut Block, forward: impl Fn(&mut Block), backward: impl Fn(&mut Block)) -> Result<(), FaultDetected> {
    let mut input = *block;
    forward(block);
    let mut check = *block;
    backward(&mut check);
    let diff = core::hint::black_box(input.iter().zip(&check).fold(0u8, |acc, (a, b)| acc | (a ^ b)));
    input.zeroize();
    check.zeroize();
    if diff == 0 {
        Ok(())
    } else {
        block.zeroize();
        Err(FaultDetected)
    }
}

/// A Turing key, expanded into its 25 round keys. The round keys are wiped
/// from memory when this is dropped.
pub struct Turing {
    keys: RoundKeys<ROUND_KEYS>,
}

impl Turing {
    /// Expands the key into round keys in their own locked memory, then
    /// overwrites the stack the key schedule used (memory.rs).
    pub fn new(key: &[u8; 32]) -> Turing {
        let t = Turing::expanded(key);
        crate::memory::burn_stack();
        t
    }

    /// The key schedule alone. Never inlined, so `new` and
    /// `new_without_stack_burn` run the same machine code and differ only in
    /// the burn that follows.
    #[inline(never)]
    fn expanded(key: &[u8; 32]) -> Turing {
        Turing { keys: keyschedule::expand(key) }
    }

    /// `new` without the stack burn, so Bombe can show what the key schedule
    /// leaves behind. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn new_without_stack_burn(key: &[u8; 32]) -> Turing {
        Turing::expanded(key)
    }

    pub fn encrypt_block(&self, block: &mut Block) {
        self.encrypt_n(block, ROUNDS);
    }

    pub fn decrypt_block(&self, block: &mut Block) {
        self.decrypt_n(block, ROUNDS);
    }

    /// Checks the stored round keys against their checksum, encrypts, decrypts
    /// the result and compares it with the input, then checks the round keys
    /// again. A transient fault in either computation (a voltage or clock
    /// glitch, Plundervolt-style undervolting) makes the two disagree; a
    /// persistent one in the stored round keys (a Rowhammer flip), which
    /// would corrupt both directions alike, fails a checksum. Either way the
    /// block is wiped instead of released (docs/11, 13). Costs about two and
    /// a half times encrypt_block.
    pub fn encrypt_block_checked(&self, block: &mut Block) -> Result<(), FaultDetected> {
        let result = self.guarded(block, true, || {});
        crate::memory::burn_stack();
        result
    }

    /// The same for decryption: checks the keys, decrypts, re-encrypts,
    /// compares and checks the keys again.
    pub fn decrypt_block_checked(&self, block: &mut Block) -> Result<(), FaultDetected> {
        let result = self.guarded(block, false, || {});
        crate::memory::burn_stack();
        result
    }

    /// The checked calls. The second key check closes a time-of-check to
    /// time-of-use gap: a round key that flips after the first check, before
    /// the computation reads it, corrupts both directions alike, passes
    /// decrypt-and-compare and would release a block computed under a wrong
    /// key. A flip at any time between the two checks now fails the second.
    /// `between` runs right after the first check; outside Bombe's fault
    /// tests it does nothing. Never inlined, so its frame and the checksum's
    /// lie below the burn in the public calls.
    #[inline(never)]
    fn guarded(&self, block: &mut Block, encrypt: bool, between: impl FnOnce()) -> Result<(), FaultDetected> {
        if !self.keys.intact() {
            block.zeroize();
            return Err(FaultDetected);
        }
        between();
        let result = if encrypt {
            checked(block, |b| self.encrypt_block(b), |b| self.decrypt_block(b))
        } else {
            checked(block, |b| self.decrypt_block(b), |b| self.encrypt_block(b))
        };
        if result.is_err() || !self.keys.intact() {
            block.zeroize();
            return Err(FaultDetected);
        }
        Ok(())
    }

    /// `encrypt_block_checked` with `between` run after the first key check,
    /// where Bombe injects a fault to test the second one. Analysis builds
    /// only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_block_checked_with(&self, block: &mut Block, between: impl FnOnce()) -> Result<(), FaultDetected> {
        self.guarded(block, true, between)
    }

    /// Flips one bit of a stored round key through the allocation's raw
    /// pointer, so it can be called with only `&self`: a fault that strikes
    /// while the cipher is in use. Analysis builds only.
    ///
    /// # Safety
    /// No reference into the round keys may be alive: call it only from the
    /// `between` hook of `encrypt_block_checked_with`, or while no other
    /// method of this cipher is running.
    #[cfg(feature = "analysis")]
    pub unsafe fn flip_round_key_bit_in_use(&self, round: usize, bit: usize) {
        self.keys.flip_bit_raw(round, bit);
    }

    /// Whether the operating system locked the round keys' memory out of the
    /// page file (docs/13).
    pub fn keys_locked(&self) -> bool {
        self.keys.locked()
    }

    /// The round keys, the check and its point (the residue sweep).
    #[cfg(test)]
    pub(crate) fn secret_blocks(&self) -> Vec<Block> {
        self.keys.secret_blocks()
    }

    /// Whether the operating system left the round keys' memory out of core
    /// dumps: MADV_DONTDUMP, on Linux and Android only; always false on
    /// Windows, whose full crash dumps include it (docs/13).
    pub fn keys_dump_excluded(&self) -> bool {
        self.keys.dump_excluded()
    }

    /// Flips one bit of a stored round key, as a Rowhammer-style fault would.
    /// Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn flip_round_key_bit(&mut self, round: usize, bit: usize) {
        self.keys.flip_bit(round, bit);
    }

    /// Flips one bit anywhere the integrity check reads: the round keys, then
    /// their checksum, then its secret point (`RoundKeys::STORED_BITS` bits).
    /// Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn flip_stored_bit(&mut self, bit: usize) {
        self.keys.flip_stored_bit(bit);
    }

    /// The first `rounds` rounds only, with the last of them missing its
    /// linear layer exactly like the full cipher's last round. Reduced-round
    /// versions exist for cryptanalysis: attacks are measured by how many
    /// rounds they break. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_rounds(&self, block: &mut Block, rounds: usize) {
        self.encrypt_n(block, rounds);
    }

    /// The inverse of `encrypt_rounds`. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn decrypt_rounds(&self, block: &mut Block, rounds: usize) {
        self.decrypt_n(block, rounds);
    }

    /// Round key `index` (0..=ROUNDS), for the round tracer and attack
    /// experiments. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn round_key(&self, index: usize) -> &Block {
        self.keys.key(index)
    }

    fn encrypt_n(&self, block: &mut Block, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        add_round_key(block, self.keys.key(0));
        for round in 1..=rounds {
            sbox::sub_bytes(block);
            if round < rounds {
                let layer = structure::layer(round).expect("every round but the last has a layer");
                *block = linear::apply_layer(layer, block);
            }
            add_round_key(block, self.keys.key(round));
        }
    }

    fn decrypt_n(&self, block: &mut Block, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        for round in (1..=rounds).rev() {
            add_round_key(block, self.keys.key(round));
            if round < rounds {
                let layer = structure::layer(round).expect("every round but the last has a layer");
                *block = linear::invert_layer(layer, block);
            }
            sbox::inv_sub_bytes(block);
        }
        add_round_key(block, self.keys.key(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round keys must never reach a log, so neither `Turing` nor `RoundKeys`
    // may implement Debug. If one ever does, both impls below apply and the
    // calls stop compiling as ambiguous (the static_assertions technique for
    // asserting that a trait is not implemented).
    trait AmbiguousIfDebug<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
    struct IsDebug;
    impl<T: ?Sized + core::fmt::Debug> AmbiguousIfDebug<IsDebug> for T {}
    const _: fn() = || {
        <Turing as AmbiguousIfDebug<_>>::check();
        <RoundKeys<ROUND_KEYS> as AmbiguousIfDebug<_>>::check();
    };

    fn key(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(71) ^ seed)
    }

    // A checked call leaves neither the checksum's secret point H nor the
    // stored check in dead stack (research/reviews/2026-09-28 R4: both were
    // there after every call, for 20 of 20 keys; with H an attacker can
    // compute faults that pass the check). Control: a copy of H left in a
    // callee's frame is found.
    #[test]
    fn checked_calls_leave_no_checksum_point_behind() {
        use crate::memory::residue::{contains, leave, run, snapshot, SCAN};
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(|| {
                let mut buf = vec![0u8; SCAN];
                for seed in 1..=5u8 {
                    let t = Turing::new(&key(seed));
                    let (point, check) = t.keys.point_and_check();
                    let found = |buf: &[u8]| [&point[..8], &point[8..], &check[..8], &check[8..]].iter().any(|n| contains(buf, n));
                    run(&mut || leave(&point));
                    snapshot(&mut buf);
                    assert!(found(&buf), "control: a copy of H in a callee's frame is found");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 16];
                        t.encrypt_block_checked(&mut b).expect("intact");
                        core::hint::black_box(&b);
                    });
                    snapshot(&mut buf);
                    assert!(!found(&buf), "encrypt_block_checked left H or the check (key {seed})");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 16];
                        t.decrypt_block_checked(&mut b).expect("intact");
                        core::hint::black_box(&b);
                    });
                    snapshot(&mut buf);
                    assert!(!found(&buf), "decrypt_block_checked left H or the check (key {seed})");
                }
            })
            .expect("thread")
            .join()
            .expect("test thread");
    }

    #[test]
    fn checked_calls_match_the_plain_ones() {
        let t = Turing::new(&key(5));
        for i in 0..64u8 {
            let plain: Block = core::array::from_fn(|k| (k as u8).wrapping_mul(i) ^ i);
            let (mut a, mut b) = (plain, plain);
            t.encrypt_block(&mut a);
            assert_eq!(t.encrypt_block_checked(&mut b), Ok(()));
            assert_eq!(a, b);
            assert_eq!(t.decrypt_block_checked(&mut b), Ok(()));
            assert_eq!(b, plain);
        }
    }

    // Faults are injected into the forward or the backward computation; both
    // must be caught, and the faulty output must not be released.
    // A bit flipped in a stored round key (Rowhammer) corrupts encryption and
    // decryption alike, so decrypt-and-compare cannot see it; the checksum
    // does, for every round key and every bit position tried.
    #[test]
    fn checked_calls_catch_corrupted_round_keys() {
        for round in [0, 1, 12, ROUNDS] {
            for bit in [0, 63, 127] {
                let mut t = Turing::new(&key(7));
                t.keys.flip_bit(round, bit);
                let mut block = [0x55u8; 16];
                let mut plain = block;
                t.encrypt_block(&mut plain);
                let mut back = plain;
                t.decrypt_block(&mut back);
                assert_eq!(back, block, "the corrupted key still inverts itself");
                assert_eq!(t.encrypt_block_checked(&mut block), Err(FaultDetected));
                assert_eq!(block, [0u8; 16]);
                let mut c = [0x66u8; 16];
                assert_eq!(t.decrypt_block_checked(&mut c), Err(FaultDetected));
            }
        }
        assert!(Turing::new(&key(7)).keys_locked() || cfg!(not(windows)));
    }

    // Two-bit faults that left version 2's first checksum, Σ x^i · RK_i,
    // unchanged (bit b of RK_i and bit b - 1 of RK_i+1, and alike): each
    // released a ciphertext under the wrong keys. The keyed checksum sees them.
    #[test]
    fn two_bit_faults_that_cancelled_in_the_public_checksum_are_caught() {
        for [(ra, ba), (rb, bb)] in [[(0, 1), (1, 0)], [(23, 1), (24, 0)], [(0, 23), (23, 0)], [(11, 70), (12, 69)]] {
            let mut t = Turing::new(&key(9));
            t.keys.flip_bit(ra, ba);
            t.keys.flip_bit(rb, bb);
            let mut block = [0x5au8; 16];
            assert_eq!(t.encrypt_block_checked(&mut block), Err(FaultDetected), "RK{ra} bit {ba}, RK{rb} bit {bb}");
            assert_eq!(block, [0u8; 16]);
            let mut c = [0x5au8; 16];
            assert_eq!(t.decrypt_block_checked(&mut c), Err(FaultDetected));
        }
    }

    // Decrypt-and-compare sees a fault in the computation at every byte of
    // the block. Until the review of 2026-09-27 a comparison that ignored
    // byte 15 passed every test here (and Bombe's classic_attacks and toctou).
    #[test]
    fn decrypt_and_compare_covers_every_byte() {
        let t = Turing::new(&key(10));
        for byte in 0..16 {
            let mut block = [0x3cu8; 16];
            // The fault hits the recomputed block, so it differs from the
            // input in this one byte only: a fault in the ciphertext would
            // change every byte after decryption and hide a partial compare.
            let result = checked(&mut block, |b| t.encrypt_block(b), |b| {
                t.decrypt_block(b);
                b[byte] ^= 0x80;
            });
            assert_eq!(result, Err(FaultDetected), "fault in byte {byte}");
            assert_eq!(block, [0u8; 16]);
        }
    }

    // A round key that flips after the first check, inside `between`, passes
    // decrypt-and-compare because both directions read the flipped key; the
    // second check catches it.
    #[test]
    fn a_key_flip_between_check_and_use_is_caught() {
        for (round, bit) in [(0, 5), (13, 64), (ROUNDS, 127)] {
            let t = Turing::new(&key(8));
            let mut expected = [0x21u8; 16];
            t.encrypt_block(&mut expected);
            let mut block = [0x21u8; 16];
            // SAFETY: no reference into the round keys is alive in `between`.
            let result = t.guarded(&mut block, true, || unsafe { t.keys.flip_bit_raw(round, bit) });
            assert_eq!(result, Err(FaultDetected));
            assert_eq!(block, [0u8; 16], "wiped, not released");
            // Control: decrypt-and-compare alone passes the flipped key and
            // releases a ciphertext under the wrong key.
            let mut c = [0x21u8; 16];
            assert_eq!(checked(&mut c, |b| t.encrypt_block(b), |b| t.decrypt_block(b)), Ok(()));
            assert_ne!(c, expected);
        }
    }

    #[test]
    fn checked_calls_catch_faults() {
        let t = Turing::new(&key(6));
        for byte in 0..16 {
            let mut block = [0x33u8; 16];
            let faulty_forward = |b: &mut Block| {
                t.encrypt_block(b);
                b[byte] ^= 0x10;
            };
            assert_eq!(checked(&mut block, faulty_forward, |b| t.decrypt_block(b)), Err(FaultDetected));
            assert_eq!(block, [0u8; 16], "a faulty ciphertext is wiped, not returned");
            let mut block = [0x44u8; 16];
            let faulty_backward = |b: &mut Block| {
                b[byte] ^= 0x01;
                t.decrypt_block(b);
            };
            assert_eq!(checked(&mut block, |b| t.encrypt_block(b), faulty_backward), Err(FaultDetected));
        }
    }

    #[test]
    fn decrypt_undoes_encrypt_at_every_round_count() {
        for seed in 0..8u8 {
            let t = Turing::new(&key(seed));
            for rounds in 1..=ROUNDS {
                let plain: Block = core::array::from_fn(|i| (i as u8) ^ seed.wrapping_mul(29) ^ rounds as u8);
                let mut b = plain;
                t.encrypt_n(&mut b, rounds);
                assert_ne!(b, plain, "{rounds} rounds left the block unchanged");
                t.decrypt_n(&mut b, rounds);
                assert_eq!(b, plain, "seed {seed}, {rounds} rounds");
            }
        }
    }

    #[test]
    fn full_cipher_runs_every_round() {
        let t = Turing::new(&key(1));
        let mut a = [0x42u8; 16];
        let mut b = a;
        t.encrypt_block(&mut a);
        t.encrypt_n(&mut b, ROUNDS);
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_give_different_ciphertexts() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        Turing::new(&key(1)).encrypt_block(&mut a);
        Turing::new(&key(2)).encrypt_block(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "rounds must be")]
    fn zero_rounds_is_refused() {
        Turing::new(&key(0)).encrypt_n(&mut [0u8; 16], 0);
    }
}
