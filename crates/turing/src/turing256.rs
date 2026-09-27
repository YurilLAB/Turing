//! Turing-256: a 256-bit block cipher with a 256-bit key, Turing's design on
//! a 32-byte state (docs/15).
//!
//! Encryption: XOR round key 0, then for rounds r = 1..=24: the S-box layer
//! on all 32 bytes, the round's linear layer (MixState256 in odd rounds,
//! ShiftRows + MixColumns on 8 columns in even rounds, none in the last),
//! and round key r. The S-box, the MixColumns matrix, the alternation and
//! the key schedule's shape are Turing's; the block is twice as wide, so the
//! birthday bound of any mode moves from 2^64 to 2^128 blocks.
//!
//! EXPERIMENTAL. Do not use this to protect real data.

use crate::keyschedule::RoundKeys;
use crate::keyschedule256::{self, sub32};
use crate::structure::Layer;
use crate::{linear256, sbox};
use zeroize::Zeroize;

pub use crate::cipher::FaultDetected;

pub type Block256 = [u8; 32];

/// Rounds, as in Turing (docs/15 for the analysis behind the number).
pub const ROUNDS: usize = 24;
pub const ROUND_KEYS: usize = ROUNDS + 1;
/// Round keys are stored as two 16-byte blocks each.
pub(crate) const STORED_BLOCKS: usize = 2 * ROUND_KEYS;
// Rounds 1 and ROUNDS - 1 use MixState, as in Turing.
const _: () = assert!(ROUNDS.is_multiple_of(2));

/// The linear layer after the S-box layer of `round` (1-based), or `None`
/// for the last round: MixState in odd rounds, ShiftRows + MixColumns in
/// even rounds.
pub const fn layer(round: usize) -> Option<Layer> {
    if round == 0 || round >= ROUNDS {
        None
    } else if round % 2 == 1 {
        Some(Layer::MixState)
    } else {
        Some(Layer::ShiftMixColumns)
    }
}

fn inv_sub32(s: &mut Block256) {
    for chunk in s.chunks_exact_mut(8) {
        let x = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        chunk.copy_from_slice(&sbox::inv_sub8(x).to_le_bytes());
    }
}

/// Runs `forward`, checks it against `backward` without branching on the
/// data and wipes the output on a mismatch (cipher.rs, `checked`).
fn checked(block: &mut Block256, forward: impl Fn(&mut Block256), backward: impl Fn(&mut Block256)) -> Result<(), FaultDetected> {
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

/// A Turing-256 key, expanded into its 25 round keys of 32 bytes, in their
/// own locked memory with a keyed checksum (docs/13), wiped when dropped.
pub struct Turing256 {
    keys: RoundKeys<STORED_BLOCKS>,
}

impl Turing256 {
    /// Expands the key, then overwrites the stack the key schedule used.
    pub fn new(key: &[u8; 32]) -> Turing256 {
        let t = Turing256::expanded(key);
        crate::memory::burn_stack();
        t
    }

    #[inline(never)]
    fn expanded(key: &[u8; 32]) -> Turing256 {
        Turing256 { keys: keyschedule256::expand(key) }
    }

    /// `new` without the stack burn, so Bombe can show what the key schedule
    /// leaves behind. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn new_without_stack_burn(key: &[u8; 32]) -> Turing256 {
        Turing256::expanded(key)
    }

    pub fn encrypt_block(&self, block: &mut Block256) {
        self.encrypt_n(block, ROUNDS);
    }

    pub fn decrypt_block(&self, block: &mut Block256) {
        self.decrypt_n(block, ROUNDS);
    }

    /// Checks the round keys against their checksum, encrypts, decrypts the
    /// result and compares, then checks the keys again; on any fault the
    /// block is wiped (Turing's `encrypt_block_checked`).
    pub fn encrypt_block_checked(&self, block: &mut Block256) -> Result<(), FaultDetected> {
        let result = self.guarded(block, true, || {});
        crate::memory::burn_stack();
        result
    }

    pub fn decrypt_block_checked(&self, block: &mut Block256) -> Result<(), FaultDetected> {
        let result = self.guarded(block, false, || {});
        crate::memory::burn_stack();
        result
    }

    /// As Turing's: `between` runs right after the first key check, where the
    /// tests inject a fault to reach the second check (until the review of
    /// 2026-09-27 no test reached it, nor decrypt-and-compare: removing both
    /// passed every test). Never inlined: its frame lies below the burn.
    #[inline(never)]
    fn guarded(&self, block: &mut Block256, encrypt: bool, between: impl FnOnce()) -> Result<(), FaultDetected> {
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

    /// Whether the operating system locked the round keys' memory.
    pub fn keys_locked(&self) -> bool {
        self.keys.locked()
    }

    /// The round-key blocks, the check and its point (the residue sweep).
    #[cfg(test)]
    pub(crate) fn secret_blocks(&self) -> Vec<crate::Block> {
        self.keys.secret_blocks()
    }

    /// Whether the round keys' memory is left out of core dumps (Linux).
    pub fn keys_dump_excluded(&self) -> bool {
        self.keys.dump_excluded()
    }

    /// The first `rounds` rounds, the last without its linear layer.
    /// Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_rounds(&self, block: &mut Block256, rounds: usize) {
        self.encrypt_n(block, rounds);
    }

    /// The inverse of `encrypt_rounds`. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn decrypt_rounds(&self, block: &mut Block256, rounds: usize) {
        self.decrypt_n(block, rounds);
    }

    /// Round key `index` (0..=ROUNDS), copied out. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn round_key(&self, index: usize) -> Block256 {
        let mut rk = [0u8; 32];
        rk[..16].copy_from_slice(self.keys.key(2 * index));
        rk[16..].copy_from_slice(self.keys.key(2 * index + 1));
        rk
    }

    /// Stored block `index` (round key i is blocks 2i and 2i + 1) where it
    /// lives, in the locked page, so Bombe's memory scan knows where round
    /// keys belong. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn stored_block(&self, index: usize) -> &crate::Block {
        self.keys.key(index)
    }

    /// Flips one bit anywhere the integrity check reads. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn flip_stored_bit(&mut self, bit: usize) {
        self.keys.flip_stored_bit(bit);
    }

    fn add_round_key(&self, block: &mut Block256, round: usize) {
        let (low, high) = (self.keys.key(2 * round), self.keys.key(2 * round + 1));
        for (i, (l, h)) in low.iter().zip(high).enumerate() {
            block[i] ^= l;
            block[16 + i] ^= h;
        }
    }

    fn encrypt_n(&self, block: &mut Block256, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        self.add_round_key(block, 0);
        for round in 1..=rounds {
            sub32(block);
            if round < rounds {
                let layer = layer(round).expect("every round but the last has a layer");
                *block = linear256::apply_layer(layer, block);
            }
            self.add_round_key(block, round);
        }
    }

    fn decrypt_n(&self, block: &mut Block256, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        for round in (1..=rounds).rev() {
            self.add_round_key(block, round);
            if round < rounds {
                let layer = layer(round).expect("every round but the last has a layer");
                *block = linear256::invert_layer(layer, block);
            }
            inv_sub32(block);
        }
        self.add_round_key(block, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    let t = Turing256::new(&[seed; 32]);
                    let (point, check) = t.keys.point_and_check();
                    let found = |buf: &[u8]| [&point[..8], &point[8..], &check[..8], &check[8..]].iter().any(|n| contains(buf, n));
                    run(&mut || leave(&point));
                    snapshot(&mut buf);
                    assert!(found(&buf), "control: a copy of H in a callee's frame is found");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 32];
                        t.encrypt_block_checked(&mut b).expect("intact");
                        core::hint::black_box(&b);
                    });
                    snapshot(&mut buf);
                    assert!(!found(&buf), "encrypt_block_checked left H or the check (key {seed})");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 32];
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
    fn decrypts_what_it_encrypts() {
        for seed in 0..20u8 {
            let t = Turing256::new(&[seed; 32]);
            let p: Block256 = core::array::from_fn(|i| (i as u8).wrapping_mul(seed).wrapping_add(7));
            let mut c = p;
            t.encrypt_block(&mut c);
            assert_ne!(c, p);
            let mut d = c;
            t.decrypt_block(&mut d);
            assert_eq!(d, p);
        }
    }

    #[test]
    fn schedule_alternates_and_ends_bare() {
        assert_eq!(layer(1), Some(Layer::MixState));
        assert_eq!(layer(2), Some(Layer::ShiftMixColumns));
        assert_eq!(layer(ROUNDS - 1), Some(Layer::MixState));
        assert_eq!(layer(ROUNDS), None);
    }

    #[test]
    fn checked_calls_pass_clean_and_catch_faults() {
        let mut t = Turing256::new(&[9; 32]);
        let mut b = [5u8; 32];
        assert!(t.encrypt_block_checked(&mut b).is_ok());
        let mut plain = [5u8; 32];
        t.encrypt_block(&mut plain);
        assert_eq!(b, plain);
        assert!(t.decrypt_block_checked(&mut b).is_ok());
        assert_eq!(b, [5u8; 32]);
        t.keys.flip_stored_bit(1000);
        let mut b = [5u8; 32];
        assert_eq!(t.encrypt_block_checked(&mut b), Err(FaultDetected));
        assert_eq!(b, [0u8; 32]);
    }

    // A round key that flips after the first check, before the computation
    // reads it, corrupts both directions alike and passes decrypt-and-compare;
    // only the second key check sees it.
    #[test]
    fn a_key_flip_between_check_and_use_is_caught() {
        for (stored, bit) in [(0, 5), (25, 64), (2 * ROUNDS + 1, 127)] {
            let t = Turing256::new(&[4; 32]);
            let mut block = [0x21u8; 32];
            let result = t.guarded(&mut block, true, || unsafe { t.keys.flip_bit_raw(stored, bit) });
            assert_eq!(result, Err(FaultDetected), "stored block {stored}, bit {bit}");
            assert_eq!(block, [0u8; 32], "wiped, not released");
        }
    }

    // Decrypt-and-compare sees a fault in the computation at every byte of
    // the block, the last one included.
    #[test]
    fn decrypt_and_compare_covers_every_byte() {
        let t = Turing256::new(&[6; 32]);
        for byte in 0..32 {
            let mut block = [0x3cu8; 32];
            // The fault hits the recomputed block, so it differs from the
            // input in this one byte only: a fault in the ciphertext would
            // change every byte after decryption and hide a partial compare.
            let result = checked(&mut block, |b| t.encrypt_block(b), |b| {
                t.decrypt_block(b);
                b[byte] ^= 0x80;
            });
            assert_eq!(result, Err(FaultDetected), "fault in byte {byte}");
            assert_eq!(block, [0u8; 32]);
        }
    }

    // One flipped plaintext bit changes about half the ciphertext bits.
    #[test]
    fn avalanche_on_the_full_cipher() {
        let t = Turing256::new(&[0x42; 32]);
        let base = [0u8; 32];
        let mut c0 = base;
        t.encrypt_block(&mut c0);
        let mut total = 0u32;
        for bit in 0..256 {
            let mut p = base;
            p[bit / 8] ^= 1 << (bit % 8);
            t.encrypt_block(&mut p);
            total += p.iter().zip(&c0).map(|(a, b)| (a ^ b).count_ones()).sum::<u32>();
        }
        let mean = total as f64 / 256.0;
        assert!((118.0..138.0).contains(&mean), "{mean}");
    }
}
