//! The Turing block cipher: 128-bit block, 256-bit key, 16 rounds.
//!
//! Encryption: XOR round key 0, then for rounds r = 1..=16: the S-box layer,
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

/// A Turing key, expanded into its 17 round keys. The round keys are wiped
/// from memory when this is dropped.
pub struct Turing {
    keys: RoundKeys<ROUND_KEYS>,
}

impl Turing {
    pub fn new(key: &[u8; 32]) -> Turing {
        Turing { keys: keyschedule::expand(key) }
    }

    pub fn encrypt_block(&self, block: &mut Block) {
        self.encrypt_n(block, ROUNDS);
    }

    pub fn decrypt_block(&self, block: &mut Block) {
        self.decrypt_n(block, ROUNDS);
    }

    /// Encrypts, then decrypts the result and compares it with the input. A
    /// transient fault in either computation (a voltage or clock glitch,
    /// Plundervolt-style undervolting) makes them disagree, and the faulty
    /// ciphertext is wiped instead of released: the countermeasure to
    /// differential fault analysis (docs/11). Costs twice encrypt_block. It
    /// cannot catch a persistent fault in the stored round keys, which
    /// corrupts both directions alike.
    pub fn encrypt_block_checked(&self, block: &mut Block) -> Result<(), FaultDetected> {
        checked(block, |b| self.encrypt_block(b), |b| self.decrypt_block(b))
    }

    /// The same for decryption: decrypts, re-encrypts and compares.
    pub fn decrypt_block_checked(&self, block: &mut Block) -> Result<(), FaultDetected> {
        checked(block, |b| self.decrypt_block(b), |b| self.encrypt_block(b))
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

    /// Round key `index` (0..=16), for the round tracer and attack
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
    fn full_cipher_is_sixteen_rounds() {
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
