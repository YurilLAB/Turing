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

pub type Block = [u8; 16];

fn add_round_key(state: &mut Block, key: &Block) {
    for (s, k) in state.iter_mut().zip(key) {
        *s ^= k;
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
        self.encrypt_rounds(block, ROUNDS);
    }

    pub fn decrypt_block(&self, block: &mut Block) {
        self.decrypt_rounds(block, ROUNDS);
    }

    /// The first `rounds` rounds only, with the last of them missing its
    /// linear layer exactly like the full cipher's last round. Reduced-round
    /// versions exist for cryptanalysis: attacks are measured by how many
    /// rounds they break.
    #[doc(hidden)]
    pub fn encrypt_rounds(&self, block: &mut Block, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        add_round_key(block, self.keys.get(0));
        for round in 1..=rounds {
            sbox::sub_bytes(block);
            if round < rounds {
                let layer = structure::layer(round).expect("every round but the last has a layer");
                *block = linear::apply_layer(layer, block);
            }
            add_round_key(block, self.keys.get(round));
        }
    }

    /// The inverse of `encrypt_rounds` with the same round count.
    #[doc(hidden)]
    pub fn decrypt_rounds(&self, block: &mut Block, rounds: usize) {
        assert!((1..=ROUNDS).contains(&rounds), "rounds must be 1..={ROUNDS}");
        for round in (1..=rounds).rev() {
            add_round_key(block, self.keys.get(round));
            if round < rounds {
                let layer = structure::layer(round).expect("every round but the last has a layer");
                *block = linear::invert_layer(layer, block);
            }
            sbox::inv_sub_bytes(block);
        }
        add_round_key(block, self.keys.get(0));
    }

    /// Round key `index` (0..=16). For analysis and the round tracer only.
    #[doc(hidden)]
    pub fn round_key(&self, index: usize) -> &Block {
        self.keys.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(71) ^ seed)
    }

    #[test]
    fn decrypt_undoes_encrypt_at_every_round_count() {
        for seed in 0..8u8 {
            let t = Turing::new(&key(seed));
            for rounds in 1..=ROUNDS {
                let plain: Block = core::array::from_fn(|i| (i as u8) ^ seed.wrapping_mul(29) ^ rounds as u8);
                let mut b = plain;
                t.encrypt_rounds(&mut b, rounds);
                assert_ne!(b, plain, "{rounds} rounds left the block unchanged");
                t.decrypt_rounds(&mut b, rounds);
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
        t.encrypt_rounds(&mut b, ROUNDS);
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
        Turing::new(&key(0)).encrypt_rounds(&mut [0u8; 16], 0);
    }
}
