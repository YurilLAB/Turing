//! AES-128 with any number of rounds, to validate attacks against their
//! published AES results before they are run on Turing. Built from Bombe's
//! AES S-box and key expansion and Turing's own ShiftRows and MixColumns
//! code with the AES matrix (AES lays out its state the same way); checked
//! against the FIPS-197 example vector. Not constant-time.

use crate::gf256;
use crate::keyrelations::aes128_expand;
use crate::provable::AES_MIX_COLUMNS;
use turing::linear::{inv_shift_rows, mix_columns_with, shift_rows};

pub type Block = [u8; 16];

/// The inverse of AES's MixColumns matrix.
pub const AES_INV_MIX_COLUMNS: [[u8; 4]; 4] = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];

/// Which rounds carry ShiftRows and MixColumns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// FIPS-197: every round has both, except that the last has no
    /// MixColumns.
    Standard,
    /// As the yoyo paper runs AES (Rønjom et al. 2017): the first round has
    /// no ShiftRows and the last has neither ShiftRows nor MixColumns, so
    /// an even number of rounds is exactly super-box layer, linear layer,
    /// super-box layer, and so on.
    Yoyo,
}

pub struct Aes {
    keys: [Block; 11],
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
}

fn add(s: &mut Block, k: &Block) {
    for (a, b) in s.iter_mut().zip(k) {
        *a ^= b;
    }
}

impl Aes {
    pub fn new(key: &[u8; 16]) -> Aes {
        let sbox = gf256::aes_sbox();
        let mut inv_sbox = [0u8; 256];
        for (x, &y) in sbox.iter().enumerate() {
            inv_sbox[y as usize] = x as u8;
        }
        Aes { keys: aes128_expand(key), sbox, inv_sbox }
    }

    fn layers(round: usize, rounds: usize, shape: Shape) -> (bool, bool) {
        match shape {
            Shape::Standard => (true, round < rounds),
            Shape::Yoyo => (round > 1 && round < rounds, round < rounds),
        }
    }

    /// Encrypts with the first `rounds` (1..=10) rounds.
    pub fn encrypt(&self, p: &Block, rounds: usize, shape: Shape) -> Block {
        assert!((1..=10).contains(&rounds));
        let mut s = *p;
        add(&mut s, &self.keys[0]);
        for round in 1..=rounds {
            s = s.map(|b| self.sbox[b as usize]);
            let (sr, mc) = Aes::layers(round, rounds, shape);
            if sr {
                s = shift_rows(&s);
            }
            if mc {
                s = mix_columns_with(&AES_MIX_COLUMNS, &s);
            }
            add(&mut s, &self.keys[round]);
        }
        s
    }

    pub fn decrypt(&self, c: &Block, rounds: usize, shape: Shape) -> Block {
        assert!((1..=10).contains(&rounds));
        let mut s = *c;
        for round in (1..=rounds).rev() {
            add(&mut s, &self.keys[round]);
            let (sr, mc) = Aes::layers(round, rounds, shape);
            if mc {
                s = mix_columns_with(&AES_INV_MIX_COLUMNS, &s);
            }
            if sr {
                s = inv_shift_rows(&s);
            }
            s = s.map(|b| self.inv_sbox[b as usize]);
        }
        add(&mut s, &self.keys[0]);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn hex(s: &str) -> Block {
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    // FIPS-197 Appendix C.1 (AES-128).
    #[test]
    fn matches_fips_197() {
        let aes = Aes::new(&hex("000102030405060708090a0b0c0d0e0f"));
        let p = hex("00112233445566778899aabbccddeeff");
        let c = aes.encrypt(&p, 10, Shape::Standard);
        assert_eq!(c, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        assert_eq!(aes.decrypt(&c, 10, Shape::Standard), p);
    }

    #[test]
    fn inverse_matrix_and_decryption() {
        let mut rng = Rng::new("aes inverse");
        let s: Block = rng.bytes();
        assert_eq!(mix_columns_with(&AES_INV_MIX_COLUMNS, &mix_columns_with(&AES_MIX_COLUMNS, &s)), s);
        let aes = Aes::new(&rng.bytes());
        for rounds in 1..=10 {
            for shape in [Shape::Standard, Shape::Yoyo] {
                let p: Block = rng.bytes();
                assert_eq!(aes.decrypt(&aes.encrypt(&p, rounds, shape), rounds, shape), p);
            }
        }
    }
}
