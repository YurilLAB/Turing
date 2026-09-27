//! Table-driven Turing for experiments that need billions of encryptions,
//! such as a 2^32-plaintext structure run through 7 rounds.
//!
//! Each round's S-box layer and linear layer are folded into sixteen tables
//! of 256 entries (one per input byte), built from the `turing` crate's own
//! S-box table and linear layers, so a round is sixteen lookups and XORs on
//! a `u128`. The round keys are the real key schedule's. The tests compare
//! it with `Turing::encrypt_rounds` block for block, and every experiment
//! that uses it spot-checks it against the real cipher again as it runs.
//! Not constant-time: for analysis only.

use std::sync::OnceLock;
use turing::structure::{self, Layer, ROUND_KEYS};
use turing::{Block, Turing};

type Table = [[u128; 256]; 16];

struct Tables {
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    /// `s_then[l][i][v]`: layer l applied to the state with S(v) in byte i
    /// and zero elsewhere (l = 0 for MixState, 1 for ShiftRows+MixColumns).
    s_then: [Table; 2],
    /// `inverse[l][i][v]`: the inverse of layer l applied to v in byte i.
    inverse: [Table; 2],
}

fn index(layer: Layer) -> usize {
    match layer {
        Layer::MixState => 0,
        Layer::ShiftMixColumns => 1,
    }
}

fn unit(i: usize, v: u8) -> Block {
    let mut b = [0u8; 16];
    b[i] = v;
    b
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Box<Tables>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let sbox = turing::sbox::TABLE;
        let mut inv_sbox = [0u8; 256];
        for (x, &y) in sbox.iter().enumerate() {
            inv_sbox[y as usize] = x as u8;
        }
        let mut t = Box::new(Tables { sbox, inv_sbox, s_then: [[[0; 256]; 16]; 2], inverse: [[[0; 256]; 16]; 2] });
        for layer in [Layer::MixState, Layer::ShiftMixColumns] {
            let l = index(layer);
            for i in 0..16 {
                for (v, &y) in sbox.iter().enumerate() {
                    t.s_then[l][i][v] = to_u128(&turing::linear::apply_layer(layer, &unit(i, y)));
                    t.inverse[l][i][v] = to_u128(&turing::linear::invert_layer(layer, &unit(i, v as u8)));
                }
            }
        }
        t
    })
}

pub fn to_u128(b: &Block) -> u128 {
    u128::from_le_bytes(*b)
}

pub fn to_block(x: u128) -> Block {
    x.to_le_bytes()
}

/// The S-box on every byte.
pub fn sub(x: u128) -> u128 {
    let t = tables();
    u128::from_le_bytes(x.to_le_bytes().map(|b| t.sbox[b as usize]))
}

/// The inverse S-box on every byte.
pub fn inv_sub(x: u128) -> u128 {
    let t = tables();
    u128::from_le_bytes(x.to_le_bytes().map(|b| t.inv_sbox[b as usize]))
}

/// The S-box layer followed by `layer` (no key).
pub fn sub_then(layer: Layer, x: u128) -> u128 {
    let table = &tables().s_then[index(layer)];
    x.to_le_bytes().iter().enumerate().fold(0, |acc, (i, &b)| acc ^ table[i][b as usize])
}

/// The inverse of `layer` alone.
pub fn invert(layer: Layer, x: u128) -> u128 {
    let table = &tables().inverse[index(layer)];
    x.to_le_bytes().iter().enumerate().fold(0, |acc, (i, &b)| acc ^ table[i][b as usize])
}

/// The inverse S-box table, for attacks that undo one byte at a time.
pub fn inv_sbox() -> &'static [u8; 256] {
    &tables().inv_sbox
}

/// A key's round keys, ready for the fast rounds.
pub struct Fast {
    keys: [u128; ROUND_KEYS],
}

impl Fast {
    /// The round keys of a real Turing key (analysis API).
    pub fn new(t: &Turing) -> Fast {
        Fast { keys: std::array::from_fn(|i| to_u128(t.round_key(i))) }
    }

    pub fn key(&self, index: usize) -> u128 {
        self.keys[index]
    }

    /// The state at the input of S-box layer `layer` (1-based): round key
    /// 0, then rounds 1..layer - 1 in full, with their linear layers.
    pub fn before_sbox(&self, plaintext: u128, layer: usize) -> u128 {
        let mut x = plaintext ^ self.keys[0];
        for round in 1..layer {
            x = sub_then(structure::layer(round).expect("a full round"), x) ^ self.keys[round];
        }
        x
    }

    /// Carries a state at the input of S-box layer `from` to the input of
    /// S-box layer `to` (full rounds, with their linear layers).
    pub fn forward(&self, mut x: u128, from: usize, to: usize) -> u128 {
        for round in from..to {
            x = sub_then(structure::layer(round).expect("a full round"), x) ^ self.keys[round];
        }
        x
    }

    /// The ciphertext of `rounds`-round Turing, given the state at the input
    /// of its last S-box layer: that layer, no linear layer, the last key.
    pub fn finish(&self, x: u128, rounds: usize) -> u128 {
        sub(x) ^ self.keys[rounds]
    }

    /// `Turing::encrypt_rounds`, table-driven.
    pub fn encrypt(&self, plaintext: u128, rounds: usize) -> u128 {
        self.finish(self.before_sbox(plaintext, rounds), rounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn matches_the_real_cipher_for_every_round_count() {
        let mut rng = Rng::new("fast rounds");
        for _ in 0..40 {
            let t = Turing::new(&rng.bytes());
            let f = Fast::new(&t);
            for rounds in 1..=structure::ROUNDS {
                let p: Block = rng.bytes();
                let mut c = p;
                t.encrypt_rounds(&mut c, rounds);
                assert_eq!(to_block(f.encrypt(to_u128(&p), rounds)), c, "{rounds} rounds");
            }
        }
    }

    #[test]
    fn inverses_undo_the_layers() {
        let mut rng = Rng::new("fast inverses");
        for _ in 0..200 {
            let x = to_u128(&rng.bytes());
            assert_eq!(inv_sub(sub(x)), x);
            for layer in [Layer::MixState, Layer::ShiftMixColumns] {
                assert_eq!(invert(layer, sub_then(layer, inv_sub(x))), x);
                assert_eq!(to_block(invert(layer, x)), turing::linear::invert_layer(layer, &to_block(x)));
            }
        }
    }
}
