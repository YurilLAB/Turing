//! Integral ("square") cryptanalysis of reduced-round Turing, the attack
//! Daemen, Knudsen and Rijmen designed against the cipher Square (FSE 1997).
//!
//! Encrypt 256 plaintexts that differ only in one byte, which takes every
//! value once. Through the first rounds, byte properties survive: "every
//! value once" through S-boxes and MixState, then "XOR over the set is zero"
//! (balanced) through MixColumns. As long as the input to the last S-box
//! layer is balanced, an attacker can guess each byte of the last round key
//! separately (2^8 guesses per byte, not 2^128), undo the last S-box, and
//! keep only guesses that make the XOR zero.

use crate::rng::Rng;
use turing::{Block, Turing};

fn inverse_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (x, &y) in turing::sbox::TABLE.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    inv
}

/// Encrypts a set of 256 plaintexts equal except in byte `active`.
fn lambda_set(t: &Turing, base: &Block, active: usize, rounds: usize) -> Vec<Block> {
    (0..=255u8)
        .map(|v| {
            let mut b = *base;
            b[active] = v;
            t.encrypt_rounds(&mut b, rounds);
            b
        })
        .collect()
}

pub struct Distinguisher {
    pub rounds: usize,
    pub sets: usize,
    /// Output bytes whose XOR over a set is zero, out of 16 per set.
    pub balanced: usize,
    /// z-score of `balanced` against the random rate of 1/256 per byte.
    pub z: f64,
}

impl Distinguisher {
    /// Distinguishable from random with overwhelming confidence.
    pub fn works(&self) -> bool {
        self.z > 5.0
    }
}

pub fn distinguisher(rounds: usize, sets: usize, label: &str) -> Distinguisher {
    let mut rng = Rng::new(label);
    let mut balanced = 0;
    for _ in 0..sets {
        let t = Turing::new(&rng.bytes());
        let base: Block = rng.bytes();
        let active = rng.below(16) as usize;
        let mut sum = [0u8; 16];
        for c in lambda_set(&t, &base, active, rounds) {
            for (s, b) in sum.iter_mut().zip(c) {
                *s ^= b;
            }
        }
        balanced += sum.iter().filter(|&&b| b == 0).count();
    }
    let n = (16 * sets) as f64;
    let p = 1.0 / 256.0;
    let z = (balanced as f64 - n * p) / (n * p * (1.0 - p)).sqrt();
    Distinguisher { rounds, sets, balanced, z }
}

pub struct KeyRecovery {
    pub rounds: usize,
    pub chosen_plaintexts: usize,
    /// Remaining guesses for each byte of the last round key.
    pub candidates: [usize; 16],
    /// The recovered last round key, if every byte came out unique.
    pub recovered: Option<Block>,
    /// Whether that equals the real round key.
    pub correct: bool,
}

/// The square attack on `rounds`-round Turing under a random key: recover
/// round key `rounds` using up to `max_sets` sets of 256 chosen plaintexts.
pub fn square_attack(rounds: usize, max_sets: usize, label: &str) -> KeyRecovery {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let inv = inverse_sbox();
    let mut candidates: Vec<Vec<u8>> = (0..16).map(|_| (0..=255u8).collect()).collect();
    let mut sets = 0;
    while sets < max_sets {
        let base: Block = rng.bytes();
        let ciphertexts = lambda_set(&t, &base, 0, rounds);
        sets += 1;
        for (j, keep) in candidates.iter_mut().enumerate() {
            keep.retain(|&k| ciphertexts.iter().fold(0u8, |acc, c| acc ^ inv[(c[j] ^ k) as usize]) == 0);
        }
        if sets >= 2 && candidates.iter().all(|c| c.len() <= 1) {
            break;
        }
    }
    let recovered = candidates
        .iter()
        .all(|c| c.len() == 1)
        .then(|| std::array::from_fn(|j| candidates[j][0]));
    let correct = recovered.as_ref() == Some(t.round_key(rounds));
    KeyRecovery {
        rounds,
        chosen_plaintexts: 256 * sets,
        candidates: std::array::from_fn(|j| candidates[j].len()),
        recovered,
        correct,
    }
}
