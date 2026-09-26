//! Related-key experiments: what an attacker who can ask for encryptions
//! under K and K ^ Delta (the 2009 AES-256 attack model) actually gets.
//! The attack needs round-key differences it can predict; here every
//! one-bit key difference is traced into all 25 round keys, with and without
//! the cSHAKE256 whitening in front of the Feistel stage.

use crate::rng::Rng;
use turing::keyschedule::{expand, expand_whitened};
use turing::structure::ROUND_KEYS;
use turing::Turing;

pub struct RoundKeyDiffs {
    pub label: &'static str,
    /// Round-key differences measured (key pairs x round keys).
    pub samples: usize,
    /// Mean Hamming weight of a round-key difference (random: 64 of 128).
    pub mean: f64,
    pub min: u32,
    pub max: u32,
    /// z-score of the mean against Binomial(128, 1/2).
    pub z: f64,
}

impl RoundKeyDiffs {
    /// No detectable bias, and no difference anywhere near zero (the lowest
    /// of this many Binomial(128, 1/2) draws stays far above 20).
    pub fn random_looking(&self) -> bool {
        self.z.abs() < 5.0 && self.min > 20
    }
}

fn weight(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn summarise(label: &'static str, weights: &[u32]) -> RoundKeyDiffs {
    let n = weights.len() as f64;
    let mean = weights.iter().map(|&w| w as f64).sum::<f64>() / n;
    RoundKeyDiffs {
        label,
        samples: weights.len(),
        mean,
        min: *weights.iter().min().unwrap_or(&0),
        max: *weights.iter().max().unwrap_or(&0),
        z: (mean - 64.0) / (32.0 / n).sqrt(),
    }
}

/// Flip each of the 256 key bits of `keys` random keys: round-key
/// difference weights over all 25 round keys.
pub fn master_key_bits(keys: usize, label: &str) -> RoundKeyDiffs {
    let mut rng = Rng::new(label);
    let mut weights = Vec::new();
    for _ in 0..keys {
        let k: [u8; 32] = rng.bytes();
        let base = expand::<ROUND_KEYS>(&k);
        for bit in 0..256 {
            let mut k2 = k;
            k2[bit / 8] ^= 1 << (bit % 8);
            let other = expand::<ROUND_KEYS>(&k2);
            weights.extend((0..ROUND_KEYS).map(|i| weight(base.get(i), other.get(i))));
        }
    }
    summarise("one-bit master-key differences", &weights)
}

/// The same with the cSHAKE256 layer removed: one-bit differences in K'
/// straight into the Feistel stage. This is the defence that must hold even
/// if an attacker could choose K' differences.
pub fn feistel_bits(keys: usize, label: &str) -> RoundKeyDiffs {
    let mut rng = Rng::new(label);
    let mut weights = Vec::new();
    for _ in 0..keys {
        let (l, r): ([u8; 16], [u8; 16]) = (rng.bytes(), rng.bytes());
        let base = expand_whitened::<ROUND_KEYS>(&l, &r);
        for bit in 0..256 {
            let (mut l2, mut r2) = (l, r);
            if bit < 128 {
                l2[bit / 8] ^= 1 << (bit % 8);
            } else {
                r2[(bit - 128) / 8] ^= 1 << (bit % 8);
            }
            let other = expand_whitened::<ROUND_KEYS>(&l2, &r2);
            weights.extend((0..ROUND_KEYS).map(|i| weight(base.get(i), other.get(i))));
        }
    }
    summarise("one-bit K' differences, no cSHAKE layer", &weights)
}

/// Related-key differential through `rounds` rounds: the same plaintext
/// under K and K with one bit flipped. Mean output-difference weight.
pub fn cipher_output(rounds: usize, keys: usize, label: &str) -> RoundKeyDiffs {
    let mut rng = Rng::new(label);
    let mut weights = Vec::new();
    for _ in 0..keys {
        let k: [u8; 32] = rng.bytes();
        let p: [u8; 16] = rng.bytes();
        let mut base = p;
        Turing::new(&k).encrypt_rounds(&mut base, rounds);
        for bit in 0..256 {
            let mut k2 = k;
            k2[bit / 8] ^= 1 << (bit % 8);
            let mut c = p;
            Turing::new(&k2).encrypt_rounds(&mut c, rounds);
            weights.push(weight(&base, &c));
        }
    }
    summarise("related-key output difference", &weights)
}
