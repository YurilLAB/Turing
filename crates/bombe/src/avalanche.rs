//! Measured avalanche (the strict avalanche criterion). For every input bit
//! i and output bit j, flip bit i and count how often bit j changes. In a
//! good cipher every one of the 128 x 128 counts behaves like a fair coin.
//! The test reports the largest deviation as a z-score and judges it against
//! a Bonferroni-corrected threshold, so a 1% false-alarm rate covers all
//! cells at once.

use crate::nist::normal_cdf;
use crate::rng::Rng;
use turing::Turing;

pub struct Avalanche {
    pub rounds: usize,
    pub samples: usize,
    /// Average fraction of output bits flipped by one input bit.
    pub mean: f64,
    /// Largest |z| over all (input bit, output bit) cells.
    pub worst_z: f64,
    /// |z| a fair coin exceeds in some cell with probability 1%.
    pub threshold: f64,
}

impl Avalanche {
    pub fn passed(&self) -> bool {
        self.worst_z < self.threshold
    }
}

/// z such that P(|Z| > z) = alpha for a standard normal Z (bisection).
pub fn two_sided_critical(alpha: f64) -> f64 {
    let (mut lo, mut hi) = (0.0f64, 40.0f64);
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if 2.0 * (1.0 - normal_cdf(mid)) > alpha {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (lo + hi) / 2.0
}

fn summarise(rounds: usize, samples: usize, counts: &[u32], inputs: usize) -> Avalanche {
    let n = samples as f64;
    let total: u64 = counts.iter().map(|&c| c as u64).sum();
    let mean = total as f64 / (n * counts.len() as f64);
    let sd = (n / 4.0).sqrt();
    let worst_z = counts.iter().map(|&c| (c as f64 - n / 2.0).abs() / sd).fold(0.0, f64::max);
    Avalanche { rounds, samples, mean, worst_z, threshold: two_sided_critical(0.01 / (inputs * 128) as f64) }
}

fn accumulate(counts: &mut [u32], row: usize, diff: &[u8; 16]) {
    for (byte, &d) in diff.iter().enumerate() {
        for k in 0..8 {
            counts[row * 128 + byte * 8 + k] += ((d >> k) & 1) as u32;
        }
    }
}

/// Plaintext avalanche through `rounds` rounds, over `samples` random
/// (key, plaintext) pairs.
pub fn plaintext(rounds: usize, samples: usize, label: &str) -> Avalanche {
    let mut rng = Rng::new(label);
    let mut counts = vec![0u32; 128 * 128];
    for _ in 0..samples {
        let t = Turing::new(&rng.bytes());
        let p: [u8; 16] = rng.bytes();
        let mut base = p;
        t.encrypt_rounds(&mut base, rounds);
        for bit in 0..128 {
            let mut q = p;
            q[bit / 8] ^= 1 << (bit % 8);
            t.encrypt_rounds(&mut q, rounds);
            let diff: [u8; 16] = std::array::from_fn(|i| q[i] ^ base[i]);
            accumulate(&mut counts, bit, &diff);
        }
    }
    summarise(rounds, samples, &counts, 128)
}

/// Key avalanche: flip each of the 256 key bits and watch the ciphertext.
pub fn key(rounds: usize, samples: usize, label: &str) -> Avalanche {
    let mut rng = Rng::new(label);
    let mut counts = vec![0u32; 256 * 128];
    for _ in 0..samples {
        let k: [u8; 32] = rng.bytes();
        let p: [u8; 16] = rng.bytes();
        let mut base = p;
        Turing::new(&k).encrypt_rounds(&mut base, rounds);
        for bit in 0..256 {
            let mut k2 = k;
            k2[bit / 8] ^= 1 << (bit % 8);
            let mut c = p;
            Turing::new(&k2).encrypt_rounds(&mut c, rounds);
            let diff: [u8; 16] = std::array::from_fn(|i| c[i] ^ base[i]);
            accumulate(&mut counts, bit, &diff);
        }
    }
    summarise(rounds, samples, &counts, 256)
}
