//! Differential and linear experiments on the real cipher: do the numbers
//! the analysis tools predict actually show up in encryptions?

use crate::analysis;
use crate::rng::Rng;
use crate::sbox::Sbox;
use turing::{linear, Block, Turing};

fn weight(b: &[u8]) -> u32 {
    b.iter().filter(|&&x| x != 0).count() as u32
}

pub struct BranchCheck {
    pub layer: &'static str,
    pub samples: usize,
    pub min_observed: u32,
    pub theory: u32,
}

/// A random difference with `active` non-zero bytes at random positions.
fn random_difference(rng: &mut Rng, len: usize, active: usize) -> Vec<u8> {
    let mut d = vec![0u8; len];
    let mut placed = 0;
    while placed < active {
        let i = rng.below(len as u64) as usize;
        if d[i] == 0 {
            d[i] = 1 + rng.below(255) as u8;
            placed += 1;
        }
    }
    d
}

/// Measured branch numbers of the implemented layers: the smallest
/// (active bytes in) + (active bytes out) seen over many differences. The
/// layers are linear, so the output difference is the layer applied to the
/// input difference.
pub fn branch_numbers(samples: usize, label: &str) -> Vec<BranchCheck> {
    let mut rng = Rng::new(label);
    let mut mix_state_min = u32::MAX;
    let mut mix_columns_min = u32::MAX;
    for i in 0..samples {
        let active = 1 + i % 16;
        let d: Block = random_difference(&mut rng, 16, active).try_into().expect("16");
        mix_state_min = mix_state_min.min(weight(&d) + weight(&linear::mix_state(&d)));
        let column_active = 1 + i % 4;
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&random_difference(&mut rng, 4, column_active));
        let out = linear::mix_columns(&s);
        mix_columns_min = mix_columns_min.min(weight(&s[..4]) + weight(&out[..4]));
    }
    vec![
        BranchCheck { layer: "MixState", samples, min_observed: mix_state_min, theory: 17 },
        BranchCheck { layer: "MixColumns", samples, min_observed: mix_columns_min, theory: 5 },
    ]
}

pub struct Measured {
    pub rounds: usize,
    pub samples: usize,
    pub measured: f64,
    pub predicted: f64,
    /// Standard error of `measured` for this many samples.
    pub standard_error: f64,
}

/// Probability of the S-box's best differential through one round of the
/// cipher, measured over random plaintext pairs, against the DDT value.
pub fn one_round_differential(pairs: usize, label: &str) -> Measured {
    let sbox = Sbox::new(turing::sbox::TABLE);
    let ddt = analysis::ddt(&sbox);
    let (mut din, mut dout, mut best) = (1u8, 0u8, 0u16);
    for a in 1..=255u8 {
        for b in 0..=255u8 {
            if ddt.get(a, b) > best {
                (din, dout, best) = (a, b, ddt.get(a, b));
            }
        }
    }
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut hits = 0;
    for _ in 0..pairs {
        let p: Block = rng.bytes();
        let mut q = p;
        q[0] ^= din;
        let (mut cp, mut cq) = (p, q);
        t.encrypt_rounds(&mut cp, 1);
        t.encrypt_rounds(&mut cq, 1);
        hits += usize::from(cp[0] ^ cq[0] == dout);
    }
    let predicted = best as f64 / 256.0;
    Measured {
        rounds: 1,
        samples: pairs,
        measured: hits as f64 / pairs as f64,
        predicted,
        standard_error: (predicted * (1.0 - predicted) / pairs as f64).sqrt(),
    }
}

pub struct Truncated {
    pub rounds: usize,
    pub pairs: usize,
    /// Output bytes with no difference.
    pub zero_bytes: u64,
    /// What a random permutation would give: 16 * pairs / 256.
    pub expected: f64,
    pub z: f64,
}

impl Truncated {
    pub fn distinguishes(&self) -> bool {
        self.z.abs() > 5.0
    }
}

/// Truncated differential: pairs differing in one input byte. After
/// MixState every byte is active with probability 1; a random permutation
/// leaves a byte unchanged 1 time in 256.
pub fn truncated(rounds: usize, pairs: usize, label: &str) -> Truncated {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut zero_bytes = 0u64;
    for _ in 0..pairs {
        let p: Block = rng.bytes();
        let mut q = p;
        q[rng.below(16) as usize] ^= 1 + rng.below(255) as u8;
        let (mut cp, mut cq) = (p, q);
        t.encrypt_rounds(&mut cp, rounds);
        t.encrypt_rounds(&mut cq, rounds);
        zero_bytes += cp.iter().zip(&cq).filter(|(a, b)| a == b).count() as u64;
    }
    let n = 16.0 * pairs as f64;
    let p = 1.0 / 256.0;
    let expected = n * p;
    Truncated { rounds, pairs, zero_bytes, expected, z: (zero_bytes as f64 - expected) / (n * p * (1.0 - p)).sqrt() }
}

/// Correlation of the S-box's best linear approximation (on byte 0 of
/// plaintext and ciphertext) through `rounds` rounds, measured.
pub fn linear_correlation(rounds: usize, samples: usize, label: &str) -> Measured {
    let lat = analysis::lat(&Sbox::new(turing::sbox::TABLE));
    let (mut a, mut b, mut best) = (1u8, 1u8, 0i16);
    for x in 1..=255u8 {
        for y in 1..=255u8 {
            if lat.get(x, y).abs() > best {
                (a, b, best) = (x, y, lat.get(x, y).abs());
            }
        }
    }
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut sum = 0i64;
    for _ in 0..samples {
        let p: Block = rng.bytes();
        let mut c = p;
        t.encrypt_rounds(&mut c, rounds);
        let parity = ((p[0] & a).count_ones() + (c[0] & b).count_ones()) & 1;
        sum += if parity == 0 { 1 } else { -1 };
    }
    let n = samples as f64;
    Measured {
        rounds,
        samples,
        measured: (sum as f64 / n).abs(),
        predicted: if rounds == 1 { best as f64 / 256.0 } else { 0.0 },
        standard_error: 1.0 / n.sqrt(),
    }
}
