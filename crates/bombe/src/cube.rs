//! Cube testers (in the family of Dinur and Shamir's cube attacks, EUROCRYPT
//! 2009, which broke 767-round Trivium). Pick d plaintext bits, sum the
//! ciphertext over all 2^d settings of them: if every output bit has
//! algebraic degree below d in those bits, the sum is zero whatever the key.
//! Unlike the byte-aligned square attack, the cube bits here are scattered
//! over the block, so this probes bit-level structure the other tests miss.

use crate::rng::Rng;
use turing::{Block, Turing};

pub struct CubeTest {
    pub rounds: usize,
    pub dimension: usize,
    pub cubes: usize,
    /// Output bits whose cube sum was zero, over all cubes.
    pub zero_bits: u64,
    /// z-score against a random function (each sum bit zero with prob. 1/2).
    pub z: f64,
}

impl CubeTest {
    pub fn distinguishes(&self) -> bool {
        self.z > 5.0
    }
}

pub fn run(rounds: usize, dimension: usize, cubes: usize, label: &str) -> CubeTest {
    let mut rng = Rng::new(label);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let mut zero_bits = 0u64;
    for _ in 0..cubes {
        let t = Turing::new(&rng.bytes());
        let base: Block = rng.bytes();
        let mut bits: Vec<usize> = Vec::with_capacity(dimension);
        while bits.len() < dimension {
            let b = rng.below(128) as usize;
            if !bits.contains(&b) {
                bits.push(b);
            }
        }
        let total = 1u64 << dimension;
        let mut sum = [0u8; 16];
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|w| {
                    let (t, bits) = (&t, &bits);
                    scope.spawn(move || {
                        let mut local = [0u8; 16];
                        for index in total * w / threads..total * (w + 1) / threads {
                            let mut p = base;
                            for (i, &bit) in bits.iter().enumerate() {
                                if index >> i & 1 == 1 {
                                    p[bit / 8] ^= 1 << (bit % 8);
                                }
                            }
                            t.encrypt_rounds(&mut p, rounds);
                            for (s, c) in local.iter_mut().zip(p) {
                                *s ^= c;
                            }
                        }
                        local
                    })
                })
                .collect();
            for w in workers {
                for (s, l) in sum.iter_mut().zip(w.join().expect("worker")) {
                    *s ^= l;
                }
            }
        });
        zero_bits += 128 - sum.iter().map(|b| b.count_ones() as u64).sum::<u64>();
    }
    let n = (128 * cubes) as f64;
    CubeTest { rounds, dimension, cubes, zero_bits, z: (zero_bits as f64 - n / 2.0) / (n / 4.0).sqrt() }
}
