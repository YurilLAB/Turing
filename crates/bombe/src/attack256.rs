//! The square attack on reduced-round Turing-256 (docs/15), as
//! `integral::structured_square_attack` runs it on Turing: structures of
//! 256^n plaintexts whose `active` bytes take every combination of values,
//! encrypted on every thread; for each byte of the last round key, the
//! guesses k for which S^-1(c ⊕ k) sums to zero over every structure.

use crate::rng::Rng;
use turing::{Block256, Turing256};

pub struct Recovery {
    pub rounds: usize,
    pub structures: usize,
    /// Plaintexts per structure.
    pub texts: u64,
    /// Guesses left for each byte of the last round key.
    pub candidates: [usize; 32],
    /// Whether every byte came out unique and equal to the real round key.
    pub correct: bool,
}

/// For each byte position, which ciphertext values occur an odd number of
/// times in the structure (all a byte-wise key guess needs).
fn parities(t: &Turing256, base: &Block256, active: &[usize], rounds: usize) -> Vec<[u64; 4]> {
    let total: u64 = 1 << (8 * active.len());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let mut out = vec![[0u64; 4]; 32];
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|w| {
                scope.spawn(move || {
                    let mut local = vec![[0u64; 4]; 32];
                    for index in total * w / threads..total * (w + 1) / threads {
                        let mut b = *base;
                        for (i, &pos) in active.iter().enumerate() {
                            b[pos] = (index >> (8 * i)) as u8;
                        }
                        t.encrypt_rounds(&mut b, rounds);
                        for (j, &c) in b.iter().enumerate() {
                            local[j][(c >> 6) as usize] ^= 1 << (c & 63);
                        }
                    }
                    local
                })
            })
            .collect();
        for worker in workers {
            for (a, b) in out.iter_mut().zip(worker.join().expect("worker")) {
                for (x, y) in a.iter_mut().zip(b) {
                    *x ^= y;
                }
            }
        }
    });
    out
}

/// Round key `rounds` XOR round constant `rounds`: everything added after
/// the last S-box layer of `rounds`-round Turing-256.
fn last_addition(t: &Turing256, rounds: usize) -> Block256 {
    let (rk, rc) = (t.round_key(rounds), turing::turing256::ROUND_CONSTANTS[rounds - 1]);
    std::array::from_fn(|j| rk[j] ^ rc[j])
}

/// Recovers round key `rounds` of a random key, if the structure keeps the
/// input of the last S-box layer balanced.
pub fn square_attack(rounds: usize, active: &[usize], max_structures: usize, label: &str) -> Recovery {
    assert!((1..=4).contains(&active.len()), "1 to 4 active bytes");
    let mut rng = Rng::new(label);
    let t = Turing256::new(&rng.bytes());
    let inv = crate::fast::inv_sbox();
    let mut candidates: Vec<Vec<u8>> = (0..32).map(|_| (0..=255u8).collect()).collect();
    let mut structures = 0;
    while structures < max_structures {
        structures += 1;
        let p = parities(&t, &rng.bytes(), active, rounds);
        for (j, keep) in candidates.iter_mut().enumerate() {
            keep.retain(|&k| (0..=255u8).filter(|&c| p[j][(c >> 6) as usize] >> (c & 63) & 1 == 1).fold(0u8, |acc, c| acc ^ inv[(c ^ k) as usize]) == 0);
        }
        if structures >= 2 && candidates.iter().all(|c| c.len() <= 1) {
            break;
        }
    }
    // What the attack recovers is the whole last-round addition: the round
    // key XOR the public round constant (v2), which gives the round key at once.
    let rk = last_addition(&t, rounds);
    let correct = (0..32).all(|j| candidates[j] == [rk[j]]);
    Recovery { rounds, structures, texts: 1 << (8 * active.len()), candidates: std::array::from_fn(|j| candidates[j].len()), correct }
}

/// Known-key check of the distinguisher: over one structure, the XOR of the
/// input to the last S-box layer of `rounds`-round Turing-256 (recovered
/// with the real last round key); how many of its 32 bytes are zero.
pub fn balanced_bytes(rounds: usize, active: &[usize], label: &str) -> usize {
    let mut rng = Rng::new(label);
    let t = Turing256::new(&rng.bytes());
    let p = parities(&t, &rng.bytes(), active, rounds);
    let (inv, rk) = (crate::fast::inv_sbox(), last_addition(&t, rounds));
    (0..32)
        .filter(|&j| (0..=255u8).filter(|&c| p[j][(c >> 6) as usize] >> (c & 63) & 1 == 1).fold(0u8, |acc, c| acc ^ inv[(c ^ rk[j]) as usize]) == 0)
        .count()
}
