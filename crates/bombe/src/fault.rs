//! Differential fault analysis (DFA), the implementation attack Piret and
//! Quisquater used at CHES 2003 to recover an AES-128 key from two faulty
//! ciphertexts. A glitch (voltage, clock, laser, Rowhammer) corrupts one
//! byte of the state near the end of an encryption; comparing the correct
//! and faulty ciphertexts pins down the last round key.
//!
//! For Turing: a byte fault just before the S-box layer of round 15 passes
//! one S-box (unknown output difference beta at unknown position p), then
//! MixState spreads it to all 16 bytes as beta times column p of the matrix.
//! Every byte of the last round key must then satisfy
//! S^-1(C_j ^ k_j) ^ S^-1(C'_j ^ k_j) = M[j][p] * beta.
//! Guessing (p, beta) is only 16 x 255 hypotheses, and each byte of the key
//! is then solved separately.

use crate::rng::Rng;
use turing::structure::{self, ROUNDS};
use turing::{gf, linear, sbox, Block, Turing};

/// Encrypts with `delta` XORed into byte `pos` of the state just before the
/// S-box layer of round `round` (a simulated transient fault).
pub fn encrypt_with_fault(t: &Turing, plaintext: &Block, round: usize, pos: usize, delta: u8) -> Block {
    let mut s = *plaintext;
    for (b, k) in s.iter_mut().zip(t.round_key(0)) {
        *b ^= k;
    }
    for r in 1..=ROUNDS {
        if r == round {
            s[pos] ^= delta;
        }
        sbox::sub_bytes(&mut s);
        if let Some(layer) = structure::layer(r) {
            s = linear::apply_layer(layer, &s);
        }
        for (b, k) in s.iter_mut().zip(t.round_key(r)) {
            *b ^= k;
        }
    }
    s
}

fn inverse_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (x, &y) in sbox::TABLE.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    inv
}

/// Last-round-key candidates consistent with one (correct, faulty) pair:
/// the union over fault hypotheses (p, beta) of the per-byte products.
fn candidate_keys(c: &Block, faulty: &Block, inv: &[u8; 256], limit: usize) -> Option<Vec<Block>> {
    let mut keys = Vec::new();
    for p in 0..16 {
        for beta in 1..=255u8 {
            let mut per_byte: Vec<Vec<u8>> = Vec::with_capacity(16);
            for j in 0..16 {
                let target = gf::mul(linear::MIX_STATE[j][p], beta);
                let ks: Vec<u8> = (0..=255u8).filter(|&k| inv[(c[j] ^ k) as usize] ^ inv[(faulty[j] ^ k) as usize] == target).collect();
                if ks.is_empty() {
                    break;
                }
                per_byte.push(ks);
            }
            if per_byte.len() < 16 {
                continue;
            }
            let count: usize = per_byte.iter().map(Vec::len).product();
            if keys.len() + count > limit {
                return None;
            }
            let mut idx = [0usize; 16];
            for _ in 0..count {
                keys.push(std::array::from_fn(|j| per_byte[j][idx[j]]));
                for (j, i) in idx.iter_mut().enumerate() {
                    *i += 1;
                    if *i < per_byte[j].len() {
                        break;
                    }
                    *i = 0;
                }
            }
        }
    }
    Some(keys)
}

/// Does some fault hypothesis explain this pair under last round key k?
fn consistent(k: &Block, c: &Block, faulty: &Block, inv: &[u8; 256]) -> bool {
    let d: Block = std::array::from_fn(|j| inv[(c[j] ^ k[j]) as usize] ^ inv[(faulty[j] ^ k[j]) as usize]);
    (0..16).any(|p| {
        let beta = gf::mul(d[0], gf::inv(linear::MIX_STATE[0][p]));
        beta != 0 && (0..16).all(|j| gf::mul(linear::MIX_STATE[j][p], beta) == d[j])
    })
}

pub struct FaultAttack {
    pub faults: usize,
    /// Candidates left for the last round key after each fault.
    pub remaining: Vec<usize>,
    pub correct: bool,
}

/// Recovers round key 16 of a random key from byte faults in round 15.
pub fn last_round_key(max_faults: usize, label: &str) -> FaultAttack {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let inv = inverse_sbox();
    let mut remaining = Vec::new();
    let mut candidates: Option<Vec<Block>> = None;
    for _ in 0..max_faults {
        let p: Block = rng.bytes();
        let mut c = p;
        t.encrypt_block(&mut c);
        let pos = rng.below(16) as usize;
        let delta = 1 + rng.below(255) as u8;
        let faulty = encrypt_with_fault(&t, &p, ROUNDS - 1, pos, delta);
        candidates = Some(match candidates {
            None => match candidate_keys(&c, &faulty, &inv, 1 << 24) {
                Some(keys) => keys,
                None => continue, // too many candidates from this fault; take another
            },
            Some(prev) => prev.into_iter().filter(|k| consistent(k, &c, &faulty, &inv)).collect(),
        });
        let left = candidates.as_ref().map_or(0, Vec::len);
        remaining.push(left);
        if left <= 1 {
            break;
        }
    }
    let correct = matches!(&candidates, Some(v) if v.len() == 1 && &v[0] == t.round_key(ROUNDS));
    FaultAttack { faults: remaining.len(), remaining, correct }
}

/// The standard countermeasure: decrypt the result and compare with the
/// input before releasing it. Returns how many of `trials` single faults
/// (random round, byte and value) the check catches.
pub fn countermeasure(trials: usize, label: &str) -> (usize, usize) {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut caught = 0;
    for _ in 0..trials {
        let p: Block = rng.bytes();
        let round = 1 + rng.below(ROUNDS as u64) as usize;
        let faulty = encrypt_with_fault(&t, &p, round, rng.below(16) as usize, 1 + rng.below(255) as u8);
        let mut back = faulty;
        t.decrypt_block(&mut back);
        caught += usize::from(back != p);
    }
    (caught, trials)
}
