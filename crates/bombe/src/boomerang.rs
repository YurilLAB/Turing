//! The boomerang attack (Wagner, FSE 1999). It glues two short
//! differentials together instead of needing one long one, and broke
//! COCONUT98, a cipher proven secure against ordinary differential attacks,
//! with 2^16 adaptively chosen texts. Trail bounds do not cover it directly,
//! so it is measured.
//!
//! One quartet: encrypt P and P ^ alpha to C and C'; shift both ciphertexts
//! by delta; decrypt to Q and Q'. The boomerang "comes back" when
//! Q ^ Q' = alpha. For a random permutation that happens with probability
//! 2^-128; for a weak cipher far more often.

use crate::rng::Rng;
use turing::{Block, Turing};

pub struct Boomerang {
    pub rounds: usize,
    pub quartets: usize,
    pub returned: usize,
    /// The best single-byte return rate through one S-box: BCT max / 256.
    pub one_sbox_rate: f64,
}

/// (alpha, delta) byte differences with the largest Boomerang Connectivity
/// Table entry for Turing's S-box, and that entry.
pub fn best_bct_pair() -> (u8, u8, u32) {
    let table = turing::sbox::TABLE;
    let mut inv = [0u8; 256];
    for (x, &y) in table.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    let mut best = (1, 1, 0);
    for a in 1..=255u8 {
        for d in 1..=255u8 {
            let count = (0..=255u8)
                .filter(|&x| {
                    let y = table[x as usize];
                    let y2 = table[(x ^ a) as usize];
                    inv[(y ^ d) as usize] ^ inv[(y2 ^ d) as usize] == a
                })
                .count() as u32;
            if count > best.2 {
                best = (a, d, count);
            }
        }
    }
    best
}

/// The exact return rate of the 2-round boomerang with `alpha` and `delta`
/// on byte 0 (round 1 uses MixState). Both pairs cross MixState with the same
/// 16-byte difference, so only S-box events count: the switch in the last
/// S-box (the pairs must be shifted alike) and a second switch in the first
/// S-box, because on the way back both pairs are shifted by the same value
/// c. The two switches are correlated (Wang and Peyrin, ToSC 2019), so the
/// rate is counted over both S-box inputs rather than multiplied from tables.
pub fn two_round_rate(alpha: u8, delta: u8) -> f64 {
    assert_eq!(turing::structure::layer(1), Some(turing::structure::Layer::MixState));
    let s = &turing::sbox::TABLE;
    let mut inv = [0u8; 256];
    for (x, &y) in s.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    let (m, m_inv) = (turing::linear::MIX_STATE[0][0], turing::linear::MIX_STATE_INV[0][0]);
    // How a ciphertext shift by delta moves the last S-box input u.
    let shift: [u8; 256] = std::array::from_fn(|u| inv[(s[u] ^ delta) as usize] ^ u as u8);
    let mut hits = 0u32;
    for x in 0..=255u8 {
        let gamma = s[x as usize] ^ s[(x ^ alpha) as usize];
        let beta = turing::gf::mul(m, gamma);
        for u in 0..=255u8 {
            let t = shift[u as usize];
            if t != shift[(u ^ beta) as usize] {
                continue;
            }
            let c = turing::gf::mul(m_inv, t);
            hits += u32::from(inv[(s[x as usize] ^ c) as usize] ^ inv[(s[(x ^ alpha) as usize] ^ c) as usize] == alpha);
        }
    }
    f64::from(hits) / 65536.0
}

/// Boomerang quartets through `rounds` rounds with alpha and delta on byte 0.
pub fn run(rounds: usize, quartets: usize, label: &str) -> Boomerang {
    let (a, d, count) = best_bct_pair();
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut returned = 0;
    for _ in 0..quartets {
        let p: Block = rng.bytes();
        let mut p2 = p;
        p2[0] ^= a;
        let (mut c, mut c2) = (p, p2);
        t.encrypt_rounds(&mut c, rounds);
        t.encrypt_rounds(&mut c2, rounds);
        c[0] ^= d;
        c2[0] ^= d;
        t.decrypt_rounds(&mut c, rounds);
        t.decrypt_rounds(&mut c2, rounds);
        let expected: Block = std::array::from_fn(|i| if i == 0 { a } else { 0 });
        let diff: Block = std::array::from_fn(|i| c[i] ^ c2[i]);
        returned += usize::from(diff == expected);
    }
    Boomerang { rounds, quartets, returned, one_sbox_rate: count as f64 / 256.0 }
}
