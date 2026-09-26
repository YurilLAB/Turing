//! Invariant attacks. The invariant subspace attack (Leander, Abdelraheem,
//! AlKhzaimi and Zenner, CRYPTO 2011) broke PRINTcipher; nonlinear
//! invariants (Todo, Leander and Sasaki, ASIACRYPT 2016) broke SCREAM,
//! iSCREAM and Midori-64 for large classes of weak keys. Both find a
//! property g of the state that every round preserves, so g survives any
//! number of rounds and adding rounds does not help.
//!
//! Beierle, Canteaut, Leander and Rotella (CRYPTO 2017, Proposition 1) showed
//! what round keys do to such a g: if two rounds share the linear layer L and
//! use round keys k_i and k_j, then k_i ^ k_j is a linear structure of g
//! (g(x ^ k_i ^ k_j) = g(x) + constant), and the linear structures of g form a
//! subspace that L maps into itself. So they contain W_L(D), the smallest
//! L-invariant subspace holding every such difference. When W_L(D) is the
//! whole state, g can only be affine, which would need an S-box with a
//! linear component; Turing's has degree 7 in every component. This holds
//! for any S-box.
//!
//! Their Theorem 1 bounds what t differences can reach: the sum of the
//! degrees of the t largest invariant factors of L. Midori-64 fell because
//! its round constants touch only the lowest bit of each cell, which keeps
//! W_L(D) at dimension 16 or below out of 64. The tests reproduce that
//! analysis from the paper as the check on this code.
//!
//! Turing has two linear layers. An invariant preserved by every round
//! contains the differences between round keys of the MixState rounds and
//! those of the ShiftRows+MixColumns rounds, and is mapped into itself by
//! both layers. The smallest such space is reported per layer and for both.

use crate::rng::Rng;
use turing::keyschedule::expand;
use turing::linear;
use turing::structure::{self, Layer, ROUNDS, ROUND_KEYS};

/// A linear map on up to 128 bits, stored as the images of the unit vectors.
pub struct LinearMap {
    columns: Vec<u128>,
}

impl LinearMap {
    /// The map on `bits` bits that agrees with the linear function `f`.
    pub fn from_fn(bits: usize, f: impl Fn(u128) -> u128) -> LinearMap {
        assert!((1..=128).contains(&bits));
        LinearMap { columns: (0..bits).map(|i| f(1u128 << i)).collect() }
    }

    /// One of Turing's linear layers on the 128-bit state (byte j in bits
    /// 8j..8j+7).
    pub fn turing(layer: Layer) -> LinearMap {
        LinearMap::from_fn(128, |v| u128::from_le_bytes(linear::apply_layer(layer, &v.to_le_bytes())))
    }

    /// The AES round's linear layer, MixColumns after ShiftRows (FIPS-197),
    /// for comparison.
    pub fn aes() -> LinearMap {
        const MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        LinearMap::from_fn(128, |v| u128::from_le_bytes(linear::mix_columns_with(&MIX, &linear::shift_rows(&v.to_le_bytes()))))
    }

    /// The linear layer of Midori-64 (Banik et al., ASIACRYPT 2015): 16
    /// 4-bit cells s_0..s_15 in column-major order, ShuffleCell, then
    /// MixColumn with the binary matrix [[0,1,1,1],[1,0,1,1],[1,1,0,1],[1,1,1,0]].
    /// Used to check this code against the published analysis.
    pub fn midori64() -> LinearMap {
        const SHUFFLE: [usize; 16] = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8];
        LinearMap::from_fn(64, |v| {
            let cell = |i: usize| (v >> (4 * i)) as u8 & 0xf;
            let s: [u8; 16] = std::array::from_fn(|i| cell(SHUFFLE[i]));
            let mut out = 0u128;
            for c in 0..4 {
                let column = &s[4 * c..4 * c + 4];
                let sum = column.iter().fold(0, |a, &b| a ^ b);
                for (r, &x) in column.iter().enumerate() {
                    out |= u128::from(sum ^ x) << (4 * (4 * c + r));
                }
            }
            out
        })
    }

    pub fn bits(&self) -> usize {
        self.columns.len()
    }

    pub fn apply(&self, mut v: u128) -> u128 {
        let mut out = 0;
        while v != 0 {
            out ^= self.columns[v.trailing_zeros() as usize];
            v &= v - 1;
        }
        out
    }
}

/// A subspace of GF(2)^128 in echelon form, one basis vector per leading bit.
struct Span {
    by_leading_bit: [u128; 128],
    dim: usize,
}

impl Span {
    fn new() -> Span {
        Span { by_leading_bit: [0; 128], dim: 0 }
    }

    /// Adds `v`; true if it was not already in the span.
    fn insert(&mut self, mut v: u128) -> bool {
        while v != 0 {
            let top = 127 - v.leading_zeros() as usize;
            if self.by_leading_bit[top] == 0 {
                self.by_leading_bit[top] = v;
                self.dim += 1;
                return true;
            }
            v ^= self.by_leading_bit[top];
        }
        false
    }
}

/// Dimension of W(D): the smallest subspace that contains `generators` and
/// is mapped into itself by every map in `maps`.
pub fn closure_dim(generators: &[u128], maps: &[&LinearMap]) -> usize {
    let mut span = Span::new();
    // Every vector that enlarged the span is queued; they form a basis, and
    // the span is closed once every basis vector's images are in it.
    let mut queue: Vec<u128> = generators.iter().copied().filter(|&g| span.insert(g)).collect();
    while let Some(v) = queue.pop() {
        for m in maps {
            let w = m.apply(v);
            if span.insert(w) {
                queue.push(w);
            }
        }
    }
    span.dim
}

/// The largest dim W_L(c_1, ..., c_t) seen over `trials` random choices of
/// t vectors, for t = 1, 2, ... until the whole space is reached. By BCLR
/// Theorem 1 the true maximum is the sum of the degrees of the t largest
/// invariant factors of L; so the first entry is the degree of L's minimal
/// polynomial and the length is its number of invariant factors.
pub fn profile(map: &LinearMap, trials: usize, label: &str) -> Vec<usize> {
    let mut rng = Rng::new(label);
    let bits = map.bits();
    let mask = if bits == 128 { u128::MAX } else { (1u128 << bits) - 1 };
    let mut out = Vec::new();
    while out.last() != Some(&bits) && out.len() < bits {
        let t = out.len() + 1;
        let best = (0..trials)
            .map(|_| {
                let d: Vec<u128> = (0..t).map(|_| u128::from_le_bytes(rng.bytes()) & mask).collect();
                closure_dim(&d, &[map])
            })
            .max()
            .unwrap_or(0);
        out.push(best);
    }
    out
}

/// BCLR section 4.2: Midori-64's linear layer has 16 invariant factors,
/// eight (X+1)^6 and eight (X+1)^2, so t differences reach at most 6t for
/// t <= 8 and 48 + 2(t - 8) after that.
pub fn midori64_published_profile() -> Vec<usize> {
    (1..=16).map(|t| if t <= 8 { 6 * t } else { 48 + 2 * (t - 8) }).collect()
}

pub struct RoundKeySpaces {
    pub keys: usize,
    /// Round-key differences available in MixState rounds and in
    /// ShiftRows+MixColumns rounds.
    pub differences: (usize, usize),
    /// Smallest dim W over the keys: MixState rounds alone,
    /// ShiftRows+MixColumns rounds alone, and every round with both layers.
    pub mix_state: usize,
    pub shift_mix: usize,
    pub both: usize,
}

impl RoundKeySpaces {
    /// Every key reaches the whole state, so only constant or affine
    /// invariants are left.
    pub fn full(&self) -> bool {
        self.both == 128 && self.mix_state == 128 && self.shift_mix == 128
    }
}

/// Round-key differences grouped by the linear layer of their round.
fn differences(round_keys: &[[u8; 16]]) -> (Vec<u128>, Vec<u128>) {
    let rounds_with = |layer: Layer| -> Vec<usize> { (1..=ROUNDS).filter(|&r| structure::layer(r) == Some(layer)).collect() };
    let diffs = |rounds: Vec<usize>| -> Vec<u128> {
        let first = u128::from_le_bytes(round_keys[rounds[0]]);
        rounds[1..].iter().map(|&r| u128::from_le_bytes(round_keys[r]) ^ first).collect()
    };
    (diffs(rounds_with(Layer::MixState)), diffs(rounds_with(Layer::ShiftMixColumns)))
}

fn spaces(round_keys: &[[u8; 16]]) -> (usize, usize, usize, (usize, usize)) {
    let (l1, l2) = (LinearMap::turing(Layer::MixState), LinearMap::turing(Layer::ShiftMixColumns));
    let (d1, d2) = differences(round_keys);
    let all: Vec<u128> = d1.iter().chain(&d2).copied().collect();
    (closure_dim(&d1, &[&l1]), closure_dim(&d2, &[&l2]), closure_dim(&all, &[&l1, &l2]), (d1.len(), d2.len()))
}

/// W for the real round keys of `keys` random master keys.
pub fn round_key_spaces(keys: usize, label: &str) -> RoundKeySpaces {
    let mut rng = Rng::new(label);
    let mut out = RoundKeySpaces { keys, differences: (0, 0), mix_state: 128, shift_mix: 128, both: 128 };
    for _ in 0..keys {
        let rk = expand::<ROUND_KEYS>(&rng.bytes());
        let (a, b, c, d) = spaces(rk.all());
        out.mix_state = out.mix_state.min(a);
        out.shift_mix = out.shift_mix.min(b);
        out.both = out.both.min(c);
        out.differences = d;
    }
    out
}

/// Negative control: a cipher that uses the same round key in every round
/// (no key schedule, no round constants). Every difference is zero, so
/// W = {0} and nothing rules invariants out.
pub fn identical_round_keys() -> usize {
    let (_, _, both, _) = spaces(&[[0x5a; 16]; ROUND_KEYS]);
    both
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproduces_the_published_midori_analysis() {
        assert_eq!(profile(&LinearMap::midori64(), 64, "test midori"), midori64_published_profile());
    }

    // BCLR section 3.1: Midori's round constants touch only the lowest bit
    // of each cell, so W_L(D) stays inside a 16-dimensional space.
    #[test]
    fn lowest_bit_constants_stay_small() {
        let l = LinearMap::midori64();
        let lowest_bits: Vec<u128> = (0..16).map(|i| 1u128 << (4 * i)).collect();
        assert_eq!(closure_dim(&lowest_bits, &[&l]), 16);
        let mut rng = Rng::new("test midori constants");
        let constants: Vec<u128> = (0..15).map(|_| u128::from_le_bytes(rng.bytes()) & 0x1111_1111_1111_1111).collect();
        assert!(closure_dim(&constants, &[&l]) <= 16);
    }

    #[test]
    fn closure_on_known_maps() {
        let identity = LinearMap::from_fn(128, |v| v);
        assert_eq!(closure_dim(&[1, 2, 3], &[&identity]), 2);
        let rotate = LinearMap::from_fn(128, |v| v.rotate_left(1));
        assert_eq!(closure_dim(&[1], &[&rotate]), 128);
        let half_turn = LinearMap::from_fn(128, |v| v.rotate_left(64));
        assert_eq!(closure_dim(&[1], &[&half_turn]), 2);
        assert_eq!(closure_dim(&[1], &[&half_turn, &rotate]), 128);
        assert_eq!(closure_dim(&[], &[&rotate]), 0);
    }

    #[test]
    fn turing_layers_match_the_cipher() {
        let mut rng = Rng::new("test layer maps");
        for layer in [Layer::MixState, Layer::ShiftMixColumns] {
            let m = LinearMap::turing(layer);
            for _ in 0..100 {
                let x: [u8; 16] = rng.bytes();
                assert_eq!(m.apply(u128::from_le_bytes(x)).to_le_bytes(), linear::apply_layer(layer, &x));
            }
        }
    }

    #[test]
    fn identical_keys_are_caught() {
        assert_eq!(identical_round_keys(), 0);
    }

    // Proposition 1 only relates rounds that share a linear layer: if every
    // MixState round used one key and every other round another, no
    // difference would count, however different the two keys are.
    #[test]
    fn only_same_layer_differences_count() {
        let keys: Vec<[u8; 16]> =
            (0..ROUND_KEYS).map(|r| if structure::layer(r) == Some(Layer::MixState) { [0xa5; 16] } else { [0x3c; 16] }).collect();
        let (mix_state, shift_mix, both, _) = spaces(&keys);
        assert_eq!((mix_state, shift_mix, both), (0, 0, 0));
    }
}
