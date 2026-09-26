//! The Turing mixing layers.
//!
//! The state is 16 bytes laid out column-major as a 4x4 grid, like AES:
//! byte 4c + r is row r, column c.
//!
//! - `shift_rows` + `mix_columns`: row r rotates left by r, then each column
//!   is multiplied by a 4x4 MDS matrix (branch number 5).
//! - `mix_state`: the whole 16-byte state is multiplied by a 16x16 MDS matrix
//!   (branch number 17): one changed byte changes all 16.
//!
//! Both matrices are Cauchy matrices over points drawn from cSHAKE256; see
//! docs/06-linear-layer.md and `bombe gen-linear`, which reproduces
//! `linear_constants.rs`. Which rounds use which layer is set in
//! `structure.rs`.

use crate::gf;
use crate::structure::Layer;

mod constants {
    include!("linear_constants.rs");
}

pub use constants::{
    COLUMNS_X, COLUMNS_Y, MIX_COLUMNS, MIX_COLUMNS_INV, MIX_STATE, MIX_STATE_INV, STATE_X, STATE_Y,
};

pub type State = [u8; 16];

/// y = M·x over GF(2^8), the plain way: the reference the fast layers below
/// are proven against. NOT constant-time. `gf::mul` has no branches in the
/// source, but when it is inlined here the optimiser turns its masks back
/// into a conditional jump on each bit of x (21 such jumps on state bits in
/// the release build of `mix_columns_with`). Compiled only for tests and
/// analysis builds, so the cipher cannot call it on secret data.
#[cfg(any(test, feature = "analysis"))]
pub fn mat_vec<const N: usize>(m: &[[u8; N]; N], x: &[u8; N]) -> [u8; N] {
    let mut y = [0u8; N];
    for (yi, row) in y.iter_mut().zip(m) {
        let mut acc = 0u8;
        for (&a, &b) in row.iter().zip(x) {
            acc ^= gf::mul(a, b);
        }
        *yi = acc;
    }
    y
}

/// Row r rotates left by r positions.
pub fn shift_rows(s: &State) -> State {
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
    out
}

pub fn inv_shift_rows(s: &State) -> State {
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[4 * ((c + r) % 4) + r] = s[4 * c + r];
        }
    }
    out
}

/// Multiplies every column by `m`, through `mat_vec`, so NOT constant-time.
/// Public so tests can run it with the AES matrix against the FIPS-197
/// vectors. Tests and analysis builds only.
#[cfg(any(test, feature = "analysis"))]
pub fn mix_columns_with(m: &[[u8; 4]; 4], s: &State) -> State {
    let mut out = [0u8; 16];
    for c in 0..4 {
        let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        out[4 * c..4 * c + 4].copy_from_slice(&mat_vec(m, &col));
    }
    out
}

// ---------------------------------------------------------------------------
// Fast constant-time layers. A matrix is prepared as, for every input byte j
// and bit k, the column vector (M[i][j] * x^k) over all outputs i. Then
// y = XOR over (j, k) of mask(bit k of x_j) AND that vector. The indices j
// and k are public loop counters; secret data only builds masks, so there
// are no secret-dependent branches or lookups, and the release build's
// assembly for these functions has no conditional jump outside the loop
// counters (docs/11). Both this and `mat_vec` are GF(2)-linear, so agreeing
// on all 128 single-bit inputs proves they agree everywhere (see the tests).
// ---------------------------------------------------------------------------

const fn prepare16(m: &[[u8; 16]; 16]) -> [[[u64; 2]; 8]; 16] {
    let mut out = [[[0u64; 2]; 8]; 16];
    let mut j = 0;
    while j < 16 {
        let mut k = 0;
        while k < 8 {
            let mut i = 0;
            while i < 16 {
                let v = gf::mul(m[i][j], 1 << k) as u64;
                out[j][k][i / 8] |= v << (8 * (i % 8));
                i += 1;
            }
            k += 1;
        }
        j += 1;
    }
    out
}

const fn prepare4(m: &[[u8; 4]; 4]) -> [[u32; 8]; 4] {
    let mut out = [[0u32; 8]; 4];
    let mut j = 0;
    while j < 4 {
        let mut k = 0;
        while k < 8 {
            let mut i = 0;
            while i < 4 {
                out[j][k] |= (gf::mul(m[i][j], 1 << k) as u32) << (8 * i);
                i += 1;
            }
            k += 1;
        }
        j += 1;
    }
    out
}

const MIX_STATE_PREPARED: [[[u64; 2]; 8]; 16] = prepare16(&MIX_STATE);
const MIX_STATE_INV_PREPARED: [[[u64; 2]; 8]; 16] = prepare16(&MIX_STATE_INV);
const MIX_COLUMNS_PREPARED: [[u32; 8]; 4] = prepare4(&MIX_COLUMNS);
const MIX_COLUMNS_INV_PREPARED: [[u32; 8]; 4] = prepare4(&MIX_COLUMNS_INV);

fn apply16(prepared: &[[[u64; 2]; 8]; 16], x: &State) -> State {
    let mut y = [0u64; 2];
    for (&xj, per_bit) in x.iter().zip(prepared) {
        for (k, column) in per_bit.iter().enumerate() {
            let mask = ((xj as u64 >> k) & 1).wrapping_neg();
            y[0] ^= mask & column[0];
            y[1] ^= mask & column[1];
        }
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&y[0].to_le_bytes());
    out[8..].copy_from_slice(&y[1].to_le_bytes());
    out
}

fn apply_columns(prepared: &[[u32; 8]; 4], s: &State) -> State {
    let mut out = [0u8; 16];
    for c in 0..4 {
        let mut y = 0u32;
        for (j, per_bit) in prepared.iter().enumerate() {
            let xj = s[4 * c + j] as u32;
            for (k, &column) in per_bit.iter().enumerate() {
                y ^= ((xj >> k) & 1).wrapping_neg() & column;
            }
        }
        out[4 * c..4 * c + 4].copy_from_slice(&y.to_le_bytes());
    }
    out
}

pub fn mix_columns(s: &State) -> State {
    apply_columns(&MIX_COLUMNS_PREPARED, s)
}

pub fn inv_mix_columns(s: &State) -> State {
    apply_columns(&MIX_COLUMNS_INV_PREPARED, s)
}

pub fn mix_state(s: &State) -> State {
    apply16(&MIX_STATE_PREPARED, s)
}

pub fn inv_mix_state(s: &State) -> State {
    apply16(&MIX_STATE_INV_PREPARED, s)
}

/// The linear layer of a round (step 7 decides which one each round uses).
pub fn apply_layer(layer: Layer, s: &State) -> State {
    match layer {
        Layer::ShiftMixColumns => mix_columns(&shift_rows(s)),
        Layer::MixState => mix_state(s),
    }
}

/// The inverse of `apply_layer`.
pub fn invert_layer(layer: Layer, s: &State) -> State {
    match layer {
        Layer::ShiftMixColumns => inv_shift_rows(&inv_mix_columns(s)),
        Layer::MixState => inv_mix_state(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

    fn hex(s: &str) -> State {
        let v: Vec<u8> = s.split(' ').map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    // FIPS-197 Appendix B, round 1: the state after SubBytes, after
    // ShiftRows, and after MixColumns. Validates the byte layout, the shift
    // direction and the column multiply against the AES reference.
    #[test]
    fn aes_round_one_vectors() {
        let after_sub = hex("d4 27 11 ae e0 bf 98 f1 b8 b4 5d e5 1e 41 52 30");
        let after_shift = hex("d4 bf 5d 30 e0 b4 52 ae b8 41 11 f1 1e 27 98 e5");
        let after_mix = hex("04 66 81 e5 e0 cb 19 9a 48 f8 d3 7a 28 06 26 4c");
        assert_eq!(shift_rows(&after_sub), after_shift);
        assert_eq!(mix_columns_with(&AES_MIX, &after_shift), after_mix);
    }

    #[test]
    fn layers_invert() {
        let s: State = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5c);
        assert_eq!(inv_shift_rows(&shift_rows(&s)), s);
        assert_eq!(inv_mix_columns(&mix_columns(&s)), s);
        assert_eq!(inv_mix_state(&mix_state(&s)), s);
    }

    #[test]
    fn one_byte_reaches_every_byte_through_mix_state() {
        for pos in 0..16 {
            let mut s = [0u8; 16];
            s[pos] = 1;
            assert!(mix_state(&s).iter().all(|&b| b != 0), "byte {pos}");
        }
    }

    type LayerFn = fn(&State) -> State;

    /// The straightforward matrix-times-vector versions, for comparison.
    fn reference_layers() -> [(&'static str, LayerFn, LayerFn); 4] {
        [
            ("MixColumns", mix_columns, |s| mix_columns_with(&MIX_COLUMNS, s)),
            ("MixColumns inverse", inv_mix_columns, |s| mix_columns_with(&MIX_COLUMNS_INV, s)),
            ("MixState", mix_state, |s| mat_vec(&MIX_STATE, s)),
            ("MixState inverse", inv_mix_state, |s| mat_vec(&MIX_STATE_INV, s)),
        ]
    }

    // Both implementations are linear over GF(2), so agreeing on all 128
    // single-bit inputs proves they agree on every input. Random inputs are
    // checked as well.
    #[test]
    fn fast_layers_equal_matrix_multiplication() {
        for (name, fast, reference) in reference_layers() {
            for bit in 0..128 {
                let mut s = [0u8; 16];
                s[bit / 8] = 1 << (bit % 8);
                assert_eq!(fast(&s), reference(&s), "{name}, input bit {bit}");
            }
            let mut s: State = core::array::from_fn(|i| i as u8);
            for _ in 0..200 {
                s = core::array::from_fn(|i| s[i].wrapping_mul(167).wrapping_add(s[(i + 5) % 16]) ^ 0x3b);
                assert_eq!(fast(&s), reference(&s), "{name}");
            }
        }
    }

    #[test]
    fn round_layers_invert() {
        let s: State = core::array::from_fn(|i| (i as u8).wrapping_mul(91) ^ 0xa7);
        for layer in [Layer::ShiftMixColumns, Layer::MixState] {
            assert_eq!(invert_layer(layer, &apply_layer(layer, &s)), s);
        }
        assert_eq!(apply_layer(Layer::ShiftMixColumns, &s), mix_columns(&shift_rows(&s)));
        assert_eq!(apply_layer(Layer::MixState, &s), mix_state(&s));
    }
}
