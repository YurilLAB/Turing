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
//! Both matrices are Cauchy matrices over points drawn from SHAKE256; see
//! docs/06-linear-layer.md and `bombe gen-linear`, which reproduces
//! `linear_constants.rs`. Which rounds use which layer is set in step 7.

use crate::gf;

mod constants {
    include!("linear_constants.rs");
}

pub use constants::{
    COLUMNS_X, COLUMNS_Y, MIX_COLUMNS, MIX_COLUMNS_INV, MIX_STATE, MIX_STATE_INV, STATE_X, STATE_Y,
};

pub type State = [u8; 16];

/// y = M·x over GF(2^8). Constant-time: fixed loops, branch-free multiply.
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

/// Multiplies every column by `m`. Public so tests can run it with the AES
/// matrix against the FIPS-197 vectors.
pub fn mix_columns_with(m: &[[u8; 4]; 4], s: &State) -> State {
    let mut out = [0u8; 16];
    for c in 0..4 {
        let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        out[4 * c..4 * c + 4].copy_from_slice(&mat_vec(m, &col));
    }
    out
}

pub fn mix_columns(s: &State) -> State {
    mix_columns_with(&MIX_COLUMNS, s)
}

pub fn inv_mix_columns(s: &State) -> State {
    mix_columns_with(&MIX_COLUMNS_INV, s)
}

pub fn mix_state(s: &State) -> State {
    mat_vec(&MIX_STATE, s)
}

pub fn inv_mix_state(s: &State) -> State {
    mat_vec(&MIX_STATE_INV, s)
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
}
