//! Turing-256's mixing layers (docs/15).
//!
//! The 32-byte state is 4 rows by 8 columns, column-major like Turing's:
//! byte 4c + r is row r, column c.
//!
//! - `shift_rows` + `mix_columns`: row r rotates left by SHIFTS[r] = 0, 1, 3
//!   or 4 positions (Rijndael's offsets for an 8-column state, which send
//!   the four bytes of every column to four different columns), then each
//!   of the 8 columns is multiplied by Turing's 4x4 MixColumns matrix
//!   (branch number 5).
//! - `mix_state`: the whole state multiplied by a 32x32 Cauchy matrix over
//!   points drawn from cSHAKE256 (`bombe gen-linear --turing-256`), MDS with
//!   branch number 33: one changed byte changes all 32.
//!
//! Every layer is constant-time in the same way as Turing's (linear.rs):
//! secret bytes only build masks over public, precomputed columns.

use crate::gf;
use crate::linear::{bit_masks, MIX_COLUMNS_INV_PREPARED, MIX_COLUMNS_PREPARED};
use crate::structure::Layer;

mod constants {
    include!("linear256_constants.rs");
}

pub use constants::{MIX_STATE_256, MIX_STATE_256_INV, STATE256_X, STATE256_Y};

pub type State256 = [u8; 32];

/// Left rotation of each row.
pub const SHIFTS: [usize; 4] = [0, 1, 3, 4];

/// Row r rotates left by SHIFTS[r]: the byte at column (c + SHIFTS[r]) mod 8
/// moves to column c.
pub fn shift_rows(s: &State256) -> State256 {
    let mut out = [0u8; 32];
    for c in 0..8 {
        for (r, &shift) in SHIFTS.iter().enumerate() {
            out[4 * c + r] = s[4 * ((c + shift) % 8) + r];
        }
    }
    out
}

pub fn inv_shift_rows(s: &State256) -> State256 {
    let mut out = [0u8; 32];
    for c in 0..8 {
        for (r, &shift) in SHIFTS.iter().enumerate() {
            out[4 * ((c + shift) % 8) + r] = s[4 * c + r];
        }
    }
    out
}

/// For every input byte j and bit k, the column (M[i][j] * x^k) over all 32
/// outputs, as four u64 lanes: y = XOR over (j, k) of mask(bit k of x_j)
/// AND that column (see linear.rs).
const fn prepare32(m: &[[u8; 32]; 32]) -> [[[u64; 4]; 8]; 32] {
    let mut out = [[[0u64; 4]; 8]; 32];
    let mut j = 0;
    while j < 32 {
        let mut k = 0;
        while k < 8 {
            let mut i = 0;
            while i < 32 {
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

const MIX_STATE_PREPARED: [[[u64; 4]; 8]; 32] = prepare32(&MIX_STATE_256);
const MIX_STATE_INV_PREPARED: [[[u64; 4]; 8]; 32] = prepare32(&MIX_STATE_256_INV);

fn apply32(prepared: &[[[u64; 4]; 8]; 32], x: &State256) -> State256 {
    let mut y = [0u64; 4];
    for (&xj, per_bit) in x.iter().zip(prepared) {
        // The masks pass through a value barrier (`bit_masks`). Without it
        // the release build turned "XOR the column AND the mask" back into
        // "if the bit is set, XOR the column": 16 conditional jumps on the
        // bits of every state byte, a timing leak dudect measured at
        // |t| > 2,500 (docs/15).
        for (mask, column) in bit_masks(xj).iter().zip(per_bit) {
            for (lane, &c) in y.iter_mut().zip(column) {
                *lane ^= mask & c;
            }
        }
    }
    let mut out = [0u8; 32];
    for (chunk, lane) in out.chunks_exact_mut(8).zip(y) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn apply_columns(prepared: &[[u32; 8]; 4], s: &State256) -> State256 {
    let mut out = [0u8; 32];
    for c in 0..8 {
        let mut y = 0u32;
        for (j, per_bit) in prepared.iter().enumerate() {
            for (mask, &column) in bit_masks(s[4 * c + j]).iter().zip(per_bit) {
                y ^= *mask as u32 & column;
            }
        }
        out[4 * c..4 * c + 4].copy_from_slice(&y.to_le_bytes());
    }
    out
}

pub fn mix_columns(s: &State256) -> State256 {
    apply_columns(&MIX_COLUMNS_PREPARED, s)
}

pub fn inv_mix_columns(s: &State256) -> State256 {
    apply_columns(&MIX_COLUMNS_INV_PREPARED, s)
}

pub fn mix_state(s: &State256) -> State256 {
    apply32(&MIX_STATE_PREPARED, s)
}

pub fn inv_mix_state(s: &State256) -> State256 {
    apply32(&MIX_STATE_INV_PREPARED, s)
}

/// The linear layer of a round.
pub fn apply_layer(layer: Layer, s: &State256) -> State256 {
    match layer {
        Layer::ShiftMixColumns => mix_columns(&shift_rows(s)),
        Layer::MixState => mix_state(s),
    }
}

/// The inverse of `apply_layer`.
pub fn invert_layer(layer: Layer, s: &State256) -> State256 {
    match layer {
        Layer::ShiftMixColumns => inv_shift_rows(&inv_mix_columns(s)),
        Layer::MixState => inv_mix_state(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linear::{mat_vec, MIX_COLUMNS};

    fn unit(i: usize, bit: usize) -> State256 {
        let mut s = [0u8; 32];
        s[i] = 1 << bit;
        s
    }

    // The fast layers are GF(2)-linear, so agreeing with the plain matrix
    // product on all 256 single-bit inputs proves they agree everywhere.
    #[test]
    fn fast_layers_match_the_plain_products() {
        for i in 0..32 {
            for bit in 0..8 {
                let x = unit(i, bit);
                assert_eq!(mix_state(&x), mat_vec(&MIX_STATE_256, &x), "MixState, byte {i} bit {bit}");
                assert_eq!(inv_mix_state(&x), mat_vec(&MIX_STATE_256_INV, &x));
                let columns = mix_columns(&x);
                for c in 0..8 {
                    let col: [u8; 4] = core::array::from_fn(|r| x[4 * c + r]);
                    assert_eq!(&columns[4 * c..4 * c + 4], &mat_vec(&MIX_COLUMNS, &col)[..]);
                }
            }
        }
    }

    #[test]
    fn inverses_undo_every_layer() {
        let mut x: State256 = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for _ in 0..50 {
            for layer in [Layer::ShiftMixColumns, Layer::MixState] {
                assert_eq!(invert_layer(layer, &apply_layer(layer, &x)), x);
            }
            x = mix_state(&x);
        }
    }

    // Every column's four bytes go to four different columns.
    #[test]
    fn shift_rows_spreads_each_column() {
        for c in 0..8 {
            let mut s = [0u8; 32];
            for r in 0..4 {
                s[4 * c + r] = 1;
            }
            let moved = shift_rows(&s);
            let columns: Vec<usize> = (0..32).filter(|&i| moved[i] == 1).map(|i| i / 4).collect();
            let mut distinct = columns.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(distinct.len(), 4, "column {c} -> {columns:?}");
        }
    }

    // One active byte through MixState activates all 32 (branch number 33).
    #[test]
    fn one_byte_reaches_every_byte() {
        for i in 0..32 {
            for v in [1u8, 0x53, 0xff] {
                let mut x = [0u8; 32];
                x[i] = v;
                assert!(mix_state(&x).iter().all(|&b| b != 0), "byte {i} value {v:#x}");
            }
        }
    }
}
