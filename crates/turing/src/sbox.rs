//! The Turing S-box: S(x) = A_out( inv( A_in(x) ) ) over GF(2^8).
//!
//! The field inverse supplies the strength (optimal differential and linear
//! properties for 8 bits). A_in and A_out are affine maps derived from
//! SHAKE256 and selected by Bombe for structural criteria; see
//! docs/05-sbox.md and `bombe gen-sbox`, which reproduces every constant in
//! `sbox_constants.rs` from a public label.
//!
//! The cipher evaluates the S-box arithmetically in constant time.
//! `TABLE` is published for analysis and tests only.

use crate::gf::{self, Affine};

mod constants {
    include!("sbox_constants.rs");
}

pub use constants::{TABLE, TABLE_COUNTER};

pub const A_IN: Affine = Affine::new(constants::IN_ROWS, constants::IN_CONST);
pub const A_OUT: Affine = Affine::new(constants::OUT_ROWS, constants::OUT_CONST);
const A_IN_INV: Affine = Affine::new(constants::IN_INV_ROWS, constants::IN_INV_CONST);
const A_OUT_INV: Affine = Affine::new(constants::OUT_INV_ROWS, constants::OUT_INV_CONST);

/// S(x), constant-time.
pub fn sub(x: u8) -> u8 {
    A_OUT.apply(gf::inv(A_IN.apply(x)))
}

/// S⁻¹(y) = A_in⁻¹( inv( A_out⁻¹(y) ) ), constant-time.
pub fn inv_sub(y: u8) -> u8 {
    A_IN_INV.apply(gf::inv(A_OUT_INV.apply(y)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_matches_published_table() {
        for x in 0..=255u8 {
            assert_eq!(sub(x), TABLE[x as usize], "S({x:#04x})");
        }
    }

    #[test]
    fn inverse_undoes_sub() {
        for x in 0..=255u8 {
            assert_eq!(inv_sub(sub(x)), x);
            assert_eq!(sub(inv_sub(x)), x);
        }
    }

    #[test]
    fn stored_inverse_maps_are_correct() {
        assert_eq!(gf::invert_affine(&A_IN), Some(A_IN_INV));
        assert_eq!(gf::invert_affine(&A_OUT), Some(A_OUT_INV));
    }

    #[test]
    fn field_inverse() {
        assert_eq!(gf::inv(0), 0);
        for x in 1..=255u8 {
            assert_eq!(gf::mul(x, gf::inv(x)), 1, "x = {x:#04x}");
        }
        // FIPS-197 §4.2 worked example: {57} · {83} = {c1}.
        assert_eq!(gf::mul(0x57, 0x83), 0xc1);
    }
}
