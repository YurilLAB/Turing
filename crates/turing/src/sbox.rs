//! The Turing S-box: S(x) = A_out( inv( A_in(x) ) ) over GF(2^8).
//!
//! The field inverse supplies the strength (the best differential and linear
//! properties known for an 8-bit permutation: uniformity 4, nonlinearity
//! 112). A_in and A_out are affine maps derived from cSHAKE256 and selected
//! by Bombe for structural criteria; see
//! docs/05-sbox.md and `bombe gen-sbox`, which reproduces every constant in
//! `sbox_constants.rs` from a public label.
//!
//! The cipher evaluates the S-box arithmetically in constant time.
//! `TABLE` is published for analysis and tests only.

use crate::gf::{self, Affine, Affine8};

mod constants {
    include!("sbox_constants.rs");
}

pub use constants::{TABLE, TABLE_COUNTER};

pub const A_IN: Affine = Affine::new(constants::IN_ROWS, constants::IN_CONST);
pub const A_OUT: Affine = Affine::new(constants::OUT_ROWS, constants::OUT_CONST);
const A_IN_INV: Affine = Affine::new(constants::IN_INV_ROWS, constants::IN_INV_CONST);
const A_OUT_INV: Affine = Affine::new(constants::OUT_INV_ROWS, constants::OUT_INV_CONST);

pub(crate) const A_IN_8: Affine8 = Affine8::new(&A_IN);
pub(crate) const A_OUT_8: Affine8 = Affine8::new(&A_OUT);
pub(crate) const A_IN_INV_8: Affine8 = Affine8::new(&A_IN_INV);
pub(crate) const A_OUT_INV_8: Affine8 = Affine8::new(&A_OUT_INV);

/// S(x) for one byte, constant-time. The reference the fast version is
/// checked against.
pub fn sub(x: u8) -> u8 {
    A_OUT.apply(gf::inv(A_IN.apply(x)))
}

/// S⁻¹(y) = A_in⁻¹( inv( A_out⁻¹(y) ) ), constant-time.
pub fn inv_sub(y: u8) -> u8 {
    A_IN_INV.apply(gf::inv(A_OUT_INV.apply(y)))
}

/// S applied to the eight bytes in the lanes of a u64.
pub fn sub8(x: u64) -> u64 {
    A_OUT_8.apply(gf::inv8(A_IN_8.apply(x)))
}

/// S⁻¹ applied to eight lanes.
pub fn inv_sub8(y: u64) -> u64 {
    A_IN_INV_8.apply(gf::inv8(A_OUT_INV_8.apply(y)))
}

fn map_halves(block: &mut [u8; 16], f: fn(u64) -> u64) {
    for half in block.chunks_exact_mut(8) {
        let x = u64::from_le_bytes(half.try_into().expect("8-byte chunk"));
        half.copy_from_slice(&f(x).to_le_bytes());
    }
}

/// The S-box layer: S on all 16 bytes, constant-time.
pub fn sub_bytes(block: &mut [u8; 16]) {
    map_halves(block, sub8);
}

/// The inverse S-box layer.
pub fn inv_sub_bytes(block: &mut [u8; 16]) {
    map_halves(block, inv_sub8);
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

    // The block layer must equal the table at every byte position, for every
    // value: each of the 256 values is placed in each of the 16 positions,
    // with different values around it.
    #[test]
    fn block_layer_matches_table_everywhere() {
        for x in 0..=255u8 {
            let mut block: [u8; 16] = core::array::from_fn(|i| x.wrapping_add((i * 17) as u8));
            let original = block;
            sub_bytes(&mut block);
            for i in 0..16 {
                assert_eq!(block[i], TABLE[original[i] as usize], "value {:#04x} at {i}", original[i]);
            }
            inv_sub_bytes(&mut block);
            assert_eq!(block, original);
        }
    }
}
