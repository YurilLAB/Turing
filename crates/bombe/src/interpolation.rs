//! The interpolation attack (Jakobsen and Knudsen, FSE 1997): write the
//! cipher as a polynomial over GF(2^8) and solve for its coefficients from
//! known plaintexts. It broke ciphers whose rounds have a sparse algebraic
//! form, among them a variant of SHARK. The work grows with the number of
//! unknown coefficients, so the first thing to measure is how many terms the
//! S-box has as a polynomial.
//!
//! Every function f on GF(2^8) is exactly one polynomial of degree below 256
//! (Lagrange interpolation, with 0^0 = 1):
//!
//!   c_0 = f(0),  c_j = sum over x != 0 of f(x) x^(255 - j)  for 1 <= j <= 254,
//!   c_255 = sum over all x of f(x).
//!
//! The AES S-box has only 9 terms (Daemen and Rijmen; Rosenthal 2003,
//! equation 2.3; reproduced in the tests), because its input goes straight
//! into x^-1 and the output affine map turns that into 8 conjugates
//! x^(-2^i) plus a constant. That sparse form is what the algebraic
//! descriptions of AES (Ferguson, Schroeppel and Whiting 2001; Murphy and
//! Robshaw 2002) build on. Turing puts an affine map in front of the
//! inversion as well.

use crate::gf256;

/// The coefficients c_0..c_255 of the polynomial that equals `f` on every
/// element of GF(2^8) (the AES field, which Turing uses).
pub fn coefficients(f: &[u8; 256]) -> [u8; 256] {
    let mut c = [0u8; 256];
    c[0] = f[0];
    c[255] = f.iter().fold(0, |acc, &y| acc ^ y);
    for x in 1..=255u8 {
        let y = f[x as usize];
        if y == 0 {
            continue;
        }
        // p runs through x^1, x^2, ..., x^254; x^e belongs to c_(255 - e).
        let mut p = x;
        for e in 1..=254usize {
            c[255 - e] ^= gf256::mul(y, p);
            p = gf256::mul(p, x);
        }
    }
    c
}

/// Evaluates the polynomial with coefficients `c` at `x` (Horner's rule).
pub fn evaluate(c: &[u8; 256], x: u8) -> u8 {
    c.iter().rev().fold(0, |acc, &coef| gf256::mul(acc, x) ^ coef)
}

/// Number of non-zero coefficients.
pub fn terms(f: &[u8; 256]) -> usize {
    coefficients(f).iter().filter(|&&c| c != 0).count()
}

/// The inverse table of a permutation.
pub fn inverse_table(f: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (x, &y) in f.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_sbox_has_the_published_nine_terms() {
        let c = coefficients(&gf256::aes_sbox());
        let published = [(254, 0x05), (253, 0x09), (251, 0xf9), (247, 0x25), (239, 0xf4), (223, 0x01), (191, 0xb5), (127, 0x8f), (0, 0x63)];
        for (e, coef) in published {
            assert_eq!(c[e], coef, "coefficient of x^{e}");
        }
        assert_eq!(c.iter().filter(|&&v| v != 0).count(), 9);
    }

    #[test]
    fn interpolation_round_trips() {
        let mut f = [0u8; 256];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for v in f.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *v = state as u8;
        }
        let c = coefficients(&f);
        for x in 0..=255u8 {
            assert_eq!(evaluate(&c, x), f[x as usize]);
        }
    }

    #[test]
    fn simple_functions() {
        let identity: [u8; 256] = std::array::from_fn(|x| x as u8);
        let c = coefficients(&identity);
        assert_eq!((c[1], terms(&identity)), (1, 1));
        let inverse: [u8; 256] = std::array::from_fn(|x| gf256::inv(x as u8));
        let c = coefficients(&inverse);
        assert_eq!((c[254], terms(&inverse)), (1, 1), "x^-1 is x^254");
        assert_eq!(terms(&[7; 256]), 1, "a constant");
    }
}
