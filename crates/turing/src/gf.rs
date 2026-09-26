//! Constant-time arithmetic over GF(2) and GF(2^8).
//!
//! "Constant-time" means the sequence of instructions and memory accesses
//! does not depend on secret values: no secret-dependent branches and no
//! lookups indexed by secret data. Every loop here has a fixed trip count and
//! choices are made with bit masks instead of `if`.

/// The field polynomial x^8 + x^4 + x^3 + x + 1 (as used by AES).
///
/// Every field with 256 elements is isomorphic to every other, and the
/// isomorphism is a linear map on the bits. Choosing a different polynomial
/// would therefore only amount to a different affine wrapper, which Turing's
/// cSHAKE256-derived affine layers already provide.
pub const POLY: u8 = 0x1b;

/// Multiplication in GF(2^8), branch-free.
pub fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        // mask = 0xff if the low bit of b is set, else 0x00.
        product ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (POLY & carry);
        b >>= 1;
    }
    product
}

/// Multiplicative inverse with inv(0) = 0, computed as x^254.
/// The exponent is public, so branching on its bits leaks nothing.
pub fn inv(x: u8) -> u8 {
    let mut result = 1u8;
    let mut base = x;
    let mut e = 254u8;
    for _ in 0..8 {
        if e & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    // x^254 of 0 is already 0 through the multiplications above.
    result
}

/// An affine map on 8 bits: y = M·x XOR c over GF(2).
/// Row i of M is `rows[i]`; output bit i is the parity of `rows[i] & x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affine {
    pub rows: [u8; 8],
    pub constant: u8,
}

impl Affine {
    pub const fn new(rows: [u8; 8], constant: u8) -> Self {
        Affine { rows, constant }
    }

    /// Applies the map. `count_ones` compiles to a constant-time popcount.
    pub fn apply(&self, x: u8) -> u8 {
        let mut y = 0u8;
        for (i, row) in self.rows.iter().enumerate() {
            y |= (((row & x).count_ones() & 1) as u8) << i;
        }
        y ^ self.constant
    }
}

/// Inverts an 8x8 matrix over GF(2) by Gauss-Jordan elimination.
/// Returns None if it is singular. Operates on public design constants only.
pub fn invert_matrix(rows: [u8; 8]) -> Option<[u8; 8]> {
    // Low byte: the matrix. High byte: the identity, which becomes the inverse.
    let mut aug: [u16; 8] = [0; 8];
    for i in 0..8 {
        aug[i] = rows[i] as u16 | (1 << (8 + i));
    }
    for col in 0..8 {
        let pivot = (col..8).find(|&r| aug[r] >> col & 1 == 1)?;
        aug.swap(col, pivot);
        for r in 0..8 {
            if r != col && aug[r] >> col & 1 == 1 {
                aug[r] ^= aug[col];
            }
        }
    }
    let mut inverse = [0u8; 8];
    for i in 0..8 {
        inverse[i] = (aug[i] >> 8) as u8;
    }
    Some(inverse)
}

/// The inverse affine map: x = M⁻¹·(y XOR c). None if M is singular.
pub fn invert_affine(a: &Affine) -> Option<Affine> {
    let inv_rows = invert_matrix(a.rows)?;
    let m_inv = Affine::new(inv_rows, 0);
    Some(Affine::new(inv_rows, m_inv.apply(a.constant)))
}
