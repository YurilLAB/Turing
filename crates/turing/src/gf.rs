//! Constant-time arithmetic over GF(2), GF(2^8) and GF(2^128).
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

/// Multiplication in GF(2^8), branch-free in the source. Also usable in
/// constant expressions, which is how the lookup-free tables below are built.
/// The source is not the machine code: inlined into a loop over secret bytes
/// the optimiser can turn the masks back into branches (it does in
/// `linear::mat_vec`). Secret data goes through `mul8`, whose compiled code
/// is checked (docs/11).
pub const fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    let mut i = 0;
    while i < 8 {
        // mask = 0xff if the low bit of b is set, else 0x00.
        product ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (POLY & carry);
        b >>= 1;
        i += 1;
    }
    product
}

// ---------------------------------------------------------------------------
// Eight field elements at once ("SWAR": SIMD within a register). Each byte
// lane of a u64 holds one GF(2^8) element. Same constant-time discipline:
// fixed loops, masks built arithmetically, no data-dependent indexing.
// ---------------------------------------------------------------------------

/// 0x01 in every byte lane.
pub const LANES_LOW_BIT: u64 = 0x0101_0101_0101_0101;
const LANES_CLEAR_LOW_BIT: u64 = 0xfefe_fefe_fefe_fefe;
const LANES_CLEAR_HIGH_BIT: u64 = 0x7f7f_7f7f_7f7f_7f7f;

/// Broadcast a byte to all eight lanes.
pub const fn broadcast(b: u8) -> u64 {
    b as u64 * LANES_LOW_BIT
}

/// 0xff in every lane whose bit `k` is set, 0x00 elsewhere. Multiplying a
/// lane value of 0 or 1 by 0xff cannot carry into the next lane.
#[inline(always)]
pub const fn lane_mask(x: u64, k: u32) -> u64 {
    ((x >> k) & LANES_LOW_BIT).wrapping_mul(0xff)
}

/// Lane-wise GF(2^8) multiplication.
pub fn mul8(mut a: u64, mut b: u64) -> u64 {
    let mut product = 0u64;
    for _ in 0..8 {
        product ^= a & lane_mask(b, 0);
        let carry = ((a >> 7) & LANES_LOW_BIT).wrapping_mul(POLY as u64);
        a = ((a << 1) & LANES_CLEAR_LOW_BIT) ^ carry;
        b = (b >> 1) & LANES_CLEAR_HIGH_BIT;
    }
    product
}

/// Squares of the basis elements x^k. Squaring is linear over GF(2) (it is
/// the Frobenius map), so the square of any element is the XOR of the
/// squares of its set bits.
const SQUARES: [u64; 8] = {
    let mut out = [0u64; 8];
    let mut k = 0;
    while k < 8 {
        let basis = 1u8 << k;
        out[k] = broadcast(mul(basis, basis));
        k += 1;
    }
    out
};

/// Lane-wise squaring.
pub fn square8(x: u64) -> u64 {
    let mut y = 0u64;
    for (k, &sq) in SQUARES.iter().enumerate() {
        y ^= lane_mask(x, k as u32) & sq;
    }
    y
}

/// Lane-wise inverse (inv(0) = 0) as x^254, by the addition chain
/// 2, 3, 6, 12, 15, 30, 60, 120, 240, 252, 254: seven squarings (cheap,
/// linear) and four multiplications.
pub fn inv8(x: u64) -> u64 {
    let x2 = square8(x);
    let x3 = mul8(x2, x);
    let x6 = square8(x3);
    let x12 = square8(x6);
    let x15 = mul8(x12, x3);
    let x30 = square8(x15);
    let x60 = square8(x30);
    let x120 = square8(x60);
    let x240 = square8(x120);
    let x252 = mul8(x240, x12);
    mul8(x252, x2)
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

    /// Column k of M, broadcast to all lanes: bit i of each lane is bit k of
    /// row i.
    pub const fn lane_columns(&self) -> [u64; 8] {
        let mut out = [0u64; 8];
        let mut k = 0;
        while k < 8 {
            let mut col = 0u8;
            let mut i = 0;
            while i < 8 {
                col |= ((self.rows[i] >> k) & 1) << i;
                i += 1;
            }
            out[k] = broadcast(col);
            k += 1;
        }
        out
    }
}

/// An affine map prepared for eight lanes: y = XOR of the columns selected
/// by the bits of x, then XOR the constant.
#[derive(Clone, Copy, Debug)]
pub struct Affine8 {
    columns: [u64; 8],
    constant: u64,
}

impl Affine8 {
    pub const fn new(a: &Affine) -> Self {
        Affine8 { columns: a.lane_columns(), constant: broadcast(a.constant) }
    }

    pub fn apply(&self, x: u64) -> u64 {
        let mut y = self.constant;
        for (k, &col) in self.columns.iter().enumerate() {
            y ^= lane_mask(x, k as u32) & col;
        }
        y
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

// ---------------------------------------------------------------------------
// GF(2^128), for the round keys' integrity checksum (keyschedule.rs). Bit j
// of a u128 is the coefficient of x^j, modulo x^128 + x^7 + x^2 + x + 1 (the
// GCM polynomial). Both operands can be secret, so carry-less products come
// from integer multiplications of operands with "holes" (BearSSL's ctmul64,
// also RustCrypto polyval's portable backend): no branches and no lookups.
// Constant-time wherever the 64-bit integer multiplier is, as on every
// x86-64 and 64-bit Arm core.
// ---------------------------------------------------------------------------

/// The low 64 bits of the carry-less product of `x` and `y`. Each operand is
/// split into four parts whose bits sit 4 apart. In an integer product of two
/// parts, the terms landing on one position below bit 64 number at most 15,
/// except 16 at the top position, whose carry leaves the word; so no sum
/// carries into the next position of its part, and the lowest bit of each
/// 4-bit field is the XOR of its terms.
fn clmul64_low(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// The full 128-bit carry-less product of two 64-bit values. Reversing both
/// inputs reverses the 127-bit product, so the high half is the low half of
/// the reversed product, reversed back.
fn clmul64(x: u64, y: u64) -> u128 {
    let low = clmul64_low(x, y);
    let high = clmul64_low(x.reverse_bits(), y.reverse_bits()).reverse_bits() >> 1;
    (u128::from(high) << 64) | u128::from(low)
}

/// Reduces low + high · x^128 using x^128 = x^7 + x^2 + x + 1. The bits that
/// multiplying `high` pushes past x^127 are folded back the same way once;
/// there are at most 7 of them, so the second fold cannot overflow.
fn reduce128(low: u128, high: u128) -> u128 {
    let over = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    low ^ high ^ (high << 1) ^ (high << 2) ^ (high << 7) ^ over ^ (over << 1) ^ (over << 2) ^ (over << 7)
}

/// a · b in GF(2^128), constant-time: Karatsuba over three carry-less 64-bit
/// products, then one reduction.
pub fn mul128(a: u128, b: u128) -> u128 {
    let (a0, a1, b0, b1) = (a as u64, (a >> 64) as u64, b as u64, (b >> 64) as u64);
    let low = clmul64(a0, b0);
    let high = clmul64(a1, b1);
    let middle = clmul64(a0 ^ a1, b0 ^ b1) ^ low ^ high;
    reduce128(low ^ (middle << 64), high ^ (middle >> 64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack eight different values into lanes: lane i gets f(i).
    fn lanes(f: impl Fn(usize) -> u8) -> u64 {
        u64::from_le_bytes(core::array::from_fn(f))
    }

    fn lane(x: u64, i: usize) -> u8 {
        x.to_le_bytes()[i]
    }

    // Every pair (a, b), with a different pair in each of the eight lanes so
    // any leak between lanes shows up.
    #[test]
    fn mul8_matches_scalar_on_every_pair() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let va = |i: usize| a.wrapping_add((i * 37) as u8);
                let vb = |i: usize| b.wrapping_add((i * 91) as u8);
                let p = mul8(lanes(va), lanes(vb));
                for i in 0..8 {
                    assert_eq!(lane(p, i), mul(va(i), vb(i)), "a={a} b={b} lane {i}");
                }
            }
        }
    }

    #[test]
    fn square8_and_inv8_match_scalar() {
        for x in 0..=255u8 {
            let v = |i: usize| x.wrapping_add((i * 53) as u8);
            let (sq, inv_l) = (square8(lanes(v)), inv8(lanes(v)));
            for i in 0..8 {
                assert_eq!(lane(sq, i), mul(v(i), v(i)));
                assert_eq!(lane(inv_l, i), inv(v(i)));
            }
        }
    }

    fn times_x(v: u128) -> u128 {
        (v << 1) ^ (0u128.wrapping_sub(v >> 127) & 0x87)
    }

    /// Bit-serial GF(2^128) product: only shifts, ANDs and XORs, so plainly
    /// bilinear. The reference `mul128` is checked against.
    fn mul128_reference(a: u128, b: u128) -> u128 {
        let mut product = 0u128;
        let mut shifted = a;
        for i in 0..128 {
            product ^= shifted & 0u128.wrapping_sub((b >> i) & 1);
            shifted = times_x(shifted);
        }
        product
    }

    // Single bits reach every position of the product without carries; dense
    // operands are where a carry would spill between positions (all ones puts
    // the most terms on each), so they are checked too, then random ones.
    #[test]
    fn mul128_matches_the_bit_serial_product() {
        for i in 0..128 {
            for j in 0..128 {
                assert_eq!(mul128(1 << i, 1 << j), mul128_reference(1 << i, 1 << j), "x^{i} x^{j}");
            }
        }
        let dense = [u128::MAX, u128::MAX >> 1, u128::MAX << 1, u128::MAX << 64, u128::from(u64::MAX), u128::MAX / 3, u128::MAX / 5];
        for a in dense {
            for b in dense {
                assert_eq!(mul128(a, b), mul128_reference(a, b), "{a:#x} {b:#x}");
            }
        }
        let mut s = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834u128;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..20_000 {
            let (a, b) = (next(), next());
            assert_eq!(mul128(a, b), mul128_reference(a, b), "{a:#x} {b:#x}");
        }
    }

    #[test]
    fn mul128_is_the_gcm_field() {
        assert_eq!(mul128(1 << 127, 2), 0x87, "x^128 = x^7 + x^2 + x + 1");
        let (a, b, c) = (0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, u128::MAX / 7, (1u128 << 100) | 0x87);
        assert_eq!(mul128(a, 1), a);
        assert_eq!(mul128(a, b), mul128(b, a));
        assert_eq!(mul128(a, b ^ c), mul128(a, b) ^ mul128(a, c));
        assert_eq!(mul128(mul128(a, b), c), mul128(a, mul128(b, c)));
    }

    #[test]
    fn affine8_matches_scalar() {
        let maps = [
            Affine::new([1, 2, 4, 8, 16, 32, 64, 128], 0),
            Affine::new([0x5f, 0x76, 0x0f, 0x88, 0x20, 0x7d, 0xec, 0xdb], 0xa8),
            Affine::new([0xff, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x03], 0x63),
        ];
        for a in maps {
            let a8 = Affine8::new(&a);
            for x in 0..=255u8 {
                let v = |i: usize| x.wrapping_add((i * 29) as u8);
                let y = a8.apply(lanes(v));
                for i in 0..8 {
                    assert_eq!(lane(y, i), a.apply(v(i)));
                }
            }
        }
    }
}
