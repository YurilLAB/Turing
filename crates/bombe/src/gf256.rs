//! Arithmetic in GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1.
//!
//! Only used to build the AES reference S-box that validates the tools.
//! Generating it from its definition avoids hand-typing 256 values.

pub fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// Multiplicative inverse, with inv(0) = 0 as AES defines it.
/// The non-zero elements form a group of order 255, so a^254 = a^-1.
pub fn inv(a: u8) -> u8 {
    let (mut result, mut base, mut e) = (1u8, a, 254u32);
    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    if a == 0 {
        0
    } else {
        result
    }
}

/// The AES S-box (FIPS-197 §5.1.1): field inverse followed by an affine map.
pub fn aes_sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    for (x, out) in table.iter_mut().enumerate() {
        let b = inv(x as u8);
        *out = b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
    }
    table
}

/// Log/antilog tables for fast multiplication in the analysis tools, built
/// from the generator 0x03. Not constant-time; never used by the cipher.
struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static TABLES: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Tables { exp: [0; 512], log: [0; 256] };
        let mut x = 1u8;
        for i in 0..255 {
            t.exp[i] = x;
            t.exp[i + 255] = x;
            t.log[x as usize] = i as u8;
            x = mul(x, 3);
        }
        t
    })
}

pub fn fast_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

pub fn fast_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}
