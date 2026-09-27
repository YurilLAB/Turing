//! The plain-LWE encryption inside Turing-1026 (docs/16), for any parameter
//! set: Turing-1026's own, and the small ones Bombe breaks and measures.
//!
//! Lindner-Peikert encryption on unstructured LWE, the scheme FrodoPKE also
//! instantiates:
//!
//! ```text
//! key generation  B  = A S + E                        A: n x n; S, E: n x nbar
//! encryption      B' = S' A + E'                      S', E': mbar x n
//!                 C  = S' B + E'' + Encode(m)         E'': mbar x nbar
//! decryption      m  = Decode(C - B' S)
//! ```
//!
//! C - B' S = Encode(m) + S'E - E'S + E'', so decryption is right while every
//! coefficient of S'E - E'S + E'' lies in [-q/4, q/4): with one message bit
//! per coefficient, Encode puts bit b at b q/2 and Decode rounds to the
//! nearer of 0 and q/2. How often that fails is docs/16's exact
//! decryption-failure computation.
//!
//! This is IND-CPA only: a building block of the KEM in `turing1026`, which
//! adds the Fujisaki-Okamoto transform. Never use it on its own.
//!
//! Arithmetic is mod q = 2^log_q in wrapping u16 arithmetic, reduced with a
//! mask at the end, so nothing divides (the KyberSlash class of leaks).
//! Secret values are only multiplied, added, masked and shifted: no branch
//! and no memory index depends on them.

use crate::xof::{self, SecretXof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

/// The public seed from which A is expanded.
pub const SEED_A_BYTES: usize = 32;
pub const MATRIX_LABEL: &str = "Turing-1026 v1 matrix";

/// A parameter set. Turing-1026's is `turing1026::PARAMS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// LWE dimension: A is n x n.
    pub n: usize,
    /// Columns of the key secret S: the public key's width.
    pub nbar: usize,
    /// Rows of the encryption secret S': the ciphertext's height.
    pub mbar: usize,
    /// q = 2^log_q.
    pub log_q: u32,
    /// The noise distribution: centred binomial CBD(eta), the difference of
    /// two sums of eta random bits (variance eta / 2).
    pub eta: u32,
}

impl Params {
    pub const fn q_mask(&self) -> u16 {
        ((1u32 << self.log_q) - 1) as u16
    }

    /// Bytes holding `coefficients` values of log_q bits each.
    pub const fn packed_bytes(&self, coefficients: usize) -> usize {
        (coefficients * self.log_q as usize).div_ceil(8)
    }

    /// seed_a, then B packed.
    pub const fn public_key_bytes(&self) -> usize {
        SEED_A_BYTES + self.packed_bytes(self.n * self.nbar)
    }

    /// B', then C, both packed.
    pub const fn ciphertext_bytes(&self) -> usize {
        self.packed_bytes(self.mbar * self.n) + self.packed_bytes(self.mbar * self.nbar)
    }

    /// One message bit per coefficient of C.
    pub const fn message_bytes(&self) -> usize {
        self.mbar * self.nbar / 8
    }

    /// Panics unless the implementation supports these parameters.
    pub fn validate(&self) {
        assert!((4..=16).contains(&self.log_q), "log_q must be 4..=16");
        assert!((1..=32).contains(&self.eta), "eta must be 1..=32");
        assert!((1..=65536).contains(&self.n), "A's row index is 2 bytes");
        assert!((1..=MAX_NBAR).contains(&self.nbar) && self.mbar >= 1, "nbar must be 1..={MAX_NBAR}");
        assert!((self.mbar * self.nbar).is_multiple_of(8), "the message must be whole bytes");
    }
}

/// Largest nbar `decrypt` supports (it keeps one row of C - B'S).
pub const MAX_NBAR: usize = 64;

/// Row i of A: cSHAKE256(X = seed_a || i as 2 bytes little-endian,
/// S = MATRIX_LABEL), 2 bytes per coefficient, little-endian, reduced mod q.
/// A is public, so the library's cSHAKE (not `SecretXof`) is fine.
pub fn matrix_row(p: &Params, seed_a: &[u8; SEED_A_BYTES], i: usize, row: &mut [u16]) {
    assert_eq!(row.len(), p.n);
    let mut input = [0u8; SEED_A_BYTES + 2];
    input[..SEED_A_BYTES].copy_from_slice(seed_a);
    input[SEED_A_BYTES..].copy_from_slice(&(i as u16).to_le_bytes());
    let mut reader = xof::cshake256(MATRIX_LABEL, &input);
    let mut buf = [0u8; 256];
    let mask = p.q_mask();
    for chunk in row.chunks_mut(128) {
        let bytes = &mut buf[..2 * chunk.len()];
        reader.read(bytes);
        for (c, b) in chunk.iter_mut().zip(bytes.chunks_exact(2)) {
            *c = u16::from_le_bytes([b[0], b[1]]) & mask;
        }
    }
}

/// Adds one CBD(eta) sample to every entry of `out` (mod 2^16). Each sample
/// takes the next 2 eta bits of `noise`, least significant bit of each byte
/// first: the first eta bits count +1 each, the next eta -1 each. Every call
/// starts at a fresh byte of the stream. The loop's shape depends only on
/// eta and the length; `count_ones` is branch-free.
pub fn add_noise(eta: u32, noise: &mut SecretXof, out: &mut [u16]) {
    let need = 2 * eta;
    let mask = (1u64 << eta) - 1;
    let mut bits: u128 = 0;
    let mut have = 0u32;
    let mut byte = [0u8; 1];
    for o in out.iter_mut() {
        while have < need {
            noise.squeeze(&mut byte);
            bits |= u128::from(byte[0]) << have;
            have += 8;
        }
        let plus = (bits as u64 & mask).count_ones() as u16;
        let minus = ((bits >> eta) as u64 & mask).count_ones() as u16;
        bits >>= need;
        have -= need;
        *o = o.wrapping_add(plus).wrapping_sub(minus);
    }
    bits.zeroize();
    byte.zeroize();
}

/// Key generation: S (n x nbar, row-major) from `noise`, then B = A S + E,
/// with E drawn from the same stream after S. `s` is secret; `b` holds A S,
/// which gives S away, until E is added at the end, so callers keep it in
/// secret memory until then.
pub fn keygen(p: &Params, seed_a: &[u8; SEED_A_BYTES], noise: &mut SecretXof, s: &mut [u16], b: &mut [u16]) {
    p.validate();
    assert!(s.len() == p.n * p.nbar && b.len() == p.n * p.nbar);
    s.fill(0);
    add_noise(p.eta, noise, s);
    // Rows are sliced by multiplying indices, not with chunks_exact, whose
    // length division by a run-time size is the only `div` rustc would emit
    // here: the division scan (tools/asm_branches.py --divs) then reads zero.
    let mut row = vec![0u16; p.n];
    for i in 0..p.n {
        matrix_row(p, seed_a, i, &mut row);
        let bi = &mut b[i * p.nbar..(i + 1) * p.nbar];
        bi.fill(0);
        for (k, &a) in row.iter().enumerate() {
            let sk = &s[k * p.nbar..(k + 1) * p.nbar];
            for (x, &y) in bi.iter_mut().zip(sk) {
                *x = x.wrapping_add(a.wrapping_mul(y));
            }
        }
    }
    add_noise(p.eta, noise, b);
    let mask = p.q_mask();
    b.iter_mut().for_each(|x| *x &= mask);
}

/// Whether `b` is A S + E for this `s` with every entry of E in [-eta, eta]:
/// B - A S recomputed row by row, each entry centred and range-checked
/// without branching on it (E is secret). A key corrupted after it was made
/// fails this whatever the corruption: an S entry changed by d changes
/// column j of A S by A[i][k] d in all n rows, and a uniform A puts some of
/// them far outside [-eta, eta] (probability about (37/32768)^1026 that none
/// does). This is the deterministic check Fahr et al. recommend for FrodoKEM
/// ("When Frodo Flips", CCS 2022, section 8.2), where a one-ciphertext
/// pair-wise check misses about 2^-8 of single-bit faults in S (research/
/// reviews/2026-09-28 R5). As costly as key generation's A S.
pub fn check_key(p: &Params, seed_a: &[u8; SEED_A_BYTES], s: &[u16], b: &[u16]) -> bool {
    p.validate();
    assert!(s.len() == p.n * p.nbar && b.len() == p.n * p.nbar);
    let (mask, eta) = (p.q_mask(), p.eta as u16);
    let mut row = vec![0u16; p.n];
    let mut acc = vec![0u16; p.nbar];
    let mut bad = 0u32;
    for i in 0..p.n {
        matrix_row(p, seed_a, i, &mut row);
        acc.fill(0);
        for (k, &a) in row.iter().enumerate() {
            for (x, &y) in acc.iter_mut().zip(&s[k * p.nbar..(k + 1) * p.nbar]) {
                *x = x.wrapping_add(a.wrapping_mul(y));
            }
        }
        for (x, &bi) in acc.iter().zip(&b[i * p.nbar..(i + 1) * p.nbar]) {
            // e + eta lies in [0, 2 eta] exactly when e is in range; outside
            // it, 2 eta - (e + eta) borrows into bit 31 (any log_q <= 16).
            let shifted = u32::from(bi.wrapping_sub(*x).wrapping_add(eta) & mask);
            bad |= (2 * u32::from(eta)).wrapping_sub(shifted) >> 31;
        }
    }
    acc.zeroize();
    core::hint::black_box(bad) == 0
}

/// Encrypts `msg` (message_bytes() bytes, bit i of the message in
/// coefficient i of C, least significant bit of each byte first) under the
/// public key (seed_a, B). S', E', E'' are drawn from `noise` in that order.
/// `sp` receives S' (mbar x n, secret), `bp` receives B' (mbar x n) and `c`
/// receives C (mbar x nbar).
#[allow(clippy::too_many_arguments)]
pub fn encrypt(p: &Params, seed_a: &[u8; SEED_A_BYTES], b: &[u16], msg: &[u8], noise: &mut SecretXof, sp: &mut [u16], bp: &mut [u16], c: &mut [u16]) {
    p.validate();
    assert!(b.len() == p.n * p.nbar && msg.len() == p.message_bytes());
    assert!(sp.len() == p.mbar * p.n && bp.len() == p.mbar * p.n && c.len() == p.mbar * p.nbar);
    sp.fill(0);
    add_noise(p.eta, noise, sp);
    // B' = S' A + E', one row of A at a time: row k of A meets column k of S'.
    bp.fill(0);
    let mut row = vec![0u16; p.n];
    for k in 0..p.n {
        matrix_row(p, seed_a, k, &mut row);
        for r in 0..p.mbar {
            let s = sp[r * p.n + k];
            for (x, &a) in bp[r * p.n..(r + 1) * p.n].iter_mut().zip(&row) {
                *x = x.wrapping_add(s.wrapping_mul(a));
            }
        }
    }
    add_noise(p.eta, noise, bp);
    // C = S' B + E'' + Encode(msg).
    c.fill(0);
    for r in 0..p.mbar {
        let cr = &mut c[r * p.nbar..(r + 1) * p.nbar];
        for k in 0..p.n {
            let s = sp[r * p.n + k];
            for (x, &y) in cr.iter_mut().zip(&b[k * p.nbar..(k + 1) * p.nbar]) {
                *x = x.wrapping_add(s.wrapping_mul(y));
            }
        }
    }
    add_noise(p.eta, noise, c);
    let half = 1u16 << (p.log_q - 1);
    for (i, x) in c.iter_mut().enumerate() {
        let bit = u16::from((msg[i / 8] >> (i % 8)) & 1);
        *x = x.wrapping_add(bit.wrapping_mul(half));
    }
    let mask = p.q_mask();
    bp.iter_mut().chain(c.iter_mut()).for_each(|x| *x &= mask);
}

/// Decrypts (B', C) with S into `msg`: each coefficient of C - B' S rounds
/// to the nearer of 0 (bit 0) and q/2 (bit 1).
pub fn decrypt(p: &Params, s: &[u16], bp: &[u16], c: &[u16], msg: &mut [u8]) {
    p.validate();
    assert!(s.len() == p.n * p.nbar && bp.len() == p.mbar * p.n && c.len() == p.mbar * p.nbar);
    assert_eq!(msg.len(), p.message_bytes());
    msg.fill(0);
    let (mask, quarter, shift) = (p.q_mask(), 1u16 << (p.log_q - 2), p.log_q - 1);
    let mut m = [0u16; MAX_NBAR];
    for r in 0..p.mbar {
        let m = &mut m[..p.nbar];
        m.copy_from_slice(&c[r * p.nbar..(r + 1) * p.nbar]);
        for k in 0..p.n {
            let v = bp[r * p.n + k];
            for (x, &y) in m.iter_mut().zip(&s[k * p.nbar..(k + 1) * p.nbar]) {
                *x = x.wrapping_sub(v.wrapping_mul(y));
            }
        }
        for (j, &x) in m.iter().enumerate() {
            let i = r * p.nbar + j;
            let bit = ((x.wrapping_add(quarter) & mask) >> shift) as u8;
            msg[i / 8] |= bit << (i % 8);
        }
    }
    m.zeroize();
}

/// Packs coefficients of log_q bits each, least significant bit first:
/// coefficient i occupies bits [i log_q, (i + 1) log_q) of `out` read as one
/// little-endian number. Entries are reduced mod q first.
pub fn pack(log_q: u32, coefficients: &[u16], out: &mut [u8]) {
    assert_eq!(out.len(), (coefficients.len() * log_q as usize).div_ceil(8));
    let mask = (1u32 << log_q) - 1;
    let (mut acc, mut bits, mut o) = (0u32, 0u32, 0usize);
    for &c in coefficients {
        acc |= (u32::from(c) & mask) << bits;
        bits += log_q;
        while bits >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    if bits > 0 {
        out[o] = acc as u8;
    }
    acc.zeroize();
}

/// The inverse of `pack`. Every log_q-bit field is a valid coefficient, so
/// there is nothing to reject; bits past the last field are ignored.
pub fn unpack(log_q: u32, bytes: &[u8], out: &mut [u16]) {
    assert_eq!(bytes.len(), (out.len() * log_q as usize).div_ceil(8));
    let mask = (1u32 << log_q) - 1;
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0usize);
    for o in out.iter_mut() {
        while bits < log_q {
            acc |= u32::from(bytes[i]) << bits;
            i += 1;
            bits += 8;
        }
        *o = (acc & mask) as u16;
        acc >>= log_q;
        bits -= log_q;
    }
    acc.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOY: Params = Params { n: 64, nbar: 8, mbar: 4, log_q: 12, eta: 2 };

    fn stream(label: &str, seed: u8) -> SecretXof {
        let mut x = SecretXof::new(label);
        x.absorb(&[seed]);
        x
    }

    #[test]
    fn pack_round_trips_and_is_little_endian() {
        for log_q in 4..=16u32 {
            let values: Vec<u16> = (0..37u32).map(|i| (i.wrapping_mul(40503) >> 3) as u16 & ((1u32 << log_q) - 1) as u16).collect();
            let mut bytes = vec![0u8; (values.len() * log_q as usize).div_ceil(8)];
            pack(log_q, &values, &mut bytes);
            let mut back = vec![0u16; values.len()];
            unpack(log_q, &bytes, &mut back);
            assert_eq!(back, values, "log_q {log_q}");
        }
        // 15-bit fields: 0x7fff then 1 -> bits 0..15 set, then bit 15.
        let mut bytes = [0u8; 4];
        pack(15, &[0x7fff, 1], &mut bytes);
        assert_eq!(bytes, [0xff, 0xff, 0x00, 0x00]);
        pack(15, &[0, 1], &mut bytes);
        assert_eq!(bytes, [0x00, 0x80, 0x00, 0x00]);
    }

    // The sampler's law is CBD(eta): over many samples the counts of each
    // value match C(2 eta, eta + v) / 4^eta.
    #[test]
    fn noise_has_the_centred_binomial_law() {
        for eta in [1u32, 2, 18] {
            let mut x = stream("Turing-1026 v1 test", eta as u8);
            let mut out = vec![0u16; 200_000];
            add_noise(eta, &mut x, &mut out);
            let mut counts = std::collections::HashMap::new();
            for &v in &out {
                *counts.entry(v as i16).or_insert(0u32) += 1;
            }
            let binom = |k: u32| -> f64 { (0..k).fold(1.0, |acc, i| acc * f64::from(2 * eta - i) / f64::from(i + 1)) };
            for v in -(eta as i32)..=eta as i32 {
                let p = binom((eta as i32 + v) as u32) / 4f64.powi(eta as i32);
                let expected = p * out.len() as f64;
                let got = f64::from(*counts.get(&(v as i16)).unwrap_or(&0));
                let sd = (expected * (1.0 - p)).sqrt().max(1.0);
                assert!((got - expected).abs() < 6.0 * sd, "eta {eta} value {v}: {got} vs {expected}");
            }
            assert!(counts.keys().all(|&v| v.unsigned_abs() as u32 <= eta));
        }
    }

    // Bit order: with eta = 1, the stream byte 0b0000_0001 gives +1, then
    // 0b0000_0010 gives -1 (first bit counts +, second -), and so on.
    #[test]
    fn noise_reads_bits_least_significant_first() {
        let mut x = stream("Turing-1026 v1 test", 7);
        let mut first = [0u8; 1];
        x.squeeze(&mut first);
        let mut y = stream("Turing-1026 v1 test", 7);
        let mut out = [0u16; 4];
        add_noise(1, &mut y, &mut out);
        for (k, &o) in out.iter().enumerate() {
            let plus = (first[0] >> (2 * k)) & 1;
            let minus = (first[0] >> (2 * k + 1)) & 1;
            assert_eq!(o, u16::from(plus).wrapping_sub(u16::from(minus)));
        }
    }

    #[test]
    fn decrypts_what_it_encrypts() {
        let p = TOY;
        let seed_a = [3u8; 32];
        let mut s = vec![0u16; p.n * p.nbar];
        let mut b = vec![0u16; p.n * p.nbar];
        keygen(&p, &seed_a, &mut stream("Turing-1026 v1 test", 1), &mut s, &mut b);
        for trial in 0..20u8 {
            let msg: Vec<u8> = (0..p.message_bytes() as u8).map(|i| i.wrapping_mul(97).wrapping_add(trial)).collect();
            let (mut sp, mut bp, mut c) = (vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.nbar]);
            encrypt(&p, &seed_a, &b, &msg, &mut stream("Turing-1026 v1 test", 100 + trial), &mut sp, &mut bp, &mut c);
            let mut back = vec![0u8; p.message_bytes()];
            decrypt(&p, &s, &bp, &c, &mut back);
            assert_eq!(back, msg, "trial {trial}");
        }
    }

    // B really is A S + E with small E, computed from the rows of A.
    #[test]
    fn public_key_is_an_lwe_sample() {
        let p = TOY;
        let seed_a = [9u8; 32];
        let mut s = vec![0u16; p.n * p.nbar];
        let mut b = vec![0u16; p.n * p.nbar];
        keygen(&p, &seed_a, &mut stream("Turing-1026 v1 test", 2), &mut s, &mut b);
        let mut row = vec![0u16; p.n];
        for i in 0..p.n {
            matrix_row(&p, &seed_a, i, &mut row);
            for j in 0..p.nbar {
                let dot = (0..p.n).fold(0u16, |acc, k| acc.wrapping_add(row[k].wrapping_mul(s[k * p.nbar + j])));
                let e = b[i * p.nbar + j].wrapping_sub(dot) & p.q_mask();
                let centred = if e >= 1 << (p.log_q - 1) { i32::from(e) - (1 << p.log_q) } else { i32::from(e) };
                assert!(centred.unsigned_abs() <= p.eta, "E[{i}][{j}] = {centred}");
            }
        }
        assert!(s.iter().all(|&v| (v as i16).unsigned_abs() as u32 <= p.eta));
    }

    // check_key accepts the key it made and refuses every single-bit change
    // of S that matters mod q: all 512 entries, all 12 bits, exhaustively.
    #[test]
    fn check_key_catches_every_single_bit_fault_in_s() {
        let p = TOY;
        let seed_a = [5u8; 32];
        let mut s = vec![0u16; p.n * p.nbar];
        let mut b = vec![0u16; p.n * p.nbar];
        keygen(&p, &seed_a, &mut stream("Turing-1026 v1 test", 3), &mut s, &mut b);
        assert!(check_key(&p, &seed_a, &s, &b), "control: the key as made passes");
        for entry in 0..s.len() {
            for bit in 0..p.log_q {
                s[entry] ^= 1 << bit;
                assert!(!check_key(&p, &seed_a, &s, &b), "S[{entry}] bit {bit} passed");
                s[entry] ^= 1 << bit;
            }
        }
        // A public key that is not A S + small noise for this S fails too.
        let mut other = b.clone();
        other[7] = other[7].wrapping_add(1 << (p.log_q - 1)) & p.q_mask();
        assert!(!check_key(&p, &seed_a, &s, &other));
        assert!(!check_key(&p, &[6u8; 32], &s, &b), "another matrix");
    }

    #[test]
    fn matrix_rows_differ_and_are_reduced() {
        let p = Params { log_q: 15, ..TOY };
        let (mut r0, mut r1) = (vec![0u16; p.n], vec![0u16; p.n]);
        matrix_row(&p, &[1; 32], 0, &mut r0);
        matrix_row(&p, &[1; 32], 1, &mut r1);
        assert_ne!(r0, r1);
        assert!(r0.iter().chain(&r1).all(|&v| v < 1 << 15));
        matrix_row(&p, &[2; 32], 0, &mut r1);
        assert_ne!(r0, r1);
    }
}
