//! ML-KEM (FIPS 203, August 2024), written from the standard for Turing's
//! hybrid key encapsulation, where ML-KEM-1024 is the second lattice beside
//! Turing-1026 (docs/18). All three parameter sets are implemented so that
//! every group of NIST's validation vectors exercises the shared code
//! (bombe tests/mlkem.rs); the hybrid uses ML-KEM-1024 only.
//!
//! The algorithm numbers below are FIPS 203's. Hash functions (section 4.1):
//! H = SHA3-256, J = SHAKE256 to 32 bytes, G = SHA3-512 split in two,
//! PRF_eta(s, b) = SHAKE256(s || b) to 64 eta bytes, XOF = SHAKE128.
//!
//! Constant time: every value derived from a secret is only added,
//! multiplied, masked and shifted. Reduction mod q is Barrett with a masked
//! final subtraction; Compress divides by q through an exact multiply and
//! shift (tests check every input), never a division instruction, which on
//! secret data is the KyberSlash leak (Bernstein et al., TCHES 2025(2)).
//! SampleNTT's rejection loop reads only public data (the matrix seed), and
//! the re-encryption check compares every byte and selects the key with a
//! mask.
//!
//! The internal, derandomised functions (FIPS 203 section 6) "should not be
//! made available to applications other than for testing": they are
//! crate-internal, and public only in analysis builds for the known-answer
//! tests.

use crate::linear::opaque;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use zeroize::Zeroize;

/// A parameter set (FIPS 203, Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: u32,
    pub dv: u32,
}

pub const ML_KEM_512: Params = Params { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 };
pub const ML_KEM_768: Params = Params { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 };
pub const ML_KEM_1024: Params = Params { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 };

impl Params {
    /// Encapsulation key: 384 k + 32 bytes (FIPS 203, Table 3).
    pub const fn ek_bytes(&self) -> usize {
        384 * self.k + 32
    }

    /// Decapsulation key: 768 k + 96 bytes.
    pub const fn dk_bytes(&self) -> usize {
        768 * self.k + 96
    }

    /// Ciphertext: 32 (du k + dv) bytes.
    pub const fn ct_bytes(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
}

const N: usize = 256;
const Q: u32 = 3329;
const MAX_K: usize = 4;
type Poly = [u16; N];

// ---------------------------------------------------------------- arithmetic

/// y - q if y >= q, else y, for y < 2q; the choice is a mask, not a branch.
#[inline]
fn csub(y: u32) -> u16 {
    let t = y.wrapping_sub(Q);
    t.wrapping_add(Q & (t >> 31).wrapping_neg()) as u16
}

/// x mod q for any x < 2^24 (Barrett): floor(x * 20642678 / 2^36) is
/// floor(x / q) or one less, so one masked subtraction finishes it. Every
/// x < 2^24 is checked in the tests.
#[inline]
fn reduce(x: u32) -> u16 {
    let t = ((u64::from(x) * 20_642_678) >> 36) as u32;
    csub(x - t * Q)
}

#[inline]
fn add(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + u32::from(b))
}

#[inline]
fn sub(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + Q - u32::from(b))
}

#[inline]
fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a) * u32::from(b))
}

/// ceil(2^40 / q): floor(v * COMPRESS_M / 2^40) = floor(v / q) for every
/// v < 2^23, which covers every numerator Compress forms (tests check all).
const COMPRESS_M: u64 = (1u64 << 40).div_ceil(Q as u64);

/// Compress_d(x) = round(2^d x / q) mod 2^d (FIPS 203, eq. 4.7), for x < q
/// and d <= 11. With q odd there are no ties, and round(a / q) = floor((a +
/// 1664) / q).
#[inline]
fn compress(x: u16, d: u32) -> u16 {
    let v = (u32::from(x) << d) + 1664;
    let quotient = ((u64::from(v) * COMPRESS_M) >> 40) as u32;
    (quotient & ((1 << d) - 1)) as u16
}

/// Decompress_d(y) = round(q y / 2^d) (eq. 4.8): a shift, exact.
#[inline]
fn decompress(y: u16, d: u32) -> u16 {
    ((u32::from(y) * Q + (1 << (d - 1))) >> d) as u16
}

// ---------------------------------------------------------------- the NTT

const fn bitrev7(i: usize) -> usize {
    let mut r = 0;
    let mut b = 0;
    while b < 7 {
        r |= ((i >> b) & 1) << (6 - b);
        b += 1;
    }
    r
}

const fn pow17(mut e: usize) -> u16 {
    let (mut r, mut b) = (1u32, 17u32);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q;
        }
        b = b * b % Q;
        e >>= 1;
    }
    r as u16
}

/// zeta^BitRev7(i) mod q, zeta = 17 (FIPS 203 Appendix A, first table).
pub(crate) const ZETAS: [u16; 128] = {
    let mut z = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow17(bitrev7(i));
        i += 1;
    }
    z
};

/// zeta^(2 BitRev7(i) + 1) mod q (Appendix A, second table).
pub(crate) const GAMMAS: [u16; 128] = {
    let mut g = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        g[i] = pow17(2 * bitrev7(i) + 1);
        i += 1;
    }
    g
};

/// Algorithm 9, in place.
fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mul(zeta, f[j + len]);
                f[j + len] = sub(f[j], t);
                f[j] = add(f[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Algorithm 10, in place; 3303 = 128^-1 mod q.
fn ntt_inverse(f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = add(t, f[j + len]);
                f[j + len] = mul(zeta, sub(f[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for x in f.iter_mut() {
        *x = mul(*x, 3303);
    }
}

/// acc += f x g in T_q (Algorithms 11 and 12).
fn multiply_ntts_add(f: &Poly, g: &Poly, acc: &mut Poly) {
    for i in 0..128 {
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        let c0 = add(mul(a0, b0), mul(mul(a1, b1), GAMMAS[i]));
        let c1 = add(mul(a0, b1), mul(a1, b0));
        acc[2 * i] = add(acc[2 * i], c0);
        acc[2 * i + 1] = add(acc[2 * i + 1], c1);
    }
}

// ---------------------------------------------------------------- encoding

/// ByteEncode_d (Algorithm 5): 256 d-bit values, least significant bit first.
fn byte_encode(d: u32, f: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d as usize);
    let (mut acc, mut bits, mut o) = (0u32, 0u32, 0usize);
    for &c in f.iter() {
        acc |= u32::from(c) << bits;
        bits += d;
        while bits >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// ByteDecode_d (Algorithm 6); for d = 12 each value is reduced mod q (a
/// masked subtraction, since values below 4096 are below 2q).
fn byte_decode(d: u32, bytes: &[u8], f: &mut Poly) {
    debug_assert_eq!(bytes.len(), 32 * d as usize);
    let mask = (1u32 << d) - 1;
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0usize);
    for c in f.iter_mut() {
        while bits < d {
            acc |= u32::from(bytes[i]) << bits;
            i += 1;
            bits += 8;
        }
        let v = acc & mask;
        acc >>= d;
        bits -= d;
        *c = if d == 12 { csub(v) } else { v as u16 };
    }
}

// ---------------------------------------------------------------- sampling

/// SampleNTT (Algorithm 7) on the public seed rho with the bytes j, i.
fn sample_ntt(rho: &[u8], j: u8, i: u8, a: &mut Poly) {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[j, i]);
    let mut reader = xof.finalize_xof();
    let mut c = [0u8; 3];
    let mut n = 0;
    while n < N {
        reader.read(&mut c);
        let d1 = u32::from(c[0]) | (u32::from(c[1] & 15) << 8);
        let d2 = u32::from(c[1] >> 4) | (u32::from(c[2]) << 4);
        if d1 < Q {
            a[n] = d1 as u16;
            n += 1;
        }
        if d2 < Q && n < N {
            a[n] = d2 as u16;
            n += 1;
        }
    }
}

/// SamplePolyCBD_eta (Algorithm 8) on 64 eta bytes.
fn sample_cbd(eta: usize, b: &[u8], f: &mut Poly) {
    debug_assert_eq!(b.len(), 64 * eta);
    for (i, c) in f.iter_mut().enumerate() {
        let (mut x, mut y) = (0u32, 0u32);
        for j in 0..eta {
            let bx = 2 * i * eta + j;
            let by = bx + eta;
            x += u32::from((b[bx >> 3] >> (bx & 7)) & 1);
            y += u32::from((b[by >> 3] >> (by & 7)) & 1);
        }
        *c = csub(x + Q - y);
    }
}

/// PRF_eta(s, b) = SHAKE256(s || b), 64 eta bytes, then SamplePolyCBD_eta.
fn prf_cbd(eta: usize, s: &[u8; 32], b: u8, f: &mut Poly) {
    let mut buf = [0u8; 64 * 3];
    let mut h = Shake256::default();
    h.update(s);
    h.update(&[b]);
    h.finalize_xof().read(&mut buf[..64 * eta]);
    sample_cbd(eta, &buf[..64 * eta], f);
    buf.zeroize();
}

fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_512::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    let mut out = h.finalize();
    let a: [u8; 32] = out[..32].try_into().expect("32 bytes");
    let b: [u8; 32] = out[32..].try_into().expect("32 bytes");
    out.zeroize();
    (a, b)
}

pub(crate) fn h(x: &[u8]) -> [u8; 32] {
    Sha3_256::digest(x).into()
}

fn j(z: &[u8], c: &[u8], out: &mut [u8; 32]) {
    let mut s = Shake256::default();
    s.update(z);
    s.update(c);
    s.finalize_xof().read(out);
}

/// A_hat[i][j] = SampleNTT(rho || j || i) (Algorithm 13, line 5).
fn matrix(p: &Params, rho: &[u8], a: &mut [[Poly; MAX_K]; MAX_K]) {
    for (i, row) in a.iter_mut().enumerate().take(p.k) {
        for (j, entry) in row.iter_mut().enumerate().take(p.k) {
            sample_ntt(rho, j as u8, i as u8, entry);
        }
    }
}

// ---------------------------------------------------------------- K-PKE

/// K-PKE.KeyGen (Algorithm 13). `ipd` uses the draft's G(d) instead of the
/// final G(d || k); it exists only to run the C2SP CCTV vectors, which were
/// made for the draft (docs/18).
fn kpke_keygen(p: &Params, d: &[u8; 32], ipd: bool, ek: &mut [u8], dk_pke: &mut [u8]) {
    let k_byte = [p.k as u8];
    let (rho, mut sigma) = if ipd { g(&[d]) } else { g(&[d, &k_byte]) };
    let mut a = [[[0u16; N]; MAX_K]; MAX_K];
    matrix(p, &rho, &mut a);
    let mut s = [[0u16; N]; MAX_K];
    let mut e = [[0u16; N]; MAX_K];
    let mut nonce = 0u8;
    for si in s.iter_mut().take(p.k) {
        prf_cbd(p.eta1, &sigma, nonce, si);
        nonce += 1;
    }
    for ei in e.iter_mut().take(p.k) {
        prf_cbd(p.eta1, &sigma, nonce, ei);
        nonce += 1;
    }
    sigma.zeroize();
    for i in 0..p.k {
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }
    for i in 0..p.k {
        let mut t = e[i];
        for jj in 0..p.k {
            multiply_ntts_add(&a[i][jj], &s[jj], &mut t);
        }
        byte_encode(12, &t, &mut ek[384 * i..384 * (i + 1)]);
        byte_encode(12, &s[i], &mut dk_pke[384 * i..384 * (i + 1)]);
        t.zeroize();
    }
    ek[384 * p.k..384 * p.k + 32].copy_from_slice(&rho);
    s.zeroize();
    e.zeroize();
}

/// K-PKE.Encrypt (Algorithm 14).
fn kpke_encrypt(p: &Params, ek: &[u8], m: &[u8; 32], r: &[u8; 32], c: &mut [u8]) {
    let mut t = [[0u16; N]; MAX_K];
    for (i, ti) in t.iter_mut().enumerate().take(p.k) {
        byte_decode(12, &ek[384 * i..384 * (i + 1)], ti);
    }
    let rho = &ek[384 * p.k..384 * p.k + 32];
    let mut a = [[[0u16; N]; MAX_K]; MAX_K];
    matrix(p, rho, &mut a);
    let mut y = [[0u16; N]; MAX_K];
    let mut e1 = [[0u16; N]; MAX_K];
    let mut e2 = [0u16; N];
    let mut nonce = 0u8;
    for yi in y.iter_mut().take(p.k) {
        prf_cbd(p.eta1, r, nonce, yi);
        nonce += 1;
    }
    for ei in e1.iter_mut().take(p.k) {
        prf_cbd(p.eta2, r, nonce, ei);
        nonce += 1;
    }
    prf_cbd(p.eta2, r, nonce, &mut e2);
    for yi in y.iter_mut().take(p.k) {
        ntt(yi);
    }
    let du_bytes = 32 * p.du as usize;
    for i in 0..p.k {
        // u[i] = NTT^-1(sum_j A_hat[j][i] o y_hat[j]) + e1[i]   (A transposed)
        let mut u = [0u16; N];
        for jj in 0..p.k {
            multiply_ntts_add(&a[jj][i], &y[jj], &mut u);
        }
        ntt_inverse(&mut u);
        for (x, &e) in u.iter_mut().zip(e1[i].iter()) {
            *x = compress(add(*x, e), p.du);
        }
        byte_encode(p.du, &u, &mut c[du_bytes * i..du_bytes * (i + 1)]);
        u.zeroize();
    }
    // v = NTT^-1(t_hat^T o y_hat) + e2 + Decompress_1(ByteDecode_1(m))
    let mut v = [0u16; N];
    for i in 0..p.k {
        multiply_ntts_add(&t[i], &y[i], &mut v);
    }
    ntt_inverse(&mut v);
    let mut mu = [0u16; N];
    byte_decode(1, m, &mut mu);
    for (x, (&e, &b)) in v.iter_mut().zip(e2.iter().zip(mu.iter())) {
        *x = compress(add(add(*x, e), decompress(b, 1)), p.dv);
    }
    let off = du_bytes * p.k;
    byte_encode(p.dv, &v, &mut c[off..off + 32 * p.dv as usize]);
    y.zeroize();
    e1.zeroize();
    e2.zeroize();
    v.zeroize();
    mu.zeroize();
}

/// K-PKE.Decrypt (Algorithm 15).
fn kpke_decrypt(p: &Params, dk_pke: &[u8], c: &[u8], m: &mut [u8; 32]) {
    let du_bytes = 32 * p.du as usize;
    let mut w = [0u16; N];
    for i in 0..p.k {
        let mut u = [0u16; N];
        byte_decode(p.du, &c[du_bytes * i..du_bytes * (i + 1)], &mut u);
        for x in u.iter_mut() {
            *x = decompress(*x, p.du);
        }
        ntt(&mut u);
        let mut s = [0u16; N];
        byte_decode(12, &dk_pke[384 * i..384 * (i + 1)], &mut s);
        multiply_ntts_add(&s, &u, &mut w);
        s.zeroize();
    }
    ntt_inverse(&mut w);
    let off = du_bytes * p.k;
    let mut v = [0u16; N];
    byte_decode(p.dv, &c[off..off + 32 * p.dv as usize], &mut v);
    for (x, &vv) in w.iter_mut().zip(v.iter()) {
        *x = compress(sub(decompress(vv, p.dv), *x), 1);
    }
    byte_encode(1, &w, m);
    w.zeroize();
}

// ---------------------------------------------------------------- ML-KEM

/// ML-KEM.KeyGen_internal (Algorithm 16): dk = dk_pke || ek || H(ek) || z.
pub(crate) fn keygen_inner(p: &Params, d: &[u8; 32], z: &[u8; 32], ipd: bool, ek: &mut [u8], dk: &mut [u8]) {
    assert!(ek.len() == p.ek_bytes() && dk.len() == p.dk_bytes());
    let pke = 384 * p.k;
    kpke_keygen(p, d, ipd, ek, &mut dk[..pke]);
    dk[pke..pke + p.ek_bytes()].copy_from_slice(ek);
    let hash = h(ek);
    dk[pke + p.ek_bytes()..pke + p.ek_bytes() + 32].copy_from_slice(&hash);
    dk[pke + p.ek_bytes() + 32..].copy_from_slice(z);
}

/// ML-KEM.Encaps_internal (Algorithm 17): (K, r) = G(m || H(ek)).
pub(crate) fn encaps_inner(p: &Params, ek: &[u8], m: &[u8; 32], c: &mut [u8], key: &mut [u8; 32]) {
    assert!(ek.len() == p.ek_bytes() && c.len() == p.ct_bytes());
    let (k, mut r) = g(&[m, &h(ek)]);
    kpke_encrypt(p, ek, m, &r, c);
    *key = k;
    r.zeroize();
}

/// 0xff if equal, else 0, reading every byte; the verdict passes a value
/// barrier so the selection it drives stays branch-free.
fn eq_mask(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    (opaque(u64::from(diff)).wrapping_sub(1) >> 8) as u8
}

/// ML-KEM.Decaps_internal (Algorithm 18), with implicit rejection: the
/// output starts as K_bar = J(z || c) and is replaced by K' through a mask
/// only when the re-encryption equals c. The flag never leaves this function.
pub(crate) fn decaps_inner(p: &Params, dk: &[u8], c: &[u8], key: &mut [u8; 32]) {
    assert!(dk.len() == p.dk_bytes() && c.len() == p.ct_bytes());
    let pke = 384 * p.k;
    let dk_pke = &dk[..pke];
    let ek = &dk[pke..pke + p.ek_bytes()];
    let hash = &dk[pke + p.ek_bytes()..pke + p.ek_bytes() + 32];
    let z = &dk[pke + p.ek_bytes() + 32..];
    let mut m = [0u8; 32];
    kpke_decrypt(p, dk_pke, c, &mut m);
    let (mut accepted, mut r) = g(&[&m, hash]);
    j(z, c, key);
    let mut again = [0u8; 4 * 352 + 160];
    let again = &mut again[..p.ct_bytes()];
    kpke_encrypt(p, ek, &m, &r, again);
    let accept = eq_mask(c, again);
    for (out, &a) in key.iter_mut().zip(accepted.iter()) {
        *out ^= (*out ^ a) & accept;
    }
    m.zeroize();
    r.zeroize();
    accepted.zeroize();
    again.zeroize();
}

/// The encapsulation-key check of FIPS 203 section 7.2: the right length,
/// and every coefficient already reduced (ByteEncode12(ByteDecode12(ek))
/// equals ek).
pub(crate) fn ek_valid(p: &Params, ek: &[u8]) -> bool {
    if ek.len() != p.ek_bytes() {
        return false;
    }
    let mut again = [0u8; 384];
    (0..p.k).all(|i| {
        let mut f = [0u16; N];
        byte_decode(12, &ek[384 * i..384 * (i + 1)], &mut f);
        byte_encode(12, &f, &mut again);
        again[..] == ek[384 * i..384 * (i + 1)]
    })
}

/// The decapsulation-key check of section 7.3: the right length, and
/// H(ek) where it belongs.
pub(crate) fn dk_valid(p: &Params, dk: &[u8]) -> bool {
    if dk.len() != p.dk_bytes() {
        return false;
    }
    let pke = 384 * p.k;
    h(&dk[pke..pke + p.ek_bytes()])[..] == dk[pke + p.ek_bytes()..pke + p.ek_bytes() + 32]
}

/// ML-KEM.KeyGen_internal. Analysis builds only (known-answer tests).
#[cfg(feature = "analysis")]
pub fn keygen_internal(p: &Params, d: &[u8; 32], z: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    keygen_inner(p, d, z, false, ek, dk);
}

/// Key generation as the FIPS 203 draft did it, G(d) without k, to run the
/// C2SP CCTV vectors. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn keygen_internal_ipd(p: &Params, d: &[u8; 32], z: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    keygen_inner(p, d, z, true, ek, dk);
}

/// ML-KEM.Encaps_internal. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn encaps_internal(p: &Params, ek: &[u8], m: &[u8; 32], c: &mut [u8], key: &mut [u8; 32]) {
    encaps_inner(p, ek, m, c, key);
}

/// ML-KEM.Decaps_internal. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn decaps_internal(p: &Params, dk: &[u8], c: &[u8], key: &mut [u8; 32]) {
    decaps_inner(p, dk, c, key);
}

/// The encapsulation-key check. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn check_encapsulation_key(p: &Params, ek: &[u8]) -> bool {
    ek_valid(p, ek)
}

/// The decapsulation-key check. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn check_decapsulation_key(p: &Params, dk: &[u8]) -> bool {
    dk_valid(p, dk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203 Appendix A as printed (the second table prints q - x as -x).
    const ZETAS_FIPS203: [u16; 128] = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289,
        331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761,
        583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298,
        2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    ];
    const GAMMAS_FIPS203: [i32; 128] = [
        17, -17, 2761, -2761, 583, -583, 2649, -2649, 1637, -1637, 723, -723, 2288, -2288, 1100, -1100, 1409, -1409, 2662, -2662, 3281, -3281, 233, -233, 756, -756, 2156, -2156, 3015, -3015, 3050,
        -3050, 1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952, -952, 1461, -1461, 2687, -2687, 939, -939, 2308, -2308, 2437, -2437, 2388, -2388, 733, -733, 2337, -2337, 268,
        -268, 641, -641, 1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, 375, -375, 2549, -2549, 2090, -2090, 1645, -1645, 1063, -1063, 319, -319, 2773, -2773, 757, -757, 2099, -2099, 561,
        -561, 2466, -2466, 2594, -2594, 2804, -2804, 1092, -1092, 403, -403, 1026, -1026, 1143, -1143, 2150, -2150, 2775, -2775, 886, -886, 1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
        2110, -2110, 2935, -2935, 885, -885, 2154, -2154,
    ];

    #[test]
    fn constant_tables_equal_fips_203_appendix_a() {
        assert_eq!(ZETAS, ZETAS_FIPS203);
        for (i, (&g, &want)) in GAMMAS.iter().zip(GAMMAS_FIPS203.iter()).enumerate() {
            assert_eq!(i32::from(g), want.rem_euclid(Q as i32), "gamma {i}");
        }
    }

    // Every input the arithmetic can see, against exact integer division.
    #[test]
    fn barrett_reduction_is_exact_for_every_input() {
        for x in 0..1u32 << 24 {
            assert_eq!(u32::from(reduce(x)), x % Q, "x = {x}");
        }
    }

    #[test]
    fn compress_and_decompress_match_the_rational_definitions() {
        for d in [1, 4, 5, 10, 11] {
            for x in 0..Q {
                // round(2^d x / q) with ties up, in exact integers: floor((2^(d+1) x + q) / 2q).
                let want = (((x << (d + 1)) + Q) / (2 * Q)) % (1 << d);
                assert_eq!(u32::from(compress(x as u16, d)), want, "Compress_{d}({x})");
            }
            for y in 0..1u32 << d {
                let want = (((y * Q) << 1) + (1 << d)) / (2 << d);
                assert_eq!(u32::from(decompress(y as u16, d)), want, "Decompress_{d}({y})");
                // FIPS 203 section 4.2.1: Compress_d(Decompress_d(y)) = y.
                assert_eq!(u32::from(compress(decompress(y as u16, d), d)), y, "round trip d = {d}, y = {y}");
            }
        }
        // The multiply-and-shift division is exact for every numerator up to 2^23.
        for v in 0..1u64 << 23 {
            assert_eq!((v * COMPRESS_M) >> 40, v / u64::from(Q), "v = {v}");
        }
    }

    fn lcg(seed: u64) -> impl FnMut() -> u16 {
        let mut s = seed;
        move || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((s >> 33) % u64::from(Q)) as u16
        }
    }

    // The NTT route to polynomial multiplication equals schoolbook
    // multiplication in Z_q[X]/(X^256 + 1), and the inverse NTT inverts.
    #[test]
    fn ntt_multiplication_equals_schoolbook() {
        let mut next = lcg(7);
        for _ in 0..20 {
            let f: Poly = core::array::from_fn(|_| next());
            let g_: Poly = core::array::from_fn(|_| next());
            let mut want = [0i64; N];
            for i in 0..N {
                for jj in 0..N {
                    let prod = i64::from(f[i]) * i64::from(g_[jj]);
                    if i + jj < N {
                        want[i + jj] += prod;
                    } else {
                        want[i + jj - N] -= prod;
                    }
                }
            }
            let (mut fh, mut gh) = (f, g_);
            ntt(&mut fh);
            ntt(&mut gh);
            let mut h_ = [0u16; N];
            multiply_ntts_add(&fh, &gh, &mut h_);
            ntt_inverse(&mut h_);
            for i in 0..N {
                assert_eq!(i64::from(h_[i]), want[i].rem_euclid(i64::from(Q)), "coefficient {i}");
            }
            ntt_inverse(&mut fh);
            assert_eq!(fh, f, "NTT^-1(NTT(f)) = f");
        }
    }

    #[test]
    fn encoding_round_trips() {
        let mut next = lcg(11);
        for d in 1..=12u32 {
            // Values below 2^d (below q for d = 12, where ByteDecode reduces).
            let bound = if d == 12 { Q as u16 } else { 1u16 << d };
            let f: Poly = core::array::from_fn(|_| next() % bound);
            let mut bytes = vec![0u8; 32 * d as usize];
            byte_encode(d, &f, &mut bytes);
            let mut back = [0u16; N];
            byte_decode(d, &bytes, &mut back);
            assert_eq!(back, f, "d = {d}");
        }
    }

    #[test]
    fn keys_round_trip_and_tampering_is_rejected() {
        for p in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
            let (d, z, m) = ([1u8; 32], [2u8; 32], [3u8; 32]);
            let (mut ek, mut dk) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
            keygen_inner(&p, &d, &z, false, &mut ek, &mut dk);
            assert!(ek_valid(&p, &ek) && dk_valid(&p, &dk));
            let (mut c, mut key) = (vec![0u8; p.ct_bytes()], [0u8; 32]);
            encaps_inner(&p, &ek, &m, &mut c, &mut key);
            let mut back = [0u8; 32];
            decaps_inner(&p, &dk, &c, &mut back);
            assert_eq!(back, key, "{p:?}");
            c[0] ^= 1;
            decaps_inner(&p, &dk, &c, &mut back);
            assert_ne!(back, key, "{p:?}: a changed ciphertext must be rejected");
            let mut rejection = [0u8; 32];
            j(&z, &c, &mut rejection);
            assert_eq!(back, rejection, "{p:?}: implicit rejection gives J(z || c)");
        }
    }
}
