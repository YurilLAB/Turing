//! rpi_oracle_probe: differential tests and timings of existing ML-KEM, FrodoKEM and X25519
//! implementations (topic rust-pqc-implementations, research/notes/pq/rust-pqc-implementations.md).
//!
//! What it reproduces, and from which source:
//!   accumulated  Go crypto/mlkem TestAccumulated (golang/go src/crypto/mlkem/mlkem_test.go): inputs
//!                drawn from SHAKE-128(""), all outputs hashed with SHAKE-128; expected ML-KEM-768
//!                values for n = 100 / 10,000 / 1,000,000 are the three hex strings in that file.
//!                Run for every implementation; for ML-KEM-512/1024 (no published value) the
//!                implementations are compared with each other.
//!   vectors      C2SP Wycheproof testvectors_v1 mlkem_* and x25519_test.json, C2SP CCTV ML-KEM
//!                strcmp/ and modulus/, RFC 7748 sections 5.2 and 6.1 (parsed from rfc7748.txt).
//!   reject       FIPS 203 Algorithm 18 implicit rejection: a modified ciphertext must decapsulate
//!                to J(z || c') = SHAKE-256(z || c', 32). Two planted mutants are the negative control.
//!   frodo-kat    FrodoKEM official KAT files (microsoft/PQCrypto-LWEKE, PQCkemKAT_*.rsp) using the
//!                NIST AES-256 CTR_DRBG (the rng.c used by all NIST PQC KAT generators).
//!   frodo-mu     Shows that frodo-kem 0.1.0 `decapsulate` returns the decrypted message mu' even
//!                for rejected ciphertexts.
//!   bench        Median TSC ticks and nanoseconds per operation on this machine.
//!
//! Deterministic: every input comes from SHAKE-128 streams or the vector files. Only `interop`
//! uses OS randomness (PQClean's own randombytes and aws-lc-rs); it prints pass/fail counts only.
//!
//! Build and run: research/scripts/pq/rpi_oracle_probe_run.sh (copies this file to the scratch
//! directory; never build inside the Turing repository).
#![allow(clippy::too_many_arguments)]

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use std::time::Instant;

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

struct Stream(sha3::Shake128Reader);
impl Stream {
    fn new(seed: &[u8]) -> Self {
        let mut h = Shake128::default();
        h.update(seed);
        Stream(h.finalize_xof())
    }
    fn read(&mut self, out: &mut [u8]) {
        self.0.read(out)
    }
}

fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut o = [0u8; 32];
    h.finalize_xof().read(&mut o);
    o
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let d = sha3::Sha3_256::digest(data);
    let mut o = [0u8; 32];
    o.copy_from_slice(&d);
    o
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("hex")
}

#[derive(Clone, Copy)]
struct Params {
    name: &'static str,
    k: usize,
    ek: usize,
    dk: usize,
    ct: usize,
}
const P512: Params = Params { name: "ML-KEM-512", k: 2, ek: 800, dk: 1632, ct: 768 };
const P768: Params = Params { name: "ML-KEM-768", k: 3, ek: 1184, dk: 2400, ct: 1088 };
const P1024: Params = Params { name: "ML-KEM-1024", k: 4, ek: 1568, dk: 3168, ct: 1568 };

fn params(name: &str) -> Params {
    match name {
        "512" | "ML-KEM-512" => P512,
        "768" | "ML-KEM-768" => P768,
        "1024" | "ML-KEM-1024" => P1024,
        _ => panic!("unknown parameter set {name}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Check {
    Accept,
    Reject,
    NoApi,
}

/// A byte-level view of one ML-KEM implementation for one parameter set.
/// keygen takes d || z (64 bytes) and returns (ek, expanded dk) as in FIPS 203.
trait Kem {
    fn name(&self) -> String;
    fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)>;
    /// None if the library refuses the encapsulation key.
    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])>;
    /// None if the library refuses the decapsulation key or the ciphertext length.
    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]>;
    fn check_ek(&self, ek: &[u8]) -> Check;
    fn check_dk(&self, dk: &[u8]) -> Check;
}

// ---------------------------------------------------------------------------------------------
// RustCrypto ml-kem 0.3.2
// ---------------------------------------------------------------------------------------------

macro_rules! rustcrypto_impl {
    ($ty:ident, $p:ty) => {
        struct $ty;
        impl Kem for $ty {
            fn name(&self) -> String {
                "ml-kem 0.3.2 (RustCrypto)".into()
            }
            fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
                #[allow(deprecated)]
                use ml_kem::ExpandedKeyEncoding;
                use ml_kem::KeyExport;
                let dk = ml_kem::DecapsulationKey::<$p>::from_seed(ml_kem::Seed::from(*seed));
                let ek = dk.encapsulation_key().to_bytes().to_vec();
                #[allow(deprecated)]
                let dkb = dk.to_expanded_bytes().to_vec();
                Some((ek, dkb))
            }
            fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                let arr: ml_kem::Key<ml_kem::EncapsulationKey<$p>> =
                    ml_kem::array::Array::try_from(ek).ok()?;
                let e = ml_kem::EncapsulationKey::<$p>::new(&arr).ok()?;
                let (c, k) = e.encapsulate_deterministic(&ml_kem::B32::from(*m));
                let mut o = [0u8; 32];
                o.copy_from_slice(&k);
                Some((c.to_vec(), o))
            }
            fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
                use ml_kem::Decapsulate;
                let arr: ml_kem::ExpandedDecapsulationKey<$p> =
                    ml_kem::array::Array::try_from(dk).ok()?;
                #[allow(deprecated)]
                let d = ml_kem::DecapsulationKey::<$p>::from_expanded(&arr).ok()?;
                let c: ml_kem::Ciphertext<$p> = ml_kem::array::Array::try_from(ct).ok()?;
                let k = d.decapsulate(&c);
                let mut o = [0u8; 32];
                o.copy_from_slice(&k);
                Some(o)
            }
            fn check_ek(&self, ek: &[u8]) -> Check {
                let arr: Result<ml_kem::Key<ml_kem::EncapsulationKey<$p>>, _> =
                    ml_kem::array::Array::try_from(ek);
                match arr {
                    Err(_) => Check::Reject,
                    Ok(a) => match ml_kem::EncapsulationKey::<$p>::new(&a) {
                        Ok(_) => Check::Accept,
                        Err(_) => Check::Reject,
                    },
                }
            }
            fn check_dk(&self, dk: &[u8]) -> Check {
                let arr: Result<ml_kem::ExpandedDecapsulationKey<$p>, _> =
                    ml_kem::array::Array::try_from(dk);
                match arr {
                    Err(_) => Check::Reject,
                    #[allow(deprecated)]
                    Ok(a) => match ml_kem::DecapsulationKey::<$p>::from_expanded(&a) {
                        Ok(_) => Check::Accept,
                        Err(_) => Check::Reject,
                    },
                }
            }
        }
    };
}
rustcrypto_impl!(Rc512, ml_kem::MlKem512);
rustcrypto_impl!(Rc768, ml_kem::MlKem768);
rustcrypto_impl!(Rc1024, ml_kem::MlKem1024);

// ---------------------------------------------------------------------------------------------
// libcrux-ml-kem 0.0.10 (portable and AVX2 backends)
// ---------------------------------------------------------------------------------------------

use libcrux_ml_kem::mlkem1024::avx2 as lc1024a;
use libcrux_ml_kem::mlkem1024::portable as lc1024p;
use libcrux_ml_kem::mlkem512::avx2 as lc512a;
use libcrux_ml_kem::mlkem512::portable as lc512p;
use libcrux_ml_kem::mlkem768::avx2 as lc768a;
use libcrux_ml_kem::mlkem768::portable as lc768p;

macro_rules! libcrux_impl {
    ($ty:ident, $label:expr, $m:ident, $ek:expr, $dk:expr, $ct:expr) => {
        struct $ty;
        impl Kem for $ty {
            fn name(&self) -> String {
                $label.into()
            }
            fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
                let kp = $m::generate_key_pair(*seed);
                Some((kp.pk().to_vec(), kp.sk().to_vec()))
            }
            fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                let a: [u8; $ek] = ek.try_into().ok()?;
                let pk = libcrux_ml_kem::MlKemPublicKey::<$ek>::from(a);
                let (c, k) = $m::encapsulate(&pk, *m);
                Some((c.as_ref().to_vec(), k))
            }
            fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
                let a: [u8; $dk] = dk.try_into().ok()?;
                let b: [u8; $ct] = ct.try_into().ok()?;
                let sk = libcrux_ml_kem::MlKemPrivateKey::<$dk>::from(a);
                let c = libcrux_ml_kem::MlKemCiphertext::<$ct>::from(b);
                Some($m::decapsulate(&sk, &c))
            }
            fn check_ek(&self, ek: &[u8]) -> Check {
                let a: Result<[u8; $ek], _> = ek.try_into();
                match a {
                    Err(_) => Check::Reject,
                    Ok(a) => {
                        let pk = libcrux_ml_kem::MlKemPublicKey::<$ek>::from(a);
                        if $m::validate_public_key(&pk) { Check::Accept } else { Check::Reject }
                    }
                }
            }
            fn check_dk(&self, dk: &[u8]) -> Check {
                let a: Result<[u8; $dk], _> = dk.try_into();
                match a {
                    Err(_) => Check::Reject,
                    Ok(a) => {
                        let sk = libcrux_ml_kem::MlKemPrivateKey::<$dk>::from(a);
                        if $m::validate_private_key_only(&sk) { Check::Accept } else { Check::Reject }
                    }
                }
            }
        }
    };
}
libcrux_impl!(Lc512P, "libcrux-ml-kem 0.0.10 portable", lc512p, 800, 1632, 768);
libcrux_impl!(Lc768P, "libcrux-ml-kem 0.0.10 portable", lc768p, 1184, 2400, 1088);
libcrux_impl!(Lc1024P, "libcrux-ml-kem 0.0.10 portable", lc1024p, 1568, 3168, 1568);
libcrux_impl!(Lc512A, "libcrux-ml-kem 0.0.10 avx2", lc512a, 800, 1632, 768);
libcrux_impl!(Lc768A, "libcrux-ml-kem 0.0.10 avx2", lc768a, 1184, 2400, 1088);
libcrux_impl!(Lc1024A, "libcrux-ml-kem 0.0.10 avx2", lc1024a, 1568, 3168, 1568);

// ---------------------------------------------------------------------------------------------
// fips203 0.4.3 (integritychain)
// ---------------------------------------------------------------------------------------------

macro_rules! fips203_impl {
    ($ty:ident, $m:ident, $ek:expr, $dk:expr, $ct:expr) => {
        struct $ty;
        impl Kem for $ty {
            fn name(&self) -> String {
                "fips203 0.4.3".into()
            }
            fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
                use fips203::traits::{KeyGen, SerDes};
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                d.copy_from_slice(&seed[..32]);
                z.copy_from_slice(&seed[32..]);
                let (ek, dk) = fips203::$m::KG::keygen_from_seed(d, z);
                Some((ek.into_bytes().to_vec(), dk.into_bytes().to_vec()))
            }
            fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                use fips203::traits::{Encaps, SerDes};
                let a: [u8; $ek] = ek.try_into().ok()?;
                let e = fips203::$m::EncapsKey::try_from_bytes(a).ok()?;
                let (k, c) = e.encaps_from_seed(m);
                Some((c.into_bytes().to_vec(), k.into_bytes()))
            }
            fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
                use fips203::traits::{Decaps, SerDes};
                let a: [u8; $dk] = dk.try_into().ok()?;
                let b: [u8; $ct] = ct.try_into().ok()?;
                let d = fips203::$m::DecapsKey::try_from_bytes(a).ok()?;
                let c = fips203::$m::CipherText::try_from_bytes(b).ok()?;
                d.try_decaps(&c).ok().map(|k| k.into_bytes())
            }
            fn check_ek(&self, ek: &[u8]) -> Check {
                use fips203::traits::SerDes;
                let a: Result<[u8; $ek], _> = ek.try_into();
                match a {
                    Err(_) => Check::Reject,
                    Ok(a) => match fips203::$m::EncapsKey::try_from_bytes(a) {
                        Ok(_) => Check::Accept,
                        Err(_) => Check::Reject,
                    },
                }
            }
            fn check_dk(&self, dk: &[u8]) -> Check {
                use fips203::traits::SerDes;
                let a: Result<[u8; $dk], _> = dk.try_into();
                match a {
                    Err(_) => Check::Reject,
                    Ok(a) => match fips203::$m::DecapsKey::try_from_bytes(a) {
                        Ok(_) => Check::Accept,
                        Err(_) => Check::Reject,
                    },
                }
            }
        }
    };
}
fips203_impl!(Fi512, ml_kem_512, 800, 1632, 768);
fips203_impl!(Fi768, ml_kem_768, 1184, 2400, 1088);
fips203_impl!(Fi1024, ml_kem_1024, 1568, 3168, 1568);

// ---------------------------------------------------------------------------------------------
// PQClean "clean" C code, as compiled by pqcrypto-mlkem 0.1.1, called through its derand entry points
// ---------------------------------------------------------------------------------------------

extern "C" {
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

macro_rules! pqclean_impl {
    ($ty:ident, $kp:ident, $enc:ident, $dec:ident, $ek:expr, $dk:expr, $ct:expr) => {
        struct $ty;
        impl Kem for $ty {
            fn name(&self) -> String {
                "PQClean clean C (via pqcrypto-mlkem 0.1.1)".into()
            }
            fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
                let mut pk = vec![0u8; $ek];
                let mut sk = vec![0u8; $dk];
                let r = unsafe { $kp(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
                assert_eq!(r, 0);
                Some((pk, sk))
            }
            fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                if ek.len() != $ek {
                    return None;
                }
                let mut ct = vec![0u8; $ct];
                let mut ss = [0u8; 32];
                let r = unsafe { $enc(ct.as_mut_ptr(), ss.as_mut_ptr(), ek.as_ptr(), m.as_ptr()) };
                if r != 0 {
                    return None;
                }
                Some((ct, ss))
            }
            fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
                if dk.len() != $dk || ct.len() != $ct {
                    return None;
                }
                let mut ss = [0u8; 32];
                let r = unsafe { $dec(ss.as_mut_ptr(), ct.as_ptr(), dk.as_ptr()) };
                if r != 0 {
                    return None;
                }
                Some(ss)
            }
            fn check_ek(&self, _ek: &[u8]) -> Check {
                Check::NoApi
            }
            fn check_dk(&self, _dk: &[u8]) -> Check {
                Check::NoApi
            }
        }
    };
}
pqclean_impl!(Pq512, PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand, PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand, PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec, 800, 1632, 768);
pqclean_impl!(Pq768, PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand, PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand, PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec, 1184, 2400, 1088);
pqclean_impl!(Pq1024, PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand, PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand, PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec, 1568, 3168, 1568);

// PQClean AVX2 code: pqcrypto-mlkem's build.rs compiles it only for x86_64 Linux (not Windows, not macOS).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern "C" {
    fn PQCLEAN_MLKEM512_AVX2_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM512_AVX2_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM512_AVX2_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_AVX2_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_AVX2_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM1024_AVX2_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod pqavx2 {
    use super::*;
    macro_rules! pqclean_avx2_impl {
        ($ty:ident, $kp:ident, $enc:ident, $dec:ident, $ek:expr, $dk:expr, $ct:expr) => {
            pub struct $ty;
            impl Kem for $ty {
                fn name(&self) -> String {
                    "PQClean avx2 C (via pqcrypto-mlkem 0.1.1)".into()
                }
                fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
                    let mut pk = vec![0u8; $ek];
                    let mut sk = vec![0u8; $dk];
                    let r = unsafe { $kp(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
                    assert_eq!(r, 0);
                    Some((pk, sk))
                }
                fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
                    if ek.len() != $ek {
                        return None;
                    }
                    let mut ct = vec![0u8; $ct];
                    let mut ss = [0u8; 32];
                    let r = unsafe { $enc(ct.as_mut_ptr(), ss.as_mut_ptr(), ek.as_ptr(), m.as_ptr()) };
                    if r != 0 {
                        return None;
                    }
                    Some((ct, ss))
                }
                fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
                    if dk.len() != $dk || ct.len() != $ct {
                        return None;
                    }
                    let mut ss = [0u8; 32];
                    let r = unsafe { $dec(ss.as_mut_ptr(), ct.as_ptr(), dk.as_ptr()) };
                    if r != 0 {
                        return None;
                    }
                    Some(ss)
                }
                fn check_ek(&self, _ek: &[u8]) -> Check {
                    Check::NoApi
                }
                fn check_dk(&self, _dk: &[u8]) -> Check {
                    Check::NoApi
                }
            }
        };
    }
    pqclean_avx2_impl!(Pq512A, PQCLEAN_MLKEM512_AVX2_crypto_kem_keypair_derand, PQCLEAN_MLKEM512_AVX2_crypto_kem_enc_derand, PQCLEAN_MLKEM512_AVX2_crypto_kem_dec, 800, 1632, 768);
    pqclean_avx2_impl!(Pq768A, PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand, PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand, PQCLEAN_MLKEM768_AVX2_crypto_kem_dec, 1184, 2400, 1088);
    pqclean_avx2_impl!(Pq1024A, PQCLEAN_MLKEM1024_AVX2_crypto_kem_keypair_derand, PQCLEAN_MLKEM1024_AVX2_crypto_kem_enc_derand, PQCLEAN_MLKEM1024_AVX2_crypto_kem_dec, 1568, 3168, 1568);
}

// ---------------------------------------------------------------------------------------------
// Planted mutants (negative controls). Each wraps ml-kem and breaks one thing on purpose.
// ---------------------------------------------------------------------------------------------

/// Mutant A: implicit rejection keyed with the wrong secret (z replaced by zeros), like a
/// decapsulation that reads the wrong field of the secret key.
struct MutantWrongZ(Params);
/// Mutant B: "cmov is a no-op": on a modified ciphertext, returns the key of the honest ciphertext
/// whenever the modification does not change the decrypted message. The probe emulates this by
/// returning the real key K for a ciphertext that differs from the honest one only in a low bit.
struct MutantNoReject(Params);

fn rc(p: Params) -> Box<dyn Kem> {
    match p.k {
        2 => Box::new(Rc512),
        3 => Box::new(Rc768),
        _ => Box::new(Rc1024),
    }
}

impl Kem for MutantWrongZ {
    fn name(&self) -> String {
        "MUTANT wrong-z (negative control)".into()
    }
    fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
        rc(self.0).keygen(seed)
    }
    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        rc(self.0).encaps(ek, m)
    }
    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
        let mut d = dk.to_vec();
        let n = d.len();
        for b in &mut d[n - 32..] {
            *b = 0;
        }
        rc(self.0).decaps(&d, ct)
    }
    fn check_ek(&self, ek: &[u8]) -> Check {
        rc(self.0).check_ek(ek)
    }
    fn check_dk(&self, dk: &[u8]) -> Check {
        rc(self.0).check_dk(dk)
    }
}

// MutantNoReject needs the honest ciphertext; it is handled inside test_reject().
impl Kem for MutantNoReject {
    fn name(&self) -> String {
        "MUTANT no-reject (negative control)".into()
    }
    fn keygen(&self, seed: &[u8; 64]) -> Option<(Vec<u8>, Vec<u8>)> {
        rc(self.0).keygen(seed)
    }
    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        rc(self.0).encaps(ek, m)
    }
    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
        rc(self.0).decaps(dk, ct)
    }
    fn check_ek(&self, ek: &[u8]) -> Check {
        rc(self.0).check_ek(ek)
    }
    fn check_dk(&self, dk: &[u8]) -> Check {
        rc(self.0).check_dk(dk)
    }
}

fn avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn impls(p: Params) -> Vec<Box<dyn Kem>> {
    let mut v: Vec<Box<dyn Kem>> = Vec::new();
    match p.k {
        2 => {
            v.push(Box::new(Rc512));
            v.push(Box::new(Lc512P));
            if avx2() {
                v.push(Box::new(Lc512A));
            }
            v.push(Box::new(Fi512));
            v.push(Box::new(Pq512));
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if avx2() {
                v.push(Box::new(pqavx2::Pq512A));
            }
        }
        3 => {
            v.push(Box::new(Rc768));
            v.push(Box::new(Lc768P));
            if avx2() {
                v.push(Box::new(Lc768A));
            }
            v.push(Box::new(Fi768));
            v.push(Box::new(Pq768));
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if avx2() {
                v.push(Box::new(pqavx2::Pq768A));
            }
        }
        _ => {
            v.push(Box::new(Rc1024));
            v.push(Box::new(Lc1024P));
            if avx2() {
                v.push(Box::new(Lc1024A));
            }
            v.push(Box::new(Fi1024));
            v.push(Box::new(Pq1024));
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if avx2() {
                v.push(Box::new(pqavx2::Pq1024A));
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------------------------
// 1. Go-style accumulated test
// ---------------------------------------------------------------------------------------------

const GO_ACC_768: [(usize, &str); 3] = [
    (100, "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"),
    (10000, "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"),
    (1000000, "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0"),
];

fn accumulated(imp: &dyn Kem, p: Params, n: usize) -> (String, usize) {
    let mut s = Stream::new(b"");
    let mut o = Shake128::default();
    let mut seed = [0u8; 64];
    let mut msg = [0u8; 32];
    let mut ct1 = vec![0u8; p.ct];
    let mut mismatches = 0usize;
    for _ in 0..n {
        s.read(&mut seed);
        let (ek, dk) = imp.keygen(&seed).expect("keygen");
        o.update(&ek);
        s.read(&mut msg);
        let (ct, k) = imp.encaps(&ek, &msg).expect("encaps");
        o.update(&ct);
        o.update(&k);
        let kk = imp.decaps(&dk, &ct).expect("decaps");
        if kk != k {
            mismatches += 1;
        }
        s.read(&mut ct1);
        let k1 = imp.decaps(&dk, &ct1).expect("decaps random ct");
        o.update(&k1);
    }
    let mut out = [0u8; 32];
    o.finalize_xof().read(&mut out);
    (h(&out), mismatches)
}

fn cmd_accumulated(args: &[String]) {
    let n: usize = args.first().map(|a| a.parse().unwrap()).unwrap_or(10000);
    let sets: Vec<Params> = if args.len() > 1 { args[1..].iter().map(|a| params(a)).collect() } else { vec![P512, P768, P1024] };
    for p in sets {
        let expected = if p.k == 3 { GO_ACC_768.iter().find(|(m, _)| *m == n).map(|(_, e)| *e) } else { None };
        let mut first: Option<String> = None;
        for imp in impls(p) {
            let t = Instant::now();
            let (got, mism) = accumulated(imp.as_ref(), p, n);
            let secs = t.elapsed().as_secs_f64();
            let verdict = match expected {
                Some(e) if e == got => "PASS (= Go TestAccumulated)".to_string(),
                Some(_) => "FAIL (differs from Go TestAccumulated)".to_string(),
                None => match &first {
                    None => "reference for cross-check".to_string(),
                    Some(f) if *f == got => "PASS (agrees with first implementation)".to_string(),
                    Some(_) => "FAIL (differs from first implementation)".to_string(),
                },
            };
            if first.is_none() {
                first = Some(got.clone());
            }
            println!("ACCUMULATED {} n={} impl=[{}] hash={} decaps_mismatch={} {:.1}s {}", p.name, n, imp.name(), got, mism, secs, verdict);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Implicit rejection with negative controls
// ---------------------------------------------------------------------------------------------

fn cmd_reject(args: &[String]) {
    let n: usize = args.first().map(|a| a.parse().unwrap()).unwrap_or(1000);
    for p in [P512, P768, P1024] {
        let mut list = impls(p);
        list.push(Box::new(MutantWrongZ(p)));
        list.push(Box::new(MutantNoReject(p)));
        for imp in list {
            let mutant_no_reject = imp.name().starts_with("MUTANT no-reject");
            let mut s = Stream::new(b"rpi reject test");
            let (mut ok, mut bad, mut same_key) = (0usize, 0usize, 0usize);
            let mut seed = [0u8; 64];
            let mut m = [0u8; 32];
            for i in 0..n {
                s.read(&mut seed);
                s.read(&mut m);
                let (ek, dk) = imp.keygen(&seed).unwrap();
                let (ct, k) = imp.encaps(&ek, &m).unwrap();
                let mut c2 = ct.clone();
                // Flip bit i mod 8 of byte (i * 131) mod len: covers every byte position over the run,
                // including the last byte (strcmp-style bugs) and the v part.
                let pos = (i * 131) % c2.len();
                c2[pos] ^= 1 << (i % 8);
                let expected = shake256_32(&[&seed[32..], &c2]);
                let got = if mutant_no_reject { k } else { imp.decaps(&dk, &c2).unwrap() };
                if got == expected && got != k {
                    ok += 1;
                } else {
                    bad += 1;
                }
                if got == k {
                    same_key += 1;
                }
            }
            println!(
                "REJECT {} impl=[{}] trials={} ok={} bad={} returned_real_key={} {}",
                p.name, imp.name(), n, ok, bad, same_key,
                if imp.name().starts_with("MUTANT") { if bad > 0 { "PASS (mutant detected)" } else { "FAIL (mutant NOT detected)" } } else if bad == 0 { "PASS" } else { "FAIL" }
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Public vectors: Wycheproof ML-KEM, CCTV strcmp / modulus, Wycheproof X25519, RFC 7748
// ---------------------------------------------------------------------------------------------

fn load_json(path: &str) -> serde_json::Value {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&s).unwrap()
}

fn tests_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            out.push(t.clone());
        }
    }
    out
}

fn s(t: &serde_json::Value, k: &str) -> String {
    t[k].as_str().unwrap_or("").to_string()
}

fn seed64(b: &[u8]) -> [u8; 64] {
    let mut a = [0u8; 64];
    a.copy_from_slice(b);
    a
}

fn cmd_vectors(args: &[String]) {
    let dir = args.first().expect("vectors dir").clone();
    let rfc = args.get(1).cloned();
    for p in [P512, P768, P1024] {
        let bits = &p.name[7..];
        // keygen_seed_test: seed -> ek, dk
        let kg = tests_of(&load_json(&format!("{dir}/wycheproof/mlkem_{bits}_keygen_seed_test.json")));
        // test: seed -> ek; decaps(c) == K ; invalid = wrong ciphertext length
        let dt = tests_of(&load_json(&format!("{dir}/wycheproof/mlkem_{bits}_test.json")));
        // encaps_test: m, ek -> c, K ; invalid = ek not reduced / wrong length
        let et = tests_of(&load_json(&format!("{dir}/wycheproof/mlkem_{bits}_encaps_test.json")));
        // semi_expanded_decaps_test: dk (expanded), c -> K ; invalid = bad dk / bad lengths
        let st = tests_of(&load_json(&format!("{dir}/wycheproof/mlkem_{bits}_semi_expanded_decaps_test.json")));
        // CCTV strcmp: dk, c, K
        let strcmp = std::fs::read_to_string(format!("{dir}/cctv/strcmp/{}.txt", p.name)).unwrap();
        let mut sc: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let (mut dk, mut c) = (Vec::new(), Vec::new());
            for line in strcmp.lines() {
                if let Some(x) = line.strip_prefix("dk = ") {
                    dk = unhex(x);
                } else if let Some(x) = line.strip_prefix("c = ") {
                    c = unhex(x);
                } else if let Some(x) = line.strip_prefix("K = ") {
                    sc.push((dk.clone(), c.clone(), unhex(x)));
                }
            }
        }
        // CCTV modulus: one invalid ek per line (gzip)
        let mut modk: Vec<Vec<u8>> = Vec::new();
        {
            let f = std::fs::File::open(format!("{dir}/cctv/modulus/{}.txt.gz", p.name)).unwrap();
            use std::io::Read as _;
            let mut gz = flate2::read::GzDecoder::new(f);
            let mut txt = String::new();
            gz.read_to_string(&mut txt).unwrap();
            for line in txt.lines() {
                if !line.trim().is_empty() {
                    modk.push(unhex(line));
                }
            }
        }
        for imp in impls(p) {
            let mut pass = 0usize;
            let mut fail: Vec<String> = Vec::new();
            // keygen
            for t in &kg {
                let (ek, dk) = imp.keygen(&seed64(&unhex(&s(t, "seed")))).unwrap();
                if ek == unhex(&s(t, "ek")) && dk == unhex(&s(t, "dk")) { pass += 1 } else { fail.push(format!("keygen tc{}", t["tcId"])) }
            }
            // decaps from seed
            let (mut len_rejected, mut len_accepted, mut bad_seed_len) = (0, 0, 0);
            for t in &dt {
                let sd = unhex(&s(t, "seed"));
                if sd.len() != 64 {
                    // every API here takes exactly 64 seed bytes, so a wrong-length seed cannot be passed
                    bad_seed_len += 1;
                    continue;
                }
                let (ek, dk) = imp.keygen(&seed64(&sd)).unwrap();
                let c = unhex(&s(t, "c"));
                if s(t, "result") == "valid" {
                    let ok = ek == unhex(&s(t, "ek")) && imp.decaps(&dk, &c).map(|k| k.to_vec()) == Some(unhex(&s(t, "K")));
                    if ok { pass += 1 } else { fail.push(format!("decaps tc{}", t["tcId"])) }
                } else {
                    // wrong ciphertext length: every API here takes fixed-size input, so the harness must reject
                    match imp.decaps(&dk, &c) { None => len_rejected += 1, Some(_) => len_accepted += 1 }
                }
            }
            // encaps
            let (mut ek_rej_ok, mut ek_acc_bad, mut ek_noapi) = (0, 0, 0);
            for t in &et {
                let ek = unhex(&s(t, "ek"));
                let m: [u8; 32] = unhex(&s(t, "m")).try_into().unwrap();
                if s(t, "result") == "valid" {
                    let ok = imp.check_ek(&ek) != Check::Reject && imp.encaps(&ek, &m).map(|(c, k)| (c, k.to_vec())) == Some((unhex(&s(t, "c")), unhex(&s(t, "K"))));
                    if ok { pass += 1 } else { fail.push(format!("encaps tc{}", t["tcId"])) }
                } else if ek.len() == p.ek {
                    match imp.check_ek(&ek) {
                        Check::Reject => ek_rej_ok += 1,
                        Check::Accept => ek_acc_bad += 1,
                        Check::NoApi => ek_noapi += 1,
                    }
                }
            }
            // CCTV modulus
            let (mut mod_rej, mut mod_acc, mut mod_noapi, mut mod_encaps_ran) = (0, 0, 0, 0);
            for ek in &modk {
                match imp.check_ek(ek) {
                    Check::Reject => mod_rej += 1,
                    Check::Accept => mod_acc += 1,
                    Check::NoApi => mod_noapi += 1,
                }
                if imp.encaps(ek, &[7u8; 32]).is_some() {
                    mod_encaps_ran += 1;
                }
            }
            // semi-expanded decaps
            let (mut dk_rej_ok, mut dk_acc_bad, mut dk_noapi) = (0, 0, 0);
            for t in &st {
                let dk = unhex(&s(t, "dk"));
                let c = unhex(&s(t, "c"));
                let flags: Vec<String> = t["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect();
                if s(t, "result") == "valid" {
                    let ok = imp.decaps(&dk, &c).map(|k| k.to_vec()) == Some(unhex(&s(t, "K")));
                    if ok { pass += 1 } else { fail.push(format!("semi-expanded tc{}", t["tcId"])) }
                } else if flags.iter().any(|f| f == "InvalidDecapsulationKey") {
                    match imp.check_dk(&dk) {
                        Check::Reject => dk_rej_ok += 1,
                        Check::Accept => dk_acc_bad += 1,
                        Check::NoApi => dk_noapi += 1,
                    }
                }
            }
            // CCTV strcmp
            for (i, (dk, c, k)) in sc.iter().enumerate() {
                if imp.decaps(dk, c).map(|x| x.to_vec()) == Some(k.clone()) { pass += 1 } else { fail.push(format!("strcmp #{i}")) }
            }
            println!(
                "VECTORS {} impl=[{}] positive_pass={} positive_fail={} {:?} | wrong-seed-length (not passable, 64-byte API)={} | wrong-ct-length rejected={} accepted={} | invalid-ek (Wycheproof, right length) rejected={} accepted={} no-check-api={} | CCTV modulus keys={} rejected={} accepted={} no-check-api={} encaps-ran-anyway={} | invalid-dk rejected={} accepted={} no-check-api={}",
                p.name, imp.name(), pass, fail.len(), fail.iter().take(5).collect::<Vec<_>>(), bad_seed_len, len_rejected, len_accepted,
                ek_rej_ok, ek_acc_bad, ek_noapi, modk.len(), mod_rej, mod_acc, mod_noapi, mod_encaps_ran, dk_rej_ok, dk_acc_bad, dk_noapi
            );
        }
    }
    // X25519 Wycheproof
    let xt = tests_of(&load_json(&format!("{dir}/wycheproof/x25519_test.json")));
    let (mut ok, mut bad, mut zero) = (0, 0, 0);
    let mut zero_flags = std::collections::BTreeMap::new();
    for t in &xt {
        let k: [u8; 32] = unhex(&s(t, "private")).try_into().unwrap();
        let u: [u8; 32] = unhex(&s(t, "public")).try_into().unwrap();
        let out = x25519_dalek::x25519(k, u);
        if out.to_vec() == unhex(&s(t, "shared")) { ok += 1 } else { bad += 1 }
        if out == [0u8; 32] {
            zero += 1;
            for f in t["flags"].as_array().unwrap() {
                *zero_flags.entry(f.as_str().unwrap().to_string()).or_insert(0) += 1;
            }
        }
    }
    println!("X25519 Wycheproof tests={} match={} mismatch={} all-zero-outputs={} flags-on-zero-outputs={:?}", xt.len(), ok, bad, zero, zero_flags);
    // RFC 7748
    if let Some(path) = rfc {
        let txt = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = txt.lines().collect();
        let after = |label: &str, nth: usize| -> [u8; 32] {
            let idx = lines.iter().enumerate().filter(|(_, l)| l.trim() == label).nth(nth).map(|(i, _)| i).unwrap_or_else(|| panic!("label {label}"));
            let hexs: String = lines[idx + 1].trim().to_string();
            unhex(&hexs).try_into().unwrap()
        };
        let mut res = Vec::new();
        for i in 0..2 {
            let k = after("Input scalar:", i);
            let u = after("Input u-coordinate:", i);
            let o = after("Output u-coordinate:", i);
            res.push((format!("5.2 vector {}", i + 1), x25519_dalek::x25519(k, u) == o));
        }
        let one = after("After one iteration:", 0);
        let thousand = after("After 1,000 iterations:", 0);
        let million = after("After 1,000,000 iterations:", 0);
        let mut k = x25519_dalek::X25519_BASEPOINT_BYTES;
        let mut u = x25519_dalek::X25519_BASEPOINT_BYTES;
        let t0 = Instant::now();
        for it in 1..=1_000_000usize {
            let r = x25519_dalek::x25519(k, u);
            u = k;
            k = r;
            if it == 1 { res.push(("5.2 iterated x1".into(), k == one)); }
            if it == 1000 { res.push(("5.2 iterated x1000".into(), k == thousand)); }
        }
        res.push((format!("5.2 iterated x1000000 ({:.1}s)", t0.elapsed().as_secs_f64()), k == million));
        let a = after("Alice's private key, a:", 0);
        let apub = after("Alice's public key, X25519(a, 9):", 0);
        let b = after("Bob's private key, b:", 0);
        let bpub = after("Bob's public key, X25519(b, 9):", 0);
        let kk = after("Their shared secret, K:", 0);
        res.push(("6.1 Alice public".into(), x25519_dalek::x25519(a, x25519_dalek::X25519_BASEPOINT_BYTES) == apub));
        res.push(("6.1 Bob public".into(), x25519_dalek::x25519(b, x25519_dalek::X25519_BASEPOINT_BYTES) == bpub));
        res.push(("6.1 shared (a, B)".into(), x25519_dalek::x25519(a, bpub) == kk));
        res.push(("6.1 shared (b, A)".into(), x25519_dalek::x25519(b, apub) == kk));
        for (name, ok) in res {
            println!("RFC7748 x25519-dalek 3.0.0 {name}: {}", if ok { "PASS" } else { "FAIL" });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 3b. X-Wing (RustCrypto x-wing 0.1.0) against draft-connolly-cfrg-xwing-kem Appendix C
// ---------------------------------------------------------------------------------------------

fn cmd_xwing(args: &[String]) {
    use x_wing::{Decapsulate, Decapsulator, KeyExport};
    let txt = std::fs::read_to_string(&args[0]).unwrap();
    // the heading also appears in the table of contents; the vectors follow the last occurrence
    let start = txt.rfind("Appendix C.  Test vectors").expect("Appendix C");
    let body = &txt[start..];
    let body = &body[body.find('\n').unwrap() + 1..];
    // records: a key at column 0 (seed, sk, pk, eseed, ct, ss) with hex on the same line or on
    // the following indented lines; a new "seed" starts a new record.
    let mut recs: Vec<std::collections::HashMap<String, String>> = Vec::new();
    let mut cur: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut key = String::new();
    for line in body.lines() {
        if line.starts_with("Appendix") || line.starts_with("Acknowledg") || line.starts_with("Authors") {
            break;
        }
        if line.trim().is_empty() || line.contains("[Page") || line.starts_with("Connolly") || line.starts_with("Internet-Draft") {
            continue;
        }
        let t = line.trim();
        if !line.starts_with(' ') {
            let mut it = t.split_whitespace();
            let k = it.next().unwrap().to_string();
            if !["seed", "sk", "pk", "eseed", "ct", "ss"].contains(&k.as_str()) {
                continue;
            }
            if k == "seed" && !cur.is_empty() {
                recs.push(std::mem::take(&mut cur));
            }
            key = k;
            cur.insert(key.clone(), it.collect::<Vec<_>>().join(""));
        } else if !key.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit()) {
            cur.get_mut(&key).unwrap().push_str(t);
        }
    }
    if !cur.is_empty() {
        recs.push(cur);
    }
    let (mut ok, mut bad) = (0, 0);
    for r in &recs {
        let seed: [u8; 32] = unhex(&r["seed"]).try_into().unwrap();
        let dk = x_wing::DecapsulationKey::from(seed);
        let pk = dk.encapsulation_key().to_bytes().to_vec();
        let eseed: [u8; 64] = unhex(&r["eseed"]).try_into().unwrap();
        let (ct, ss) = dk.encapsulation_key().encapsulate_deterministic(&ml_kem::array::Array::from(eseed));
        let ss2 = dk.decapsulate(&ct);
        let good = unhex(&r["sk"]) == seed.to_vec()
            && pk == unhex(&r["pk"])
            && ct.to_vec() == unhex(&r["ct"])
            && ss.to_vec() == unhex(&r["ss"])
            && ss2 == ss;
        if good { ok += 1 } else { bad += 1 }
    }
    println!("XWING x-wing 0.1.0 vs {} Appendix C: vectors={} pass={} fail={} {}", args[0].rsplit(['/', '\\']).next().unwrap(), recs.len(), ok, bad, if bad == 0 && ok > 0 { "PASS" } else { "FAIL" });
}

// ---------------------------------------------------------------------------------------------
// 4. Interop with PQClean's randomised API (and aws-lc-rs when built with --features awslc)
// ---------------------------------------------------------------------------------------------

fn cmd_interop(args: &[String]) {
    use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
    let n: usize = args.first().map(|a| a.parse().unwrap()).unwrap_or(200);
    let mut ok = 0;
    let mut bad = 0;
    for _ in 0..n {
        let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
        let (ss, ct) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);
        for imp in impls(P768) {
            let k = imp.decaps(sk.as_bytes(), ct.as_bytes());
            if k.map(|x| x.to_vec()) == Some(ss.as_bytes().to_vec()) { ok += 1 } else { bad += 1 }
            let (c2, k2) = imp.encaps(pk.as_bytes(), &[9u8; 32]).unwrap();
            let c2 = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(&c2).unwrap();
            let k3 = pqcrypto_mlkem::mlkem768::decapsulate(&c2, &sk);
            if k3.as_bytes() == k2 { ok += 1 } else { bad += 1 }
        }
    }
    println!("INTEROP pqcrypto-mlkem randomised keypair/encapsulate vs all impls (ML-KEM-768): trials={} ok={} bad={}", n, ok, bad);
    #[cfg(feature = "awslc")]
    awslc_interop(n, args.get(1).cloned());
}

#[cfg(feature = "awslc")]
fn awslc_interop(n: usize, vectors: Option<String>) {
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024, ML_KEM_512, ML_KEM_768};
    for (p, alg) in [(P512, &ML_KEM_512), (P768, &ML_KEM_768), (P1024, &ML_KEM_1024)] {
        let (mut ok, mut bad) = (0, 0);
        for i in 0..n {
            let d = DecapsulationKey::generate(alg).unwrap();
            let ek = d.encapsulation_key().unwrap();
            let ekb = ek.key_bytes().unwrap();
            let dkb = d.key_bytes().unwrap();
            let (ct, ss) = ek.encapsulate().unwrap();
            for imp in impls(p) {
                let k = imp.decaps(dkb.as_ref(), ct.as_ref());
                if k.map(|x| x.to_vec()) == Some(ss.as_ref().to_vec()) { ok += 1 } else { bad += 1 }
                let (c2, k2) = imp.encaps(ekb.as_ref(), &[(i % 251) as u8; 32]).unwrap();
                let k3 = d.decapsulate(Ciphertext::from(c2.as_slice())).unwrap();
                if k3.as_ref() == k2 { ok += 1 } else { bad += 1 }
                // implicit rejection: modified ciphertext must give J(z || c')
                let mut c4 = c2.clone();
                let l = c4.len();
                c4[i % l] ^= 1;
                let k4 = d.decapsulate(Ciphertext::from(c4.as_slice())).unwrap();
                let z = &dkb.as_ref()[p.dk - 32..];
                if k4.as_ref() == shake256_32(&[z, &c4]) { ok += 1 } else { bad += 1 }
            }
        }
        // encapsulation-key check: first CCTV-style bad key (coefficient = q at position 0)
        let mut bad_ek = vec![0u8; p.ek];
        bad_ek[0] = 0x01;
        bad_ek[1] = 0x0d; // 12-bit little-endian value 0xd01 = 3329 = q
        let rejected = EncapsulationKey::new(alg, &bad_ek).is_err();
        // CCTV modulus keys through the aws-lc-rs public constructor
        let (mut mrej, mut macc, mut menc_err) = (0, 0, 0);
        let q_key_encaps_err = EncapsulationKey::new(alg, &bad_ek).map(|k| k.encapsulate().is_err()).unwrap_or(true);
        if let Some(dir) = &vectors {
            use std::io::Read as _;
            let f = std::fs::File::open(format!("{dir}/cctv/modulus/{}.txt.gz", p.name)).unwrap();
            let mut txt = String::new();
            flate2::read::GzDecoder::new(f).read_to_string(&mut txt).unwrap();
            for line in txt.lines().filter(|l| !l.trim().is_empty()) {
                match EncapsulationKey::new(alg, &unhex(line)) {
                    Err(_) => mrej += 1,
                    Ok(k) => {
                        macc += 1;
                        if k.encapsulate().is_err() { menc_err += 1 }
                    }
                }
            }
        }
        println!("INTEROP aws-lc-rs 1.18.1 {} vs all impls: trials={} ok={} bad={} (decaps of aws ct, aws decaps of our ct, aws implicit rejection = J(z||c')) ek-with-coefficient-q rejected-by-new={} encapsulate-errors={} | CCTV-modulus rejected-by-new={} accepted-by-new={} of-those-encapsulate-errors={}", p.name, n, ok, bad, rejected, q_key_encaps_err, mrej, macc, menc_err);
    }
}

// ---------------------------------------------------------------------------------------------
// 5. FrodoKEM KATs through the NIST AES-256 CTR_DRBG
// ---------------------------------------------------------------------------------------------

/// NIST PQC KAT generator's AES256_CTR_DRBG (rng.c): no derivation function, no personalization.
struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
    calls: Vec<usize>,
}

impl NistDrbg {
    fn aes(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let c = aes::Aes256::new(&(*key).into());
        let mut b = aes::Block::from(*block);
        c.encrypt_block(&mut b);
        let mut o = [0u8; 16];
        o.copy_from_slice(&b);
        o
    }
    fn inc(v: &mut [u8; 16]) {
        for j in (0..16).rev() {
            if v[j] == 0xff {
                v[j] = 0;
            } else {
                v[j] += 1;
                break;
            }
        }
    }
    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];
        for i in 0..3 {
            Self::inc(&mut self.v);
            temp[16 * i..16 * i + 16].copy_from_slice(&Self::aes(&self.key, &self.v));
        }
        if let Some(p) = provided {
            for i in 0..48 {
                temp[i] ^= p[i];
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }
    fn new(seed: &[u8; 48]) -> Self {
        let mut d = NistDrbg { key: [0; 32], v: [0; 16], calls: Vec::new() };
        d.update(Some(seed));
        d
    }
    fn randombytes(&mut self, out: &mut [u8]) {
        self.calls.push(out.len());
        let mut off = 0;
        while off < out.len() {
            Self::inc(&mut self.v);
            let b = Self::aes(&self.key, &self.v);
            let n = (out.len() - off).min(16);
            out[off..off + n].copy_from_slice(&b[..n]);
            off += n;
        }
        self.update(None);
    }
}

impl rand_core::TryRng for NistDrbg {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.randombytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.randombytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.randombytes(dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for NistDrbg {}

fn frodo_alg(name: &str) -> frodo_kem::Algorithm {
    use frodo_kem::Algorithm::*;
    match name {
        "FrodoKEM-640-SHAKE" => FrodoKem640Shake,
        "FrodoKEM-976-SHAKE" => FrodoKem976Shake,
        "FrodoKEM-1344-SHAKE" => FrodoKem1344Shake,
        "FrodoKEM-640-AES" => FrodoKem640Aes,
        "FrodoKEM-976-AES" => FrodoKem976Aes,
        "FrodoKEM-1344-AES" => FrodoKem1344Aes,
        "eFrodoKEM-640-SHAKE" => EphemeralFrodoKem640Shake,
        "eFrodoKEM-976-SHAKE" => EphemeralFrodoKem976Shake,
        "eFrodoKEM-1344-SHAKE" => EphemeralFrodoKem1344Shake,
        "eFrodoKEM-640-AES" => EphemeralFrodoKem640Aes,
        "eFrodoKEM-976-AES" => EphemeralFrodoKem976Aes,
        "eFrodoKEM-1344-AES" => EphemeralFrodoKem1344Aes,
        _ => panic!("unknown FrodoKEM variant {name}"),
    }
}

fn cmd_frodo_kat(args: &[String]) {
    let path = &args[0];
    let alg = frodo_alg(&args[1]);
    let txt = std::fs::read_to_string(path).unwrap();
    let mut recs: Vec<std::collections::HashMap<String, String>> = Vec::new();
    let mut cur = std::collections::HashMap::new();
    for line in txt.lines() {
        if let Some((k, v)) = line.split_once(" = ") {
            if k == "count" && !cur.is_empty() {
                recs.push(std::mem::take(&mut cur));
            }
            cur.insert(k.to_string(), v.to_string());
        }
    }
    if !cur.is_empty() {
        recs.push(cur);
    }
    let (mut pk_ok, mut sk_ok, mut ct_ok, mut ss_ok, mut dec_ok) = (0, 0, 0, 0, 0);
    let mut call_pattern = String::new();
    let mut all = Shake128::default();
    for r in &recs {
        let seed: [u8; 48] = unhex(&r["seed"]).try_into().unwrap();
        let mut rng = NistDrbg::new(&seed);
        let (pk, sk) = alg.generate_keypair(&mut rng);
        let (ct, ss) = alg.encapsulate_with_rng(&pk, &mut rng).unwrap();
        let (ss2, _mu) = alg.decapsulate(&sk, &ct).unwrap();
        if pk.value() == unhex(&r["pk"]).as_slice() { pk_ok += 1 }
        if sk.value() == unhex(&r["sk"]).as_slice() { sk_ok += 1 }
        if ct.value() == unhex(&r["ct"]).as_slice() { ct_ok += 1 }
        if ss.value() == unhex(&r["ss"]).as_slice() { ss_ok += 1 }
        if ss2.value() == ss.value() { dec_ok += 1 }
        all.update(pk.value());
        all.update(ct.value());
        all.update(ss.value());
        if call_pattern.is_empty() {
            call_pattern = format!("{:?}", rng.calls);
        }
    }
    let mut d = [0u8; 32];
    all.finalize_xof().read(&mut d);
    println!(
        "FRODO-KAT {} file={} records={} pk_match={} sk_match={} ct_match={} ss_match={} decaps_roundtrip={} drbg_call_lengths={} sizes pk={} sk={} ct={} {}",
        args[1], path.rsplit(['/', '\\']).next().unwrap(), recs.len(), pk_ok, sk_ok, ct_ok, ss_ok, dec_ok, call_pattern,
        unhex(&recs[0]["pk"]).len(), unhex(&recs[0]["sk"]).len(), unhex(&recs[0]["ct"]).len(),
        if pk_ok == recs.len() && sk_ok == recs.len() && ct_ok == recs.len() && ss_ok == recs.len() { "PASS" } else { "FAIL" }
    );
    let _ = d;
}

/// frodo-kem 0.1.0 decapsulate returns (shared secret, mu'). Show what mu' is for a rejected ciphertext.
fn cmd_frodo_mu(args: &[String]) {
    let n: usize = args.first().map(|a| a.parse().unwrap()).unwrap_or(200);
    let alg = frodo_alg(args.get(1).map(|s| s.as_str()).unwrap_or("FrodoKEM-976-SHAKE"));
    let mut rng = NistDrbg::new(&[42u8; 48]);
    let (pk, sk) = alg.generate_keypair(&mut rng);
    let mut stream = Stream::new(b"rpi frodo mu");
    let (mut rejected, mut mu_equal_original) = (0, 0);
    for _ in 0..n {
        let params_mu = match alg { frodo_kem::Algorithm::FrodoKem640Shake | frodo_kem::Algorithm::FrodoKem640Aes | frodo_kem::Algorithm::EphemeralFrodoKem640Shake | frodo_kem::Algorithm::EphemeralFrodoKem640Aes => 16, frodo_kem::Algorithm::FrodoKem976Shake | frodo_kem::Algorithm::FrodoKem976Aes | frodo_kem::Algorithm::EphemeralFrodoKem976Shake | frodo_kem::Algorithm::EphemeralFrodoKem976Aes => 24, _ => 32 };
        let salt_len = match alg { frodo_kem::Algorithm::FrodoKem640Shake | frodo_kem::Algorithm::FrodoKem640Aes => 32, frodo_kem::Algorithm::FrodoKem976Shake | frodo_kem::Algorithm::FrodoKem976Aes => 48, frodo_kem::Algorithm::FrodoKem1344Shake | frodo_kem::Algorithm::FrodoKem1344Aes => 64, _ => 0 };
        let mut mu = vec![0u8; params_mu];
        let mut salt = vec![0u8; salt_len];
        stream.read(&mut mu);
        stream.read(&mut salt);
        let (ct, ss) = alg.encapsulate(&pk, &mu, &salt).unwrap();
        let mut c = ct.value().to_vec();
        c[0] ^= 1; // lowest bit of the first ciphertext byte: packing is MSB-first, so this adds a small error (2^8 for D = 16) to the first coefficient of B', which decoding absorbs
        let ct2 = alg.ciphertext_from_bytes(&c).unwrap();
        let (ss2, mu2) = alg.decapsulate(&sk, &ct2).unwrap();
        if ss2.value() != ss.value() {
            rejected += 1;
        }
        if mu2 == mu {
            mu_equal_original += 1;
        }
    }
    println!("FRODO-MU frodo-kem 0.1.0 {:?}: modified ciphertexts={} rejected(ss differs)={} returned mu' == original mu in {} cases", alg, n, rejected, mu_equal_original);
}

// ---------------------------------------------------------------------------------------------
// 6. Timings
// ---------------------------------------------------------------------------------------------

fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Median over `reps` single calls of (TSC ticks, nanoseconds).
fn time_it<F: FnMut()>(reps: usize, mut f: F) -> (u64, u64) {
    for _ in 0..(reps / 10).max(3) {
        f();
    }
    let mut tk = Vec::with_capacity(reps);
    let mut ns = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t0 = Instant::now();
        let c0 = ticks();
        f();
        let c1 = ticks();
        ns.push(t0.elapsed().as_nanos() as u64);
        tk.push(c1 - c0);
    }
    tk.sort_unstable();
    ns.sort_unstable();
    (tk[reps / 2], ns[reps / 2])
}

fn cmd_bench(args: &[String]) {
    let reps: usize = args.first().map(|a| a.parse().unwrap()).unwrap_or(2000);
    let freps: usize = args.get(1).map(|a| a.parse().unwrap()).unwrap_or(200);
    // Warm the TSC frequency estimate: ticks per ns over 200 ms.
    let t0 = Instant::now();
    let c0 = ticks();
    while t0.elapsed().as_millis() < 200 {}
    let tsc_ghz = (ticks() - c0) as f64 / t0.elapsed().as_nanos() as f64;
    println!("BENCH tsc_ticks_per_ns={:.3} avx2={} (TSC ticks are reference cycles at the nominal clock, not core cycles)", tsc_ghz, avx2());
    let seed = [3u8; 64];
    let m = [5u8; 32];
    macro_rules! bench_rc {
        ($p:ty, $name:expr) => {{
            use ml_kem::{Decapsulate, KeyExport};
            let dk = ml_kem::DecapsulationKey::<$p>::from_seed(ml_kem::Seed::from(seed));
            let ek = dk.encapsulation_key().clone();
            let (ct, _) = ek.encapsulate_deterministic(&ml_kem::B32::from(m));
            let kg = time_it(reps, || { std::hint::black_box(ml_kem::DecapsulationKey::<$p>::from_seed(ml_kem::Seed::from(std::hint::black_box(seed)))); });
            let en = time_it(reps, || { std::hint::black_box(ek.encapsulate_deterministic(&ml_kem::B32::from(std::hint::black_box(m)))); });
            let de = time_it(reps, || { std::hint::black_box(dk.decapsulate(std::hint::black_box(&ct))); });
            let _ = ek.to_bytes();
            println!("BENCH {} ml-kem 0.3.2 keygen={:?} encaps={:?} decaps={:?} (ticks, ns)", $name, kg, en, de);
        }};
    }
    bench_rc!(ml_kem::MlKem512, "ML-KEM-512");
    bench_rc!(ml_kem::MlKem768, "ML-KEM-768");
    bench_rc!(ml_kem::MlKem1024, "ML-KEM-1024");
    macro_rules! bench_lc {
        ($m:ident, $name:expr, $label:expr) => {{
            let kp = $m::generate_key_pair(seed);
            let (ct, _) = $m::encapsulate(kp.public_key(), m);
            let kg = time_it(reps, || { std::hint::black_box($m::generate_key_pair(std::hint::black_box(seed))); });
            let en = time_it(reps, || { std::hint::black_box($m::encapsulate(kp.public_key(), std::hint::black_box(m))); });
            let de = time_it(reps, || { std::hint::black_box($m::decapsulate(kp.private_key(), std::hint::black_box(&ct))); });
            println!("BENCH {} {} keygen={:?} encaps={:?} decaps={:?} (ticks, ns)", $name, $label, kg, en, de);
        }};
    }
    bench_lc!(lc512p, "ML-KEM-512", "libcrux portable");
    bench_lc!(lc768p, "ML-KEM-768", "libcrux portable");
    bench_lc!(lc1024p, "ML-KEM-1024", "libcrux portable");
    if avx2() {
        bench_lc!(lc512a, "ML-KEM-512", "libcrux avx2");
        bench_lc!(lc768a, "ML-KEM-768", "libcrux avx2");
        bench_lc!(lc1024a, "ML-KEM-1024", "libcrux avx2");
    }
    macro_rules! bench_fi {
        ($m:ident, $name:expr) => {{
            use fips203::traits::{Decaps, Encaps, KeyGen};
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            d.copy_from_slice(&seed[..32]);
            z.copy_from_slice(&seed[32..]);
            let (ek, dk) = fips203::$m::KG::keygen_from_seed(d, z);
            let (_, ct) = ek.encaps_from_seed(&m);
            let kg = time_it(reps, || { std::hint::black_box(fips203::$m::KG::keygen_from_seed(std::hint::black_box(d), z)); });
            let en = time_it(reps, || { std::hint::black_box(ek.encaps_from_seed(std::hint::black_box(&m))); });
            let de = time_it(reps, || { std::hint::black_box(dk.try_decaps(std::hint::black_box(&ct)).unwrap()); });
            println!("BENCH {} fips203 0.4.3 keygen={:?} encaps={:?} decaps={:?} (ticks, ns)", $name, kg, en, de);
        }};
    }
    bench_fi!(ml_kem_512, "ML-KEM-512");
    bench_fi!(ml_kem_768, "ML-KEM-768");
    bench_fi!(ml_kem_1024, "ML-KEM-1024");
    for (p, imp) in [(P512, Box::new(Pq512) as Box<dyn Kem>), (P768, Box::new(Pq768)), (P1024, Box::new(Pq1024))] {
        let (ek, dk) = imp.keygen(&seed).unwrap();
        let (ct, _) = imp.encaps(&ek, &m).unwrap();
        let kg = time_it(reps, || { std::hint::black_box(imp.keygen(std::hint::black_box(&seed))); });
        let en = time_it(reps, || { std::hint::black_box(imp.encaps(&ek, std::hint::black_box(&m))); });
        let de = time_it(reps, || { std::hint::black_box(imp.decaps(&dk, std::hint::black_box(&ct))); });
        println!("BENCH {} PQClean clean C keygen={:?} encaps={:?} decaps={:?} (ticks, ns; includes Vec allocation)", p.name, kg, en, de);
    }
    for name in ["FrodoKEM-640-SHAKE", "FrodoKEM-976-SHAKE", "FrodoKEM-1344-SHAKE", "FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES"] {
        let alg = frodo_alg(name);
        let mut rng = NistDrbg::new(&[1u8; 48]);
        let (pk, sk) = alg.generate_keypair(&mut rng);
        let (ct, _) = alg.encapsulate_with_rng(&pk, &mut rng).unwrap();
        let kg = time_it(freps, || { std::hint::black_box(alg.generate_keypair(&mut rng)); });
        let en = time_it(freps, || { std::hint::black_box(alg.encapsulate_with_rng(&pk, &mut rng).unwrap()); });
        let de = time_it(freps, || { std::hint::black_box(alg.decapsulate(&sk, &ct).unwrap()); });
        println!("BENCH {} frodo-kem 0.1.0 keygen={:?} encaps={:?} decaps={:?} (ticks, ns)", name, kg, en, de);
    }
    {
        let k = [9u8; 32];
        let u = x25519_dalek::X25519_BASEPOINT_BYTES;
        let x = time_it(reps, || { std::hint::black_box(x25519_dalek::x25519(std::hint::black_box(k), u)); });
        println!("BENCH X25519 x25519-dalek 3.0.0 scalar-mult={:?} (ticks, ns)", x);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[2.min(args.len())..];
    let _ = sha3_256(b"");
    match cmd {
        "accumulated" => cmd_accumulated(rest),
        "reject" => cmd_reject(rest),
        "vectors" => cmd_vectors(rest),
        "interop" => cmd_interop(rest),
        "xwing" => cmd_xwing(rest),
        "frodo-kat" => cmd_frodo_kat(rest),
        "frodo-mu" => cmd_frodo_mu(rest),
        "bench" => cmd_bench(rest),
        _ => {
            eprintln!("usage: rpi_oracle_probe accumulated N [512|768|1024 ...] | reject N | vectors VECTOR_DIR [RFC7748_TXT] | interop N [VECTOR_DIR] | xwing DRAFT_TXT | frodo-kat RSP VARIANT | frodo-mu N VARIANT | bench REPS FRODO_REPS");
            std::process::exit(2);
        }
    }
}
