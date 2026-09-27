//! Known-answer self-test, in the spirit of the cryptographic algorithm
//! self-tests FIPS 140-3 requires before a module uses an algorithm. A
//! miscompiled or corrupted build (a compiler that rewrites the bit-sliced
//! code, a flipped bit in the binary, a broken sha3 dependency) fails here,
//! loudly, instead of producing ciphertexts nobody can decrypt or, worse,
//! weak ones. Call it once at start-up, before any real key is used.
//!
//! The vectors come from `vectors/turing-v2.txt`,
//! `vectors/turing-256-v1.txt` and `vectors/turing-1026-v1.txt` (generated
//! by the independent reference implementations in Bombe, whose tests check
//! these constants against them) and NIST's published cSHAKE256 example
//! values. Every implementation of a primitive is run, not only one: the
//! masked cipher (its own S-box over two shares, with real masks from the
//! OS) must give the plain cipher's vectors, and the mask stream must be
//! cSHAKE256 of its seed. Until the review of 2026-09-28 (R9) neither was
//! run, and a masked S-box computing x^9, or masks repeating every 136
//! bytes, passed. The Turing-1026 check takes most of the time, about 60 ms
//! (twice that with its key check).

use crate::random::{self, MaskStream};
use crate::turing1026::DecapsulationKey;
use crate::{xof, MaskedTuring, Turing, Turing256};
use sha3::digest::XofReader;
use sha3::{Digest, Sha3_256};

/// Which part of the self-test failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestError {
    /// cSHAKE256 does not reproduce NIST's example value.
    Xof,
    /// A known-answer vector encrypted to the wrong ciphertext.
    Encrypt,
    /// A known-answer ciphertext did not decrypt back to its plaintext.
    Decrypt,
    /// Turing-1026 produced a wrong public key, ciphertext or shared key.
    Kem,
    /// The masked cipher encrypted or decrypted a known-answer vector wrongly.
    Masked,
    /// The mask stream is not cSHAKE256 of its seed.
    Masks,
    /// The operating system gave no randomness for the masked cipher.
    Randomness,
}

/// NIST SP 800-185 cSHAKE256 sample #3: S = "Email Signature", X = 00010203.
pub const XOF_SAMPLE: [u8; 32] = [
    0xd0, 0x08, 0x82, 0x8e, 0x2b, 0x80, 0xac, 0x9d, 0x22, 0x18, 0xff, 0xee, 0x1d, 0x07, 0x0c, 0x48, 0xb8, 0xe4, 0xc8, 0x7b,
    0xff, 0x32, 0xc9, 0x69, 0x9d, 0x5b, 0x68, 0x96, 0xee, 0xe0, 0xed, 0xd1,
];

/// (key, plaintext, ciphertext): vectors 0 and 2 of `vectors/turing-v2.txt`.
pub const VECTORS: [([u8; 32], [u8; 16], [u8; 16]); 2] = [
    (
        [0; 32],
        [0; 16],
        [0x09, 0xae, 0x63, 0xc1, 0xfc, 0x6c, 0xe9, 0xd0, 0xe7, 0xb8, 0x1a, 0x53, 0xf0, 0x7f, 0x85, 0x7f],
    ),
    (
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x13, 0xce, 0x4b, 0xdc, 0xb5, 0x48, 0x22, 0x8c, 0xa2, 0x71, 0xf9, 0xdd, 0xcc, 0xa3, 0x07, 0xd8],
    ),
];

/// (key, plaintext, ciphertext): vectors 0 and 2 of `vectors/turing-256-v1.txt`.
pub const VECTORS_256: [([u8; 32], [u8; 32], [u8; 32]); 2] = [
    (
        [0; 32],
        [0; 32],
        [
            0x56, 0x61, 0x4f, 0xa2, 0xdc, 0xa3, 0xc4, 0x51, 0xa2, 0x8b, 0x8e, 0x29, 0x01, 0x07, 0xed, 0x9d, 0x7b, 0x32, 0xc9, 0x1c,
            0x08, 0xff, 0x1f, 0x2a, 0x26, 0xa8, 0x79, 0x64, 0x5d, 0xfb, 0x96, 0x76,
        ],
    ),
    (
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ],
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x21, 0x32, 0x43,
            0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        ],
        [
            0x5f, 0x56, 0x06, 0x29, 0x12, 0x63, 0x04, 0xf8, 0x89, 0x42, 0x4a, 0xc9, 0xc0, 0x60, 0xc1, 0xee, 0x36, 0x00, 0x63, 0xe1,
            0xe5, 0xf3, 0x63, 0x82, 0xcd, 0xbe, 0x19, 0x1a, 0x3a, 0xe7, 0x32, 0x59,
        ],
    ),
];

/// Vector 2 of `vectors/turing-1026-v1.txt`: seed, message, salt, then
/// SHA3-256 of the public key and of the ciphertext, the shared key, and the
/// key decapsulation returns once the ciphertext's first byte is flipped.
pub struct KemVector {
    pub seed: [u8; 32],
    pub message: [u8; 32],
    pub salt: [u8; 64],
    pub public_key_sha3: [u8; 32],
    pub ciphertext_sha3: [u8; 32],
    pub shared_key: [u8; 32],
    pub rejected_key: [u8; 32],
}

pub const KEM_VECTOR: KemVector = KemVector {
    seed: hex32("b6ee9d9a8c8f56563c0fe074c4b80605348825842394fc41f1b9bebfc320fd8a"),
    message: hex32("5c9b5a9dccf0b5fe7d3fc1aad4a8dd0be79187eed9b37aec6d5e0a89bf1c9dda"),
    salt: hex64("016fcf04ecdda2b483978f13e3dac78a93c239e6bfa2cecdb150fca0c7c2255378e9af5833641e48bbe87cf872f42519c6a3b9bc4dfeb9e42a2f7029d8564100"),
    public_key_sha3: hex32("ec4ce8f425754e72401e3bf15c7d3f95b563c499d208ac72896cfec10aba3c0c"),
    ciphertext_sha3: hex32("45f1cb783b1283a9179031b0fefacbe77785b8b9b491ddc16a4cf846b7530f23"),
    shared_key: hex32("e9e4e409016004780566ea449cbb533ec441940afaeb0f833d7150ec8a90c185"),
    rejected_key: hex32("17f5a1f3b474d09537d086af62abcc95af225a8f0e949e637af5f52b53318c4c"),
};

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lower-case hex digit"),
    }
}

const fn hex_bytes<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert!(s.len() == 2 * N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = 16 * hex_digit(s[2 * i]) + hex_digit(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex32(s: &str) -> [u8; 32] {
    hex_bytes(s)
}

const fn hex64(s: &str) -> [u8; 64] {
    hex_bytes(s)
}

fn kem_self_test() -> Result<(), SelfTestError> {
    let v = &KEM_VECTOR;
    let dk = DecapsulationKey::expanded(&v.seed);
    let (mut ciphertext, key) = dk.encapsulation_key().encapsulate_fixed(&v.message, &v.salt);
    let sha3 = |data: &[u8]| -> [u8; 32] { Sha3_256::digest(data).into() };
    let right = sha3(dk.encapsulation_key().as_bytes()) == v.public_key_sha3 && sha3(&ciphertext) == v.ciphertext_sha3 && key[..] == v.shared_key;
    let back = dk.decapsulate(&ciphertext).map_err(|_| SelfTestError::Kem)?;
    ciphertext[0] ^= 1;
    let rejected = dk.decapsulate(&ciphertext).map_err(|_| SelfTestError::Kem)?;
    if right && back[..] == v.shared_key && rejected[..] == v.rejected_key {
        Ok(())
    } else {
        Err(SelfTestError::Kem)
    }
}

/// Runs every check; the first failure is returned.
pub fn self_test() -> Result<(), SelfTestError> {
    let mut out = [0u8; 32];
    xof::cshake256("Email Signature", &[0, 1, 2, 3]).read(&mut out);
    let mut secret = [0u8; 32];
    xof::cshake256_secret("Email Signature", &[0, 1, 2, 3], &mut secret);
    if out != XOF_SAMPLE || secret != XOF_SAMPLE {
        return Err(SelfTestError::Xof);
    }
    for (key, plaintext, ciphertext) in &VECTORS {
        let t = Turing::new(key);
        let mut block = *plaintext;
        t.encrypt_block(&mut block);
        if block != *ciphertext {
            return Err(SelfTestError::Encrypt);
        }
        t.decrypt_block(&mut block);
        if block != *plaintext {
            return Err(SelfTestError::Decrypt);
        }
    }
    for (key, plaintext, ciphertext) in &VECTORS {
        let mut m = MaskedTuring::new(key).map_err(|_| SelfTestError::Randomness)?;
        let mut block = *plaintext;
        m.encrypt_block(&mut block);
        if block != *ciphertext {
            return Err(SelfTestError::Masked);
        }
        m.decrypt_block(&mut block);
        if block != *plaintext {
            return Err(SelfTestError::Masked);
        }
    }
    // Across two block boundaries of the stream (136 bytes each).
    let seed: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
    let (mut got, mut want) = ([0u8; 300], [0u8; 300]);
    MaskStream::from_seed(&seed).fill(&mut got);
    xof::cshake256(random::STREAM_LABEL, &seed).read(&mut want);
    if got != want {
        return Err(SelfTestError::Masks);
    }
    for (key, plaintext, ciphertext) in &VECTORS_256 {
        let t = Turing256::new(key);
        let mut block = *plaintext;
        t.encrypt_block(&mut block);
        if block != *ciphertext {
            return Err(SelfTestError::Encrypt);
        }
        t.decrypt_block(&mut block);
        if block != *plaintext {
            return Err(SelfTestError::Decrypt);
        }
    }
    kem_self_test()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_passes() {
        assert_eq!(self_test(), Ok(()));
    }
}
