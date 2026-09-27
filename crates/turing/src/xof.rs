//! Domain-separated derivation of every Turing constant and key-derived value.
//!
//! All derivations use cSHAKE256 from NIST SP 800-185 with the function name
//! N empty (reserved for NIST) and the customization string S set to a
//! "Turing v1 ..." label (the S-box and matrices) or a "Turing v2 ..." one
//! (the key schedule, key generation, masks and key shielding, docs/13).
//! cSHAKE encodes S with its length before the input, so two derivations
//! with different labels can never be fed the same bytes, whatever the input
//! lengths. Plain SHAKE256(label || input) only has that property while
//! every label/input combination happens to differ in length.

use sha3::digest::core_api::{BlockSizeUser, Buffer, CoreWrapper, ExtendableOutputCore, UpdateCore, XofReaderCore};
use sha3::digest::generic_array::GenericArray;
use sha3::digest::{ExtendableOutput, Update};
use sha3::{CShake256Core, CShake256Reader};
use zeroize::Zeroize;

/// cSHAKE256(X = input, N = "", S = label). The label must not be empty:
/// with N and S both empty, cSHAKE is defined to be plain SHAKE256, which
/// would silently drop the domain separation.
///
/// For public data only: the digest crate's internal buffers are not wiped
/// when dropped. Secrets go through `cshake256_secret`.
pub fn cshake256(label: &str, input: &[u8]) -> CShake256Reader {
    assert!(!label.is_empty(), "cSHAKE label must not be empty");
    let mut h = CoreWrapper::from_core(CShake256Core::new(label.as_bytes()));
    h.update(input);
    h.finalize_xof()
}

/// The same function for secret input and output (key whitening, key
/// shielding), leaving no copy behind. The high-level API above keeps the
/// input and the last output block in the digest crate's buffers, which are
/// never wiped. Here full input blocks are absorbed straight from the
/// caller's slice (cSHAKE's buffer is "eager", so this is exactly what the
/// high-level API does), the partial last block goes into a block buffer we
/// wipe, every output block is wiped after copying, and the Keccak state
/// itself is wiped on drop by the sha3 crate (its `zeroize` feature).
pub fn cshake256_secret(label: &str, input: &[u8], out: &mut [u8]) {
    assert!(!label.is_empty(), "cSHAKE label must not be empty");
    let mut core = CShake256Core::new(label.as_bytes());
    let block_len = CShake256Core::block_size();
    let (full, rest) = input.split_at(input.len() - input.len() % block_len);
    for chunk in full.chunks_exact(block_len) {
        core.update_blocks(core::slice::from_ref(GenericArray::from_slice(chunk)));
    }
    let mut buffer = Buffer::<CShake256Core>::new(rest);
    let mut reader = core.finalize_xof_core(&mut buffer);
    // SAFETY: a BlockBuffer is a byte array, a u8 position and a PhantomData:
    // no references, no Drop impl, and all zeroes is a valid (empty) buffer.
    // It is not used again.
    unsafe { zeroize::zeroize_flat_type(&mut buffer) };
    for chunk in out.chunks_mut(block_len) {
        let mut block = reader.read_block();
        chunk.copy_from_slice(&block[..chunk.len()]);
        block.as_mut_slice().zeroize();
    }
}

/// cSHAKE256's rate in bytes.
const RATE: usize = 136;

/// SP 800-185 left_encode(x): the byte length of x, then x big-endian.
fn left_encode(x: u64, out: &mut [u8; 9]) -> &[u8] {
    let len = (8 - (x.leading_zeros() as usize / 8)).max(1);
    out[0] = len as u8;
    out[1..=len].copy_from_slice(&x.to_be_bytes()[8 - len..]);
    &out[..=len]
}

/// cSHAKE256 (N = "", S = label) for secret data that arrives in parts and
/// leaves in parts: Turing-1026 hashes a secret message together with
/// public bytes, and draws hundreds of kilobytes of secret noise from one
/// stream (docs/16). Written directly on Keccak-f[1600], like the mask
/// stream (random.rs), so the whole state is one array this type owns and
/// wipes when dropped; nothing is left in a library buffer.
///
/// Absorb everything first, then squeeze; absorbing after the first squeeze
/// panics.
pub struct SecretXof {
    lanes: [u64; 25],
    /// Byte position within the current rate block.
    pos: usize,
    squeezing: bool,
}

impl SecretXof {
    pub fn new(label: &str) -> SecretXof {
        assert!(!label.is_empty(), "cSHAKE label must not be empty");
        let mut x = SecretXof { lanes: [0; 25], pos: 0, squeezing: false };
        // bytepad(encode_string(N) || encode_string(S), 136) with N empty.
        let mut buf = [0u8; 9];
        x.absorb(left_encode(RATE as u64, &mut buf));
        x.absorb(left_encode(0, &mut buf));
        x.absorb(left_encode(8 * label.len() as u64, &mut buf));
        x.absorb(label.as_bytes());
        if x.pos != 0 {
            // The zero padding XORs nothing into the state.
            keccak::f1600(&mut x.lanes);
            x.pos = 0;
        }
        x
    }

    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "absorb after squeeze");
        for &b in data {
            self.lanes[self.pos / 8] ^= u64::from(b) << (8 * (self.pos % 8));
            self.pos += 1;
            if self.pos == RATE {
                keccak::f1600(&mut self.lanes);
                self.pos = 0;
            }
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            // cSHAKE's two zero domain bits, then pad10*1: 0x04 ... 0x80.
            self.lanes[self.pos / 8] ^= 0x04 << (8 * (self.pos % 8));
            self.lanes[(RATE - 1) / 8] ^= 0x80 << (8 * ((RATE - 1) % 8));
            keccak::f1600(&mut self.lanes);
            self.pos = 0;
            self.squeezing = true;
        }
        for b in out {
            if self.pos == RATE {
                keccak::f1600(&mut self.lanes);
                self.pos = 0;
            }
            *b = (self.lanes[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }
}

impl Drop for SecretXof {
    fn drop(&mut self) {
        self.lanes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::digest::XofReader;

    // The hand-written cSHAKE256 equals the sha3 crate's for labels whose
    // prefix ends inside, at and past a block boundary, every input length
    // up to three blocks split into two parts at every point, and output
    // read in pieces across block boundaries; and NIST's sample #3.
    #[test]
    fn secret_xof_matches_the_library() {
        let long_label: String = "Turing-1026 v1 ".repeat(9);
        // 2 + 2 + 3 + 129 bytes: the prefix fills exactly one block.
        let exact_label: String = "y".repeat(129);
        let data: Vec<u8> = (0..420u32).map(|i| (i * 13 + 5) as u8).collect();
        for label in ["Turing-1026 v1 coins", "x", long_label.as_str(), exact_label.as_str()] {
            for len in 0..=409usize {
                let mut expected = [0u8; 300];
                cshake256(label, &data[..len]).read(&mut expected);
                for split in [0, len / 3, len] {
                    let mut x = SecretXof::new(label);
                    x.absorb(&data[..split]);
                    x.absorb(&data[split..len]);
                    let mut got = [0u8; 300];
                    let (a, b) = got.split_at_mut(137);
                    x.squeeze(a);
                    x.squeeze(b);
                    assert_eq!(got, expected, "label {label:?} input {len} split {split}");
                }
            }
        }
        let mut x = SecretXof::new("Email Signature");
        x.absorb(&[0, 1, 2, 3]);
        let mut nist = [0u8; 8];
        x.squeeze(&mut nist);
        assert_eq!(hex(&nist), "D008828E2B80AC9D");
    }

    #[test]
    fn left_encode_matches_sp_800_185() {
        let mut buf = [0u8; 9];
        assert_eq!(left_encode(0, &mut buf), &[1, 0]);
        assert_eq!(left_encode(136, &mut buf), &[1, 136]);
        assert_eq!(left_encode(256, &mut buf), &[2, 1, 0]);
        assert_eq!(left_encode(u64::MAX, &mut buf), &[8, 255, 255, 255, 255, 255, 255, 255, 255]);
    }

    #[test]
    #[should_panic(expected = "absorb after squeeze")]
    fn secret_xof_refuses_absorb_after_squeeze() {
        let mut x = SecretXof::new("Turing-1026 v1 test");
        x.squeeze(&mut [0u8; 1]);
        x.absorb(b"late");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    // NIST SP 800-185 example values (cSHAKE_samples.pdf), samples #3 and #4:
    // cSHAKE256 with N = "" and S = "Email Signature", 512-bit output.
    #[test]
    fn matches_nist_samples() {
        let mut out = [0u8; 64];
        cshake256("Email Signature", &[0, 1, 2, 3]).read(&mut out);
        assert_eq!(
            hex(&out),
            "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1\
             64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"
        );
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        cshake256("Email Signature", &data).read(&mut out);
        assert_eq!(
            hex(&out),
            "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917\
             27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB"
        );
    }

    // Different labels give unrelated output for the same input, and the
    // input is not simply appended to the label.
    #[test]
    fn labels_separate_domains() {
        let read = |label: &str, input: &[u8]| {
            let mut out = [0u8; 32];
            cshake256(label, input).read(&mut out);
            out
        };
        assert_ne!(read("Turing v1 key", b" schedule constants"), read("Turing v1 key schedule constants", b""));
        assert_ne!(read("Turing v1 a", b"b"), read("Turing v1 ab", b""));
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn empty_label_is_refused() {
        cshake256("", b"x");
    }

    // The wiping version computes exactly the same function, for every input
    // length up to three blocks, the 16 KB shielding prekey, and output
    // lengths within and across block boundaries.
    #[test]
    fn secret_version_matches() {
        let data: Vec<u8> = (0..16384u32).map(|i| (i * 7 + 3) as u8).collect();
        let lengths = (0..=409usize).chain([16384]);
        for len in lengths {
            let mut expected = [0u8; 300];
            cshake256("Turing v1 test", &data[..len]).read(&mut expected);
            for out_len in [1usize, 16, 32, 135, 136, 137, 272, 300] {
                let mut got = vec![0u8; out_len];
                cshake256_secret("Turing v1 test", &data[..len], &mut got);
                assert_eq!(got, expected[..out_len], "input {len}, output {out_len}");
            }
        }
        let mut nist = [0u8; 64];
        cshake256_secret("Email Signature", &[0, 1, 2, 3], &mut nist);
        assert_eq!(hex(&nist[..8]), "D008828E2B80AC9D");
    }
}
