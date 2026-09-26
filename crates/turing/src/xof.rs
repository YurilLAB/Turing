//! Domain-separated derivation of every Turing constant and key-derived value.
//!
//! All derivations use cSHAKE256 from NIST SP 800-185 with the function name
//! N empty (reserved for NIST) and the customization string S set to a
//! "Turing v1 ..." label. cSHAKE encodes S with its length before the input,
//! so two derivations with different labels can never be fed the same bytes,
//! whatever the input lengths. Plain SHAKE256(label || input) only has that
//! property while every label/input combination happens to differ in length.

use sha3::digest::core_api::{Buffer, CoreWrapper, ExtendableOutputCore, XofReaderCore};
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

/// The same function for secret input and output (key whitening), leaving no
/// copy behind. The high-level API above keeps the input and the last output
/// block in the digest crate's buffers, which are never wiped. Here the
/// buffers are ours: the input goes into a block buffer we wipe, the output
/// block is wiped after copying, and the Keccak state itself is wiped on
/// drop by the sha3 crate (its `zeroize` feature, enabled in Cargo.toml).
///
/// Handles input shorter than one block (136 bytes) and output of at most
/// one block, which covers a 32-byte key.
pub fn cshake256_secret(label: &str, input: &[u8], out: &mut [u8]) {
    assert!(!label.is_empty(), "cSHAKE label must not be empty");
    let mut core = CShake256Core::new(label.as_bytes());
    let mut buffer = Buffer::<CShake256Core>::new(input);
    let mut reader = core.finalize_xof_core(&mut buffer);
    let mut block = reader.read_block();
    assert!(out.len() <= block.len(), "at most one block of output");
    out.copy_from_slice(&block[..out.len()]);
    block.as_mut_slice().zeroize();
    // SAFETY: a BlockBuffer is a byte array, a u8 position and a PhantomData:
    // no references, no Drop impl, and all zeroes is a valid (empty) buffer.
    // It is not used again.
    unsafe { zeroize::zeroize_flat_type(&mut buffer) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::digest::XofReader;

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
    // length it accepts and every output length.
    #[test]
    fn secret_version_matches() {
        let data: Vec<u8> = (0..136u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in 0..136 {
            let mut expected = [0u8; 136];
            cshake256("Turing v1 test", &data[..len]).read(&mut expected);
            for out_len in [1usize, 16, 32, 135, 136] {
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
