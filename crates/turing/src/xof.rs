//! Domain-separated derivation of every Turing constant and key-derived value.
//!
//! All derivations use cSHAKE256 from NIST SP 800-185 with the function name
//! N empty (reserved for NIST) and the customization string S set to a
//! "Turing v1 ..." label. cSHAKE encodes S with its length before the input,
//! so two derivations with different labels can never be fed the same bytes,
//! whatever the input lengths. Plain SHAKE256(label || input) only has that
//! property while every label/input combination happens to differ in length.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update};
use sha3::{CShake256Core, CShake256Reader};

/// cSHAKE256(X = input, N = "", S = label). The label must not be empty:
/// with N and S both empty, cSHAKE is defined to be plain SHAKE256, which
/// would silently drop the domain separation.
pub fn cshake256(label: &str, input: &[u8]) -> CShake256Reader {
    assert!(!label.is_empty(), "cSHAKE label must not be empty");
    let mut h = CoreWrapper::from_core(CShake256Core::new(label.as_bytes()));
    h.update(input);
    h.finalize_xof()
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
}
