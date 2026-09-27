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

use crate::memory::{SecretBox, Zeroable};
use sha3::digest::core_api::CoreWrapper;
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

/// The same function for secret input and output (key whitening, the checksum
/// point, key generation, key shielding), leaving no copy behind. It runs on
/// `SecretXof`, whose whole Keccak state lives in its own locked allocation
/// and is wiped in place. The sha3 crate's API was used here before: its
/// buffers are never wiped, and `finalize_xof_core` takes the state by value,
/// so every call moved a copy of the state through the stack (a leftover
/// state gives the input back through one inverse permutation, research/
/// reviews/2026-09-28 R1).
pub fn cshake256_secret(label: &str, input: &[u8], out: &mut [u8]) {
    let mut x = SecretXof::new(label);
    x.absorb(input);
    x.squeeze(out);
    x.wipe();
}

/// cSHAKE256's and SHAKE256's rate in bytes (capacity 512 bits).
const RATE: usize = 136;
/// SHA3-512's rate in bytes (capacity 1024 bits).
const RATE_SHA3_512: usize = 72;

/// SP 800-185 left_encode(x): the byte length of x, then x big-endian.
fn left_encode(x: u64, out: &mut [u8; 9]) -> &[u8] {
    let len = (8 - (x.leading_zeros() as usize / 8)).max(1);
    out[0] = len as u8;
    out[1..=len].copy_from_slice(&x.to_be_bytes()[8 - len..]);
    &out[..=len]
}

/// A Keccak sponge's whole state: 25 lanes, where in the rate block it is,
/// whether it squeezes, whether it was wiped.
struct SpongeState {
    lanes: [u64; 25],
    pos: u64,
    squeezing: u64,
    wiped: u64,
}

impl Zeroize for SpongeState {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
        self.pos.zeroize();
        self.squeezing.zeroize();
        self.wiped.zeroize();
    }
}

// SAFETY: 28 u64s, so no padding; all zeroes is a valid (empty) state.
unsafe impl Zeroable for SpongeState {}

/// A Keccak-f[1600] sponge for secret data that arrives in parts and leaves
/// in parts: cSHAKE256 for Turing-1026's hashes of a secret message with
/// public bytes and its hundreds of kilobytes of secret noise (docs/16), and
/// SHAKE256 and SHA3-512 for ML-KEM's secret hashes (FIPS 203 G, J, PRF).
/// Written directly on Keccak-f[1600], like the mask stream (random.rs).
///
/// The state is never on the stack. A leftover Keccak state gives its input
/// back through one inverse permutation, and a value on the stack leaves a
/// copy wherever it is moved: `drop(x)` wipes the moved copy, not the
/// original (research/reviews/2026-09-28 R1, where that left Turing-1026's
/// seed behind). Three defences, each enough on its own for that bug:
/// - the state lives in its own locked allocation (memory.rs), so moving a
///   `SecretXof` moves a pointer and no state;
/// - `wipe` clears it in place, and any use after that panics; dropping
///   wipes too;
/// - every caller that absorbs a secret runs below a stack burn, for the
///   compiler temporaries of Keccak-f itself (memory.rs).
///
/// Absorb everything first, then squeeze; absorbing after the first squeeze
/// panics.
pub struct SecretXof {
    state: SecretBox<SpongeState>,
    rate: usize,
    /// The domain bits and the first padding bit: 0x04 for cSHAKE, 0x1F for
    /// SHAKE, 0x06 for SHA-3 (FIPS 202 section 6, SP 800-185 section 3.3).
    suffix: u8,
}

impl SecretXof {
    /// cSHAKE256(X, N = "", S = label).
    pub fn new(label: &str) -> SecretXof {
        assert!(!label.is_empty(), "cSHAKE label must not be empty");
        let mut x = SecretXof::sponge(RATE, 0x04);
        // bytepad(encode_string(N) || encode_string(S), 136) with N empty.
        let mut buf = [0u8; 9];
        x.absorb(left_encode(RATE as u64, &mut buf));
        x.absorb(left_encode(0, &mut buf));
        x.absorb(left_encode(8 * label.len() as u64, &mut buf));
        x.absorb(label.as_bytes());
        if x.state.pos != 0 {
            // The zero padding XORs nothing into the state.
            keccak::f1600(&mut x.state.lanes);
            x.state.pos = 0;
        }
        x
    }

    /// SHAKE256 (FIPS 202): ML-KEM's J and PRF.
    pub fn shake256() -> SecretXof {
        SecretXof::sponge(RATE, 0x1f)
    }

    /// SHA3-512 (FIPS 202): squeeze exactly 64 bytes for the digest (ML-KEM's
    /// G). One squeeze of at most 72 bytes needs no further permutation.
    pub fn sha3_512() -> SecretXof {
        SecretXof::sponge(RATE_SHA3_512, 0x06)
    }

    fn sponge(rate: usize, suffix: u8) -> SecretXof {
        SecretXof { state: SecretBox::zeroed(), rate, suffix }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let rate = self.rate;
        let st = &mut *self.state;
        assert!(st.wiped == 0, "use after wipe");
        assert!(st.squeezing == 0, "absorb after squeeze");
        for &b in data {
            let pos = st.pos as usize;
            st.lanes[pos / 8] ^= u64::from(b) << (8 * (pos % 8));
            st.pos += 1;
            if st.pos as usize == rate {
                keccak::f1600(&mut st.lanes);
                st.pos = 0;
            }
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        let (rate, suffix) = (self.rate, self.suffix);
        let st = &mut *self.state;
        assert!(st.wiped == 0, "use after wipe");
        if st.squeezing == 0 {
            // The domain bits and pad10*1: `suffix` ... 0x80.
            let pos = st.pos as usize;
            st.lanes[pos / 8] ^= u64::from(suffix) << (8 * (pos % 8));
            st.lanes[(rate - 1) / 8] ^= 0x80 << (8 * ((rate - 1) % 8));
            keccak::f1600(&mut st.lanes);
            st.pos = 0;
            st.squeezing = 1;
        }
        for b in out {
            if st.pos as usize == rate {
                keccak::f1600(&mut st.lanes);
                st.pos = 0;
            }
            let pos = st.pos as usize;
            *b = (st.lanes[pos / 8] >> (8 * (pos % 8))) as u8;
            st.pos += 1;
        }
    }

    /// Wipes the state where it lives; any later absorb or squeeze panics.
    /// Call it as soon as the output is read, instead of relying on the end
    /// of a scope (and never through `drop(x)`, which moves).
    pub fn wipe(&mut self) {
        #[cfg(test)]
        recorded::note(&self.state.lanes);
        self.state.zeroize();
        self.state.wiped = 1;
    }
}

impl Drop for SecretXof {
    fn drop(&mut self) {
        if self.state.wiped == 0 {
            self.wipe();
        }
    }
}

/// Test builds record each sponge's last state just before it is wiped, so
/// the residue tests can search the stack for whole Keccak states, the form
/// of leftover that raw-byte needles miss (research/reviews/2026-09-28 R1).
/// Room is reserved up front: recording must not call the allocator in the
/// middle of the operation whose stack is then searched.
#[cfg(test)]
pub(crate) mod recorded {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static ON: Cell<bool> = const { Cell::new(false) };
        static STATES: RefCell<Vec<[u64; 25]>> = const { RefCell::new(Vec::new()) };
    }

    /// Starts recording on this thread (up to 4096 states).
    pub fn start() {
        STATES.with(|s| {
            let mut s = s.borrow_mut();
            s.clear();
            s.reserve(4096);
        });
        ON.with(|o| o.set(true));
    }

    /// Stops recording and returns the states recorded since `start`.
    pub fn stop() -> Vec<[u64; 25]> {
        ON.with(|o| o.set(false));
        STATES.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }

    pub(super) fn note(lanes: &[u64; 25]) {
        if ON.with(|o| o.get()) {
            STATES.with(|s| {
                let mut s = s.borrow_mut();
                if s.len() < s.capacity() {
                    s.push(*lanes);
                }
            });
        }
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

    // SHAKE256 and SHA3-512 on the same sponge equal the sha3 crate's, for
    // every input length across two rate blocks, split in two parts, and
    // output read across block boundaries.
    #[test]
    fn shake256_and_sha3_512_match_the_library() {
        use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
        let data: Vec<u8> = (0..300u32).map(|i| (i * 29 + 7) as u8).collect();
        for len in 0..=300usize {
            let mut want = [0u8; 300];
            let mut h = sha3::Shake256::default();
            Update::update(&mut h, &data[..len]);
            h.finalize_xof().read(&mut want);
            let split = len / 3;
            let mut x = SecretXof::shake256();
            x.absorb(&data[..split]);
            x.absorb(&data[split..len]);
            let mut got = [0u8; 300];
            let (a, b) = got.split_at_mut(137);
            x.squeeze(a);
            x.squeeze(b);
            assert_eq!(got, want, "SHAKE256, input {len}");

            let want512 = sha3::Sha3_512::digest(&data[..len]);
            let mut y = SecretXof::sha3_512();
            y.absorb(&data[..split]);
            y.absorb(&data[split..len]);
            let mut got512 = [0u8; 64];
            y.squeeze(&mut got512);
            assert_eq!(got512[..], want512[..], "SHA3-512, input {len}");
        }
    }

    // The sponge's state is not inside the value (it cannot be: the value is
    // smaller than the 200-byte state), so moving a SecretXof moves no state.
    #[test]
    fn secret_xof_state_lives_off_the_stack() {
        assert!(core::mem::size_of::<SecretXof>() < core::mem::size_of::<[u64; 25]>());
        let mut x = SecretXof::new("Turing v1 test");
        x.absorb(b"secret");
        // A SecretBox allocation is page-aligned, unlike a stack slot or a heap block.
        assert_eq!(&*x.state as *const SpongeState as usize % 4096, 0);
    }

    // wipe clears the whole state where it is, and refuses further use.
    #[test]
    fn wipe_clears_the_state_in_place() {
        let mut x = SecretXof::new("Turing v1 test");
        x.absorb(&[0xa5; 200]);
        let mut out = [0u8; 10];
        x.squeeze(&mut out);
        assert!(x.state.lanes.iter().any(|&l| l != 0));
        x.wipe();
        assert!(x.state.lanes.iter().all(|&l| l == 0) && x.state.pos == 0 && x.state.squeezing == 0);
    }

    #[test]
    #[should_panic(expected = "use after wipe")]
    fn secret_xof_refuses_use_after_wipe() {
        let mut x = SecretXof::shake256();
        x.absorb(b"secret");
        x.wipe();
        x.squeeze(&mut [0u8; 1]);
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
