//! Checks the Turing S-box: that its derivation is reproducible, that the
//! committed constants match it exactly, and that it passes Bombe.

use bombe::analysis::*;
use bombe::gen;
use bombe::report::Report;
use bombe::sbox::Sbox;
use sha3::digest::XofReader;

// Published SHAKE256 test vector (FIPS 202): the first 32 output bytes for
// the empty message. Confirms the crate computes standard SHAKE256, which
// is what lets anyone reproduce Turing's constants with other tools.
#[test]
fn shake256_matches_fips202() {
    use sha3::digest::{ExtendableOutput, Update};
    let mut h = sha3::Shake256::default();
    h.update(b"");
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

// The committed constants file must be exactly what the generator produces.
// A hand edit to the S-box, or a change to the derivation, fails here.
#[test]
fn committed_constants_are_reproducible() {
    let committed = include_str!("../../turing/src/sbox_constants.rs").replace("\r\n", "\n");
    assert_eq!(gen::render_rust(&gen::search()), committed);
}

#[test]
fn turing_sbox_passes_bombe() {
    let s = Sbox::new(turing::sbox::TABLE);
    let r = Report::new("turing", &s);
    let failed: Vec<_> = r.checks.iter().filter(|c| !c.pass).map(|c| c.name).collect();
    assert!(failed.is_empty(), "failed: {failed:?}");
    assert_ne!(s, Sbox::aes());
}

// The constant-time arithmetic S-box in the cipher agrees with the table.
#[test]
fn cipher_sbox_agrees_with_table() {
    for x in 0..=255u8 {
        assert_eq!(turing::sbox::sub(x), turing::sbox::TABLE[x as usize]);
        assert_eq!(turing::sbox::inv_sub(turing::sbox::sub(x)), x);
    }
}

// Why the search keeps optimal strength: differential uniformity, linearity,
// boomerang uniformity, degree and the implicit-equation counts are affine
// invariants, so every candidate A_out∘inv∘A_in scores exactly like AES.
// Only structural properties (fixed points, cycles) vary between candidates.
#[test]
fn every_candidate_has_the_optimal_core() {
    for counter in 0..12 {
        let s = gen::candidate(counter).sbox;
        assert_eq!(ddt(&s).uniformity(), 4, "candidate {counter}");
        assert_eq!(lat(&s).linearity(), 32, "candidate {counter}");
        assert_eq!(boomerang_uniformity(&s), Some(6), "candidate {counter}");
        assert_eq!(degrees(&s).component_min, 7, "candidate {counter}");
        let eq = implicit_equations(&s);
        assert_eq!((eq.quadratic, eq.bi_affine), (39, 23), "candidate {counter}");
    }
}

// The search accepts the first passing candidate and rejects all earlier ones.
#[test]
fn search_takes_the_first_passing_candidate() {
    let s = gen::search();
    assert_eq!(s.chosen.counter, turing::sbox::TABLE_COUNTER);
    assert_eq!(s.rejected.len() as u32, s.chosen.counter);
    for (counter, failed) in &s.rejected {
        assert!(!failed.is_empty());
        assert!(!Report::new("", &gen::candidate(*counter).sbox).passed());
    }
}
