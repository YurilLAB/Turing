//! Validates Bombe against published values for the AES S-box, and against
//! negative controls that must fail. If these pass, the tools measure what
//! they claim to; only then are their verdicts on Turing's S-box meaningful.

use bombe::analysis::*;
use bombe::report::Report;
use bombe::sbox::{Sbox, N};

#[test]
fn aes_sbox_matches_fips197() {
    let s = Sbox::aes();
    // Spot values from the FIPS-197 S-box table.
    for (x, y) in [(0x00, 0x63), (0x01, 0x7c), (0x10, 0xca), (0x53, 0xed), (0xff, 0x16)] {
        assert_eq!(s.get(x), y, "S({x:#04x})");
    }
    assert!(s.is_bijective());
}

// Published: differential uniformity 4 (Daemen & Rijmen, "The Design of Rijndael").
// Each non-zero row has exactly one 4 and 126 twos.
#[test]
fn aes_differential() {
    let d = ddt(&Sbox::aes());
    assert_eq!(d.uniformity(), 4);
    let spec = d.spectrum();
    assert_eq!(spec.get(&4), Some(&255));
    assert_eq!(spec.get(&2), Some(&(255 * 126)));
}

// Published: nonlinearity 112, i.e. max |Walsh| 32, correlation 2^-3.
#[test]
fn aes_linear() {
    let l = lat(&Sbox::aes());
    assert_eq!(l.linearity(), 32);
    assert_eq!(l.nonlinearity(), 112);
}

// Published: boomerang uniformity 6 (Cid, Huang, Peyrin, Sasaki, Song, EUROCRYPT 2018).
#[test]
fn aes_boomerang() {
    assert_eq!(boomerang_uniformity(&Sbox::aes()), Some(6));
}

// Published: every component has degree 7; the S-box satisfies 39 linearly
// independent quadratic equations, 23 of them bi-affine (Courtois & Pieprzyk, 2002).
#[test]
fn aes_algebraic() {
    let s = Sbox::aes();
    let d = degrees(&s);
    assert_eq!((d.component_min, d.component_max), (7, 7));
    let eq = implicit_equations(&s);
    assert_eq!(eq.quadratic, 39);
    assert_eq!(eq.bi_affine, 23);
}

#[test]
fn aes_structure() {
    let s = Sbox::aes();
    assert_eq!(fixed_points(&s), 0);
    assert_eq!(opposite_fixed_points(&s), 0);
    assert_eq!(cycles(&s), Some(vec![87, 81, 59, 27, 2]));
    assert_eq!(differential_branch_number(&s), 2);
    assert_eq!(linear_branch_number(&lat(&s)), 2);
}

// Turing's criteria are AES's plus one hygiene rule: AES's S-box has a
// 2-cycle, so it fails "shortest cycle" and nothing else.
#[test]
fn aes_fails_only_the_cycle_rule_and_inverse_is_equally_strong() {
    let r = Report::new("aes", &Sbox::aes());
    let failed: Vec<_> = r.checks.iter().filter(|c| !c.pass).map(|c| c.name).collect();
    assert_eq!(failed, ["shortest cycle"]);
    let inv = Sbox::aes().inverse().unwrap();
    assert_eq!(ddt(&inv).uniformity(), 4);
    assert_eq!(lat(&inv).linearity(), 32);
    assert_eq!(boomerang_uniformity(&inv), Some(6));
}

// Negative control: a linear S-box must fail every strength criterion.
#[test]
fn identity_is_rejected() {
    let s = Sbox::identity();
    assert_eq!(ddt(&s).uniformity(), 256);
    assert_eq!(lat(&s).nonlinearity(), 0);
    assert_eq!(degrees(&s).component_max, 1);
    assert_eq!(fixed_points(&s), 256);
    // Distinct functions spanned: 1, 8 linear, 28 quadratic = 37; 137 - 37.
    assert_eq!(implicit_equations(&s).quadratic, 100);
    let r = Report::new("identity", &s);
    assert!(!r.passed());
    assert_eq!(r.checks.iter().filter(|c| !c.pass).count(), 6);
}

// Negative control: an affine S-box (rotate, XOR constant) has no fixed
// points, so it tests that the strength checks catch it on their own.
#[test]
fn affine_is_rejected() {
    let mut t = [0u8; N];
    for (x, v) in t.iter_mut().enumerate() {
        *v = (x as u8).rotate_left(3) ^ 0x5a;
    }
    let s = Sbox::new(t);
    assert_eq!(ddt(&s).uniformity(), 256);
    assert_eq!(lat(&s).linearity(), 256);
    assert_eq!(degrees(&s).component_max, 1);
    assert!(!Report::new("affine", &s).passed());
}

#[test]
fn non_bijective_is_rejected() {
    let mut t = *Sbox::aes().table();
    t[0] = t[1];
    let s = Sbox::new(t);
    assert!(!s.is_bijective());
    assert_eq!(s.inverse(), None);
    assert_eq!(boomerang_uniformity(&s), None);
    assert!(!Report::new("broken", &s).passed());
}

// A single swap in AES must be detected: it breaks the field-inverse structure.
#[test]
fn one_swap_in_aes_is_detected() {
    let mut t = *Sbox::aes().table();
    t.swap(0x10, 0x20);
    assert!(!Report::new("swapped", &Sbox::new(t)).passed());
}

// Structural invariants that hold for every S-box, independent of the answer.
#[test]
fn invariants_hold_for_random_sboxes() {
    for seed in 0..8 {
        let s = Sbox::random(seed);
        let d = ddt(&s);
        for dx in 0..N {
            let row: u32 = (0..N).map(|dy| d.get(dx as u8, dy as u8) as u32).sum();
            assert_eq!(row, 256, "DDT row {dx} must sum to 256");
            for dy in 0..N {
                assert_eq!(d.get(dx as u8, dy as u8) % 2, 0, "DDT entries are even");
            }
        }
        let l = lat(&s);
        for b in 0..N {
            // Parseval: the squared Walsh coefficients of any Boolean function sum to 2^16.
            let energy: i64 = (0..N).map(|a| (l.get(a as u8, b as u8) as i64).pow(2)).sum();
            assert_eq!(energy, 1 << 16, "Parseval, column {b}");
        }
        assert_eq!(cycles(&s).unwrap().iter().sum::<usize>(), 256);
        assert_eq!(s.inverse().unwrap().inverse().unwrap(), s);
    }
}

#[test]
fn parse_round_trip() {
    let s = Sbox::aes();
    let text: String = s.table().iter().map(|b| format!("0x{b:02x}, ")).collect();
    assert_eq!(Sbox::parse(&format!("# AES\n{text}")).unwrap(), s);
    assert!(Sbox::parse("00 01").is_err());
    assert!(Sbox::parse(&"zz ".repeat(256)).is_err());
}
