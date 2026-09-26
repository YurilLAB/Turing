//! Attacks by someone who knows every constant (Kerckhoffs's principle):
//! provable bounds that count every trail, symmetries, reflection, key
//! schedule relations and differential-linear distinguishers. Each tool is
//! validated on a published result or a control that must be caught.

use bombe::invariant::LinearMap;
use bombe::{difflinear, gf256, keyrelations, provable, symmetry};
use turing::linear;
use turing::structure::Layer;

// Keliher and Sui (ePrint 2005/321): the exact 2-round AES MEDP is 53/2^34.
#[test]
fn keliher_sui_aes_value_is_reproduced() {
    let aes = provable::ks_lower_bound(&gf256::aes_sbox(), &provable::AES_MIX_COLUMNS, 255);
    assert_eq!(aes.units, 106, "53/2^34 = 106/2^35");
    assert_eq!(aes.pattern, (vec![0], vec![0, 1, 2, 3]));
}

// About a minute: run with `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn turing_best_minimal_differential_is_57_over_2_35() {
    let t = provable::ks_lower_bound(&turing::sbox::TABLE, &linear::MIX_COLUMNS, 255);
    assert_eq!(t.units, 57);
}

// Turing's S-box has the same difference and correlation distribution per
// row as AES's (both are affine equivalent to x^-1), so the same Park bounds
// hold, and the B = 17 window gives about 2^-102.
#[test]
fn turing_provable_bounds() {
    let table = &turing::sbox::TABLE;
    assert_eq!(provable::dp_bound(table, 5).exact, Some((79 << 6, 40)));
    assert_eq!(provable::lp_bound(table, 5).exact, Some((192_773_764u128 << 26, 80)));
    let dp17 = provable::dp_bound(table, 17);
    assert_eq!(dp17.exact, Some(((1u128 << 34) + 126 * (1u128 << 17), 136)), "one entry 4 and 126 entries 2 per row");
    assert!(dp17.log2 < -101.99 && provable::lp_bound(table, 17).log2 < -99.6);
}

#[test]
fn no_symmetries_and_no_reflection() {
    let ms = symmetry::byte_matrix(|x| linear::apply_layer(Layer::MixState, x));
    let sm = symmetry::byte_matrix(|x| linear::apply_layer(Layer::ShiftMixColumns, x));
    assert_eq!(symmetry::permutation_symmetries(&ms).len(), 1);
    let identity: [usize; 16] = std::array::from_fn(|i| i);
    assert_eq!(symmetry::permutation_pairs(&ms), [(identity, identity)], "no shuffle pair crosses MixState");
    assert_eq!(symmetry::permutation_symmetries(&sm).len(), 4, "the column rotations, as in AES");
    assert!(symmetry::cross_ratios_generate(&ms) && symmetry::cross_ratios_generate(&sm));
    assert_eq!(symmetry::scalar_symmetries(&turing::sbox::TABLE), [(1, 0)]);
    let t = symmetry::turing_reflection_map();
    for l in [Layer::MixState, Layer::ShiftMixColumns] {
        let inv = LinearMap::from_fn(128, |v| u128::from_le_bytes(linear::invert_layer(l, &v.to_le_bytes())));
        for target in [Layer::MixState, Layer::ShiftMixColumns] {
            assert!(symmetry::reflection_distance(&t, &inv, &LinearMap::turing(target)) > 64);
        }
    }
}

#[test]
fn key_schedule_has_no_linear_relations() {
    assert_eq!(keyrelations::aes128(128, "test aes relations").count(), 1088, "the control: 128 key bits + 320 S-box outputs + 1 span everything");
    assert_eq!(keyrelations::turing(128, "test relations").count(), 0);
    assert_eq!(keyrelations::turing_feistel(128, "test feistel relations").count(), 0);
}

// Two rounds match the exact prediction; three rounds show nothing.
#[test]
fn differential_linear_matches_theory() {
    let predicted = difflinear::predict_two_rounds(0x01);
    let d = difflinear::measure(2, 0x01, 1 << 20, "test dl 2");
    assert!(d.distinguishes());
    let expected = predicted[d.byte][d.mask as usize].abs();
    assert!((d.max_correlation - expected).abs() < 5.0 / (d.pairs as f64).sqrt(), "{} vs {expected}", d.max_correlation);
    assert!(!difflinear::measure(3, 0x01, 1 << 20, "test dl 3").distinguishes());
}
