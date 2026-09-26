//! The masked cipher against simulated power analysis (leakage.rs).

use bombe::leakage::{self, View};
use bombe::rng::Rng;

const SIGMA: f64 = std::f64::consts::SQRT_2; // SNR 1: noise variance 2, like a byte's weight

#[test]
fn first_order_attacks_on_one_share_fail_and_the_control_succeeds() {
    let mut rng = Rng::new("leakage test");
    let key: [u8; 32] = rng.bytes();
    let t = leakage::collect(&key, 4000, &mut rng);
    let share0 = leakage::cpa(&t, View::Share(0), SIGMA, "share 0");
    let share1 = leakage::cpa(&t, View::Share(1), SIGMA, "share 1");
    let unmasked = leakage::cpa(&t, View::Unmasked, SIGMA, "unmasked");
    println!("bytes recovered: share 0 {share0}, share 1 {share1}, unmasked (control) {unmasked}");
    assert!(share0 <= 2 && share1 <= 2, "a single share must not give the key away");
    assert_eq!(unmasked, 16, "control: the same attack on the unmasked value");
}

#[test]
fn a_second_order_attack_succeeds_as_theory_says() {
    let mut rng = Rng::new("second order test");
    let key: [u8; 32] = rng.bytes();
    let t = leakage::collect(&key, 8000, &mut rng);
    let product = leakage::cpa(&t, View::Product, SIGMA, "product");
    println!("second order, 8000 traces: {product} bytes");
    assert!(product >= 12);
}

#[test]
fn tvla_passes_at_first_order_and_fails_at_second() {
    let key = [0x42u8; 32];
    let r = leakage::tvla(&key, 20_000, SIGMA, false, "tvla test");
    println!("shares {:?}\nunmasked {:?}\nproduct {:?}", r.shares, r.unmasked, r.product);
    assert!(!r.shares.leaks(), "first order");
    assert!(r.unmasked.leaks(), "control");
    assert!(r.product.leaks(), "second order is visible");
}

#[test]
fn control_tvla_sees_masks_that_repeat() {
    let r = leakage::tvla(&[0x42u8; 32], 4000, SIGMA, true, "tvla repeat");
    println!("shares with repeated masks {:?}", r.shares);
    assert!(r.shares.leaks());
}

#[test]
fn every_intermediate_of_the_masked_sbox_passes_first_order_tvla() {
    let r = leakage::tvla_intermediates(&[0x42u8; 32], 20_000, 0.0, false, "tvla intermediates");
    println!("intermediates {r:?}");
    assert!(r.points > 1000);
    assert!(!r.leaks());
}

#[test]
fn control_intermediate_tvla_sees_masks_that_repeat() {
    let r = leakage::tvla_intermediates(&[0x42u8; 32], 2000, 0.0, true, "tvla intermediates repeat");
    println!("intermediates with repeated masks {r:?}");
    assert!(r.leaks());
}
