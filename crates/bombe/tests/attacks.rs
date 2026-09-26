//! The attack experiments themselves must work: each must break the
//! reduced-round versions the analysis says are weak, and must not "break"
//! versions it cannot, or its verdict on the full cipher means nothing.

use bombe::{avalanche, battery, differential, integral, keycheck, timing};
use turing::structure::ROUNDS;

// The square attack recovers the real round key of 3-round Turing, and gets
// nothing at 4 rounds.
#[test]
fn square_attack_breaks_three_rounds_not_four() {
    let three = integral::square_attack(3, 6, "test square 3");
    assert!(three.correct, "3 rounds: {:?}", three.candidates);
    assert!(three.chosen_plaintexts <= 1024);
    let four = integral::square_attack(4, 6, "test square 4");
    assert!(four.recovered.is_none());
    assert!(four.candidates.iter().all(|&c| c == 0), "{:?}", four.candidates);
}

#[test]
fn integral_distinguisher_stops_after_two_rounds() {
    assert!(integral::distinguisher(2, 8, "test integral 2").works());
    assert!(!integral::distinguisher(3, 64, "test integral 3").works());
}

// After one MixState, one active byte makes all 16 active with certainty,
// so 2-round Turing never leaves an output byte unchanged. A random
// permutation does so for 1 byte in 256; so does 3-round Turing.
#[test]
fn truncated_differential_matches_the_trail_model() {
    let two = differential::truncated(2, 4096, "test truncated 2");
    assert_eq!(two.zero_bytes, 0);
    assert!(two.distinguishes());
    assert!(!differential::truncated(3, 16384, "test truncated 3").distinguishes());
}

// The S-box's best linear approximation has correlation 32/256 through one
// round, as the LAT says, and vanishes after two.
#[test]
fn linear_correlation_matches_the_lat() {
    let one = differential::linear_correlation(1, 1 << 16, "test linear 1");
    assert!((one.measured - 0.125).abs() < 5.0 * one.standard_error, "{}", one.measured);
    let two = differential::linear_correlation(2, 1 << 16, "test linear 2");
    assert!(two.measured < 5.0 * two.standard_error, "{}", two.measured);
}

#[test]
fn one_round_differential_matches_the_ddt() {
    let m = differential::one_round_differential(1 << 16, "test differential");
    assert_eq!(m.predicted, 4.0 / 256.0);
    assert!((m.measured - m.predicted).abs() < 5.0 * m.standard_error);
}

#[test]
fn measured_branch_numbers() {
    for c in differential::branch_numbers(20_000, "test branch") {
        assert_eq!(c.min_observed, c.theory, "{}", c.layer);
    }
}

// One round has no linear layer, so a flipped bit stays in its byte: the
// avalanche test must catch that; the full cipher must pass.
#[test]
fn avalanche_catches_one_round_and_passes_the_cipher() {
    let one = avalanche::plaintext(1, 200, "test avalanche 1");
    assert!(!one.passed());
    assert!(one.mean < 0.05);
    let full = avalanche::plaintext(ROUNDS, 200, "test avalanche full");
    assert!(full.passed(), "worst z {}", full.worst_z);
    assert!((full.mean - 0.5).abs() < 0.01);
}

#[test]
fn critical_value() {
    // P(|Z| > 1.959964) = 0.05 and P(|Z| > 2.575829) = 0.01.
    assert!((avalanche::two_sided_critical(0.05) - 1.959964).abs() < 1e-5);
    assert!((avalanche::two_sided_critical(0.01) - 2.575829).abs() < 1e-5);
}

#[test]
fn nist_decision_rules() {
    // NIST 4.2.1 worked example: 1000 sequences, alpha 0.01, the proportion
    // must be at least 0.99 - 3 sqrt(0.99 * 0.01 / 1000) = 0.980561.
    assert_eq!(battery::minimum_passing(1000), 981);
    assert_eq!(battery::minimum_passing(64), 61);
    // The exact binomial bound the campaign uses. By hand for m = 64
    // (Poisson mean 0.64): P(X >= 6) is about 5e-5, below 0.001 / 11 = 9e-5,
    // while P(X >= 5) is about 5e-4, so up to 5 failures are allowed.
    assert_eq!(battery::max_failures(64), 5);
    assert_eq!(battery::max_failures(16), 3);
    assert_eq!(battery::max_failures(8), 2);
    // It must still reject a generator where many sequences fail.
    assert!(battery::max_failures(64) < 10);
    let uniform: Vec<f64> = (0..1000).map(|i| (i as f64 + 0.5) / 1000.0).collect();
    assert!(battery::uniformity(&uniform) > 0.99);
    let lumped = vec![0.5; 100];
    assert!(battery::uniformity(&lumped) < 0.0001);
}

// The battery accepts a good generator and rejects the plain counter.
#[test]
fn battery_separates_good_from_bad() {
    assert!(battery::run(battery::Source::Cshake, 8, "test battery").passed());
    assert!(!battery::run(battery::Source::Counter, 8, "test battery").passed());
}

#[test]
fn welch_t_statistic() {
    let a: Vec<f64> = (0..1000).map(|i| (i % 10) as f64).collect();
    let b: Vec<f64> = (0..1000).map(|i| (i % 10) as f64 + 1.0).collect();
    assert!(timing::welch_t(&a, &a).abs() < 1e-9);
    // By hand: means 4.5 and 5.5, sample variance 8.25 * 1000 / 999 each,
    // t = -1 / sqrt(2 * 8.258258 / 1000) = -7.7811.
    assert!((timing::welch_t(&a, &b) + 7.7811).abs() < 1e-3, "{}", timing::welch_t(&a, &b));
}

// The timing test must see a leak that is really there. (Whether Turing's
// own code shows no leak depends on the machine's noise, so that verdict
// lives in the campaign, not in a unit test.)
#[test]
fn timing_test_catches_a_leaky_sbox() {
    let r = timing::dudect("test leaky", 30_000, 16, |input| {
        let mut b: [u8; 16] = input.try_into().unwrap();
        timing::leaky_sub_bytes(&mut b);
        std::hint::black_box(b);
    });
    assert!(r.leaks(), "max t {}", r.max_t);
}

#[test]
fn keys_have_no_obvious_weaknesses() {
    assert!(keycheck::scan(&keycheck::suspicious_keys()).clean());
}
