//! Attacks that broke other ciphers, run against reduced and full Turing.
//! Each must reproduce its theoretical behaviour on the rounds it should
//! break, or its verdict on the rest means nothing.

use bombe::invariant::LinearMap;
use bombe::{boomerang, cube, fault, integral, interpolation, invariant, power, relatedkey};
use turing::structure::{Layer, ROUNDS};
use turing::Turing;

// The best Boomerang Connectivity Table entry of Turing's S-box is its
// boomerang uniformity, 6 (the S-box lab measures the same value).
#[test]
fn best_bct_entry_is_the_boomerang_uniformity() {
    assert_eq!(boomerang::best_bct_pair().2, 6);
}

// Through one round (a single S-box layer between keys) a quartet returns
// with the BCT probability, 6/256; from three rounds nothing comes back.
#[test]
fn boomerang_matches_the_bct_then_dies() {
    let one = boomerang::run(1, 1 << 15, "test boomerang 1");
    let rate = one.returned as f64 / one.quartets as f64;
    let sd = (one.one_sbox_rate * (1.0 - one.one_sbox_rate) / one.quartets as f64).sqrt();
    assert!((rate - one.one_sbox_rate).abs() < 5.0 * sd, "rate {rate}");
    assert_eq!(boomerang::run(3, 1 << 14, "test boomerang 3").returned, 0);
}

// Two rounds return at exactly the rate the S-box predicts once the two
// correlated switches are counted: 8/65536 = 2^-13 for the best BCT pair.
// (Multiplying the tables as if independent predicts 2^-15.2.)
#[test]
fn two_round_boomerang_matches_the_exact_rate() {
    let (alpha, delta, _) = boomerang::best_bct_pair();
    let rate = boomerang::two_round_rate(alpha, delta);
    assert_eq!(rate, 8.0 / 65536.0);
    let quartets = 1 << 20;
    let b = boomerang::run(2, quartets, "test boomerang 2");
    let expected = rate * quartets as f64;
    assert!((b.returned as f64 - expected).abs() < 5.0 * expected.sqrt(), "{} returned, {expected} expected", b.returned);
}

// Cube sums over 16 scattered plaintext bits vanish while the degree stays
// below 16, and look random from 3 rounds. After 1 round an output bit
// depends on one byte; after 2, every term of the last S-box (degree 7)
// involves at most 7 first-round bytes, and 16 random bits almost always
// (99.65%) spread over more than 7 bytes.
#[test]
fn cube_testers_find_low_degree_only() {
    assert!(cube::run(1, 16, 4, "test cube 1").distinguishes());
    assert!(cube::run(2, 16, 4, "test cube 2").distinguishes());
    assert!(!cube::run(3, 16, 8, "test cube 3").distinguishes());
}

// Bigger square structures reach exactly as far as the division property
// says: 2^16 still breaks 3 rounds and not 4.
#[test]
fn structured_square_attack_follows_the_division_property() {
    assert!(integral::structured_square_attack(3, &[0, 1], 4, "test structured 3").correct);
    let four = integral::structured_square_attack(4, &[0, 1], 4, "test structured 4");
    assert!(four.recovered.is_none());
}

// Related keys: one-bit key differences give random-looking round-key
// differences, even with the cSHAKE256 layer removed.
#[test]
fn related_keys_give_attackers_nothing() {
    assert!(relatedkey::master_key_bits(2, "test related").random_looking());
    assert!(relatedkey::feistel_bits(2, "test related feistel").random_looking());
    assert!(relatedkey::cipher_output(1, 2, "test related out").random_looking());
}

#[test]
fn fault_simulation_is_faithful() {
    let t = Turing::new(&[3; 32]);
    let p = [9u8; 16];
    let mut c = p;
    t.encrypt_block(&mut c);
    assert_eq!(fault::encrypt_with_fault(&t, &p, ROUNDS - 1, 5, 0), c, "a zero fault changes nothing");
    assert_ne!(fault::encrypt_with_fault(&t, &p, ROUNDS - 1, 5, 1), c);
}

// Differential fault analysis recovers the last round key of the full
// cipher from a couple of faults, as it does for AES; decrypt-and-compare
// catches every single fault.
#[test]
fn fault_attack_and_countermeasure() {
    let f = fault::last_round_key(6, "test dfa");
    assert!(f.correct, "{:?}", f.remaining);
    assert!(f.faults <= 3);
    let (caught, trials) = fault::countermeasure(500, "test countermeasure");
    assert_eq!(caught, trials);
}

// Persistent faults in the stored round keys. Version 2's first checksum,
// Σ x^i · RK_i, missed every two-bit fault with i + b = j + c; the keyed
// checksum catches all 35,800 through the library's checked call, and the
// control shows each one leaves the public checksum unchanged.
#[test]
fn persistent_key_faults_the_public_checksum_missed_are_caught() {
    let (caught, blind, tried) = fault::two_bit_key_faults("test two-bit key faults");
    assert_eq!(tried, 35_800);
    assert_eq!(caught, tried, "caught by the keyed checksum, block wiped");
    assert_eq!(blind, tried, "control: the public checksum sees none of them");
    let (caught, trials) = fault::multi_bit_key_faults(2000, "test multi-bit key faults");
    assert_eq!(caught, trials);
}

// Interpolation: Turing's S-box and its inverse are as dense as a random
// permutation's (about 254 of 256 coefficients), unlike the 9-term AES S-box.
#[test]
fn sbox_has_no_sparse_polynomial() {
    let table = &turing::sbox::TABLE;
    assert!(interpolation::terms(table) >= 240);
    assert!(interpolation::terms(&interpolation::inverse_table(table)) >= 240);
}

// Invariant attacks: both linear layers have a single invariant factor
// (minimal polynomial of degree 128), and the real round-key differences
// fill the whole state for every key tried, so BCLR's criterion leaves only
// affine invariants.
#[test]
fn round_keys_rule_out_invariants() {
    for layer in [Layer::MixState, Layer::ShiftMixColumns] {
        assert_eq!(invariant::profile(&LinearMap::turing(layer), 16, "test profile"), [128]);
    }
    assert!(invariant::round_key_spaces(8, "test invariants").full());
}

// Power analysis: an unmasked implementation gives up round key 0 to a few
// dozen noisy traces; with too few traces for the noise the attack fails.
#[test]
fn cpa_recovers_the_key_of_an_unmasked_implementation() {
    assert_eq!(power::attack(2f64.sqrt(), 400, "test cpa").bytes_correct, 16);
    assert!(power::attack(20.0, 10, "test cpa weak").bytes_correct < 16);
}
