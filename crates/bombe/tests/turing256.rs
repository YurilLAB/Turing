//! Turing-256 against its independent reference implementation, its
//! known-answer vectors and its generated constants (docs/15).

use bombe::refcipher256::{self, Reference256};
use bombe::{gen, keyschedule, rng::Rng};
use turing::keyschedule256::round_key_depth;
use turing::turing256::{ROUNDS, ROUND_KEYS};
use turing::{Block256, Turing256};

#[test]
fn matches_the_independent_reference() {
    let mut rng = Rng::new("turing-256 reference");
    for _ in 0..60 {
        let key: [u8; 32] = rng.bytes();
        let (t, r) = (Turing256::new(&key), Reference256::new(&key));
        for (i, rk) in r.round_keys().iter().enumerate() {
            assert_eq!(&t.round_key(i), rk, "round key {i}");
        }
        for rounds in [1, 2, 3, 7, 12, ROUNDS - 1, ROUNDS] {
            let p: Block256 = rng.bytes();
            let mut c = p;
            t.encrypt_rounds(&mut c, rounds);
            assert_eq!(c, r.encrypt(&p, rounds), "{rounds} rounds");
            assert_eq!(r.decrypt(&c, rounds), p);
            t.decrypt_rounds(&mut c, rounds);
            assert_eq!(c, p);
        }
    }
}

#[test]
fn reproduces_the_known_answer_vectors() {
    let text = include_str!("../../../vectors/turing-256-v1.txt");
    let vectors = refcipher256::parse_vectors(text).expect("parse");
    assert_eq!(vectors.len(), 8);
    for v in vectors {
        let t = Turing256::new(&v.key);
        let mut b = v.plaintext;
        t.encrypt_block(&mut b);
        assert_eq!(b, v.ciphertext);
        t.decrypt_block(&mut b);
        assert_eq!(b, v.plaintext);
    }
    assert_eq!(refcipher256::render_vectors(), text.replace("\r\n", "\n"), "the committed file is what the reference generates");
    // The self-test's embedded vectors are the reference's outputs.
    for (key, plain, cipher) in turing::selftest::VECTORS_256 {
        assert_eq!(bombe::refcipher256::Reference256::new(&key).encrypt(&plain, turing::turing256::ROUNDS), cipher);
    }
}

#[test]
fn committed_mix_state_is_reproducible() {
    let c = gen::linear256();
    assert!(c.report.passed());
    let committed = include_str!("../../turing/src/linear256_constants.rs").replace("\r\n", "\n");
    assert_eq!(gen::render_linear256_rust(&c), committed);
}

// Every round key sits behind at least 43 active S-boxes of the key
// schedule's Feistel (2^-258), as for Turing: here at least 67, because 8
// rounds of 32-byte halves with branch number 33 force that many.
#[test]
fn every_round_key_is_behind_the_target() {
    let bounds = keyschedule::feistel_min_active_general(32, 33, round_key_depth(ROUND_KEYS - 1));
    for i in 0..ROUND_KEYS {
        let depth = round_key_depth(i);
        assert!(bounds[depth - 1] >= keyschedule::ROUND_KEY_TARGET, "round key {i}: depth {depth}, {}", bounds[depth - 1]);
    }
    assert_eq!(bounds[7], 67);
    // One warm-up round fewer would leave round key 1 behind 7 rounds: 36.
    assert!(bounds[6] < keyschedule::ROUND_KEY_TARGET);
}

// Faults in the stored round keys are caught by the checked calls, as for
// Turing: a sample of single-bit faults over the whole stored material.
#[test]
fn stored_key_faults_are_caught() {
    let mut rng = Rng::new("turing-256 faults");
    let key: [u8; 32] = rng.bytes();
    let bits = (2 * ROUND_KEYS + 2) * 128;
    for _ in 0..200 {
        let mut t = Turing256::new(&key);
        t.flip_stored_bit(rng.below(bits as u64) as usize);
        let mut b: Block256 = rng.bytes();
        assert!(t.encrypt_block_checked(&mut b).is_err());
        assert_eq!(b, [0; 32]);
    }
}

// The square attack on reduced Turing-256 reaches exactly as far as the
// division property says: one active byte (2^8 texts) keeps S-box layer 3's
// input balanced in all 32 bytes, so round key 3 falls byte by byte; layer
// 4's input is no longer balanced, and the attack on 4 rounds finds nothing.
#[test]
fn square_attack_follows_the_division_property() {
    use bombe::attack256::{balanced_bytes, square_attack};
    assert_eq!(balanced_bytes(3, &[0], "test 256 balance 3"), 32);
    assert!(balanced_bytes(4, &[0], "test 256 balance 4") < 32);
    let three = square_attack(3, &[0], 6, "test 256 square 3");
    assert!(three.correct, "{:?}", three.candidates);
    assert!(!square_attack(4, &[0], 2, "test 256 square 4").correct);
}
