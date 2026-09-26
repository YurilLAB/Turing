//! Does the cipher work? The `turing` crate is checked against Bombe's
//! independent reference implementation and against the committed
//! known-answer vectors.

use bombe::refcipher::{self, Reference};
use bombe::rng::Rng;
use turing::structure::ROUNDS;
use turing::Turing;

// The two implementations agree on random keys and blocks at every round
// count, in both directions, and on every round key.
#[test]
fn turing_matches_the_reference_implementation() {
    let mut rng = Rng::new("cipher equivalence");
    for _ in 0..300 {
        let key: [u8; 32] = rng.bytes();
        let (t, r) = (Turing::new(&key), Reference::new(&key));
        for i in 0..=ROUNDS {
            assert_eq!(t.round_key(i), &r.round_keys()[i], "round key {i}");
        }
        for rounds in 1..=ROUNDS {
            let plain: [u8; 16] = rng.bytes();
            let mut b = plain;
            t.encrypt_rounds(&mut b, rounds);
            assert_eq!(b, r.encrypt(&plain, rounds), "encrypt, {rounds} rounds");
            let cipher: [u8; 16] = rng.bytes();
            let mut d = cipher;
            t.decrypt_rounds(&mut d, rounds);
            assert_eq!(d, r.decrypt(&cipher, rounds), "decrypt, {rounds} rounds");
        }
    }
}

#[test]
fn decryption_inverts_encryption() {
    let mut rng = Rng::new("round trip");
    for _ in 0..2000 {
        let t = Turing::new(&rng.bytes());
        let plain: [u8; 16] = rng.bytes();
        let mut b = plain;
        t.encrypt_block(&mut b);
        t.decrypt_block(&mut b);
        assert_eq!(b, plain);
    }
}

// The committed vector file is exactly what the reference produces, and the
// turing crate reproduces every vector in it.
#[test]
fn known_answer_vectors() {
    let committed = include_str!("../../../vectors/turing-v1.txt").replace("\r\n", "\n");
    assert_eq!(refcipher::render_vectors(), committed, "vectors/turing-v1.txt is stale");
    let vectors = refcipher::parse_vectors(&committed).unwrap();
    assert_eq!(vectors.len(), 8);
    for v in vectors {
        let t = Turing::new(&v.key);
        let mut b = v.plaintext;
        t.encrypt_block(&mut b);
        assert_eq!(b, v.ciphertext, "key {}", refcipher::hex(&v.key));
        t.decrypt_block(&mut b);
        assert_eq!(b, v.plaintext);
    }
}

// A permutation never maps two inputs to one output: 2^16 consecutive
// counters under one key give 2^16 different ciphertexts.
#[test]
fn distinct_inputs_give_distinct_outputs() {
    let t = Turing::new(&[0x5a; 32]);
    let mut seen = std::collections::HashSet::new();
    for i in 0..1u32 << 16 {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_le_bytes());
        t.encrypt_block(&mut b);
        assert!(seen.insert(b), "collision at counter {i}");
    }
}

// The self-test's embedded vectors must be the reference implementation's
// outputs, so turing::self_test checks the cipher against something
// independent of the code it tests.
#[test]
fn self_test_vectors_come_from_the_reference() {
    for (key, plain, cipher) in turing::selftest::VECTORS {
        assert_eq!(Reference::new(&key).encrypt(&plain, ROUNDS), cipher);
    }
    assert_eq!(turing::self_test(), Ok(()));
}
