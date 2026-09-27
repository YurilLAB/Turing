//! Turing-1026 (docs/16) against its independent reference and its
//! known-answer vectors.

use bombe::refkem1026::{self, ReferenceKem, TURING_1026};
use bombe::rng::Rng;
use turing::lwe::{self, Params};
use turing::turing1026::{DecapsulationKey, EncapsulationKey, CIPHERTEXT_BYTES};
use turing::xof::SecretXof;

fn noise(label: &str, seed: &[u8]) -> SecretXof {
    let mut x = SecretXof::new(label);
    x.absorb(seed);
    x
}

// The plain-LWE core at small parameter sets, including ones where a
// sample's bits do not end on a byte (eta 3: 6 bits) and odd dimensions:
// key generation, encryption and decryption agree with the reference
// coefficient for coefficient.
#[test]
fn lwe_core_matches_the_reference_at_small_sizes() {
    let sets = [
        Params { n: 16, nbar: 4, mbar: 2, log_q: 10, eta: 3 },
        Params { n: 33, nbar: 8, mbar: 3, log_q: 12, eta: 1 },
        Params { n: 64, nbar: 8, mbar: 8, log_q: 15, eta: 18 },
        Params { n: 50, nbar: 16, mbar: 1, log_q: 16, eta: 5 },
    ];
    let mut rng = Rng::new("turing-1026 lwe core");
    for p in sets {
        for _ in 0..4 {
            let seed_a: [u8; 32] = rng.bytes();
            let key_seed: [u8; 32] = rng.bytes();
            let (mut s, mut b) = (vec![0u16; p.n * p.nbar], vec![0u16; p.n * p.nbar]);
            lwe::keygen(&p, &seed_a, &mut noise("test key noise", &key_seed), &mut s, &mut b);
            let r = refkem1026::pke_keygen(&p, &seed_a, "test key noise", &key_seed);
            assert_eq!(s.iter().map(|&v| i64::from(v as i16)).collect::<Vec<_>>(), r.s, "{p:?}: S");
            assert_eq!(b.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), r.b, "{p:?}: B");
            let msg: Vec<u8> = (0..p.message_bytes()).map(|_| rng.bytes::<1>()[0]).collect();
            let enc_seed: [u8; 64] = rng.bytes();
            let (mut sp, mut bp, mut c) = (vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.nbar]);
            lwe::encrypt(&p, &seed_a, &b, &msg, &mut noise("test enc noise", &enc_seed), &mut sp, &mut bp, &mut c);
            let (rbp, rc) = refkem1026::pke_encrypt(&p, &seed_a, &r.b, &msg, "test enc noise", &enc_seed);
            assert_eq!(bp.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), rbp, "{p:?}: B'");
            assert_eq!(c.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), rc, "{p:?}: C");
            // Decryption of arbitrary (not only honest) ciphertexts.
            let junk_bp: Vec<u16> = (0..p.mbar * p.n).map(|_| u16::from_le_bytes(rng.bytes()) & p.q_mask()).collect();
            let mut got = vec![0u8; p.message_bytes()];
            lwe::decrypt(&p, &s, &junk_bp, &c, &mut got);
            let want = refkem1026::pke_decrypt(&p, &r.s, &junk_bp.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), &rc);
            assert_eq!(got, want, "{p:?}: decryption");
        }
    }
}

#[test]
fn kem_matches_the_reference() {
    let mut rng = Rng::new("turing-1026 kem");
    for _ in 0..2 {
        let seed: [u8; 32] = rng.bytes();
        let dk = DecapsulationKey::from_seed(&seed).expect("consistent");
        let r = ReferenceKem::from_seed(&seed);
        assert_eq!(dk.encapsulation_key().as_bytes(), &r.public_key[..], "public key");
        let (mu, salt): ([u8; 32], [u8; 64]) = (rng.bytes(), rng.bytes());
        let (ct, key) = dk.encapsulation_key().encapsulate_with(&mu, &salt);
        let (rct, rkey) = r.encapsulate(&mu, &salt);
        assert_eq!(ct, rct, "ciphertext");
        assert_eq!(key[..], rkey, "shared key");
        assert_eq!(dk.decapsulate(&ct).expect("length")[..], rkey, "decapsulation");
        // Tampered ciphertexts, in B', in C and in the salt: the reference's
        // rejection key.
        for position in [3, 9_000, 15_500, CIPHERTEXT_BYTES - 1] {
            let mut bad = ct.clone();
            bad[position] ^= 0x40;
            assert_eq!(dk.decapsulate(&bad).expect("length")[..], r.decapsulate(&bad).expect("length"), "byte {position}");
        }
        // An encapsulation from a public key parsed from bytes.
        let pk = EncapsulationKey::from_bytes(&r.public_key).expect("length");
        assert_eq!(pk.encapsulate_with(&mu, &salt).0, rct);
    }
}

const VECTORS: &str = include_str!("../../../vectors/turing-1026-v1.txt");

#[test]
fn reproduces_the_known_answer_vectors() {
    let vectors = refkem1026::parse_vectors(VECTORS).expect("parse");
    assert_eq!(vectors.len(), 4);
    for v in &vectors {
        let dk = DecapsulationKey::from_seed(&v.seed).expect("consistent");
        assert_eq!(refkem1026::sha3_256(dk.encapsulation_key().as_bytes()), v.public_key_sha3);
        let (ct, key) = dk.encapsulation_key().encapsulate_with(&v.message, &v.salt);
        assert_eq!(refkem1026::sha3_256(&ct), v.ciphertext_sha3);
        assert_eq!(key[..], v.shared_key);
        assert_eq!(dk.decapsulate(&ct).expect("length")[..], v.shared_key);
        let mut bad = ct;
        bad[0] ^= 1;
        assert_eq!(dk.decapsulate(&bad).expect("length")[..], v.rejected_key);
    }
}

// The vectors file is what the reference generates now, and the vector
// embedded in turing::self_test is its vector 2.
#[test]
fn vectors_file_is_current_and_feeds_the_self_test() {
    assert_eq!(refkem1026::render_vectors(), VECTORS.replace("\r\n", "\n"), "the committed file is what the reference generates");
    let v = &refkem1026::parse_vectors(VECTORS).expect("parse")[2];
    let s = &turing::selftest::KEM_VECTOR;
    assert_eq!((s.seed, s.message, s.salt), (v.seed, v.message, v.salt));
    assert_eq!((s.public_key_sha3, s.ciphertext_sha3, s.shared_key, s.rejected_key), (v.public_key_sha3, v.ciphertext_sha3, v.shared_key, v.rejected_key));
    assert_eq!(turing::self_test(), Ok(()));
}

#[test]
fn parameters_are_turing_1026s() {
    assert_eq!(TURING_1026, turing::turing1026::PARAMS);
}

// A bit of S flipped between the expansion and the pair-wise check (a fault
// during key generation) is caught; bit 15 is the exception, since S is
// used mod 2^15 and a change of 2^15 changes nothing.
#[test]
fn key_generation_faults_are_caught() {
    for (entry, bit) in [(0, 0), (5_000, 7), (32_831, 13), (100, 3)] {
        assert!(DecapsulationKey::from_seed_with_fault(&[3; 32], entry, bit).is_err(), "entry {entry} bit {bit}");
    }
    let dk = DecapsulationKey::from_seed_with_fault(&[3; 32], 100, 15).expect("bit 15 is harmless");
    let (ct, key) = dk.encapsulation_key().encapsulate_with(&[4; 32], &[5; 64]);
    assert_eq!(dk.decapsulate(&ct).expect("length")[..], key[..]);
}

// End to end: the sender's lattice encapsulation gives the Turing-256 key,
// and only the recipient's lattice decryption (Decode(C - B'S), then the
// re-encryption check) gives it back. A tampered ciphertext gives the
// rejection key instead, which does not decrypt.
#[test]
fn turing_1026_keys_turing_256() {
    use turing::Turing256;
    let recipient = DecapsulationKey::from_seed(&[7; 32]).expect("consistent");
    let public = EncapsulationKey::from_bytes(recipient.encapsulation_key().as_bytes()).expect("length");
    let (ciphertext, sender_key) = public.encapsulate().expect("OS randomness");
    let plaintext: [u8; 32] = *b"a file key, wrapped post-quantum";
    let mut block = plaintext;
    Turing256::new(&sender_key).encrypt_block(&mut block);
    assert_ne!(block, plaintext);
    let recipient_key = recipient.decapsulate(&ciphertext).expect("length");
    let mut opened = block;
    Turing256::new(&recipient_key).decrypt_block(&mut opened);
    assert_eq!(opened, plaintext);
    let mut tampered = ciphertext;
    tampered[500] ^= 1;
    let mut wrong = block;
    Turing256::new(&recipient.decapsulate(&tampered).expect("length")).decrypt_block(&mut wrong);
    assert_ne!(wrong, plaintext);
}
