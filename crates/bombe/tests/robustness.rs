//! Rare, boundary and out-of-range inputs (tools/CI.md, "robustness").
//!
//! The other tests draw keys, blocks and seeds at random, and a random draw
//! almost never produces the inputs where implementations break: all-zero
//! or all-one keys, single-bit patterns, the ends of every range, lengths
//! just off the valid ones, and parameter sets at the edges of what
//! `lwe::Params::validate` accepts. Each check here compares the library
//! with its independent reference implementation (refcipher, refcipher256,
//! refkem1026) on such inputs, or checks that an out-of-range input is
//! refused instead of read past.
//!
//! `TURING_CI_ITERS` multiplies the randomized parts (default 1;
//! `python tools/ci.py --profile deep` sets 25).

use std::panic::{catch_unwind, AssertUnwindSafe};

use bombe::refcipher::Reference;
use bombe::refcipher256::Reference256;
use bombe::refkem1026::{self, ReferenceKem};
use bombe::rng::Rng;
use turing::lwe::{self, Params};
use turing::turing1026::{DecapsulationKey, EncapsulationKey, CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES};
use turing::xof::SecretXof;
use turing::{Block, Block256, MaskedTuring, Turing, Turing256};

fn iters() -> usize {
    std::env::var("TURING_CI_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1)
}

/// Byte strings a random draw almost never produces: constant bytes at both
/// ends of the range and the alternating patterns, counting up and down,
/// and a single set or a single cleared bit at the first, second, last and
/// middle positions.
fn structured<const N: usize>() -> Vec<[u8; N]> {
    let mut out: Vec<[u8; N]> = [0x00, 0xff, 0x55, 0xaa, 0x80, 0x01, 0x7f, 0xfe].iter().map(|&b| [b; N]).collect();
    out.push(core::array::from_fn(|i| i as u8));
    out.push(core::array::from_fn(|i| (N - 1 - i) as u8));
    for bit in [0, 1, 7, 8 * N / 2, 8 * N - 1] {
        let mut one = [0u8; N];
        one[bit / 8] |= 1 << (bit % 8);
        out.push(one);
        let mut hole = [0xffu8; N];
        hole[bit / 8] &= !(1 << (bit % 8));
        out.push(hole);
    }
    out
}

fn panics(f: impl FnOnce()) -> bool {
    catch_unwind(AssertUnwindSafe(f)).is_err()
}

// Every structured key against every structured block: the cipher, its
// fault-checked calls and the masked implementation all agree with the
// reference, and decryption inverts encryption.
#[test]
fn turing_agrees_with_the_reference_on_structured_keys_and_blocks() {
    let keys = structured::<32>();
    let blocks = structured::<16>();
    for key in &keys {
        let cipher = Turing::new(key);
        let reference = Reference::new(key);
        let mut masked = MaskedTuring::with_mask_seed(key, &[0x3c; 64]);
        for block in &blocks {
            let want = reference.encrypt(block, turing::structure::ROUNDS);
            let mut got: Block = *block;
            cipher.encrypt_block(&mut got);
            assert_eq!(got, want, "key {key:02x?} block {block:02x?}");
            let mut checked: Block = *block;
            cipher.encrypt_block_checked(&mut checked).expect("no fault");
            assert_eq!(checked, want, "checked call, key {key:02x?}");
            let mut m: Block = *block;
            masked.encrypt_block(&mut m);
            assert_eq!(m, want, "masked, key {key:02x?} block {block:02x?}");
            cipher.decrypt_block(&mut got);
            assert_eq!(&got, block, "decryption, key {key:02x?}");
            masked.decrypt_block(&mut m);
            assert_eq!(&m, block, "masked decryption, key {key:02x?}");
        }
    }
}

#[test]
fn turing_256_agrees_with_the_reference_on_structured_keys_and_blocks() {
    let keys = structured::<32>();
    for key in &keys {
        let cipher = Turing256::new(key);
        let reference = Reference256::new(key);
        for block in &keys {
            let want = reference.encrypt(block, turing::turing256::ROUNDS);
            let mut got: Block256 = *block;
            cipher.encrypt_block(&mut got);
            assert_eq!(got, want, "key {key:02x?} block {block:02x?}");
            let mut checked: Block256 = *block;
            cipher.encrypt_block_checked(&mut checked).expect("no fault");
            assert_eq!(checked, want, "checked call, key {key:02x?}");
            cipher.decrypt_block(&mut got);
            assert_eq!(&got, block, "decryption, key {key:02x?}");
        }
    }
}

// Reduced-round calls (analysis builds) at every round count from 1 to the
// full 24 agree with the reference, and the counts just outside that range
// are refused, not read past the round keys.
#[test]
fn every_round_count_agrees_and_out_of_range_counts_are_refused() {
    for key in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
        let (t, r) = (Turing::new(&key), Reference::new(&key));
        let (t2, r2) = (Turing256::new(&key), Reference256::new(&key));
        for rounds in 1..=turing::structure::ROUNDS {
            let block: Block = [0x5a; 16];
            let mut got = block;
            t.encrypt_rounds(&mut got, rounds);
            assert_eq!(got, r.encrypt(&block, rounds), "Turing, {rounds} rounds");
            t.decrypt_rounds(&mut got, rounds);
            assert_eq!(got, block, "Turing inverse, {rounds} rounds");
        }
        for rounds in 1..=turing::turing256::ROUNDS {
            let block: Block256 = [0xa5; 32];
            let mut got = block;
            t2.encrypt_rounds(&mut got, rounds);
            assert_eq!(got, r2.encrypt(&block, rounds), "Turing-256, {rounds} rounds");
            t2.decrypt_rounds(&mut got, rounds);
            assert_eq!(got, block, "Turing-256 inverse, {rounds} rounds");
        }
        for rounds in [0, turing::structure::ROUNDS + 1, usize::MAX] {
            assert!(panics(|| t.encrypt_rounds(&mut [0u8; 16], rounds)), "Turing accepted {rounds} rounds");
            assert!(panics(|| t.decrypt_rounds(&mut [0u8; 16], rounds)), "Turing inverse accepted {rounds} rounds");
        }
        for rounds in [0, turing::turing256::ROUNDS + 1, usize::MAX] {
            assert!(panics(|| t2.encrypt_rounds(&mut [0u8; 32], rounds)), "Turing-256 accepted {rounds} rounds");
            assert!(panics(|| t2.decrypt_rounds(&mut [0u8; 32], rounds)), "Turing-256 inverse accepted {rounds} rounds");
        }
    }
}

fn noise(label: &str, seed: &[u8]) -> SecretXof {
    let mut x = SecretXof::new(label);
    x.absorb(seed);
    x
}

/// Key generation, encryption and decryption of the plain-LWE core at one
/// parameter set, coefficient for coefficient against refkem1026.
fn lwe_matches_reference(p: &Params, rng: &mut Rng) {
    let seed_a: [u8; 32] = rng.bytes();
    let key_seed: [u8; 32] = rng.bytes();
    let (mut s, mut b) = (vec![0u16; p.n * p.nbar], vec![0u16; p.n * p.nbar]);
    lwe::keygen(p, &seed_a, &mut noise("ci key noise", &key_seed), &mut s, &mut b);
    let r = refkem1026::pke_keygen(p, &seed_a, "ci key noise", &key_seed);
    assert_eq!(s.iter().map(|&v| i64::from(v as i16)).collect::<Vec<_>>(), r.s, "{p:?}: S");
    assert_eq!(b.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), r.b, "{p:?}: B");
    let msg: Vec<u8> = (0..p.message_bytes()).map(|_| rng.bytes::<1>()[0]).collect();
    let enc_seed: [u8; 64] = rng.bytes();
    let (mut sp, mut bp, mut c) = (vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.nbar]);
    lwe::encrypt(p, &seed_a, &b, &msg, &mut noise("ci enc noise", &enc_seed), &mut sp, &mut bp, &mut c);
    let (rbp, rc) = refkem1026::pke_encrypt(p, &seed_a, &r.b, &msg, "ci enc noise", &enc_seed);
    assert_eq!(bp.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), rbp, "{p:?}: B'");
    assert_eq!(c.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), rc, "{p:?}: C");
    // Decryption of the honest ciphertext and of one with extreme
    // coefficients (all q - 1), which exercises the wrap-around of C - B'S.
    for (label, bp_in) in [("honest", bp.clone()), ("extreme", vec![p.q_mask(); p.mbar * p.n])] {
        let mut got = vec![0u8; p.message_bytes()];
        lwe::decrypt(p, &s, &bp_in, &c, &mut got);
        let want = refkem1026::pke_decrypt(p, &r.s, &bp_in.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), &rc);
        assert_eq!(got, want, "{p:?}: decryption of the {label} ciphertext");
    }
}

// The existing test covers four parameter sets. `Params::validate` accepts
// far more (q from 2^4 to 2^16, noise width 1 to 32, nbar up to 64), and the
// corners run different code: fields that are whole bytes or straddle
// three, noise samples of 64 bits (eta 32), noise far wider than q/4, a
// 1 x 1 matrix. The corners below are fixed; the rest are drawn at random
// from the whole accepted space.
#[test]
fn lwe_core_matches_the_reference_across_the_parameter_space() {
    let corners = [
        Params { n: 1, nbar: 8, mbar: 1, log_q: 4, eta: 1 },
        Params { n: 1, nbar: 64, mbar: 1, log_q: 16, eta: 32 },
        Params { n: 7, nbar: 1, mbar: 8, log_q: 16, eta: 32 },
        Params { n: 9, nbar: 64, mbar: 8, log_q: 4, eta: 32 },
        Params { n: 17, nbar: 8, mbar: 1, log_q: 9, eta: 4 },
        Params { n: 23, nbar: 24, mbar: 1, log_q: 13, eta: 31 },
        Params { n: 64, nbar: 8, mbar: 8, log_q: 8, eta: 8 },
        Params { n: 33, nbar: 40, mbar: 3, log_q: 11, eta: 17 },
        Params { n: 40, nbar: 16, mbar: 2, log_q: 15, eta: 18 },
    ];
    let mut rng = Rng::new("robustness lwe parameter space");
    for p in &corners {
        p.validate();
        lwe_matches_reference(p, &mut rng);
    }
    for _ in 0..12 * iters() {
        let p = loop {
            let p = Params {
                n: 1 + rng.below(72) as usize,
                nbar: 1 + rng.below(64) as usize,
                mbar: 1 + rng.below(12) as usize,
                log_q: 4 + rng.below(13) as u32,
                eta: 1 + rng.below(32) as u32,
            };
            if (p.mbar * p.nbar).is_multiple_of(8) {
                break p;
            }
        };
        lwe_matches_reference(&p, &mut rng);
    }
}

// Packing at every field width the parameters allow and every length from
// 0 to 40, with the extreme values: unpack inverts pack, pack reduces
// entries mod q first, and packing what unpack read from arbitrary bytes
// gives the same bytes back with only the unused padding bits cleared.
#[test]
fn packing_round_trips_at_every_width_and_length() {
    let mut rng = Rng::new("robustness packing");
    for log_q in 4..=16u32 {
        let mask = ((1u32 << log_q) - 1) as u16;
        for len in 0..=40usize {
            let bytes_len = (len * log_q as usize).div_ceil(8);
            let patterns: [Vec<u16>; 4] = [
                vec![0; len],
                vec![mask; len],
                (0..len).map(|i| if i % 2 == 0 { mask } else { 0 }).collect(),
                (0..len).map(|_| u16::from_le_bytes(rng.bytes()) & mask).collect(),
            ];
            for values in &patterns {
                let mut packed = vec![0u8; bytes_len];
                lwe::pack(log_q, values, &mut packed);
                let mut back = vec![0u16; len];
                lwe::unpack(log_q, &packed, &mut back);
                assert_eq!(&back, values, "log_q {log_q}, {len} values");
                // Entries above q are reduced first.
                let high: Vec<u16> = values.iter().map(|&v| v | !mask).collect();
                let mut packed_high = vec![0u8; bytes_len];
                lwe::pack(log_q, &high, &mut packed_high);
                assert_eq!(packed_high, packed, "log_q {log_q}, {len} values above q");
            }
            let mut arbitrary = vec![0u8; bytes_len];
            rng.fill(&mut arbitrary);
            let mut fields = vec![0u16; len];
            lwe::unpack(log_q, &arbitrary, &mut fields);
            assert!(fields.iter().all(|&v| v <= mask), "log_q {log_q}: unpack produced a value above q");
            let mut again = vec![0u8; bytes_len];
            lwe::pack(log_q, &fields, &mut again);
            let used = len * log_q as usize;
            if !used.is_multiple_of(8) {
                *arbitrary.last_mut().expect("a partial byte") &= (1u8 << (used % 8)) - 1;
            }
            assert_eq!(again, arbitrary, "log_q {log_q}, {len} values from arbitrary bytes");
        }
    }
}

// Every length around the valid ones is refused, never read past, for both
// byte-string inputs of the KEM.
#[test]
fn turing_1026_refuses_every_wrong_length() {
    let dk = DecapsulationKey::from_seed(&[0x11; 32]).expect("consistent");
    for len in [0, 1, 31, 32, 33, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1, 2 * PUBLIC_KEY_BYTES] {
        assert!(EncapsulationKey::from_bytes(&vec![0u8; len]).is_err(), "public key of {len} bytes accepted");
    }
    for len in [0, 1, 63, 64, 65, CIPHERTEXT_BYTES - 64, CIPHERTEXT_BYTES - 1, CIPHERTEXT_BYTES + 1, 2 * CIPHERTEXT_BYTES] {
        assert!(dk.decapsulate(&vec![0u8; len]).is_err(), "ciphertext of {len} bytes accepted");
    }
}

// Seeds, messages and salts at the ends of their ranges: key generation and
// encapsulation agree with the reference byte for byte, and decapsulation of
// constant ciphertexts is deterministic and agrees with the reference too.
#[test]
fn turing_1026_agrees_with_the_reference_on_structured_seeds() {
    let mut one_bit = [0u8; 32];
    one_bit[31] = 0x80;
    for seed in [[0u8; 32], [0xff; 32], one_bit] {
        let dk = DecapsulationKey::from_seed(&seed).expect("consistent");
        let r = ReferenceKem::from_seed(&seed);
        assert_eq!(dk.encapsulation_key().as_bytes(), &r.public_key[..], "public key, seed {seed:02x?}");
        for (mu, salt) in [([0u8; 32], [0u8; 64]), ([0xff; 32], [0xff; 64])] {
            let (ct, key) = dk.encapsulation_key().encapsulate_with(&mu, &salt);
            let (rct, rkey) = r.encapsulate(&mu, &salt);
            assert_eq!(ct, rct, "ciphertext, seed {seed:02x?}");
            assert_eq!(key[..], rkey, "shared key, seed {seed:02x?}");
        }
        for fill in [0x00u8, 0xff] {
            let ct = vec![fill; CIPHERTEXT_BYTES];
            let first = dk.decapsulate(&ct).expect("length");
            let second = dk.decapsulate(&ct).expect("length");
            assert_eq!(first[..], second[..], "decapsulation is not deterministic");
            assert_eq!(first[..], r.decapsulate(&ct).expect("length"), "constant {fill:#04x} ciphertext, seed {seed:02x?}");
        }
    }
}
