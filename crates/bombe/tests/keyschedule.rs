//! Validates the key-schedule prover against Kanda's published theorem, then
//! checks Turing's key schedule against an independent reference model and
//! measures its avalanche.

use bombe::keyschedule::*;
use bombe::matrix;
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use turing::keyschedule::{self as ks, expand};
use turing::structure::ROUND_KEYS;

// Kanda (SAC 2000), as stated in eprint 2010/426: a Feistel cipher whose
// round function is S-boxes followed by a linear layer of branch number B has
// at least rB + floor(r/2) active S-boxes in every 4r rounds. The prover
// must respect this lower bound for several sizes, not just ours.
#[test]
fn prover_respects_kanda_theorem() {
    for n in [4usize, 8, 16] {
        let b = (n + 1) as u32;
        let bounds = feistel_min_active_general(n, n + 1, 16);
        for r in 1..=4u32 {
            let kanda = r * b + r / 2;
            assert!(bounds[4 * r as usize - 1] >= kanda, "n = {n}, {} rounds", 4 * r);
        }
        // For 4 and 8 rounds the prover lands exactly on Kanda's value.
        assert_eq!(bounds[3], b, "n = {n}, 4 rounds");
        assert_eq!(bounds[7], 2 * b + 1, "n = {n}, 8 rounds");
    }
}

// Bounds never decrease with more rounds.
#[test]
fn prover_is_monotone() {
    let bounds = feistel_min_active(24);
    assert!(bounds.windows(2).all(|w| w[0] <= w[1]));
}

// Every round key the cipher uses, and many more, sits behind at least
// ROUND_KEY_TARGET active S-boxes, counting the one-round lag of the R half.
// 13 warm-up rounds is the least that achieves it: with 12, round key 1
// depends on only 11 rounds (38 active S-boxes).
#[test]
fn every_round_key_meets_the_target() {
    let bounds: Vec<u32> = (0..64).map(round_key_bound).collect();
    assert!(bounds.iter().all(|&b| b >= ROUND_KEY_TARGET), "{bounds:?}");
    assert_eq!(bounds.iter().min(), Some(&53));
    assert_eq!(round_key_bound(1), 53, "the lagging R half of the first pair is the weakest");
    assert_eq!(ks::round_key_depth(0), ks::WARMUP_ROUNDS);
    assert_eq!(ks::round_key_depth(1), ks::WARMUP_ROUNDS - 1);
    assert_eq!(rounds_for(ROUND_KEY_TARGET, 32), Some(ks::WARMUP_ROUNDS - 1));
    assert!(feistel_min_active(11)[10] < ROUND_KEY_TARGET, "12 warm-up rounds would not be enough");
    const { assert!(ROUND_KEYS <= 64) };
}

// Negative control: with a weak linear layer (branch 2, e.g. none at all)
// the same target needs far more rounds, so it is not met by accident.
#[test]
fn weak_mixing_needs_many_more_rounds() {
    let weak = feistel_min_active_general(16, 2, 40);
    let rounds = weak.iter().position(|&b| b >= ROUND_KEY_TARGET).map(|i| i + 1);
    assert!(rounds.unwrap_or(usize::MAX) > 3 * ks::WARMUP_ROUNDS, "{rounds:?}");
}

/// cSHAKE256 straight from the sha3 crate (not through turing::xof).
fn cshake(label: &[u8], input: &[u8]) -> impl XofReader {
    let mut h = CoreWrapper::from_core(sha3::CShake256Core::new(label));
    h.update(input);
    h.finalize_xof()
}

/// An independent model of the key schedule: table-lookup S-box, Bombe's
/// table-based field arithmetic, same published labels, round counts
/// written out. `feed_forward` switches the final XOR with K' off to show
/// it matters.
fn reference(key: &[u8; 32], n: usize, feed_forward: bool) -> Vec<[u8; 16]> {
    let mut kp = [0u8; 32];
    cshake(b"Turing v1 key", key).read(&mut kp);
    let (k_l, k_r) = (kp[..16].to_vec(), kp[16..].to_vec());
    let (mut l, mut r) = (k_l.clone(), k_r.clone());
    let mut cs = cshake(b"Turing v1 key schedule constants", &[]);
    let m = matrix::from_array(&turing::linear::MIX_STATE);
    let mut round = |l: &mut Vec<u8>, r: &mut Vec<u8>| {
        let mut c = [0u8; 16];
        cs.read(&mut c);
        let s: Vec<u8> = (0..16).map(|i| turing::sbox::TABLE[(l[i] ^ c[i]) as usize]).collect();
        let fo = matrix::mat_vec(&m, &s);
        let new_l: Vec<u8> = (0..16).map(|i| r[i] ^ fo[i]).collect();
        *r = std::mem::replace(l, new_l);
    };
    for _ in 0..13 {
        round(&mut l, &mut r);
    }
    let mut out = Vec::new();
    while out.len() < n {
        if !out.is_empty() {
            for _ in 0..8 {
                round(&mut l, &mut r);
            }
        }
        let mix = |a: &[u8], k: &[u8]| -> [u8; 16] { std::array::from_fn(|i| a[i] ^ if feed_forward { k[i] } else { 0 }) };
        out.push(mix(&l, &k_l));
        out.push(mix(&r, &k_r));
    }
    out.truncate(n);
    out
}

fn test_key(i: u32) -> [u8; 32] {
    std::array::from_fn(|j| (i.wrapping_mul(2654435761).rotate_left(j as u32) ^ j as u32) as u8)
}

#[test]
fn cipher_key_schedule_matches_reference_model() {
    for i in 0..40 {
        let key = test_key(i);
        assert_eq!(expand::<16>(&key).all().to_vec(), reference(&key, 16, true), "key {i}");
    }
}

// Negative control for the reference comparison and proof the feed-forward
// is applied: the model without it must disagree on every round key.
#[test]
fn feed_forward_is_applied() {
    let key = test_key(99);
    let with = expand::<16>(&key);
    let without = reference(&key, 16, false);
    for (i, rk) in without.iter().enumerate() {
        assert_ne!(with.get(i), rk, "round key {i}");
    }
}

// Non-linearity of the Feistel stage itself (cSHAKE256 removed). Any affine
// map E satisfies E(a) ^ E(b) ^ E(c) ^ E(a ^ b ^ c) = 0; the AES-256 schedule
// is close to that, which is what the 2009 attacks exploited. Every Turing
// round key must break the identity. An avalanche test cannot see this: a
// schedule with the S-boxes removed still avalanches, but fails here.
#[test]
fn feistel_stage_is_not_affine() {
    for t in 0..20u32 {
        let block = |s: u32| -> [u8; 16] { std::array::from_fn(|i| (s.wrapping_mul(0x9e37_79b9) >> (i % 25)) as u8 ^ i as u8) };
        let (a, b, c) = ((block(3 * t + 1), block(3 * t + 2)), (block(7 * t + 5), block(7 * t + 6)), (block(11 * t + 9), block(t + 70)));
        let x = |p: &[u8; 16], q: &[u8; 16], r: &[u8; 16]| -> [u8; 16] { std::array::from_fn(|i| p[i] ^ q[i] ^ r[i]) };
        let d = (x(&a.0, &b.0, &c.0), x(&a.1, &b.1, &c.1));
        let e = |k: &([u8; 16], [u8; 16])| ks::expand_whitened::<16>(&k.0, &k.1);
        let (ea, eb, ec, ed) = (e(&a), e(&b), e(&c), e(&d));
        for i in 0..16 {
            let sum = x(&x(ea.get(i), eb.get(i), ec.get(i)), ed.get(i), &[0u8; 16]);
            assert_ne!(sum, [0u8; 16], "trial {t}, round key {i} behaves affinely");
        }
    }
}

// Avalanche: flipping any single key bit should flip about half of all
// round-key bits. 16 keys x 128 bits = 2048 bits per flip, standard
// deviation about 22.6 bits, so [0.42, 0.58] is a window of more than 7
// standard deviations: a correct schedule never leaves it, a weak one does.
#[test]
fn every_key_bit_avalanches_into_every_round_key() {
    for k in 0..4 {
        let key = test_key(1000 + k);
        let base = expand::<16>(&key);
        for bit in 0..256 {
            let mut flipped = key;
            flipped[bit / 8] ^= 1 << (bit % 8);
            let other = expand::<16>(&flipped);
            let changed: u32 = base
                .all()
                .iter()
                .zip(other.all())
                .flat_map(|(a, b)| a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()))
                .sum();
            let fraction = changed as f64 / 2048.0;
            assert!((0.42..=0.58).contains(&fraction), "key {k} bit {bit}: {fraction:.3}");
        }
    }
}
