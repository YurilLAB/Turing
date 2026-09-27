//! Turing-1026 against deliberately built ciphertexts (docs/16): decoding
//! boundaries, extreme coefficient patterns, structured edits of valid
//! ciphertexts, and a key-recovery attack that works on the bare lattice
//! decryption but gets nothing through the KEM. The independent reference
//! (`refkem1026`) must agree with the implementation on every one.

use bombe::refkem1026::{self, ReferenceKem};
use turing::lwe;
use turing::turing1026::{DecapsulationKey, PARAMS};

const Q: u16 = 1 << 15;
const MASK: u16 = Q - 1;
const BP_BYTES: usize = 15_390;
const PKE_BYTES: usize = 15_870;

struct Setup {
    dk: DecapsulationKey,
    reference: ReferenceKem,
    s: Vec<u16>,
}

fn setup(seed: u8) -> Setup {
    let dk = DecapsulationKey::from_seed(&[seed; 32]).expect("consistent");
    let reference = ReferenceKem::from_seed(&[seed; 32]);
    let s = dk.secret_matrix().to_vec();
    Setup { dk, reference, s }
}

fn pack(bp: &[u16], c: &[u16], salt: &[u8; 64]) -> Vec<u8> {
    let mut ct = vec![0u8; PKE_BYTES];
    lwe::pack(15, bp, &mut ct[..BP_BYTES]);
    lwe::pack(15, c, &mut ct[BP_BYTES..]);
    ct.extend_from_slice(salt);
    ct
}

fn unpack(ct: &[u8]) -> (Vec<u16>, Vec<u16>) {
    let (mut bp, mut c) = (vec![0u16; PARAMS.mbar * PARAMS.n], vec![0u16; PARAMS.mbar * PARAMS.nbar]);
    lwe::unpack(15, &ct[..BP_BYTES], &mut bp);
    lwe::unpack(15, &ct[BP_BYTES..PKE_BYTES], &mut c);
    (bp, c)
}

/// B' S (mbar x nbar), the part of C - B'S the attacker cancels.
fn bp_times_s(bp: &[u16], s: &[u16]) -> Vec<u16> {
    let (n, nbar) = (PARAMS.n, PARAMS.nbar);
    let mut m = vec![0u16; PARAMS.mbar * nbar];
    for r in 0..PARAMS.mbar {
        for k in 0..n {
            for j in 0..nbar {
                m[r * nbar + j] = m[r * nbar + j].wrapping_add(bp[r * n + k].wrapping_mul(s[k * nbar + j]));
            }
        }
    }
    m
}

fn decrypt(s: &[u16], bp: &[u16], c: &[u16]) -> Vec<u8> {
    let mut msg = vec![0u8; 32];
    lwe::decrypt(&PARAMS, s, bp, c, &mut msg);
    msg
}

fn bit(msg: &[u8], i: usize) -> u8 {
    (msg[i / 8] >> (i % 8)) & 1
}

/// The implementation's and the reference's decapsulation of `ct` agree,
/// and neither returns `forbidden` (the real shared key of a valid
/// ciphertext this was derived from, if any).
fn same_decapsulation(t: &Setup, ct: &[u8], forbidden: Option<&[u8]>) {
    let got = t.dk.decapsulate(ct).expect("length");
    assert_eq!(got[..], t.reference.decapsulate(ct).expect("length"));
    if let Some(k) = forbidden {
        assert_ne!(&got[..], k);
    }
}

// C - B'S placed exactly on each side of each decoding boundary: bit 0 on
// [-q/4, q/4), bit 1 elsewhere. The decoded bits are the specified ones,
// the reference agrees, and decapsulation gives the reference's rejection
// key.
#[test]
fn decoding_boundaries() {
    let t = setup(11);
    let bp: Vec<u16> = (0..PARAMS.mbar * PARAMS.n).map(|i| (i as u16).wrapping_mul(40503) & MASK).collect();
    let base = bp_times_s(&bp, &t.s);
    let q4 = Q / 4;
    // (offset of C - B'S, the bit it must decode to)
    let edges: [(u16, u8); 8] = [(0, 0), (q4 - 1, 0), (q4, 1), (Q / 2, 1), (3 * q4 - 1, 1), (3 * q4, 0), (Q - 1, 0), (Q / 2 - 1, 1)];
    for (round, salt_byte) in [(0usize, 0u8), (1, 0x5a)] {
        let c: Vec<u16> = (0..256).map(|i| base[i].wrapping_add(edges[(i + round) % edges.len()].0) & MASK).collect();
        let msg = decrypt(&t.s, &bp, &c);
        let reference = refkem1026::pke_decrypt(&PARAMS, &t.s.iter().map(|&v| i64::from(v as i16)).collect::<Vec<_>>(), &bp.iter().map(|&v| i64::from(v)).collect::<Vec<_>>(), &c.iter().map(|&v| i64::from(v)).collect::<Vec<_>>());
        assert_eq!(msg, reference);
        for i in 0..256 {
            assert_eq!(bit(&msg, i), edges[(i + round) % edges.len()].1, "coefficient {i}");
        }
        same_decapsulation(&t, &pack(&bp, &c, &[salt_byte; 64]), None);
    }
}

// Extreme and degenerate ciphertexts: all zero, all ones, alternating
// bytes, a single nonzero coefficient, B' zero with C at q/2, maximal
// coefficients. Every one decapsulates, to the reference's rejection key.
#[test]
fn extreme_patterns() {
    let t = setup(12);
    let n = PARAMS.mbar * PARAMS.n;
    let mut cases: Vec<Vec<u8>> = vec![vec![0u8; 15_934], vec![0xff; 15_934], (0..15_934).map(|i| if i % 2 == 0 { 0x55 } else { 0xaa }).collect()];
    let mut single = vec![0u16; n];
    single[777] = 1;
    cases.push(pack(&single, &[0; 256], &[0; 64]));
    cases.push(pack(&vec![0; n], &[Q / 2; 256], &[1; 64]));
    // Every coefficient q - 1 packs to all-ones bytes: with salt 0xff this
    // would be case 2 again, and the same ciphertext gives the same key.
    assert_eq!(pack(&vec![MASK; n], &[MASK; 256], &[0xff; 64]), cases[1]);
    cases.push(pack(&vec![MASK; n], &[MASK; 256], &[0xfe; 64]));
    cases.push(pack(&vec![Q / 2; n], &[Q / 4; 256], &[7; 64]));
    for ct in &cases {
        same_decapsulation(&t, ct, None);
    }
    // All different rejection keys: each hashes its whole ciphertext.
    let keys: Vec<Vec<u8>> = cases.iter().map(|ct| t.dk.decapsulate(ct).expect("length").to_vec()).collect();
    for i in 0..keys.len() {
        for j in 0..i {
            assert_ne!(keys[i], keys[j]);
        }
    }
}

// Edits of a valid ciphertext aimed at the message the decapsulator
// decodes: q/2 added to a coefficient of C flips one message bit; a small
// change to C or B' keeps the decoded message but not the re-encryption;
// salts swapped between ciphertexts; B' of one ciphertext with C of
// another. Each gives the rejection key, never the real one.
#[test]
fn structured_edits() {
    let t = setup(13);
    let pk = t.dk.encapsulation_key();
    let (ct, key) = pk.encapsulate_with(&[0x3c; 32], &[0x11; 64]);
    let (ct2, key2) = pk.encapsulate_with(&[0xc3; 32], &[0x22; 64]);
    let (bp, c) = unpack(&ct);
    let (bp2, c2) = unpack(&ct2);
    let salt: [u8; 64] = ct[PKE_BYTES..].try_into().expect("64");
    let salt2: [u8; 64] = ct2[PKE_BYTES..].try_into().expect("64");
    // q/2 on coefficient j: the decoded message changes in exactly bit j.
    for j in [0usize, 31, 128, 255] {
        let mut cj = c.clone();
        cj[j] = cj[j].wrapping_add(Q / 2) & MASK;
        let d = decrypt(&t.s, &bp, &cj);
        let honest = decrypt(&t.s, &bp, &c);
        for i in 0..256 {
            assert_eq!(bit(&d, i) != bit(&honest, i), i == j, "coefficient {i} after editing {j}");
        }
        same_decapsulation(&t, &pack(&bp, &cj, &salt), Some(&key[..]));
    }
    // Small changes: the message decodes the same, the ciphertext is still rejected.
    for (j, delta) in [(5usize, 1u16), (100, 64), (200, MASK)] {
        let mut cj = c.clone();
        cj[j] = cj[j].wrapping_add(delta) & MASK;
        assert_eq!(decrypt(&t.s, &bp, &cj), decrypt(&t.s, &bp, &c));
        same_decapsulation(&t, &pack(&bp, &cj, &salt), Some(&key[..]));
        let mut bj = bp.clone();
        bj[j * 7] = bj[j * 7].wrapping_add(delta) & MASK;
        same_decapsulation(&t, &pack(&bj, &c, &salt), Some(&key[..]));
    }
    // Salts swapped, and halves of two valid ciphertexts spliced.
    same_decapsulation(&t, &pack(&bp, &c, &salt2), Some(&key[..]));
    same_decapsulation(&t, &pack(&bp2, &c2, &salt), Some(&key2[..]));
    same_decapsulation(&t, &pack(&bp, &c2, &salt), Some(&key[..]));
    same_decapsulation(&t, &pack(&bp2, &c, &salt2), Some(&key2[..]));
}

// The key-mismatch attack on lattice encryption with a reused key. With a
// decryption oracle that returns the decoded message (the bare lattice
// scheme), the attacker sets row 0 of B' to a unit vector at k, so
// coefficient (0, j) of C - B'S is C[0][j] - S[k][j], and binary-searches
// C[0][j] for the point where the decoded bit flips: S[k][j] comes out in
// about 6 queries. Through the KEM the same ciphertexts all give the
// reference's rejection key cSHAKE256(z || H(pk) || c), a function of z and
// the ciphertext alone, so the answers carry nothing about S.
#[test]
fn key_mismatch_attack() {
    let t = setup(14);
    let n = PARAMS.mbar * PARAMS.n;
    let mut queries: Vec<Vec<u8>> = Vec::new();
    let mut recovered = Vec::new();
    for k in [0usize, 1, 500, 1025] {
        let mut bp = vec![0u16; n];
        bp[k] = 1;
        for j in [0usize, 7, 31] {
            // bit(c0) = 1 iff c0 - s lies in [q/4, 3q/4); for c0 near q/4 the
            // bit flips from 0 to 1 at c0 = q/4 + s. Find that c0.
            let query = |c0: u16, queries: &mut Vec<Vec<u8>>| {
                let mut c = vec![0u16; 256];
                c[j] = c0 & MASK;
                queries.push(pack(&bp, &c, &[0; 64]));
                bit(&decrypt(&t.s, &bp, &c), j)
            };
            let (mut lo, mut hi) = (Q / 4 - 40, Q / 4 + 40);
            assert_eq!(query(lo, &mut queries), 0);
            assert_eq!(query(hi, &mut queries), 1);
            while hi - lo > 1 {
                let mid = (lo + hi) / 2;
                if query(mid, &mut queries) == 1 {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            let s = i32::from(hi) - i32::from(Q / 4);
            assert_eq!(s, i32::from(t.s[k * PARAMS.nbar + j] as i16), "S[{k}][{j}]");
            recovered.push(s);
        }
    }
    assert_eq!(recovered.len(), 12);
    // The same ciphertexts through the KEM.
    for ct in &queries {
        same_decapsulation(&t, ct, None);
    }
}
