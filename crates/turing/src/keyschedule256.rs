//! Turing-256's key schedule (docs/15): Turing's three layers (docs/07) on
//! 32-byte halves.
//!
//! 1. **Whitening**: K' = cSHAKE256(K, S = "Turing-256 v1 key"), 64 bytes.
//! 2. **Feistel expansion** on K' = (L, R): (L, R) -> (R XOR F_j(L), L)
//!    with F_j(x) = MixState256(S(x XOR C_j)) and 32-byte constants C_j from
//!    cSHAKE256("", S = "Turing-256 v1 key schedule constants"). Round keys
//!    are taken in pairs (L, R) after 9 warm-up rounds, then every 8 rounds.
//!    With 32-byte halves and branch number 33, 8 Feistel rounds already
//!    force at least 67 active S-boxes (`bombe key-schedule`), so the first R
//!    round key, 8 rounds deep, meets Turing's target of 43 (2^-258).
//! 3. **Feed-forward**: each round key is a Feistel half XOR the matching
//!    half of K'.
//!
//! Each 32-byte round key is stored as two 16-byte blocks in Turing's
//! locked, checksummed `RoundKeys`, so Turing-256 inherits the memory
//! protection and the keyed fault check (docs/13) unchanged.

use crate::keyschedule::{Block, RoundKeys};
use crate::{linear256, sbox, xof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

pub const KEY_LABEL: &str = "Turing-256 v1 key";
pub const CONSTANTS_LABEL: &str = "Turing-256 v1 key schedule constants";
/// Label for the secret point of the round keys' integrity checksum.
pub const CHECK_LABEL: &str = "Turing-256 v1 key check";
/// Feistel rounds before the first round keys are taken.
pub const WARMUP_ROUNDS: usize = 9;
/// Feistel rounds between consecutive round-key pairs.
pub const ROUNDS_PER_PAIR: usize = 8;

/// How many Feistel rounds determine round key `index` (as in Turing's
/// schedule, an R half lags its L half by one round).
pub const fn round_key_depth(index: usize) -> usize {
    let l_depth = WARMUP_ROUNDS + index / 2 * ROUNDS_PER_PAIR;
    if index.is_multiple_of(2) {
        l_depth
    } else {
        l_depth - 1
    }
}

type Half = [u8; 32];

fn xor(a: &Half, b: &Half) -> Half {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// The S-box layer on 32 bytes, constant-time.
pub(crate) fn sub32(s: &mut [u8; 32]) {
    for chunk in s.chunks_exact_mut(8) {
        let x = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        chunk.copy_from_slice(&sbox::sub8(x).to_le_bytes());
    }
}

/// F_j(x) = MixState256(S(x XOR C_j)), constant-time.
fn f(x: &Half, c: &Half) -> Half {
    let mut t = xor(x, c);
    sub32(&mut t);
    let out = linear256::mix_state(&t);
    t.zeroize();
    out
}

fn feistel_round(l: &mut Half, r: &mut Half, constants: &mut impl XofReader) {
    let mut c = [0u8; 32];
    constants.read(&mut c);
    let mut new_l = xor(r, &f(l, &c));
    *r = *l;
    *l = new_l;
    new_l.zeroize();
}

/// Expands `key` into B / 2 round keys of 32 bytes, stored as B blocks:
/// round key i is blocks 2i (bytes 0-15) and 2i + 1 (bytes 16-31).
pub fn expand<const B: usize>(key: &[u8; 32]) -> RoundKeys<B> {
    assert!(B.is_multiple_of(2), "two blocks per round key");
    let mut whitened = [0u8; 64];
    xof::cshake256_secret(KEY_LABEL, key, &mut whitened);
    let keys = from_whitened::<B>(&whitened);
    whitened.zeroize();
    keys
}

/// Layers 2 and 3 alone, from K' (64 bytes), for Bombe. Analysis builds only.
#[cfg(feature = "analysis")]
pub fn expand_whitened<const B: usize>(whitened: &[u8; 64]) -> RoundKeys<B> {
    from_whitened::<B>(whitened)
}

fn from_whitened<const B: usize>(whitened: &[u8; 64]) -> RoundKeys<B> {
    let mut k_left: Half = core::array::from_fn(|i| whitened[i]);
    let mut k_right: Half = core::array::from_fn(|i| whitened[32 + i]);
    let (mut l, mut r) = (k_left, k_right);
    let mut constants = xof::cshake256(CONSTANTS_LABEL, &[]);
    for _ in 0..WARMUP_ROUNDS {
        feistel_round(&mut l, &mut r, &mut constants);
    }
    let keys = RoundKeys::<B>::sealed(
        |blocks: &mut [Block; B]| {
            let round_keys = B / 2;
            for pair in 0..round_keys.div_ceil(2) {
                if pair > 0 {
                    for _ in 0..ROUNDS_PER_PAIR {
                        feistel_round(&mut l, &mut r, &mut constants);
                    }
                }
                for (half, (value, base)) in [(&l, &k_left), (&r, &k_right)].into_iter().enumerate() {
                    let index = 2 * pair + half;
                    if index < round_keys {
                        let mut rk = xor(value, base);
                        blocks[2 * index].copy_from_slice(&rk[..16]);
                        blocks[2 * index + 1].copy_from_slice(&rk[16..]);
                        rk.zeroize();
                    }
                }
            }
        },
        CHECK_LABEL,
        whitened,
    );
    l.zeroize();
    r.zeroize();
    k_left.zeroize();
    k_right.zeroize();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_keys(key: &[u8; 32]) -> Vec<[u8; 32]> {
        let k = expand::<50>(key);
        (0..25)
            .map(|i| {
                let mut rk = [0u8; 32];
                rk[..16].copy_from_slice(k.key(2 * i));
                rk[16..].copy_from_slice(k.key(2 * i + 1));
                rk
            })
            .collect()
    }

    #[test]
    fn deterministic_distinct_and_key_dependent() {
        let a = round_keys(&[1; 32]);
        assert_eq!(a, round_keys(&[1; 32]));
        let mut all = a.clone();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 25);
        let mut k = [1u8; 32];
        k[31] ^= 1;
        let b = round_keys(&k);
        assert!(a.iter().zip(&b).all(|(x, y)| x != y));
    }

    // The same whitened key gives the same first round keys whatever the
    // count (prefix consistency, as in Turing's schedule).
    #[test]
    fn expansion_is_prefix_consistent() {
        let short = expand::<10>(&[7; 32]);
        let long = expand::<50>(&[7; 32]);
        for i in 0..10 {
            assert_eq!(short.key(i), long.key(i));
        }
    }

    #[test]
    fn depths_meet_the_target() {
        // 8 Feistel rounds of 32-byte halves force at least 67 active S-boxes.
        assert_eq!(round_key_depth(0), 9);
        assert_eq!(round_key_depth(1), 8);
        assert!((0..25).all(|i| round_key_depth(i) >= 8));
    }

    #[test]
    fn keys_are_sealed_and_checked() {
        let mut k = expand::<50>(&[3; 32]);
        assert!(k.intact());
        k.flip_bit(17, 5);
        assert!(!k.intact());
    }
}
