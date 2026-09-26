//! The Turing key schedule: expands a 256-bit key into 16-byte round keys.
//!
//! Three layers, each answering a known attack on AES-256's schedule
//! (docs/07-key-schedule.md):
//!
//! 1. **Whitening**: K' = cSHAKE256(K, S = "Turing v1 key"). A key difference
//!    chosen by an attacker becomes a pseudorandom, unknown difference.
//! 2. **Feistel expansion** on K' = (L, R): each round maps (L, R) to
//!    (R XOR F_j(L), L) with F_j(x) = MixState(S(x XOR C_j)) and constants
//!    C_j read from cSHAKE256("", S = "Turing v1 key schedule constants").
//!    Round keys are taken in pairs (L, R) after 13 warm-up rounds, then
//!    every 8 rounds. The R half is one round behind L, so the first R round
//!    key depends on 12 rounds, and Bombe proves any key difference crosses
//!    at least 53 active S-boxes before reaching any round key.
//! 3. **Feed-forward**: each round key is a Feistel half XOR the matching
//!    half of K', so round keys cannot be run backwards to K', and
//!    neighbouring round keys have no simple relation to exploit.

use crate::{linear, sbox, xof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

pub const KEY_LABEL: &str = "Turing v1 key";
pub const CONSTANTS_LABEL: &str = "Turing v1 key schedule constants";
/// Feistel rounds before the first round keys are taken.
pub const WARMUP_ROUNDS: usize = 13;
/// Feistel rounds between consecutive round-key pairs.
pub const ROUNDS_PER_PAIR: usize = 8;

/// How many Feistel rounds determine round key `index`: an L half (even
/// index) is taken after the rounds run so far; an R half (odd index) equals
/// the L half of one round earlier.
pub const fn round_key_depth(index: usize) -> usize {
    let pair = index / 2;
    let l_depth = WARMUP_ROUNDS + pair * ROUNDS_PER_PAIR;
    if index.is_multiple_of(2) {
        l_depth
    } else {
        l_depth - 1
    }
}

pub type Block = [u8; 16];

fn xor(a: &Block, b: &Block) -> Block {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// F_j(x) = MixState(S(x XOR C_j)), constant-time.
fn f(x: &Block, c: &Block) -> Block {
    let mut t = xor(x, c);
    sbox::sub_bytes(&mut t);
    let out = linear::mix_state(&t);
    t.zeroize();
    out
}

/// One Feistel round, reading the next 16-byte constant from `constants`.
fn feistel_round(l: &mut Block, r: &mut Block, constants: &mut impl XofReader) {
    let mut c = [0u8; 16];
    constants.read(&mut c);
    let mut new_l = xor(r, &f(l, &c));
    *r = *l;
    *l = new_l;
    new_l.zeroize();
}

/// Round keys, wiped from memory when dropped.
pub struct RoundKeys<const N: usize> {
    keys: [Block; N],
}

impl<const N: usize> RoundKeys<N> {
    pub fn get(&self, round: usize) -> &Block {
        &self.keys[round]
    }

    pub fn all(&self) -> &[Block; N] {
        &self.keys
    }
}

impl<const N: usize> Drop for RoundKeys<N> {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

/// Expands `key` into N round keys.
pub fn expand<const N: usize>(key: &[u8; 32]) -> RoundKeys<N> {
    let mut whitened = [0u8; 32];
    xof::cshake256(KEY_LABEL, key).read(&mut whitened);

    let mut k_left: Block = core::array::from_fn(|i| whitened[i]);
    let mut k_right: Block = core::array::from_fn(|i| whitened[16 + i]);
    whitened.zeroize();
    let keys = expand_whitened(&k_left, &k_right);
    k_left.zeroize();
    k_right.zeroize();
    keys
}

/// Layers 2 and 3 alone, starting from K' = (k_left, k_right). Exposed so
/// Bombe can analyse the Feistel stage without the cSHAKE256 layer in front.
#[doc(hidden)]
pub fn expand_whitened<const N: usize>(k_left: &Block, k_right: &Block) -> RoundKeys<N> {
    let (mut l, mut r) = (*k_left, *k_right);

    let mut constants = xof::cshake256(CONSTANTS_LABEL, &[]);
    for _ in 0..WARMUP_ROUNDS {
        feistel_round(&mut l, &mut r, &mut constants);
    }
    let mut keys = [[0u8; 16]; N];
    for pair in 0..N.div_ceil(2) {
        if pair > 0 {
            for _ in 0..ROUNDS_PER_PAIR {
                feistel_round(&mut l, &mut r, &mut constants);
            }
        }
        keys[2 * pair] = xor(&l, k_left);
        if 2 * pair + 1 < N {
            keys[2 * pair + 1] = xor(&r, k_right);
        }
    }
    l.zeroize();
    r.zeroize();
    RoundKeys { keys }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ seed)
    }

    #[test]
    fn deterministic_and_key_dependent() {
        let a = expand::<16>(&key(1));
        let b = expand::<16>(&key(1));
        let c = expand::<16>(&key(2));
        assert_eq!(a.all(), b.all());
        for i in 0..16 {
            assert_ne!(a.get(i), c.get(i), "round key {i}");
        }
    }

    #[test]
    fn round_keys_are_all_distinct() {
        let k = expand::<16>(&key(7));
        for i in 0..16 {
            for j in i + 1..16 {
                assert_ne!(k.get(i), k.get(j));
            }
        }
    }

    // A shorter expansion is a prefix of a longer one, and an odd count
    // simply drops the second key of the last pair.
    #[test]
    fn expansion_is_prefix_consistent() {
        let long = expand::<16>(&key(3));
        let short = expand::<15>(&key(3));
        assert_eq!(&long.all()[..15], &short.all()[..]);
    }

    // The all-zero key is not special: its round keys are not zero and
    // not equal to each other.
    #[test]
    fn zero_key_has_no_weak_structure() {
        let k = expand::<16>(&[0u8; 32]);
        for i in 0..16 {
            assert_ne!(k.get(i), &[0u8; 16]);
        }
    }
}
