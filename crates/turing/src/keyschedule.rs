//! The Turing key schedule: expands a 256-bit key into 16-byte round keys.
//!
//! Three layers, each answering a known attack on AES-256's schedule
//! (docs/07-key-schedule.md):
//!
//! 1. **Whitening**: K' = cSHAKE256(K, S = "Turing v2 key"). A key difference
//!    chosen by an attacker becomes a pseudorandom, unknown difference.
//! 2. **Feistel expansion** on K' = (L, R): each round maps (L, R) to
//!    (R XOR F_j(L), L) with F_j(x) = MixState(S(x XOR C_j)) and constants
//!    C_j read from cSHAKE256("", S = "Turing v2 key schedule constants").
//!    Round keys are taken in pairs (L, R) after 13 warm-up rounds, then
//!    every 8 rounds. The R half is one round behind L, so the first R round
//!    key depends on 12 rounds, and Bombe proves any key difference crosses
//!    at least 53 active S-boxes before reaching any round key.
//! 3. **Feed-forward**: each round key is a Feistel half XOR the matching
//!    half of K', so round keys cannot be run backwards to K', and
//!    neighbouring round keys have no simple relation to exploit.

use crate::memory::{SecretBox, Zeroable};
use crate::{linear, sbox, xof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

/// Version 2 labels. The schedule is prefix-consistent, so with version 1's
/// labels a key would give version 2 the same first 17 round keys, and a
/// v1 ciphertext and a v2 ciphertext of the same block would be related
/// through only v2's last rounds. New labels make the versions independent.
pub const KEY_LABEL: &str = "Turing v2 key";
pub const CONSTANTS_LABEL: &str = "Turing v2 key schedule constants";
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

/// Multiplication by x in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1,
/// without branches.
fn times_x(v: u128) -> u128 {
    (v << 1) ^ (0u128.wrapping_sub(v >> 127) & 0x87)
}

/// Integrity checksum sum over i of x^i * k_i in GF(2^128). It is linear, so
/// the checksum of two XOR shares of the keys XORs to the checksum of the
/// keys (the masked cipher relies on that), and since x is invertible any
/// change confined to one round key changes it.
pub(crate) fn checksum(keys: &[Block]) -> Block {
    keys.iter().rev().fold(0u128, |acc, k| times_x(acc) ^ u128::from_le_bytes(*k)).to_le_bytes()
}

/// Round keys and their checksum, stored together.
pub(crate) struct KeyMaterial<const N: usize> {
    pub(crate) keys: [Block; N],
    pub(crate) check: Block,
}

impl<const N: usize> Zeroize for KeyMaterial<N> {
    fn zeroize(&mut self) {
        self.keys.zeroize();
        self.check.zeroize();
    }
}

// SAFETY: byte arrays only; all zeroes is a valid value.
unsafe impl<const N: usize> Zeroable for KeyMaterial<N> {}

/// Round keys, in their own locked allocation (memory.rs), wiped when
/// dropped. Moving a `RoundKeys` moves only a pointer, so no unwiped copies
/// are left behind (zeroize can only wipe the copy it is given). A checksum
/// kept beside them lets `intact` detect a round key corrupted in memory, by
/// a Rowhammer-style bit flip for instance, which decrypt-and-compare alone
/// cannot see because both directions would use the same corrupted key.
pub struct RoundKeys<const N: usize> {
    material: SecretBox<KeyMaterial<N>>,
}

impl<const N: usize> RoundKeys<N> {
    pub(crate) fn key(&self, round: usize) -> &Block {
        &self.material.keys[round]
    }

    pub(crate) fn keys(&self) -> &[Block; N] {
        &self.material.keys
    }

    /// Whether the round keys still match their checksum. Compares without
    /// branching on the data.
    pub(crate) fn intact(&self) -> bool {
        let now = checksum(&self.material.keys);
        now.iter().zip(&self.material.check).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }

    /// Whether the operating system locked the round keys' memory.
    pub fn locked(&self) -> bool {
        self.material.locked()
    }

    /// Round key `round`. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn get(&self, round: usize) -> &Block {
        self.key(round)
    }

    /// All round keys. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn all(&self) -> &[Block; N] {
        &self.material.keys
    }

    /// Flips one bit of a stored round key, as a Rowhammer-style fault would.
    /// Tests and analysis builds only (feature `analysis`).
    #[cfg(any(test, feature = "analysis"))]
    pub fn flip_bit(&mut self, round: usize, bit: usize) {
        self.material.keys[round][bit / 8] ^= 1 << (bit % 8);
    }

    /// The same through the allocation's raw pointer, with only `&self`: a
    /// fault striking while the keys are in use (cipher.rs, `guarded`).
    ///
    /// # Safety
    /// No reference into the round keys may be alive.
    #[cfg(any(test, feature = "analysis"))]
    pub(crate) unsafe fn flip_bit_raw(&self, round: usize, bit: usize) {
        assert!(round < N && bit < 128);
        let material = self.material.raw();
        // SAFETY: in bounds by the assertion; the caller guarantees that no
        // reference aliases the byte; volatile so the write is not elided.
        unsafe {
            let byte = core::ptr::addr_of_mut!((*material).keys).cast::<u8>().add(round * 16 + bit / 8);
            byte.write_volatile(byte.read_volatile() ^ (1 << (bit % 8)));
        }
    }
}

/// Expands `key` into N round keys.
pub fn expand<const N: usize>(key: &[u8; 32]) -> RoundKeys<N> {
    let mut whitened = [0u8; 32];
    xof::cshake256_secret(KEY_LABEL, key, &mut whitened);

    let mut k_left: Block = core::array::from_fn(|i| whitened[i]);
    let mut k_right: Block = core::array::from_fn(|i| whitened[16 + i]);
    whitened.zeroize();
    let keys = from_whitened(&k_left, &k_right);
    k_left.zeroize();
    k_right.zeroize();
    keys
}

/// Layers 2 and 3 alone, starting from K' = (k_left, k_right), so Bombe can
/// analyse the Feistel stage without the cSHAKE256 layer in front. Analysis
/// builds only (feature `analysis`).
#[cfg(feature = "analysis")]
pub fn expand_whitened<const N: usize>(k_left: &Block, k_right: &Block) -> RoundKeys<N> {
    from_whitened(k_left, k_right)
}

fn from_whitened<const N: usize>(k_left: &Block, k_right: &Block) -> RoundKeys<N> {
    let (mut l, mut r) = (*k_left, *k_right);

    let mut constants = xof::cshake256(CONSTANTS_LABEL, &[]);
    for _ in 0..WARMUP_ROUNDS {
        feistel_round(&mut l, &mut r, &mut constants);
    }
    // Allocated first and filled in place: the keys are written only into
    // their own locked pages.
    let mut material: SecretBox<KeyMaterial<N>> = SecretBox::zeroed();
    for pair in 0..N.div_ceil(2) {
        if pair > 0 {
            for _ in 0..ROUNDS_PER_PAIR {
                feistel_round(&mut l, &mut r, &mut constants);
            }
        }
        material.keys[2 * pair] = xor(&l, k_left);
        if 2 * pair + 1 < N {
            material.keys[2 * pair + 1] = xor(&r, k_right);
        }
    }
    l.zeroize();
    r.zeroize();
    material.check = checksum(&material.keys);
    RoundKeys { material }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ seed)
    }

    fn all<const N: usize>(k: &RoundKeys<N>) -> Vec<Block> {
        (0..N).map(|i| *k.key(i)).collect()
    }

    #[test]
    fn deterministic_and_key_dependent() {
        let a = expand::<16>(&key(1));
        let b = expand::<16>(&key(1));
        let c = expand::<16>(&key(2));
        assert_eq!(all(&a), all(&b));
        for i in 0..16 {
            assert_ne!(a.key(i), c.key(i), "round key {i}");
        }
    }

    #[test]
    fn round_keys_are_all_distinct() {
        let k = expand::<16>(&key(7));
        for i in 0..16 {
            for j in i + 1..16 {
                assert_ne!(k.key(i), k.key(j));
            }
        }
    }

    // A shorter expansion is a prefix of a longer one, and an odd count
    // simply drops the second key of the last pair.
    #[test]
    fn expansion_is_prefix_consistent() {
        let long = expand::<16>(&key(3));
        let short = expand::<15>(&key(3));
        assert_eq!(all(&long)[..15], all(&short)[..]);
    }

    // The all-zero key is not special: its round keys are not zero and
    // not equal to each other.
    #[test]
    fn zero_key_has_no_weak_structure() {
        let k = expand::<16>(&[0u8; 32]);
        for i in 0..16 {
            assert_ne!(k.key(i), &[0u8; 16]);
        }
    }

    // The whitening goes through the wiping cSHAKE path and still computes
    // the same K' as the streaming one (so the schedule is unchanged).
    #[test]
    fn whitening_is_unchanged() {
        use sha3::digest::XofReader;
        let k = key(9);
        let mut streaming = [0u8; 32];
        xof::cshake256(KEY_LABEL, &k).read(&mut streaming);
        let mut wiped = [0u8; 32];
        xof::cshake256_secret(KEY_LABEL, &k, &mut wiped);
        assert_eq!(streaming, wiped);
    }
}
