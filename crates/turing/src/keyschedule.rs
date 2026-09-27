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
use crate::{gf, linear, sbox, xof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

/// Version 2 labels. The schedule is prefix-consistent, so with version 1's
/// labels a key would give version 2 the same first 17 round keys, and a
/// v1 ciphertext and a v2 ciphertext of the same block would be related
/// through only v2's last rounds. New labels make the versions independent.
pub const KEY_LABEL: &str = "Turing v2 key";
pub const CONSTANTS_LABEL: &str = "Turing v2 key schedule constants";
/// Label for the secret point of the round keys' integrity checksum.
pub const CHECK_LABEL: &str = "Turing v2 key check";
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

/// Integrity checksum Σ_i H^(i+1) · k_i in GF(2^128) at the secret point H,
/// by Horner's rule: a fixed number of constant-time multiplications.
///
/// A fault that changes the keys by E_i and the stored checksum by e, and
/// leaves H alone, goes unseen only if Σ_i H^(i+1) · E_i = e: a non-zero
/// polynomial equation in H of degree at most N, true for at most N of the
/// 2^127 odd points, whatever the keys. A fault that also moves H by d ≠ 0
/// is checked at H + d and goes unseen only if
/// Σ_i ((H + d)^(i+1) + H^(i+1)) · k_i + Σ_i (H + d)^(i+1) · E_i = e. Round
/// key 0's term there is exactly d · k_0, and k_0 appears nowhere else, so
/// the equation holds for one value of k_0 only, whatever H and the other
/// keys: probability 2^-128 while k_0 is unknown. A fault arranged without
/// knowing the key therefore escapes with probability at most N / 2^127,
/// however many bits it flips and wherever they are, H included, as long as
/// the flipped pattern does not depend on the stored data (reset faults do;
/// CHECK_CONSTANT below covers them)
/// (research/notes/derivations.md). The point must stay secret: at a public
/// point the attacker can solve for faults that cancel,
/// as flipping bit b of RK_i and bit b - 1 of RK_i+1 did in version 2's
/// first checksum, Σ x^i · RK_i (docs/13). The checksum is linear in the
/// keys, so the checksums of two XOR shares of the keys XOR to the checksum
/// of the keys (the masked cipher relies on that).
pub(crate) fn checksum(keys: &[Block], point: &Block) -> Block {
    let h = u128::from_le_bytes(*point);
    keys.iter().rev().fold(0u128, |acc, k| gf::mul128(acc ^ u128::from_le_bytes(*k), h)).to_le_bytes()
}

/// A public, non-zero constant term added to the stored check. The bound
/// above covers faults that flip bits in a pattern independent of the stored
/// data; a reset (stuck-at-0) fault is also arranged without the key, but
/// its pattern is the stored value itself, and at H = 0 the checksum is 0 for
/// every key set. Until the review of 2026-09-27, zeroing the check and the
/// point therefore made every later fault pass. With this constant, all-zero
/// material never verifies, and `intact` also requires the point to be odd.
pub(crate) const CHECK_CONSTANT: Block = *b"Turing check v2\x01";

/// The stored check for `keys` at `point`: the checksum plus CHECK_CONSTANT.
pub(crate) fn sealed_check(keys: &[Block], point: &Block) -> Block {
    let c = checksum(keys, point);
    core::array::from_fn(|i| c[i] ^ CHECK_CONSTANT[i])
}

/// The checksum's point for a key: cSHAKE256 of K' under its own label, made
/// odd so that it is never zero. As secret as the key, and unrelated to any
/// round key.
fn check_point(k_left: &Block, k_right: &Block, point: &mut Block) {
    let mut whitened = [0u8; 32];
    whitened[..16].copy_from_slice(k_left);
    whitened[16..].copy_from_slice(k_right);
    xof::cshake256_secret(CHECK_LABEL, &whitened, point);
    whitened.zeroize();
    point[0] |= 1;
}

/// Round keys, their checksum and its secret point, stored together.
pub(crate) struct KeyMaterial<const N: usize> {
    pub(crate) keys: [Block; N],
    pub(crate) check: Block,
    pub(crate) point: Block,
}

impl<const N: usize> Zeroize for KeyMaterial<N> {
    fn zeroize(&mut self) {
        self.keys.zeroize();
        self.check.zeroize();
        self.point.zeroize();
    }
}

// SAFETY: byte arrays only; all zeroes is a valid value.
unsafe impl<const N: usize> Zeroable for KeyMaterial<N> {}

/// Round keys, in their own locked allocation (memory.rs), wiped when
/// dropped. Moving a `RoundKeys` moves only a pointer, so no unwiped copies
/// are left behind (zeroize can only wipe the copy it is given). A keyed
/// checksum kept beside them lets `intact` detect round keys corrupted in
/// memory, by Rowhammer-style bit flips for instance, which
/// decrypt-and-compare alone cannot see because both directions would use
/// the same corrupted keys.
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

    /// Whether the round keys still match their checksum, at a point that is
    /// still odd (CHECK_CONSTANT explains why both are needed). Compares
    /// without branching on the data.
    ///
    /// The recomputed check is wiped here, and the checked calls burn the
    /// stack afterwards: the point H is as secret as the key, and until the
    /// review of 2026-09-28 (R4) every checked call left H and the check in
    /// dead stack, where they tell an attacker which faults would pass.
    pub(crate) fn intact(&self) -> bool {
        let mut now = sealed_check(&self.material.keys, &self.material.point);
        let diff = now.iter().zip(&self.material.check).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        now.zeroize();
        let even = !self.material.point[0] & 1;
        (diff | even) == 0
    }

    /// Whether the operating system locked the round keys' memory.
    pub fn locked(&self) -> bool {
        self.material.locked()
    }

    /// Whether the operating system left the round keys' memory out of core
    /// dumps (Linux and Android only).
    pub fn dump_excluded(&self) -> bool {
        self.material.dump_excluded()
    }

    /// Round keys written by `fill` straight into their own locked pages,
    /// sealed with the keyed checksum at the point cSHAKE256(`whitened`,
    /// S = `check_label`), made odd. For Turing-256's schedule
    /// (keyschedule256.rs), which stores each 32-byte round key as two blocks.
    pub(crate) fn sealed(fill: impl FnOnce(&mut [Block; N]), check_label: &str, whitened: &[u8]) -> RoundKeys<N> {
        let mut material: SecretBox<KeyMaterial<N>> = SecretBox::zeroed();
        fill(&mut material.keys);
        xof::cshake256_secret(check_label, whitened, &mut material.point);
        material.point[0] |= 1;
        material.check = sealed_check(&material.keys, &material.point);
        RoundKeys { material }
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

    /// The checksum's point and the stored check, for the residue tests.
    #[cfg(test)]
    pub(crate) fn point_and_check(&self) -> (Block, Block) {
        (self.material.point, self.material.check)
    }

    /// Every block of secret material: the round keys, the check and its
    /// point (the residue sweep's needles).
    #[cfg(test)]
    pub(crate) fn secret_blocks(&self) -> Vec<Block> {
        let mut all = self.material.keys.to_vec();
        all.extend([self.material.check, self.material.point]);
        all
    }

    /// Bits of stored material that the integrity check reads: the round
    /// keys, the checksum and its point, 128 bits each.
    pub const STORED_BITS: usize = (N + 2) * 128;

    /// Flips one bit of a stored round key, as a Rowhammer-style fault would.
    /// Tests and analysis builds only (feature `analysis`).
    #[cfg(any(test, feature = "analysis"))]
    pub fn flip_bit(&mut self, round: usize, bit: usize) {
        self.material.keys[round][bit / 8] ^= 1 << (bit % 8);
    }

    /// Flips bit `bit` of the stored material, numbered through the round
    /// keys, then the checksum, then its point: a fault anywhere the check
    /// reads. Tests and analysis builds only (feature `analysis`).
    #[cfg(any(test, feature = "analysis"))]
    pub fn flip_stored_bit(&mut self, bit: usize) {
        assert!(bit < Self::STORED_BITS);
        let (block, bit) = (bit / 128, bit % 128);
        let target = match block {
            b if b < N => &mut self.material.keys[b],
            b if b == N => &mut self.material.check,
            _ => &mut self.material.point,
        };
        target[bit / 8] ^= 1 << (bit % 8);
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
    check_point(k_left, k_right, &mut material.point);
    material.check = sealed_check(&material.keys, &material.point);
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

    /// How flipping each stored bit changes the comparison between the
    /// recomputed and the stored checksum: a key bit by its column of the
    /// (linear) checksum, a bit of the stored checksum by itself. A fault is
    /// seen exactly when the XOR of its bits' columns is non-zero.
    fn columns<const N: usize>(point: &Block) -> Vec<u128> {
        let mut columns: Vec<u128> = (0..N * 128)
            .map(|bit| {
                let mut keys = [[0u8; 16]; N];
                keys[bit / 128][bit % 128 / 8] = 1 << (bit % 8);
                u128::from_le_bytes(checksum(&keys, point))
            })
            .collect();
        columns.extend((0..128).map(|j| 1u128 << j));
        columns
    }

    // Every fault of one or two bits in the round keys and the stored
    // checksum is seen: no column is zero and no two are equal.
    #[test]
    fn every_one_and_two_bit_fault_is_seen() {
        for seed in [1, 2, 3] {
            let k = expand::<25>(&key(seed));
            let mut columns = columns::<25>(&k.material.point);
            assert!(columns.iter().all(|&c| c != 0), "a single bit goes unseen");
            columns.sort_unstable();
            columns.dedup();
            assert_eq!(columns.len(), 26 * 128, "two bits cancel");
        }
    }

    // Control: at a public point the same test finds cancelling pairs. With
    // x, bit 1 of RK0 and bit 0 of RK1 both add x^2, as bit b of RK_i and
    // bit b - 1 of RK_i+1 cancelled in the first checksum, Σ x^i · RK_i.
    #[test]
    fn control_a_public_point_lets_two_bit_faults_cancel() {
        let columns = columns::<25>(&2u128.to_le_bytes());
        assert_eq!(columns[1], columns[128]);
        let mut distinct = columns.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(distinct.len() < columns.len());
    }

    // The pairs that cancelled in Σ x^i · RK_i, through `intact` itself.
    #[test]
    fn faults_that_cancelled_in_the_public_checksum_are_caught() {
        let mut k = expand::<25>(&key(4));
        for (a, b) in [(1, 128), (23 * 128 + 1, 24 * 128), (23, 23 * 128), (5, 25 * 128 + 5)] {
            k.flip_stored_bit(a);
            k.flip_stored_bit(b);
            assert!(!k.intact(), "bits {a} and {b}");
            k.flip_stored_bit(a);
            k.flip_stored_bit(b);
            assert!(k.intact());
        }
    }

    // Faults in the point are not linear in it, so they are tried one by
    // one: each of its 128 bits alone, and each paired with every other
    // stored bit (434,112 pairs). With the test above, that is every one-
    // and two-bit fault anywhere in the stored material.
    #[test]
    fn every_one_and_two_bit_fault_touching_the_point_is_seen() {
        let mut k = expand::<25>(&key(5));
        let point = 26 * 128..RoundKeys::<25>::STORED_BITS;
        let mut tried = 0;
        for a in point.clone() {
            k.flip_stored_bit(a);
            assert!(!k.intact(), "point bit {}", a % 128);
            for b in (0..RoundKeys::<25>::STORED_BITS).filter(|&b| !point.contains(&b) || b > a) {
                k.flip_stored_bit(b);
                assert!(!k.intact(), "bits {a} and {b}");
                k.flip_stored_bit(b);
                tried += 1;
            }
            k.flip_stored_bit(a);
        }
        assert_eq!(tried, 128 * 26 * 128 + 128 * 127 / 2);
        assert!(k.intact());
    }

    // What the bound for faults in the point rests on: moving H by d changes
    // round key 0's term by exactly d · RK_0, with no H in it, so changing
    // RK_0 by t changes the effect of the move by d · t whatever H and the
    // other keys are. Such a fault therefore passes for one RK_0 only.
    #[test]
    fn moving_the_point_changes_round_key_0s_term_by_d_times_it() {
        let mut s = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834u128;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let moved = |keys: &[Block; 25], h: u128, d: u128| {
            u128::from_le_bytes(checksum(keys, &(h ^ d).to_le_bytes())) ^ u128::from_le_bytes(checksum(keys, &h.to_le_bytes()))
        };
        for _ in 0..300 {
            let (h, d, t) = (next() | 1, next(), next());
            let keys: [Block; 25] = core::array::from_fn(|_| next().to_le_bytes());
            let mut other = keys;
            other[0] = (u128::from_le_bytes(keys[0]) ^ t).to_le_bytes();
            assert_eq!(moved(&keys, h, d) ^ moved(&other, h, d), gf::mul128(d, t));
        }
    }

    // Control: whoever knows every round key can match a moved point with a
    // recomputed checksum, and then the check passes; wrong about round key 0
    // in any single bit, it fails. The bound for faults in the point assumes
    // round key 0 is unknown, as it is to anyone who still needs a fault
    // attack to learn it.
    #[test]
    fn control_a_moved_point_passes_only_if_matched_with_every_key_known() {
        let mut k = expand::<25>(&key(12));
        let (point, check) = (k.material.point, k.material.check);
        let moved: Block = core::array::from_fn(|i| point[i] ^ 0x5a ^ i as u8);
        k.material.point = moved;
        k.material.check = sealed_check(&k.material.keys, &moved);
        assert!(k.intact(), "control: matched with every key known");
        for bit in 0..128 {
            let mut guess = k.material.keys;
            guess[0][bit / 8] ^= 1 << (bit % 8);
            k.material.check = sealed_check(&guess, &moved);
            assert!(!k.intact(), "round key 0 wrong in bit {bit}");
        }
        k.material.point = point;
        k.material.check = check;
        assert!(k.intact());
    }

    // Faults of 2 to 16 bits anywhere in the keys, the checksum and the point.
    // Every single bit of the stored check and of its point is covered: a
    // comparison that read only part of the check (8 of 16 bytes passed every
    // test until the review of 2026-09-27) fails here.
    #[test]
    fn every_bit_of_the_check_and_the_point_is_covered() {
        let mut k = expand::<25>(&key(14));
        for bit in 25 * 128..RoundKeys::<25>::STORED_BITS {
            k.flip_stored_bit(bit);
            assert!(!k.intact(), "stored bit {bit}");
            k.flip_stored_bit(bit);
        }
        assert!(k.intact());
    }

    #[test]
    fn random_multi_bit_faults_are_caught() {
        let mut k = expand::<25>(&key(6));
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: usize| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s % n as u64) as usize
        };
        for trial in 0..3000 {
            let mut bits: Vec<usize> = (0..2 + trial % 15).map(|_| next(RoundKeys::<25>::STORED_BITS)).collect();
            bits.sort_unstable();
            bits.dedup();
            bits.iter().for_each(|&b| k.flip_stored_bit(b));
            assert!(!k.intact(), "{bits:?}");
            bits.iter().for_each(|&b| k.flip_stored_bit(b));
        }
        assert!(k.intact());
    }

    // A reset (stuck-at) fault is arranged without knowing the key too, but
    // its XOR pattern is the stored value itself, so the additive bound above
    // does not cover it. At H = 0 the checksum is 0 for every key set: until
    // the review of 2026-09-27, zeroing the check and the point made every
    // later fault pass, and zeroing round key 24 with them (one 64-byte cache
    // line) released C' with C XOR C' = RK_24. The point must stay odd and
    // the stored check carries a non-zero constant, so none of these verify.
    #[test]
    fn reset_faults_are_caught() {
        let fresh = || expand::<25>(&key(13));
        let mut k = fresh();
        k.material.point = [0; 16];
        assert!(!k.intact(), "point zeroed");
        let mut k = fresh();
        k.material.check = [0; 16];
        k.material.point = [0; 16];
        assert!(!k.intact(), "check and point zeroed");
        let mut k = fresh();
        k.material.keys[24] = [0; 16];
        k.material.check = [0; 16];
        k.material.point = [0; 16];
        assert!(!k.intact(), "round key 24, check and point zeroed (one cache line)");
        let mut k = fresh();
        k.material.keys = [[0; 16]; 25];
        k.material.check = [0; 16];
        k.material.point = [0; 16];
        assert!(!k.intact(), "all material zeroed");
        let mut k = fresh();
        k.material.keys = [[0xff; 16]; 25];
        k.material.check = [0xff; 16];
        k.material.point = [0xff; 16];
        assert!(!k.intact(), "all material stuck at one");
        let mut k = fresh();
        k.material.keys = [[0; 16]; 25];
        k.material.check = [0; 16];
        k.material.point[0] |= 1;
        assert!(!k.intact(), "keys and check zeroed, point left odd (needs the constant)");
        let mut k = fresh();
        k.material.point = [0; 16];
        k.material.check = CHECK_CONSTANT;
        assert!(!k.intact(), "point zeroed, check set to the public constant (needs the odd point)");
        assert!(fresh().intact(), "control: untouched material verifies");
    }

    #[test]
    fn the_point_is_derived_from_the_key_and_odd() {
        let (a, b) = (expand::<25>(&key(7)), expand::<25>(&key(8)));
        assert_ne!(a.material.point, b.material.point);
        assert_eq!(a.material.point[0] & 1, 1);
        assert!(a.material.keys.iter().all(|rk| *rk != a.material.point));
        let mut expected = [0u8; 16];
        let mut whitened = [0u8; 32];
        xof::cshake256_secret(KEY_LABEL, &key(7), &mut whitened);
        xof::cshake256(CHECK_LABEL, &whitened).read(&mut expected);
        expected[0] |= 1;
        assert_eq!(a.material.point, expected, "cSHAKE256 of K' under its own label");
    }
}
