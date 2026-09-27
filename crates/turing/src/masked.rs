//! First-order masked Turing. Every secret value inside encryption and
//! decryption is split into two shares whose XOR is the value, with fresh
//! random masks for every block, so no single intermediate value depends on
//! the key or the data. Key setup is not masked: the key schedule runs in the
//! clear, as the plain cipher's does, and the round keys exist unshared, in
//! locked memory, until `with_stream` has split them into shares and wiped
//! them (research/reviews/2026-09-28 R12).
//! A single intermediate value is exactly what power and EM analysis,
//! software power meters (PLATYPUS) and Hertzbleed's frequency leak observe
//! (docs/13).
//!
//! - XORs and the linear layers act on each share separately.
//! - Affine maps put their constant into one share only.
//! - The inversion x^254 follows Rivain and Prouff (CHES 2010, Algorithm 3):
//!   squarings share by share, two mask refreshes, and four secure
//!   multiplications in the style of Ishai, Sahai and Wagner (CRYPTO 2003).
//!   Coron, Prouff, Rivain and Roche (FSE 2013) showed that this refreshing
//!   falls to an attack of order ceil(d/2) + 1. At masking order d = 1 that
//!   is order 2, which first-order masking does not claim to resist.
//! - Round keys are stored as two shares in locked memory, re-randomised on
//!   every call, so after key setup the key never sits in memory as itself.
//!   Their checksum
//!   is shared the same way and catches corrupted shares. Its secret point
//!   is drawn at random, not derived from the key, so checking it handles
//!   no value that depends on the key.
//!
//! First order: one probe learns nothing, two probes combined can (Bombe's
//! leakage tests show both, on every value this code computes). A compiler
//! may still reorder XORs and bring two shares together in a register; the
//! secure multiplication fences its cross term with `black_box`, but the
//! machine code is not checked for that (docs/13). About five times slower
//! than `Turing`.
//!
//! Masks must never repeat: the stream is private to one object and one
//! process (random.rs checks for fork on every operation), and the type is
//! deliberately not `Clone`, since a copy would draw the same masks:
//!
//! ```compile_fail,E0277
//! fn copy<T: Clone>(_: &T) {}
//! copy(&turing::MaskedTuring::new(&[0; 32]).unwrap());
//! ```
//!
//! It can move to another thread; sharing one between threads takes a lock,
//! because every operation needs `&mut self`:
//!
//! ```
//! fn send<T: Send>(_: &T) {}
//! let mut m = turing::MaskedTuring::new(&[0; 32]).unwrap();
//! send(&m);
//! m.encrypt_block(&mut [0; 16]);
//! ```
//!
//! ```compile_fail,E0596
//! let m = turing::MaskedTuring::new(&[0; 32]).unwrap();
//! m.encrypt_block(&mut [0; 16]);
//! ```

use crate::cipher::FaultDetected;
use crate::gf::{self, Affine8};
use crate::keyschedule::{self, checksum};
use crate::memory::{self, SecretBox, Zeroable};
use crate::random::{MaskStream, RandomnessError};
use crate::structure::{self, ROUNDS, ROUND_KEYS};
use crate::{linear, sbox, Block};
use core::hint::black_box;
use zeroize::Zeroize;

/// Round keys and their checksum, each as two XOR shares, and the checksum's
/// secret point (keyschedule.rs).
struct Shares {
    keys: [[Block; ROUND_KEYS]; 2],
    check: [Block; 2],
    point: Block,
}

impl Zeroize for Shares {
    fn zeroize(&mut self) {
        self.keys.zeroize();
        self.check.zeroize();
        self.point.zeroize();
    }
}

// SAFETY: byte arrays only; all zeroes is a valid value.
unsafe impl Zeroable for Shares {}

fn xor(a: &Block, b: &Block) -> Block {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn halves(b: &Block) -> [u64; 2] {
    [u64::from_le_bytes(b[..8].try_into().expect("8 bytes")), u64::from_le_bytes(b[8..].try_into().expect("8 bytes"))]
}

fn bytes(h: &[u64; 2]) -> Block {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&h[0].to_le_bytes());
    out[8..].copy_from_slice(&h[1].to_le_bytes());
    out
}

/// Analysis builds record every product and every share the masked S-box
/// computes, so Bombe can test each one for first-order leakage, not only
/// the state between layers (leakage.rs). A relaxed atomic load decides,
/// so the cost when nothing records is one load per value; normal builds
/// compile `note` to nothing.
#[cfg(feature = "analysis")]
mod record {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub static ON: AtomicBool = AtomicBool::new(false);
    thread_local! {
        pub static VALUES: RefCell<Option<Vec<u64>>> = const { RefCell::new(None) };
    }

    #[inline(always)]
    pub fn note(v: u64) {
        if ON.load(Ordering::Relaxed) {
            VALUES.with(|r| {
                if let Some(list) = r.borrow_mut().as_mut() {
                    list.push(v);
                }
            });
        }
    }
}

#[cfg(not(feature = "analysis"))]
mod record {
    #[inline(always)]
    pub fn note(_: u64) {}
}

use record::note;

/// A product in the field, recorded.
fn mul(a: u64, b: u64) -> u64 {
    let v = gf::mul8(a, b);
    note(v);
    v
}

/// A pair of shares, recorded.
fn noted(x: (u64, u64)) -> (u64, u64) {
    note(x.0);
    note(x.1);
    x
}

/// Ishai-Sahai-Wagner multiplication for two shares (Rivain-Prouff
/// Algorithm 1 with d = 1), in all eight byte lanes: c0 ^ c1 = (a0 ^ a1)(b0 ^ b1).
/// The masked cross term r ^ a0 b1 is formed first and fenced, so it cannot
/// be merged with a1 b0 into (a0 ^ a1)(b0 ^ b1) ^ a0 b0 ^ a1 b1, which
/// would depend on the secret product.
fn sec_mult(a: (u64, u64), b: (u64, u64), stream: &mut MaskStream) -> (u64, u64) {
    let r = stream.draw_u64();
    let cross = black_box(r ^ mul(a.0, b.1));
    note(cross);
    let r10 = cross ^ mul(a.1, b.0);
    note(r10);
    noted((mul(a.0, b.0) ^ r, mul(a.1, b.1) ^ r10))
}

/// RefreshMasks (Rivain-Prouff Algorithm 4, d = 1).
fn refresh(x: (u64, u64), stream: &mut MaskStream) -> (u64, u64) {
    let r = stream.draw_u64();
    noted((x.0 ^ r, x.1 ^ r))
}

fn square(x: (u64, u64)) -> (u64, u64) {
    noted((gf::square8(x.0), gf::square8(x.1)))
}

/// x^254 on shares: Rivain-Prouff Algorithm 3 (SecExp254) with d = 1.
fn sec_exp254(x: (u64, u64), stream: &mut MaskStream) -> (u64, u64) {
    let z = refresh(square(x), stream); // x^2
    let y = sec_mult(z, x, stream); // x^3
    let w = refresh(square(square(y)), stream); // x^12
    let y = sec_mult(y, w, stream); // x^15
    let y = square(square(square(square(y)))); // x^240
    let y = sec_mult(y, w, stream); // x^252
    sec_mult(y, z, stream) // x^254
}

/// out(inv(in(x))) on shares: the affine constants go into share 0 only.
fn masked_sbox8(x: (u64, u64), map_in: &Affine8, map_out: &Affine8, stream: &mut MaskStream) -> (u64, u64) {
    let a = noted((map_in.apply(x.0), map_in.apply(x.1) ^ map_in.apply(0)));
    let y = sec_exp254(a, stream);
    noted((map_out.apply(y.0), map_out.apply(y.1) ^ map_out.apply(0)))
}

/// The masked state: two shares, each as two 8-byte halves.
struct State {
    s: [[u64; 2]; 2],
}

impl State {
    fn sub_layer(&mut self, forward: bool, stream: &mut MaskStream) {
        let (map_in, map_out) = if forward { (&sbox::A_IN_8, &sbox::A_OUT_8) } else { (&sbox::A_OUT_INV_8, &sbox::A_IN_INV_8) };
        for half in 0..2 {
            let y = masked_sbox8((self.s[0][half], self.s[1][half]), map_in, map_out, stream);
            self.s[0][half] = y.0;
            self.s[1][half] = y.1;
        }
    }

    fn linear(&mut self, round: usize, forward: bool) {
        if let Some(layer) = structure::layer(round) {
            for share in self.s.iter_mut() {
                let b = bytes(share);
                *share = halves(&if forward { linear::apply_layer(layer, &b) } else { linear::invert_layer(layer, &b) });
            }
        }
    }

    fn add_key(&mut self, keys: &Shares, round: usize) {
        for (share, key) in self.s.iter_mut().zip(&keys.keys) {
            let k = halves(&key[round]);
            share[0] ^= k[0];
            share[1] ^= k[1];
        }
    }

    fn shares(&self) -> (Block, Block) {
        (bytes(&self.s[0]), bytes(&self.s[1]))
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.s.zeroize();
    }
}

/// Called after every S-box layer with the round number and both shares
/// (analysis builds, for Bombe's leakage tests).
type Probe<'a> = Option<&'a mut dyn FnMut(usize, &Block, &Block)>;

/// A Turing key held as shares, encrypting with first-order masking.
pub struct MaskedTuring {
    shares: SecretBox<Shares>,
    stream: MaskStream,
}

impl MaskedTuring {
    /// Expands `key`, splits every round key and the checksum into two
    /// random shares, and wipes the plain round keys and the stack the key
    /// schedule used. Fails closed without operating-system randomness.
    pub fn new(key: &[u8; 32]) -> Result<MaskedTuring, RandomnessError> {
        let m = MaskedTuring::with_stream(key, MaskStream::new()?);
        memory::burn_stack();
        Ok(m)
    }

    /// A masked cipher whose masks come from a fixed seed, so every run uses
    /// the same masks: masking with broken randomness, the control for
    /// Bombe's leakage tests. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn with_mask_seed(key: &[u8; 32], seed: &[u8; 64]) -> MaskedTuring {
        MaskedTuring::with_stream(key, MaskStream::from_seed(seed))
    }

    /// The stream was seeded by this process just before, so its draws
    /// need no process check.
    fn with_stream(key: &[u8; 32], mut stream: MaskStream) -> MaskedTuring {
        let plain = keyschedule::expand::<ROUND_KEYS>(key);
        let mut shares: SecretBox<Shares> = SecretBox::zeroed();
        for round in 0..ROUND_KEYS {
            let mask = stream.draw_block();
            shares.keys[0][round] = mask;
            shares.keys[1][round] = xor(plain.key(round), &mask);
        }
        shares.point = stream.draw_block();
        shares.point[0] |= 1;
        let mut sum = keyschedule::sealed_check(plain.keys(), &shares.point);
        let mask = stream.draw_block();
        shares.check = [mask, xor(&sum, &mask)];
        sum.zeroize();
        MaskedTuring { shares, stream }
    }

    /// Re-randomises every share (called on every operation, after the
    /// fork check).
    fn refresh(&mut self) {
        for round in 0..ROUND_KEYS {
            let mask = self.stream.draw_block();
            for share in self.shares.keys.iter_mut() {
                share[round] = xor(&share[round], &mask);
            }
        }
        let mask = self.stream.draw_block();
        for c in self.shares.check.iter_mut() {
            *c = xor(c, &mask);
        }
    }

    /// Checksum(share 0) ^ check 0 equals checksum(share 1) ^ check 1
    /// exactly when the shared keys match the shared checksum; each side is
    /// masked, so the comparison never handles an unmasked key value.
    /// The shared check carries keyschedule's CHECK_CONSTANT (in share 1),
    /// and the point must still be odd, so a reset fault on the point and
    /// both check shares no longer verifies (review of 2026-09-27).
    fn intact(&self) -> bool {
        let mut a = xor(&checksum(&self.shares.keys[0], &self.shares.point), &self.shares.check[0]);
        let mut b = xor(&xor(&checksum(&self.shares.keys[1], &self.shares.point), &self.shares.check[1]), &keyschedule::CHECK_CONSTANT);
        let diff = a.iter().zip(&b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        a.zeroize();
        b.zeroize();
        let even = !self.shares.point[0] & 1;
        (diff | even) == 0
    }

    fn encrypt_inner(&mut self, block: &mut Block, mut probe: Probe) {
        self.stream.check_fork();
        self.refresh();
        let mask = halves(&self.stream.draw_block());
        let data = halves(block);
        let mut st = State { s: [[data[0] ^ mask[0], data[1] ^ mask[1]], mask] };
        st.add_key(&self.shares, 0);
        for round in 1..=ROUNDS {
            st.sub_layer(true, &mut self.stream);
            if let Some(p) = probe.as_mut() {
                let (a, b) = st.shares();
                p(round, &a, &b);
            }
            if round < ROUNDS {
                st.linear(round, true);
            }
            st.add_key(&self.shares, round);
        }
        *block = bytes(&[st.s[0][0] ^ st.s[1][0], st.s[0][1] ^ st.s[1][1]]);
    }

    pub fn encrypt_block(&mut self, block: &mut Block) {
        self.encrypt_inner(block, None);
    }

    pub fn decrypt_block(&mut self, block: &mut Block) {
        self.stream.check_fork();
        self.refresh();
        let mask = halves(&self.stream.draw_block());
        let data = halves(block);
        let mut st = State { s: [[data[0] ^ mask[0], data[1] ^ mask[1]], mask] };
        for round in (1..=ROUNDS).rev() {
            st.add_key(&self.shares, round);
            if round < ROUNDS {
                st.linear(round, false);
            }
            st.sub_layer(false, &mut self.stream);
        }
        st.add_key(&self.shares, 0);
        *block = bytes(&[st.s[0][0] ^ st.s[1][0], st.s[0][1] ^ st.s[1][1]]);
    }

    /// Checks the shared key checksum, encrypts, decrypts the result and
    /// compares, and checks the checksum again; a fault anywhere wipes the
    /// block (as `Turing`'s checked calls, which explain the second check).
    pub fn encrypt_block_checked(&mut self, block: &mut Block) -> Result<(), FaultDetected> {
        let result = self.guarded(block, true, |_| {});
        memory::burn_stack();
        result
    }

    /// The same for decryption.
    pub fn decrypt_block_checked(&mut self, block: &mut Block) -> Result<(), FaultDetected> {
        let result = self.guarded(block, false, |_| {});
        memory::burn_stack();
        result
    }

    /// Never inlined: its frame, and the checksums', lie below the burn.
    #[inline(never)]
    fn guarded(&mut self, block: &mut Block, encrypt: bool, between: impl FnOnce(&mut MaskedTuring)) -> Result<(), FaultDetected> {
        if !self.intact() {
            block.zeroize();
            return Err(FaultDetected);
        }
        between(self);
        let mut input = *block;
        if encrypt {
            self.encrypt_block(block);
        } else {
            self.decrypt_block(block);
        }
        let mut check = *block;
        if encrypt {
            self.decrypt_block(&mut check);
        } else {
            self.encrypt_block(&mut check);
        }
        let diff = black_box(input.iter().zip(&check).fold(0u8, |acc, (a, b)| acc | (a ^ b)));
        input.zeroize();
        check.zeroize();
        if diff != 0 || !self.intact() {
            block.zeroize();
            return Err(FaultDetected);
        }
        Ok(())
    }

    /// `encrypt_block_checked` with `between` run after the first key check,
    /// where Bombe injects a fault. Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_block_checked_with(&mut self, block: &mut Block, between: impl FnOnce(&mut MaskedTuring)) -> Result<(), FaultDetected> {
        self.guarded(block, true, between)
    }

    /// Whether the operating system locked the key shares' memory.
    pub fn keys_locked(&self) -> bool {
        self.shares.locked()
    }

    /// What must never appear unshared: each round key (the XOR of its two
    /// shares), the checksum (likewise) and the point (the residue sweep).
    #[cfg(test)]
    pub(crate) fn secret_blocks(&self) -> Vec<Block> {
        let mut all: Vec<Block> = (0..ROUND_KEYS).map(|r| xor(&self.shares.keys[0][r], &self.shares.keys[1][r])).collect();
        all.extend([xor(&self.shares.check[0], &self.shares.check[1]), self.shares.point]);
        all
    }

    /// Whether the operating system left the key shares' memory out of core
    /// dumps (Linux and Android only; always false on Windows).
    pub fn keys_dump_excluded(&self) -> bool {
        self.shares.dump_excluded()
    }

    /// Encrypts, handing both shares to `probe` after every S-box layer.
    /// Analysis builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_probed(&mut self, block: &mut Block, probe: &mut dyn FnMut(usize, &Block, &Block)) {
        self.encrypt_inner(block, Some(probe));
    }

    /// Encrypts and returns every value the masked S-boxes computed, in
    /// order: each round's layer computes the same number of values, for its
    /// two halves in turn, each value holding eight byte lanes. Analysis
    /// builds only (feature `analysis`).
    #[cfg(feature = "analysis")]
    pub fn encrypt_recorded(&mut self, block: &mut Block) -> Vec<u64> {
        record::VALUES.with(|r| *r.borrow_mut() = Some(Vec::with_capacity(4096)));
        record::ON.store(true, std::sync::atomic::Ordering::Relaxed);
        self.encrypt_inner(block, None);
        record::VALUES.with(|r| r.borrow_mut().take()).unwrap_or_default()
    }

    /// Flips one bit of the first share of a stored round key, as a
    /// Rowhammer-style fault would. Tests and analysis builds only.
    #[cfg(any(test, feature = "analysis"))]
    pub fn flip_share_bit(&mut self, round: usize, bit: usize) {
        self.shares.keys[0][round][bit / 8] ^= 1 << (bit % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Turing;

    fn key(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ seed)
    }

    // The masked counterpart of keyschedule's reset_faults_are_caught: zeroing
    // the point and both check shares (with or without a round key's shares)
    // used to verify for any keys, since at H = 0 both checksums are 0.
    #[test]
    fn reset_faults_are_caught() {
        let fresh = || MaskedTuring::new(&key(9)).expect("OS randomness");
        let mut m = fresh();
        m.shares.point = [0; 16];
        assert!(!m.intact(), "point zeroed");
        let mut m = fresh();
        m.shares.point = [0; 16];
        m.shares.check = [[0; 16]; 2];
        assert!(!m.intact(), "point and both check shares zeroed");
        let mut m = fresh();
        m.shares.keys[0][24] = [0; 16];
        m.shares.keys[1][24] = [0; 16];
        m.shares.point = [0; 16];
        m.shares.check = [[0; 16]; 2];
        assert!(!m.intact(), "round key 24's shares, point and check zeroed");
        let mut m = fresh();
        m.shares.keys = [[[0; 16]; ROUND_KEYS]; 2];
        m.shares.point = [0; 16];
        m.shares.check = [[0; 16]; 2];
        assert!(!m.intact(), "all shares zeroed");
        let mut m = fresh();
        m.shares.keys = [[[0xff; 16]; ROUND_KEYS]; 2];
        m.shares.point = [0xff; 16];
        m.shares.check = [[0xff; 16]; 2];
        assert!(!m.intact(), "all shares stuck at one");
        let mut m = fresh();
        m.shares.point = [0; 16];
        m.shares.check = [[0; 16], keyschedule::CHECK_CONSTANT];
        assert!(!m.intact(), "point zeroed, check shares set to the public constant (needs the odd point)");
        assert!(fresh().intact(), "control: untouched shares verify");
    }

    // Every bit of both check shares and of the point is covered (a
    // comparison of 8 of 16 bytes passed every test until the review of
    // 2026-09-27).
    #[test]
    fn every_bit_of_the_check_shares_and_the_point_is_covered() {
        let mut m = MaskedTuring::new(&key(11)).expect("OS randomness");
        for bit in 0..128 {
            for target in 0..3 {
                let place = match target {
                    0 => &mut m.shares.check[0],
                    1 => &mut m.shares.check[1],
                    _ => &mut m.shares.point,
                };
                place[bit / 8] ^= 1 << (bit % 8);
                let caught = !m.intact();
                let place = match target {
                    0 => &mut m.shares.check[0],
                    1 => &mut m.shares.check[1],
                    _ => &mut m.shares.point,
                };
                place[bit / 8] ^= 1 << (bit % 8);
                assert!(caught, "bit {bit} of {}", ["check share 0", "check share 1", "the point"][target]);
            }
        }
        assert!(m.intact());
    }

    // A masked checked call leaves no half of its checksum point in dead
    // stack (research/reviews/2026-09-28 R4). Control: a copy of the point
    // in a callee's frame is found.
    #[test]
    fn checked_calls_leave_no_checksum_point_behind() {
        use crate::memory::residue::{contains, leave, run, snapshot, SCAN};
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(|| {
                let mut buf = vec![0u8; SCAN];
                for seed in 1..=5u8 {
                    let mut m = MaskedTuring::new(&key(seed)).expect("OS randomness");
                    let point = m.shares.point;
                    let found = |buf: &[u8]| contains(buf, &point[..8]) || contains(buf, &point[8..]);
                    run(&mut || leave(&point));
                    snapshot(&mut buf);
                    assert!(found(&buf), "control: a copy of the point in a callee's frame is found");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 16];
                        m.encrypt_block_checked(&mut b).expect("intact");
                        core::hint::black_box(&b);
                    });
                    snapshot(&mut buf);
                    assert!(!found(&buf), "encrypt_block_checked left the point (key {seed})");
                    crate::memory::burn_stack();
                    run(&mut || {
                        let mut b = [0x5au8; 16];
                        m.decrypt_block_checked(&mut b).expect("intact");
                        core::hint::black_box(&b);
                    });
                    snapshot(&mut buf);
                    assert!(!found(&buf), "decrypt_block_checked left the point (key {seed})");
                }
            })
            .expect("thread")
            .join()
            .expect("test thread");
    }

    #[test]
    fn masked_equals_plain() {
        for seed in 0..6u8 {
            let (plain, mut masked) = (Turing::new(&key(seed)), MaskedTuring::new(&key(seed)).unwrap());
            for i in 0..20u8 {
                let p: Block = core::array::from_fn(|k| (k as u8).wrapping_mul(i) ^ seed);
                let (mut a, mut b) = (p, p);
                plain.encrypt_block(&mut a);
                masked.encrypt_block(&mut b);
                assert_eq!(a, b, "encrypt, seed {seed}, block {i}");
                masked.decrypt_block(&mut b);
                assert_eq!(b, p, "decrypt, seed {seed}, block {i}");
            }
        }
    }

    // The shares change on every call while still encoding the same keys.
    #[test]
    fn shares_are_rerandomised() {
        let mut m = MaskedTuring::new(&key(1)).unwrap();
        let before = m.shares.keys[0][5];
        let mut b = [0u8; 16];
        m.encrypt_block(&mut b);
        assert_ne!(m.shares.keys[0][5], before);
        let plain = keyschedule::expand::<ROUND_KEYS>(&key(1));
        assert_eq!(xor(&m.shares.keys[0][5], &m.shares.keys[1][5]), *plain.key(5));
    }

    #[test]
    fn checked_calls_work_and_catch_corrupted_shares() {
        let mut m = MaskedTuring::new(&key(2)).unwrap();
        let mut b = [0x42u8; 16];
        let mut expected = b;
        Turing::new(&key(2)).encrypt_block(&mut expected);
        assert_eq!(m.encrypt_block_checked(&mut b), Ok(()));
        assert_eq!(b, expected);
        assert_eq!(m.decrypt_block_checked(&mut b), Ok(()));
        assert_eq!(b, [0x42u8; 16]);
        m.flip_share_bit(9, 77);
        let mut c = [0x42u8; 16];
        assert_eq!(m.encrypt_block_checked(&mut c), Err(FaultDetected));
        assert_eq!(c, [0u8; 16]);
        assert_eq!(m.decrypt_block_checked(&mut c), Err(FaultDetected));
    }

    // Share faults that left the public checksum Σ x^i · RK_i unchanged.
    #[test]
    fn two_bit_share_faults_are_caught() {
        for [(ra, ba), (rb, bb)] in [[(0, 1), (1, 0)], [(23, 1), (24, 0)], [(3, 40), (7, 36)]] {
            let mut m = MaskedTuring::new(&key(5)).unwrap();
            m.flip_share_bit(ra, ba);
            m.flip_share_bit(rb, bb);
            let mut b = [0x42u8; 16];
            assert_eq!(m.encrypt_block_checked(&mut b), Err(FaultDetected), "RK{ra} bit {ba}, RK{rb} bit {bb}");
            assert_eq!(b, [0u8; 16]);
        }
    }

    // Each masked cipher draws its own point; it is not the key's.
    #[test]
    fn the_checksum_point_is_drawn_at_random() {
        let (a, b) = (MaskedTuring::new(&key(6)).unwrap(), MaskedTuring::new(&key(6)).unwrap());
        assert_ne!(a.shares.point, b.shares.point);
        assert_eq!(a.shares.point[0] & 1, 1);
    }

    // A share that flips after the first check still inverts itself (both
    // directions use it) and is caught by the second check.
    #[test]
    fn a_share_flip_between_check_and_use_is_caught() {
        let mut m = MaskedTuring::new(&key(3)).unwrap();
        let mut b = [0x17u8; 16];
        assert_eq!(m.guarded(&mut b, true, |m| m.flip_share_bit(20, 3)), Err(FaultDetected));
        assert_eq!(b, [0u8; 16]);
        // Control: with the flipped share, encryption still inverts.
        let mut c = [0x17u8; 16];
        m.encrypt_block(&mut c);
        m.decrypt_block(&mut c);
        assert_eq!(c, [0x17u8; 16]);
    }

    // A fork on a system without MADV_WIPEONFORK, simulated by changing the
    // process ID the stream recorded: the next operation must reseed, so its
    // masks differ from those of a twin that was not "forked".
    #[test]
    fn a_new_process_id_makes_the_next_operation_reseed() {
        let seed = [6u8; 64];
        let mut twins = [MaskedTuring::with_stream(&key(4), MaskStream::from_seed(&seed)), MaskedTuring::with_stream(&key(4), MaskStream::from_seed(&seed))];
        twins[1].stream.pretend_other_process();
        let shares: Vec<Block> = twins
            .iter_mut()
            .map(|m| {
                let mut first = [0u8; 16];
                let mut probe = |round: usize, s0: &Block, _: &Block| {
                    if round == 1 {
                        first = *s0;
                    }
                };
                m.encrypt_inner(&mut [9u8; 16], Some(&mut probe));
                first
            })
            .collect();
        assert_ne!(shares[0], shares[1]);
    }

    // Control for the test above: identical twins draw identical masks.
    #[test]
    fn twins_from_one_seed_draw_the_same_masks() {
        let seed = [6u8; 64];
        let shares: Vec<Block> = (0..2)
            .map(|_| {
                let mut m = MaskedTuring::with_stream(&key(4), MaskStream::from_seed(&seed));
                let mut first = [0u8; 16];
                let mut probe = |round: usize, s0: &Block, _: &Block| {
                    if round == 1 {
                        first = *s0;
                    }
                };
                m.encrypt_inner(&mut [9u8; 16], Some(&mut probe));
                first
            })
            .collect();
        assert_eq!(shares[0], shares[1]);
    }

    // The secure multiplication and the chain compute the right values.
    #[test]
    fn masked_inversion_is_inversion() {
        let mut stream = MaskStream::from_seed(&[3; 64]);
        for x in 0..=255u8 {
            let mask = stream.u64();
            let xs = gf::broadcast(x);
            let (y0, y1) = sec_exp254((xs ^ mask, mask), &mut stream);
            assert_eq!(y0 ^ y1, gf::broadcast(gf::inv(x)), "x = {x}");
        }
    }
}
