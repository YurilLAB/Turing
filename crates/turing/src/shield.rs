//! A key at rest in memory, shielded the way OpenSSH has shielded private
//! keys since version 8.1 (2019). There it is "against speculation and memory
//! side-channel attacks like Spectre, Meltdown and Rambleed": the key is
//! kept XORed with a mask derived from a large random "prekey" (16 KB).
//! RAMBleed reads memory bit by bit through Rowhammer, and Spectre-style
//! leaks are slow and noisy. Such an attacker must recover all 16,416 bytes
//! (prekey and shielded key) with high accuracy, as OpenSSH puts it, rather
//! than strictly without error: each bit still unknown doubles the
//! candidates for the key, each testable against a known plaintext and
//! ciphertext at the cost of a 16 KB cSHAKE256 and a key setup, and a wrong
//! bit in an unknown place multiplies them by about 131,000. A few bad bits
//! can be searched; with 256 unknown, the search is no faster than guessing
//! the key.
//!
//! The key is unshielded only inside `cipher` and `masked`, into a locked
//! allocation of its own (`with_key`) that is wiped straight after the key
//! schedule has run, and the stack below it is burned (memory.rs). `refresh` replaces the prekey and
//! re-masks by XORing in the combined mask difference, so the plain key
//! never appears.

use crate::masked::MaskedTuring;
use crate::memory::{self, SecretBox};
use crate::random::{os_random, RandomnessError};
use crate::{xof, Turing};
use core::hint::black_box;


/// The prekey size OpenSSH uses (16 KB).
pub const PREKEY_BYTES: usize = 16 * 1024;
const SHIELD_LABEL: &str = "Turing v2 key shield";

/// The mask, written straight into the caller's buffer. It must never be
/// returned by value: a returned array is moved through the caller's own
/// frame, above the part of the stack that `burn_stack` reaches, and mask
/// XOR shielded key is the key. Until the review of 2026-09-27 it was, and
/// `new` and `refresh` each left a whole mask in dead stack
/// (bombe tests/memory.rs, shield_mask_is_nowhere_in_memory).
fn mask_into(prekey: &[u8; PREKEY_BYTES], out: &mut [u8; 32]) {
    xof::cshake256_secret(SHIELD_LABEL, prekey, out);
}

/// A fresh locked, wiped-on-drop buffer holding the mask.
fn mask(prekey: &[u8; PREKEY_BYTES]) -> SecretBox<[u8; 32]> {
    let mut m: SecretBox<[u8; 32]> = SecretBox::zeroed();
    mask_into(prekey, &mut m);
    m
}

pub struct ShieldedKey {
    prekey: SecretBox<[u8; PREKEY_BYTES]>,
    shielded: SecretBox<[u8; 32]>,
}

impl ShieldedKey {
    /// Shields `key` under a fresh random prekey; the caller should wipe its
    /// own copy of `key` afterwards. Fails closed without OS randomness.
    pub fn new(key: &[u8; 32]) -> Result<ShieldedKey, RandomnessError> {
        let mut prekey: SecretBox<[u8; PREKEY_BYTES]> = SecretBox::zeroed();
        os_random(&mut prekey[..])?;
        let m = mask(&prekey);
        let mut shielded: SecretBox<[u8; 32]> = SecretBox::zeroed();
        for (s, (k, mk)) in shielded.iter_mut().zip(key.iter().zip(m.iter())) {
            *s = k ^ mk;
        }
        drop(m);
        memory::burn_stack();
        Ok(ShieldedKey { prekey, shielded })
    }

    /// Runs `f` on the unshielded key, then wipes it. The mask and the key
    /// live only in locked memory that is wiped when dropped.
    fn with_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        let m = mask(&self.prekey);
        let mut key: SecretBox<[u8; 32]> = SecretBox::zeroed();
        for (k, (s, mk)) in key.iter_mut().zip(self.shielded.iter().zip(m.iter())) {
            *k = s ^ mk;
        }
        drop(m);
        let out = f(&key);
        drop(key);
        memory::burn_stack();
        out
    }

    /// An ordinary cipher for this key (round keys in locked memory).
    pub fn cipher(&self) -> Turing {
        self.with_key(Turing::new)
    }

    /// A masked cipher for this key.
    pub fn masked(&self) -> Result<MaskedTuring, RandomnessError> {
        self.with_key(MaskedTuring::new)
    }

    /// Replaces the prekey and re-masks the key. The old and new masks are
    /// combined first and that difference is XORed in, so no intermediate
    /// value is the key itself.
    pub fn refresh(&mut self) -> Result<(), RandomnessError> {
        let mut fresh: SecretBox<[u8; PREKEY_BYTES]> = SecretBox::zeroed();
        os_random(&mut fresh[..])?;
        let (old, new) = (mask(&self.prekey), mask(&fresh));
        let mut delta: SecretBox<[u8; 32]> = SecretBox::zeroed();
        for (d, (o, n)) in delta.iter_mut().zip(old.iter().zip(new.iter())) {
            *d = black_box(o ^ n);
        }
        drop((old, new));
        for (s, d) in self.shielded.iter_mut().zip(delta.iter()) {
            *s ^= d;
        }
        drop(delta);
        self.prekey = fresh;
        memory::burn_stack();
        Ok(())
    }

    /// Writes the current mask into `out`, for Bombe's memory scan: the mask
    /// is a secret the key scans cannot recognise (it is neither the key nor
    /// a key-schedule value), yet mask XOR shielded key is the key. Analysis
    /// builds only.
    #[cfg(feature = "analysis")]
    pub fn mask_for_analysis(&self, out: &mut [u8; 32]) {
        mask_into(&self.prekey, out);
    }

    /// Whether the operating system locked both allocations.
    pub fn locked(&self) -> bool {
        self.prekey.locked() && self.shielded.locked()
    }

    /// Whether the operating system left both allocations out of core dumps
    /// (Linux and Android only; always false on Windows).
    pub fn dump_excluded(&self) -> bool {
        self.prekey.dump_excluded() && self.shielded.dump_excluded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shielded_key_encrypts_like_the_key() {
        let key = [0x3cu8; 32];
        let mut s = ShieldedKey::new(&key).unwrap();
        let mut expected = [7u8; 16];
        Turing::new(&key).encrypt_block(&mut expected);
        let mut b = [7u8; 16];
        s.cipher().encrypt_block(&mut b);
        assert_eq!(b, expected);
        let before = *s.shielded;
        s.refresh().unwrap();
        assert_ne!(*s.shielded, before, "the stored bytes change");
        let mut c = [7u8; 16];
        s.masked().unwrap().encrypt_block(&mut c);
        assert_eq!(c, expected, "and still hold the same key");
    }

    // What sits in memory is neither the key nor anything simple of it.
    #[test]
    fn memory_does_not_hold_the_key() {
        let key = [0x11u8; 32];
        let s = ShieldedKey::new(&key).unwrap();
        assert_ne!(*s.shielded, key);
        assert!(s.prekey.windows(32).all(|w| w != key));
    }
}
