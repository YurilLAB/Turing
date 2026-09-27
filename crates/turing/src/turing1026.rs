//! Turing-1026: a post-quantum key-encapsulation mechanism on plain LWE in
//! dimension 1026 (docs/16).
//!
//! The hard problem is standard, unstructured LWE, the most conservative of
//! the lattice assumptions (no ring or module structure). What is Turing's
//! own is everything around it, each part chosen with the attack-cost and
//! exact decryption-failure computations of docs/16:
//!
//! - Parameters: n = 1026, q = 2^15, secrets and noise CBD(18) (standard
//!   deviation 3), S is 1026 x 32, S' is 8 x 1026, one message bit per
//!   coefficient of the 8 x 32 matrix C: a 256-bit message.
//! - Sizes: public key 61,592 bytes, ciphertext 15,934 bytes, secret key a
//!   32-byte seed, shared key 32 bytes (a Turing or Turing-256 key).
//! - Hashing: cSHAKE256 under "Turing-1026 v1 ..." labels, one per use.
//! - Transform: Fujisaki-Okamoto with implicit rejection, salted, with the
//!   public key's hash in the coins and in the rejection key:
//!
//! ```text
//! encapsulate  mu, salt random
//!              (r, k) = G(H(pk), mu, salt);  c = Enc(pk, mu; r) || salt;  K = KDF(c, k)
//! decapsulate  mu' = Dec(sk, c);  (r', k') = G(H(pk), mu', salt)
//!              K = KDF(c, k')                  if Enc(pk, mu'; r') = c
//!              K = KDF_reject(z, H(pk), c)     otherwise, indistinguishably
//! ```
//!
//!   Salted FrodoKEM puts the salt into both keys, FO_M (Krämer, Struck and
//!   Weishäupl) puts H(pk) into the rejection key, and every secret comes
//!   from one seed (Schmieg); docs/16 says what each buys.
//!
//! EXPERIMENTAL. Do not use this to protect real data.

use crate::cipher::FaultDetected;
use crate::linear::opaque;
use crate::lwe::{self, Params, SEED_A_BYTES};
use crate::memory::{SecretBox, Zeroable};
use crate::random::{self, RandomnessError};
use crate::xof::{self, SecretXof};
use sha3::digest::XofReader;
use zeroize::Zeroize;

pub const PARAMS: Params = Params { n: 1026, nbar: 32, mbar: 8, log_q: 15, eta: 18 };
const N: usize = PARAMS.n;
const NBAR: usize = PARAMS.nbar;
const MBAR: usize = PARAMS.mbar;
const LOG_Q: u32 = PARAMS.log_q;

/// The secret key: everything secret is derived from it.
pub const SEED_BYTES: usize = 32;
pub const SALT_BYTES: usize = 64;
pub const SHARED_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = PARAMS.public_key_bytes();
pub const CIPHERTEXT_BYTES: usize = PKE_BYTES + SALT_BYTES;

const MESSAGE_BYTES: usize = PARAMS.message_bytes();
const HASH_BYTES: usize = 32;
/// The seed of the encryption noise (S', E', E''), then k.
const COIN_SEED_BYTES: usize = 64;
const COINS_BYTES: usize = COIN_SEED_BYTES + 32;
const B_PRIME_BYTES: usize = PARAMS.packed_bytes(MBAR * N);
const PKE_BYTES: usize = PARAMS.ciphertext_bytes();

const _: () = assert!(MESSAGE_BYTES == 32 && PUBLIC_KEY_BYTES == 61_592 && CIPHERTEXT_BYTES == 15_934);
// Every packed bit belongs to a coefficient, so packing is a bijection and
// comparing packed bytes compares coefficients.
const _: () = assert!((N * NBAR * LOG_Q as usize).is_multiple_of(8) && (MBAR * N * LOG_Q as usize).is_multiple_of(8));
const _: () = assert!((MBAR * NBAR * LOG_Q as usize).is_multiple_of(8));

const KEY_GENERATION_LABEL: &str = "Turing-1026 v1 key generation";
const KEY_NOISE_LABEL: &str = "Turing-1026 v1 key noise";
const PUBLIC_KEY_LABEL: &str = "Turing-1026 v1 public key";
const KEY_CHECK_LABEL: &str = "Turing-1026 v1 key check";
const ENCAPSULATION_LABEL: &str = "Turing-1026 v1 encapsulation";
const COINS_LABEL: &str = "Turing-1026 v1 coins";
const ENCRYPTION_NOISE_LABEL: &str = "Turing-1026 v1 encryption noise";
const SHARED_KEY_LABEL: &str = "Turing-1026 v1 shared key";
const REJECTION_KEY_LABEL: &str = "Turing-1026 v1 rejection key";

/// A public key or ciphertext of the wrong length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthError;

/// Why a new key pair could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGenError {
    /// The operating system supplied no randomness.
    Randomness,
    /// The pair-wise consistency check failed: the key was corrupted while
    /// it was being made.
    Fault,
}

/// The secret scratch of one encapsulation or decapsulation, in its own
/// locked allocation, wiped when dropped.
struct Workspace {
    mu: [u8; MESSAGE_BYTES],
    coins: [u8; COINS_BYTES],
    sp: [u16; MBAR * N],
    bp: [u16; MBAR * N],
    c: [u16; MBAR * NBAR],
    /// The (re-)encryption, packed.
    packed: [u8; PKE_BYTES],
    /// The accepted key, before the selection (decapsulation).
    key: [u8; SHARED_KEY_BYTES],
}

impl Zeroize for Workspace {
    fn zeroize(&mut self) {
        self.mu.zeroize();
        self.coins.zeroize();
        self.sp.zeroize();
        self.bp.zeroize();
        self.c.zeroize();
        self.packed.zeroize();
        self.key.zeroize();
    }
}

// SAFETY: integer arrays only; all zeroes is a valid value.
unsafe impl Zeroable for Workspace {}

/// A Turing-1026 public key: seed_a (32 bytes), then B packed.
pub struct EncapsulationKey {
    bytes: Box<[u8]>,
    seed_a: [u8; SEED_A_BYTES],
    b: Box<[u16]>,
    /// H(pk): cSHAKE256(pk, "Turing-1026 v1 public key").
    hash: [u8; HASH_BYTES],
}

impl EncapsulationKey {
    /// Every byte string of the right length is a public key: each 15-bit
    /// field is a valid coefficient, and no bit is left over.
    pub fn from_bytes(bytes: &[u8]) -> Result<EncapsulationKey, LengthError> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(LengthError);
        }
        let mut b = vec![0u16; N * NBAR].into_boxed_slice();
        lwe::unpack(LOG_Q, &bytes[SEED_A_BYTES..], &mut b);
        let seed_a = bytes[..SEED_A_BYTES].try_into().expect("32 bytes");
        Ok(EncapsulationKey::assemble(bytes.into(), seed_a, b))
    }

    fn assemble(bytes: Box<[u8]>, seed_a: [u8; SEED_A_BYTES], b: Box<[u16]>) -> EncapsulationKey {
        let mut hash = [0u8; HASH_BYTES];
        xof::cshake256(PUBLIC_KEY_LABEL, &bytes).read(&mut hash);
        EncapsulationKey { bytes, seed_a, b, hash }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A fresh ciphertext and the shared key it carries. The message and salt
    /// come from a 64-byte OS seed through cSHAKE256, as `random::new_key`
    /// does for keys; the stack is burned afterwards.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>), RandomnessError> {
        let result = self.encapsulated();
        crate::memory::burn_stack();
        result
    }

    #[inline(never)]
    fn encapsulated(&self) -> Result<(Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>), RandomnessError> {
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        let mut salt = [0u8; SALT_BYTES];
        {
            let mut seed: SecretBox<[u8; 64]> = SecretBox::zeroed();
            random::os_random(&mut seed[..])?;
            let mut x = SecretXof::new(ENCAPSULATION_LABEL);
            x.absorb(&seed[..]);
            x.squeeze(&mut w.mu);
            x.squeeze(&mut salt);
        }
        Ok(self.encapsulate_in(&salt, &mut w))
    }

    /// Encapsulation with a chosen message and salt, for known-answer tests
    /// and Bombe; like `encapsulate`, it burns the stack afterwards.
    /// Analysis builds only.
    #[cfg(any(test, feature = "analysis"))]
    pub fn encapsulate_with(&self, mu: &[u8; MESSAGE_BYTES], salt: &[u8; SALT_BYTES]) -> (Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>) {
        let out = self.encapsulate_fixed(mu, salt);
        crate::memory::burn_stack();
        out
    }

    /// `encapsulate_with` without the stack burn, so Bombe can measure how
    /// deep encapsulation goes. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn encapsulate_with_no_burn(&self, mu: &[u8; MESSAGE_BYTES], salt: &[u8; SALT_BYTES]) -> (Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>) {
        self.encapsulate_fixed(mu, salt)
    }

    /// The same, for the self-test.
    pub(crate) fn encapsulate_fixed(&self, mu: &[u8; MESSAGE_BYTES], salt: &[u8; SALT_BYTES]) -> (Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>) {
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        w.mu = *mu;
        self.encapsulate_in(salt, &mut w)
    }

    fn encapsulate_in(&self, salt: &[u8; SALT_BYTES], w: &mut Workspace) -> (Vec<u8>, SecretBox<[u8; SHARED_KEY_BYTES]>) {
        self.encrypt_message(salt, w);
        let mut ciphertext = Vec::with_capacity(CIPHERTEXT_BYTES);
        ciphertext.extend_from_slice(&w.packed);
        ciphertext.extend_from_slice(salt);
        let mut key: SecretBox<[u8; SHARED_KEY_BYTES]> = SecretBox::zeroed();
        shared_key(&ciphertext, &w.coins[COIN_SEED_BYTES..], &mut key);
        (ciphertext, key)
    }

    /// The deterministic encryption of w.mu: (r, k) = G(H(pk), mu, salt) into
    /// w.coins, then Enc(pk, mu; r), packed into w.packed.
    fn encrypt_message(&self, salt: &[u8; SALT_BYTES], w: &mut Workspace) {
        let mut g = SecretXof::new(COINS_LABEL);
        g.absorb(&self.hash);
        g.absorb(&w.mu);
        g.absorb(salt);
        g.squeeze(&mut w.coins);
        drop(g);
        let mut noise = SecretXof::new(ENCRYPTION_NOISE_LABEL);
        noise.absorb(&w.coins[..COIN_SEED_BYTES]);
        let Workspace { mu, sp, bp, c, packed, .. } = w;
        lwe::encrypt(&PARAMS, &self.seed_a, &self.b, mu, &mut noise, sp, bp, c);
        let (packed_bp, packed_c) = packed.split_at_mut(B_PRIME_BYTES);
        lwe::pack(LOG_Q, bp, packed_bp);
        lwe::pack(LOG_Q, c, packed_c);
    }
}

/// K = cSHAKE256(c || k, "Turing-1026 v1 shared key"): the whole ciphertext,
/// salt included, and k, which carries H(pk) and the message.
fn shared_key(ciphertext: &[u8], k: &[u8], out: &mut [u8; SHARED_KEY_BYTES]) {
    let mut h = SecretXof::new(SHARED_KEY_LABEL);
    h.absorb(ciphertext);
    h.absorb(k);
    h.squeeze(out);
}

/// `eq_mask`, for Bombe's timing test of the re-encryption check. Analysis
/// builds only.
#[cfg(feature = "analysis")]
pub fn eq_mask_for_timing(a: &[u8], b: &[u8]) -> u8 {
    eq_mask(a, b)
}

/// 0xff if the slices are equal, else 0. Every byte is read whatever the
/// contents, and the verdict passes through a value barrier, so the compiler
/// cannot turn the selection it drives into a branch.
fn eq_mask(a: &[u8], b: &[u8]) -> u8 {
    assert_eq!(a.len(), b.len());
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    (opaque(u64::from(diff)).wrapping_sub(1) >> 8) as u8
}

struct Secret {
    seed: [u8; SEED_BYTES],
    /// S, n x nbar, entries mod 2^16.
    s: [u16; N * NBAR],
    /// The rejection secret.
    z: [u8; 32],
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.s.zeroize();
        self.z.zeroize();
    }
}

// SAFETY: integer arrays only; all zeroes is a valid value.
unsafe impl Zeroable for Secret {}

/// A Turing-1026 key pair. Only the 32-byte seed needs storing: `from_seed`
/// rebuilds everything from it, and the decapsulator never accepts the
/// expanded secret from outside (single-seed keys, docs/16). The expansion
/// lives in its own locked memory and is wiped when dropped.
pub struct DecapsulationKey {
    secret: SecretBox<Secret>,
    public: EncapsulationKey,
}

impl DecapsulationKey {
    /// A new key pair from a fresh 256-bit seed (`random::new_key`).
    pub fn generate() -> Result<DecapsulationKey, KeyGenError> {
        let seed = random::new_key().map_err(|_| KeyGenError::Randomness)?;
        DecapsulationKey::from_seed(&seed).map_err(|_| KeyGenError::Fault)
    }

    /// Expands the seed: (seed_a, noise seed, z) = cSHAKE256(seed), S and E
    /// from the noise seed, B = A S + E. Then encapsulates to the new public
    /// key with coins derived from the seed and decapsulates (a pair-wise
    /// consistency check: a key corrupted while being made, as Rowhammer did
    /// to FrodoKEM, fails here instead of failing decryptions later). The
    /// stack is burned afterwards.
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Result<DecapsulationKey, FaultDetected> {
        let dk = DecapsulationKey::expanded(seed);
        let consistent = dk.pair_consistent();
        crate::memory::burn_stack();
        if consistent {
            Ok(dk)
        } else {
            Err(FaultDetected)
        }
    }

    /// The expansion alone, without the pair-wise check (the self-test
    /// compares against known answers instead).
    #[inline(never)]
    pub(crate) fn expanded(seed: &[u8; SEED_BYTES]) -> DecapsulationKey {
        let mut secret: SecretBox<Secret> = SecretBox::zeroed();
        secret.seed.copy_from_slice(seed);
        let mut derived: SecretBox<[u8; 96]> = SecretBox::zeroed();
        xof::cshake256_secret(KEY_GENERATION_LABEL, seed, &mut derived[..]);
        let seed_a: [u8; SEED_A_BYTES] = derived[..SEED_A_BYTES].try_into().expect("32 bytes");
        secret.z.copy_from_slice(&derived[64..]);
        let mut noise = SecretXof::new(KEY_NOISE_LABEL);
        noise.absorb(&derived[32..64]);
        drop(derived);
        // B holds A S, which gives S away, until E is added: secret memory.
        let mut b: SecretBox<[u16; N * NBAR]> = SecretBox::zeroed();
        lwe::keygen(&PARAMS, &seed_a, &mut noise, &mut secret.s, &mut b[..]);
        drop(noise);
        let mut bytes = vec![0u8; PUBLIC_KEY_BYTES].into_boxed_slice();
        bytes[..SEED_A_BYTES].copy_from_slice(&seed_a);
        lwe::pack(LOG_Q, &b[..], &mut bytes[SEED_A_BYTES..]);
        let public = EncapsulationKey::assemble(bytes, seed_a, b[..].into());
        DecapsulationKey { secret, public }
    }

    fn pair_consistent(&self) -> bool {
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        let mut salt = [0u8; SALT_BYTES];
        let mut x = SecretXof::new(KEY_CHECK_LABEL);
        x.absorb(&self.secret.seed);
        x.squeeze(&mut w.mu);
        x.squeeze(&mut salt);
        drop(x);
        let (ciphertext, key) = self.public.encapsulate_in(&salt, &mut w);
        drop(w);
        let back = self.decapsulated(&ciphertext);
        eq_mask(&key[..], &back[..]) == 0xff
    }

    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.public
    }

    /// The seed: the one thing to store.
    pub fn seed(&self) -> &[u8; SEED_BYTES] {
        &self.secret.seed
    }

    /// Whether the operating system locked the secret's memory.
    pub fn keys_locked(&self) -> bool {
        self.secret.locked()
    }

    /// The shared key a ciphertext carries. A ciphertext of the right length
    /// always gives a key: one that fails the re-encryption check gives the
    /// rejection key cSHAKE256(z || H(pk) || c), which looks random to anyone
    /// without z, so the caller learns nothing from the key itself. The
    /// check, the hashes and the selection take the same time either way.
    /// Only a wrong length is an error. The stack is burned afterwards.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBox<[u8; SHARED_KEY_BYTES]>, LengthError> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(LengthError);
        }
        let key = self.decapsulated(ciphertext);
        crate::memory::burn_stack();
        Ok(key)
    }

    #[inline(never)]
    fn decapsulated(&self, ciphertext: &[u8]) -> SecretBox<[u8; SHARED_KEY_BYTES]> {
        let (body, salt) = ciphertext.split_at(PKE_BYTES);
        let salt: &[u8; SALT_BYTES] = salt.try_into().expect("64 bytes");
        let mut received_bp = vec![0u16; MBAR * N];
        let mut received_c = [0u16; MBAR * NBAR];
        lwe::unpack(LOG_Q, &body[..B_PRIME_BYTES], &mut received_bp);
        lwe::unpack(LOG_Q, &body[B_PRIME_BYTES..], &mut received_c);
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        lwe::decrypt(&PARAMS, &self.secret.s, &received_bp, &received_c, &mut w.mu);
        self.public.encrypt_message(salt, &mut w);
        let accept = eq_mask(&w.packed, body);
        // Default-fail order: the output is the rejection key unless the
        // mask installs the accepted one, so a skipped instruction leaves it
        // rejecting (the pqm4 fault attacks skipped the final copy).
        let mut key: SecretBox<[u8; SHARED_KEY_BYTES]> = SecretBox::zeroed();
        let mut h = SecretXof::new(REJECTION_KEY_LABEL);
        h.absorb(&self.secret.z);
        h.absorb(&self.public.hash);
        h.absorb(ciphertext);
        h.squeeze(&mut key[..]);
        drop(h);
        let Workspace { coins, key: accepted, .. } = &mut *w;
        shared_key(ciphertext, &coins[COIN_SEED_BYTES..], accepted);
        for (out, &k) in key.iter_mut().zip(accepted.iter()) {
            *out ^= (*out ^ k) & accept;
        }
        key
    }

    /// S. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn secret_matrix(&self) -> &[u16] {
        &self.secret.s
    }

    /// z. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn rejection_secret(&self) -> &[u8; 32] {
        &self.secret.z
    }

    /// Where the expanded secret (seed, S, z) lives, as (address, bytes), so
    /// Bombe's memory scan knows where key material belongs. Analysis builds
    /// only.
    #[cfg(feature = "analysis")]
    pub fn secret_memory(&self) -> (usize, usize) {
        (&*self.secret as *const Secret as usize, core::mem::size_of::<Secret>())
    }

    /// `from_seed` with one bit of S flipped between the expansion and the
    /// pair-wise check, as a fault during key generation would. Analysis
    /// builds only.
    #[cfg(feature = "analysis")]
    pub fn from_seed_with_fault(seed: &[u8; SEED_BYTES], entry: usize, bit: u32) -> Result<DecapsulationKey, FaultDetected> {
        let mut dk = DecapsulationKey::expanded(seed);
        dk.secret.s[entry] ^= 1 << bit;
        let consistent = dk.pair_consistent();
        crate::memory::burn_stack();
        if consistent {
            Ok(dk)
        } else {
            Err(FaultDetected)
        }
    }

    /// `decapsulate` without the stack burn, so Bombe can measure how deep
    /// decapsulation goes. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn decapsulate_no_burn(&self, ciphertext: &[u8]) -> Result<SecretBox<[u8; SHARED_KEY_BYTES]>, LengthError> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(LengthError);
        }
        Ok(self.decapsulated(ciphertext))
    }

    /// `from_seed` without the stack burn (and without the pair-wise check),
    /// so Bombe can show what key generation leaves behind. Analysis builds
    /// only.
    #[cfg(feature = "analysis")]
    pub fn from_seed_without_stack_burn(seed: &[u8; SEED_BYTES]) -> DecapsulationKey {
        DecapsulationKey::expanded(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> DecapsulationKey {
        DecapsulationKey::from_seed(&[seed; 32]).expect("consistent")
    }

    #[test]
    fn sizes() {
        let dk = key(1);
        assert_eq!(dk.encapsulation_key().as_bytes().len(), 61_592);
        let (ct, _) = dk.encapsulation_key().encapsulate().expect("randomness");
        assert_eq!(ct.len(), 15_934);
    }

    #[test]
    fn decapsulation_recovers_the_key() {
        let dk = key(2);
        for _ in 0..3 {
            let (ct, k) = dk.encapsulation_key().encapsulate().expect("randomness");
            assert_eq!(dk.decapsulate(&ct).expect("length")[..], k[..]);
        }
    }

    // Any change to the ciphertext, salt included, gives the rejection key
    // cSHAKE256(z || H(pk) || c'), not the real one.
    #[test]
    fn tampering_gives_the_rejection_key() {
        let dk = key(3);
        let (ct, k) = dk.encapsulation_key().encapsulate_with(&[7; 32], &[8; 64]);
        for position in [0, 1, 7_000, B_PRIME_BYTES - 1, B_PRIME_BYTES, PKE_BYTES - 1, PKE_BYTES, CIPHERTEXT_BYTES - 1] {
            let mut bad = ct.clone();
            bad[position] ^= 0x10;
            let got = dk.decapsulate(&bad).expect("length");
            assert_ne!(got[..], k[..], "byte {position}");
            let mut expected = [0u8; 32];
            let mut h = SecretXof::new(REJECTION_KEY_LABEL);
            h.absorb(&dk.secret.z);
            h.absorb(&dk.public.hash);
            h.absorb(&bad);
            h.squeeze(&mut expected);
            assert_eq!(got[..], expected, "byte {position}");
        }
    }

    #[test]
    fn wrong_lengths_are_refused() {
        let dk = key(4);
        assert_eq!(dk.decapsulate(&[0u8; CIPHERTEXT_BYTES - 1]).err(), Some(LengthError));
        assert_eq!(dk.decapsulate(&[0u8; CIPHERTEXT_BYTES + 1]).err(), Some(LengthError));
        assert!(EncapsulationKey::from_bytes(&[0u8; PUBLIC_KEY_BYTES - 1]).is_err());
        let pk = EncapsulationKey::from_bytes(dk.encapsulation_key().as_bytes()).expect("length");
        let (ct, k) = pk.encapsulate_with(&[1; 32], &[2; 64]);
        assert_eq!(dk.decapsulate(&ct).expect("length")[..], k[..]);
    }

    #[test]
    fn the_seed_determines_everything() {
        let (a, b) = (key(5), key(5));
        assert_eq!(a.encapsulation_key().as_bytes(), b.encapsulation_key().as_bytes());
        assert_eq!(a.seed(), &[5; 32]);
        assert_ne!(key(6).encapsulation_key().as_bytes(), a.encapsulation_key().as_bytes());
        let (c1, k1) = a.encapsulation_key().encapsulate_with(&[9; 32], &[9; 64]);
        let (c2, k2) = b.encapsulation_key().encapsulate_with(&[9; 32], &[9; 64]);
        assert_eq!((c1, &k1[..]), (c2, &k2[..]));
    }

    // The same message under another salt, or another public key, gives an
    // unrelated ciphertext and key.
    #[test]
    fn salt_and_public_key_enter_the_key() {
        let (a, b) = (key(7), key(8));
        let (ca, ka) = a.encapsulation_key().encapsulate_with(&[1; 32], &[0; 64]);
        let (cs, ks) = a.encapsulation_key().encapsulate_with(&[1; 32], &[1; 64]);
        let (cb, kb) = b.encapsulation_key().encapsulate_with(&[1; 32], &[0; 64]);
        assert_ne!(ca[..PKE_BYTES], cs[..PKE_BYTES]);
        assert_ne!(ka[..], ks[..]);
        assert_ne!(ca, cb);
        assert_ne!(ka[..], kb[..]);
    }

    #[test]
    fn eq_mask_is_all_or_nothing() {
        assert_eq!(eq_mask(&[1, 2, 3], &[1, 2, 3]), 0xff);
        for i in 0..3 {
            for bit in 0..8 {
                let mut b = [1u8, 2, 3];
                b[i] ^= 1 << bit;
                assert_eq!(eq_mask(&[1, 2, 3], &b), 0);
            }
        }
        assert_eq!(eq_mask(&[0; 5], &[0xff; 5]), 0);
    }
}
