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
    /// The first selection's result (decapsulation), read by the second.
    tmp: [u8; SHARED_KEY_BYTES],
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
        self.tmp.zeroize();
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
            x.wipe();
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
    /// w.coins, then Enc(pk, mu; r) into w.sp/bp/c, packed into w.packed.
    fn encrypt_message(&self, salt: &[u8; SALT_BYTES], w: &mut Workspace) {
        self.derive_coins(salt, w);
        self.reencrypt(w);
        self.pack_reencryption(w);
    }

    /// (r, k) = G(H(pk), mu, salt) into w.coins.
    fn derive_coins(&self, salt: &[u8; SALT_BYTES], w: &mut Workspace) {
        let mut g = SecretXof::new(COINS_LABEL);
        g.absorb(&self.hash);
        g.absorb(&w.mu);
        g.absorb(salt);
        g.squeeze(&mut w.coins);
        g.wipe();
    }

    /// Enc(pk, mu; r) into w.sp/bp/c, r the seed in w.coins. Deterministic in
    /// (mu, coins), so calling it twice recomputes the same B', C from scratch:
    /// decapsulation does, into the same buffers, so the two re-encryption
    /// checks read values from two independent computations. A transient fault
    /// in one computation cannot then fool the other's comparison.
    fn reencrypt(&self, w: &mut Workspace) {
        let mut noise = SecretXof::new(ENCRYPTION_NOISE_LABEL);
        noise.absorb(&w.coins[..COIN_SEED_BYTES]);
        let Workspace { mu, sp, bp, c, .. } = w;
        lwe::encrypt(&PARAMS, &self.seed_a, &self.b, mu, &mut noise, sp, bp, c);
        noise.wipe();
    }

    /// Pack w.bp, w.c into w.packed.
    fn pack_reencryption(&self, w: &mut Workspace) {
        let Workspace { bp, c, packed, .. } = w;
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
    h.wipe();
}

/// out = candidate if `mask` is 0xff, else out unchanged; byte by byte,
/// branch-free. Never inlined, and the mask passes a value barrier, so the
/// compiler can neither fuse decapsulation's two chained selections into one
/// (algebraically they are `out ^= (out ^ k) & (a & b)`: one mask, one fault)
/// nor learn that a mask is 0 or 0xff. The release build did fuse them, into
/// one `sar` (research/reviews/2026-09-28 R2); `tools/ct_check.py` now checks
/// the machine code.
#[inline(never)]
fn select_into(out: &mut [u8; SHARED_KEY_BYTES], candidate: &[u8; SHARED_KEY_BYTES], mask: u8) {
    let mask = opaque(u64::from(mask)) as u8;
    for (o, &c) in out.iter_mut().zip(candidate) {
        *o ^= (*o ^ c) & mask;
    }
}

/// k'' = k' xor (K-bar and not `accept`): k' itself when the re-encryption
/// matched (`accept` = 0xff), otherwise k' masked with the rejection key,
/// which only the holder of z can compute. A fault that forces both
/// selections to install the accepted key then releases cSHAKE256(c || k''),
/// useless to the attacker, unless a third fault also forces this verdict.
/// Never inlined, the verdict behind a value barrier.
#[inline(never)]
fn bind_to_verdict(k: &mut [u8], rejection: &[u8; SHARED_KEY_BYTES], accept: u8) {
    let reject = !(opaque(u64::from(accept)) as u8);
    for (x, &r) in k.iter_mut().zip(rejection) {
        *x ^= r & reject;
    }
}

/// `eq_mask`, for Bombe's timing test of the re-encryption check. Analysis
/// builds only.
#[cfg(feature = "analysis")]
pub fn eq_mask_for_timing(a: &[u8], b: &[u8]) -> u8 {
    eq_mask(a, b)
}

/// 0xff if `diff` is zero, else 0, in constant time and independent of the
/// accumulator's width: only diff == 0 makes `diff - 1` borrow into bit 63,
/// for any `diff` below 2^63 (both callers accumulate far less). The earlier
/// `(diff - 1) >> 8` form was correct only for a byte difference, whose
/// `diff - 1` never reaches bit 8; a 16-bit difference does (diff = 257 gave
/// 0x01, neither 0 nor 0xff), so both callers now share this.
fn zero_mask(diff: u64) -> u8 {
    0u8.wrapping_sub((opaque(diff).wrapping_sub(1) >> 63) as u8)
}

/// 0xff if the byte slices are equal, else 0. Every byte is read whatever the
/// contents, and the verdict passes through a value barrier, so the compiler
/// cannot turn the selection it drives into a branch.
fn eq_mask(a: &[u8], b: &[u8]) -> u8 {
    assert_eq!(a.len(), b.len());
    zero_mask(u64::from(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))))
}

/// The same for u16 slices: 0xff if equal, else 0.
fn eq_mask_u16(a: &[u16], b: &[u16]) -> u8 {
    assert_eq!(a.len(), b.len());
    zero_mask(u64::from(a.iter().zip(b).fold(0u16, |acc, (x, y)| acc | (x ^ y))))
}

/// Hooks for injecting transient faults into decapsulation, so the fault
/// analysis (Bombe's `fault1026`) runs on the real decapsulation code rather
/// than a copy that could drift from it. In production the only implementor
/// is the zero-sized `NoFault`, whose methods are the identity and compile
/// away, so `decapsulate` is exactly `decapsulated_faulted(.., &NoFault)`.
/// Every method is a place a glitch could strike, one per item of the fault
/// model in docs/16. The two instantiations compile separately, so what the
/// optimiser does to the production one is checked on its machine code
/// (`tools/ct_check.py`), not by this map: it once fused the verdicts that
/// the hooks here keep apart (R2).
trait DecapFault {
    /// The decoded message mu' = Dec(sk, c), before re-encryption (shared by
    /// both re-encryptions, so a fault here fails both checks: a rejection).
    fn message(&self, _mu: &mut [u8]) {}
    /// The coins (rho' || k') = G(h, mu', salt) (also shared).
    fn coins(&self, _coins: &mut [u8]) {}
    /// The coefficients B', C of one re-encryption before they are read, `pass`
    /// 1 (compared as packed bytes) or 2 (compared as coefficients). The two
    /// passes are independent computations, so this is where the user-found
    /// single-fault bypass would strike: faulting one pass is caught by the
    /// other; only faulting both (a correlated pair) bypasses.
    fn intermediate(&self, _pass: u8, _bp: &mut [u16], _c: &mut [u16]) {}
    /// The packed first re-encryption that the byte comparison reads.
    fn reencryption(&self, _packed: &mut [u8]) {}
    /// The verdict of the packed-byte comparison (first re-encryption).
    fn accept_packed(&self, mask: u8) -> u8 {
        mask
    }
    /// The verdict of the coefficient comparison (second re-encryption).
    fn accept_coeffs(&self, mask: u8) -> u8 {
        mask
    }
    /// The third verdict (second re-encryption, packed and compared as
    /// bytes), which binds the accepted key to the comparison.
    fn accept_binding(&self, mask: u8) -> u8 {
        mask
    }
    /// Whether to skip absorbing z into the rejection key (an XOF-state
    /// fault that would make the rejection key independent of the secret).
    fn skip_rejection_z(&self) -> bool {
        false
    }
    /// The rejection key K-bar, after it is derived.
    fn rejection_key(&self, _key: &mut [u8]) {}
    /// The accepted key K', after it is derived.
    fn accepted_key(&self, _key: &mut [u8]) {}
    /// Whether to skip the final masked selection (the copy pqm4 faults
    /// skipped); default-fail order means a skip leaves the rejection key.
    fn skip_selection(&self) -> bool {
        false
    }
}

/// No fault: the production path. Every hook is the identity and inlines to
/// nothing, so decapsulation's machine code is unchanged.
struct NoFault;
impl DecapFault for NoFault {}

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
    /// from the noise seed, B = A S + E. Then two checks, each of which
    /// refuses a key corrupted while it was made (as Rowhammer corrupted
    /// FrodoKEM's, Fahr et al., CCS 2022): B - A S must be small noise
    /// (deterministic: it catches every change of S, `lwe::check_key`), and
    /// an encapsulation to the new public key with coins derived from the
    /// seed must decapsulate (the whole pipeline, z included). The stack
    /// is burned afterwards.
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Result<DecapsulationKey, FaultDetected> {
        let dk = DecapsulationKey::from_seed_below_the_burn(seed);
        crate::memory::burn_stack();
        dk
    }

    /// The work of `from_seed`, in a frame of its own: `burn_stack` reaches
    /// only frames below its caller, and with the expansion and the checks
    /// inlined into `from_seed` the key check's cSHAKE state stayed in
    /// `from_seed`'s own frame, where one inverse permutation gave the seed
    /// back (research/reviews/2026-09-28 R1).
    #[inline(never)]
    fn from_seed_below_the_burn(seed: &[u8; SEED_BYTES]) -> Result<DecapsulationKey, FaultDetected> {
        let dk = DecapsulationKey::expanded(seed);
        if dk.checks_pass() {
            Ok(dk)
        } else {
            Err(FaultDetected)
        }
    }

    /// Both key checks, each computed whatever the other says.
    fn checks_pass(&self) -> bool {
        let key_matches = lwe::check_key(&PARAMS, &self.public.seed_a, &self.secret.s, &self.public.b);
        let pair = self.pair_consistent();
        key_matches & pair
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
        noise.wipe();
        let mut bytes = vec![0u8; PUBLIC_KEY_BYTES].into_boxed_slice();
        bytes[..SEED_A_BYTES].copy_from_slice(&seed_a);
        lwe::pack(LOG_Q, &b[..], &mut bytes[SEED_A_BYTES..]);
        let public = EncapsulationKey::assemble(bytes, seed_a, b[..].into());
        DecapsulationKey { secret, public }
    }

    /// The pair-wise check. Never inlined, and its XOF is wiped in place:
    /// `drop(x)` here once wiped a moved copy and left the state, which had
    /// absorbed the seed, in the caller's frame (R1).
    #[inline(never)]
    fn pair_consistent(&self) -> bool {
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        let mut salt = [0u8; SALT_BYTES];
        let mut x = SecretXof::new(KEY_CHECK_LABEL);
        x.absorb(&self.secret.seed);
        x.squeeze(&mut w.mu);
        x.squeeze(&mut salt);
        x.wipe();
        let (ciphertext, key) = self.public.encapsulate_in(&salt, &mut w);
        salt.zeroize();
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
        self.decapsulated_faulted(ciphertext, &NoFault)
    }

    /// Decapsulation with fault hooks. `NoFault` is the production path and
    /// compiles to the same code; the analysis-only `decapsulate_with_faults`
    /// drives the other implementors.
    ///
    /// The re-encryption is computed twice, independently, and compared three
    /// ways: the first run as packed bytes (`eq_mask`), the second as
    /// coefficients B', C (`eq_mask_u16`) and, packed again, as bytes. The
    /// output starts as the rejection key K-bar, and two chained selections,
    /// separate non-inlined calls with their masks behind value barriers,
    /// install the accepted key only if the first two verdicts both accept;
    /// the third binds the accepted key itself to the comparison (it is
    /// cSHAKE256(c || k' xor K-bar) unless the third verdict accepts). So:
    /// - a fault on one re-encryption's data is caught by the other run;
    /// - forcing one verdict, or skipping the selection, still rejects;
    /// - forcing both selection verdicts releases a key derived with K-bar,
    ///   which needs z: useless to the attacker;
    /// - a bypass takes both runs' data (two correlated faults), or all
    ///   three verdicts (three).
    ///
    /// Bombe's fault map checks each case; `tools/ct_check.py` checks that
    /// the release build keeps the selections apart (it had fused them into
    /// one mask, research/reviews/2026-09-28 R2). The cost is a second
    /// re-encryption, decapsulation's main work done twice.
    #[inline(never)]
    fn decapsulated_faulted(&self, ciphertext: &[u8], fault: &impl DecapFault) -> SecretBox<[u8; SHARED_KEY_BYTES]> {
        let (body, salt) = ciphertext.split_at(PKE_BYTES);
        let salt: &[u8; SALT_BYTES] = salt.try_into().expect("64 bytes");
        let mut received_bp = vec![0u16; MBAR * N];
        let mut received_c = [0u16; MBAR * NBAR];
        lwe::unpack(LOG_Q, &body[..B_PRIME_BYTES], &mut received_bp);
        lwe::unpack(LOG_Q, &body[B_PRIME_BYTES..], &mut received_c);
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        lwe::decrypt(&PARAMS, &self.secret.s, &received_bp, &received_c, &mut w.mu);
        fault.message(&mut w.mu);
        self.public.derive_coins(salt, &mut w);
        fault.coins(&mut w.coins);
        // First re-encryption, compared as packed bytes.
        self.public.reencrypt(&mut w);
        {
            let Workspace { bp, c, .. } = &mut *w;
            fault.intermediate(1, bp, c);
        }
        self.public.pack_reencryption(&mut w);
        fault.reencryption(&mut w.packed);
        let accept_bytes = fault.accept_packed(eq_mask(&w.packed, body));
        // A second, independent re-encryption into the same buffers, compared
        // as coefficients: reads a separate computation from the first.
        self.public.reencrypt(&mut w);
        {
            let Workspace { bp, c, .. } = &mut *w;
            fault.intermediate(2, bp, c);
        }
        let accept_coeffs = fault.accept_coeffs(eq_mask_u16(&w.bp, &received_bp) & eq_mask_u16(&w.c, &received_c));
        // The third verdict: the second run packed and compared as bytes.
        self.public.pack_reencryption(&mut w);
        let accept_binding = fault.accept_binding(eq_mask(&w.packed, body));
        // Default-fail order: the output is the rejection key unless both
        // selections install the accepted one, so a skipped instruction or a
        // forced mask leaves it rejecting (the pqm4 fault attacks skipped the
        // final copy; forcing one comparison is the accept-mask fault).
        let mut key: SecretBox<[u8; SHARED_KEY_BYTES]> = SecretBox::zeroed();
        let mut h = SecretXof::new(REJECTION_KEY_LABEL);
        if !fault.skip_rejection_z() {
            h.absorb(&self.secret.z);
        }
        h.absorb(&self.public.hash);
        h.absorb(ciphertext);
        h.squeeze(&mut key[..]);
        h.wipe();
        fault.rejection_key(&mut key[..]);
        let Workspace { coins, key: accepted, tmp, .. } = &mut *w;
        bind_to_verdict(&mut coins[COIN_SEED_BYTES..], &key, accept_binding);
        shared_key(ciphertext, &coins[COIN_SEED_BYTES..], accepted);
        fault.accepted_key(accepted);
        if !fault.skip_selection() {
            // tmp = accepted key if the byte comparison accepts, else K-bar;
            // out = tmp if the coefficient comparison accepts, else K-bar.
            tmp.copy_from_slice(&key[..]);
            select_into(tmp, accepted, accept_bytes);
            select_into(&mut key, tmp, accept_coeffs);
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
        let pass = dk.checks_pass();
        crate::memory::burn_stack();
        if pass {
            Ok(dk)
        } else {
            Err(FaultDetected)
        }
    }

    /// `from_seed_with_fault` with only the pair-wise check, as key
    /// generation was before the review of 2026-09-28 (R5), so Bombe can
    /// show the faults it missed. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn from_seed_with_fault_pairwise_only(seed: &[u8; SEED_BYTES], entry: usize, bit: u32) -> Result<DecapsulationKey, FaultDetected> {
        let mut dk = DecapsulationKey::expanded(seed);
        dk.secret.s[entry] ^= 1 << bit;
        let pass = dk.pair_consistent();
        crate::memory::burn_stack();
        if pass {
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

    /// Decapsulation with a set of transient faults injected, for the fault
    /// analysis. The faults run on the real decapsulation code path (through
    /// the same hooks `NoFault` leaves inert), and several at once model a
    /// correlated multi-fault attack. No stack burn. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn decapsulate_with_faults(&self, ciphertext: &[u8], faults: &[Fault]) -> Result<SecretBox<[u8; SHARED_KEY_BYTES]>, LengthError> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(LengthError);
        }
        Ok(self.decapsulated_faulted(ciphertext, &Faults(faults)))
    }

    /// The shared key decapsulation would return for `ciphertext` if the
    /// re-encryption check accepted it: K' = X("shared key", c || k'),
    /// k' from G(h, Dec(sk, c), salt). This is what a fault that defeats the
    /// check leaks; the fault map compares against it to tell an FO bypass
    /// (the check defeated, the bare decryption exposed) from a mere denial
    /// of service. Analysis builds only.
    #[cfg(feature = "analysis")]
    pub fn accepted_key_for(&self, ciphertext: &[u8]) -> [u8; SHARED_KEY_BYTES] {
        assert_eq!(ciphertext.len(), CIPHERTEXT_BYTES);
        let (body, salt) = ciphertext.split_at(PKE_BYTES);
        let salt: &[u8; SALT_BYTES] = salt.try_into().expect("64 bytes");
        let mut received_bp = vec![0u16; MBAR * N];
        let mut received_c = [0u16; MBAR * NBAR];
        lwe::unpack(LOG_Q, &body[..B_PRIME_BYTES], &mut received_bp);
        lwe::unpack(LOG_Q, &body[B_PRIME_BYTES..], &mut received_c);
        let mut w: SecretBox<Workspace> = SecretBox::zeroed();
        lwe::decrypt(&PARAMS, &self.secret.s, &received_bp, &received_c, &mut w.mu);
        self.public.encrypt_message(salt, &mut w);
        let mut out = [0u8; SHARED_KEY_BYTES];
        shared_key(ciphertext, &w.coins[COIN_SEED_BYTES..], &mut out);
        out
    }
}

/// Where a transient fault strikes decapsulation, one per hook of
/// `DecapFault`. Analysis builds only.
#[cfg(feature = "analysis")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    /// The decoded message mu' before re-encryption.
    Message,
    /// The coins (rho' || k').
    Coins,
    /// The coefficients B', C of the first re-encryption, before they are
    /// packed and compared as bytes.
    Intermediate1,
    /// The coefficients B', C of the second re-encryption, before they are
    /// compared as coefficients.
    Intermediate2,
    /// The packed first re-encryption the byte comparison reads.
    Reencryption,
    /// The verdict of the packed-byte comparison.
    AcceptBytes,
    /// The verdict of the coefficient comparison.
    AcceptCoeffs,
    /// The third verdict, which binds the accepted key to the comparison.
    AcceptBinding,
    /// Absorbing the secret z into the rejection key (skipped).
    RejectionZ,
    /// The rejection key K-bar.
    RejectionKey,
    /// The accepted key K'.
    AcceptedKey,
    /// The final masked selection (skipped).
    Selection,
}

/// Which coefficient matrix of a re-encryption an `AddCoeff` fault hits.
#[cfg(feature = "analysis")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matrix {
    /// B' (mbar x n).
    Bp,
    /// C (mbar x nbar).
    C,
}

/// One transient fault. Analysis builds only.
#[cfg(feature = "analysis")]
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// Flip bit `bit` of byte `byte` of a byte-buffer point (Message, Coins,
    /// Reencryption, RejectionKey, AcceptedKey).
    FlipBit(FaultPoint, usize, u32),
    /// Add `delta` (mod q) to coefficient `index` of B' or C of a
    /// re-encryption (Intermediate1, Intermediate2): the coefficient-level
    /// fault that can force a re-encryption to match a chosen ciphertext.
    AddCoeff(FaultPoint, Matrix, usize, u16),
    /// Force a verdict mask (AcceptBytes, AcceptCoeffs) to this value: 0xff
    /// accepts, 0 rejects.
    Verdict(FaultPoint, u8),
    /// Skip a step (RejectionZ, Selection).
    Skip(FaultPoint),
}

#[cfg(feature = "analysis")]
struct Faults<'a>(&'a [Fault]);

#[cfg(feature = "analysis")]
impl Faults<'_> {
    fn flip(&self, point: FaultPoint, buf: &mut [u8]) {
        for f in self.0 {
            if let Fault::FlipBit(p, byte, bit) = *f {
                if p == point {
                    buf[byte] ^= 1u8 << bit;
                }
            }
        }
    }
    fn verdict(&self, point: FaultPoint, mask: u8) -> u8 {
        self.0
            .iter()
            .find_map(|f| match f {
                Fault::Verdict(p, v) if *p == point => Some(*v),
                _ => None,
            })
            .unwrap_or(mask)
    }
    fn skip(&self, point: FaultPoint) -> bool {
        self.0.iter().any(|f| matches!(f, Fault::Skip(p) if *p == point))
    }
    fn add_coeff(&self, point: FaultPoint, bp: &mut [u16], c: &mut [u16]) {
        let mask = (1u16 << LOG_Q) - 1;
        for f in self.0 {
            if let Fault::AddCoeff(p, m, i, d) = *f {
                if p == point {
                    let buf = match m {
                        Matrix::Bp => &mut *bp,
                        Matrix::C => &mut *c,
                    };
                    buf[i] = buf[i].wrapping_add(d) & mask;
                }
            }
        }
    }
}

#[cfg(feature = "analysis")]
impl DecapFault for Faults<'_> {
    fn message(&self, mu: &mut [u8]) {
        self.flip(FaultPoint::Message, mu);
    }
    fn coins(&self, coins: &mut [u8]) {
        self.flip(FaultPoint::Coins, coins);
    }
    fn intermediate(&self, pass: u8, bp: &mut [u16], c: &mut [u16]) {
        self.add_coeff(if pass == 1 { FaultPoint::Intermediate1 } else { FaultPoint::Intermediate2 }, bp, c);
    }
    fn reencryption(&self, packed: &mut [u8]) {
        self.flip(FaultPoint::Reencryption, packed);
    }
    fn accept_packed(&self, mask: u8) -> u8 {
        self.verdict(FaultPoint::AcceptBytes, mask)
    }
    fn accept_coeffs(&self, mask: u8) -> u8 {
        self.verdict(FaultPoint::AcceptCoeffs, mask)
    }
    fn accept_binding(&self, mask: u8) -> u8 {
        self.verdict(FaultPoint::AcceptBinding, mask)
    }
    fn skip_rejection_z(&self) -> bool {
        self.skip(FaultPoint::RejectionZ)
    }
    fn rejection_key(&self, key: &mut [u8]) {
        self.flip(FaultPoint::RejectionKey, key);
    }
    fn accepted_key(&self, key: &mut [u8]) {
        self.flip(FaultPoint::AcceptedKey, key);
    }
    fn skip_selection(&self) -> bool {
        self.skip(FaultPoint::Selection)
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

    // No secret sponge (key generation, key noise, the key check, the
    // encapsulation seed, coins, encryption noise, the shared and the
    // rejection key) leaves its state in dead stack after key generation,
    // encapsulation or decapsulation. research/reviews/2026-09-28 R1: the key
    // check's state did, whole, and one inverse permutation of it gave the
    // seed, the whole private key. Every state is recorded as it is wiped
    // (test builds) and searched for; control: a state copied into a
    // callee's frame is found.
    #[test]
    fn no_sponge_state_is_left_on_the_stack() {
        use crate::memory::residue::{contains_state, leave, run, snapshot, SCAN};
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(|| {
                let mut buf = vec![0u8; SCAN];
                let planted: [u64; 25] = core::array::from_fn(|i| 0x7475_7269_6e67_0000 ^ ((i as u64) << 8));
                run(&mut || leave(&planted));
                snapshot(&mut buf);
                assert!(contains_state(&buf, &planted), "control: a state in a callee's frame is found");

                let mut searched = 0;
                let mut check = |name: &str, op: &mut dyn FnMut()| {
                    crate::memory::burn_stack();
                    xof::recorded::start();
                    run(op);
                    snapshot(&mut buf);
                    let states = xof::recorded::stop();
                    assert!(!states.is_empty(), "{name}: no sponge state was recorded");
                    for (i, st) in states.iter().enumerate() {
                        assert!(!contains_state(&buf, st), "{name}: sponge state {i} of {} is in dead stack", states.len());
                    }
                    searched += states.len();
                };
                let mut kept = None;
                check("from_seed", &mut || kept = Some(DecapsulationKey::from_seed(&[0x42; 32]).expect("consistent")));
                let dk = kept.take().expect("key");
                check("generate", &mut || kept = Some(DecapsulationKey::generate().expect("keygen")));
                let mut encapsulated = None;
                check("encapsulate", &mut || encapsulated = Some(dk.encapsulation_key().encapsulate().expect("randomness")));
                let (ct, k) = encapsulated.take().expect("ciphertext");
                let mut back = None;
                check("decapsulate", &mut || back = Some(dk.decapsulate(&ct).expect("length")));
                assert_eq!(back.take().expect("key")[..], k[..]);
                let mut bad = ct.clone();
                bad[100] ^= 1;
                check("decapsulate (rejected)", &mut || back = Some(dk.decapsulate(&bad).expect("length")));
                assert!(searched >= 15, "only {searched} states searched");
            })
            .expect("thread")
            .join()
            .expect("test thread");
    }

    // Single-bit faults in S that the one-ciphertext pair-wise check missed
    // (found by sampling 3,000 flips of seed [0x3c; 32], research/reviews/
    // 2026-09-28 R5): the pair-wise check alone still passes them (the
    // control), and the key check now refuses every one.
    #[test]
    fn faults_the_pair_wise_check_missed_are_caught() {
        let seed = [0x3cu8; 32];
        let clean = DecapsulationKey::expanded(&seed);
        assert!(clean.checks_pass(), "control: the key as made passes both checks");
        // (entry = 32 * row + column, bit)
        for (entry, bit) in [(24_960, 12), (5_507, 0), (25_638, 8), (4_126, 0), (2_324, 3), (657, 14), (658, 14), (651, 14)] {
            let mut dk = DecapsulationKey::expanded(&seed);
            dk.secret.s[entry] ^= 1 << bit;
            assert!(dk.pair_consistent(), "control: the pair-wise check alone misses S[{entry}] bit {bit}");
            assert!(!lwe::check_key(&PARAMS, &dk.public.seed_a, &dk.secret.s, &dk.public.b), "S[{entry}] bit {bit} passed the key check");
            assert!(!dk.checks_pass(), "S[{entry}] bit {bit} passed");
        }
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

    // The u16 mask must be exactly 0 or 0xff for every difference, including
    // ones whose OR reaches bit 8 or higher: the earlier `>> 8` form returned
    // 0x01 for a coefficient difference of 257 and other partial bytes for
    // larger ones, which the chained selection could have leaked bits through.
    #[test]
    fn eq_mask_u16_is_all_or_nothing() {
        assert_eq!(eq_mask_u16(&[1, 2, 3], &[1, 2, 3]), 0xff);
        assert_eq!(eq_mask_u16(&[0], &[257]), 0, "diff 257 (the >> 8 bug)");
        // Every single-coefficient difference, across the whole 16-bit range.
        for base in [0u16, 0x1234, 0x7fff, 0x8000, 0xffff] {
            for bit in 0..16 {
                assert_eq!(eq_mask_u16(&[base], &[base ^ (1 << bit)]), 0, "base {base:#x} bit {bit}");
            }
        }
        // Differences whose OR is a value with a nonzero high byte.
        for diff in [0x0100u16, 0x0101, 0x00ff, 0x0200, 0xff00, 0xffff] {
            assert_eq!(eq_mask_u16(&[0], &[diff]), 0, "diff {diff:#x}");
        }
    }
}
