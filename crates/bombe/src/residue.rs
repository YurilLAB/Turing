//! Where key material is left in memory: the memory-dump attacker
//! (memscan.rs) run against each way of holding a Turing key. The secrets
//! searched for are the key, the whitened key K' (which determines every
//! round key and is never meant to be stored), the Feistel states of the key
//! schedule at each round-key pair (with K' they give the round keys), and
//! all 25 round keys. A hit is expected only where a secret is meant to
//! live: the caller's own key buffer, and a plain `Turing`'s locked round-key
//! page. Anything else, a dead stack frame or a freed heap block, is
//! residue.

use crate::memscan::{self, Hit, Needles, Parker, Scan};
use std::sync::atomic::{AtomicUsize, Ordering};
use turing::keyschedule::KEY_LABEL;
use turing::memory::{burn_stack, SecretBox};
use turing::structure::ROUND_KEYS;
use turing::{random, xof, Block, MaskedTuring, ShieldedKey, Turing};

/// One scan in one scenario.
pub struct Snapshot {
    pub scenario: &'static str,
    /// Fragments found where the secrets belong.
    pub expected: usize,
    /// Fragments found anywhere else.
    pub stray: Vec<Hit>,
    /// Of the stray fragments, how many were in the stack of the thread that
    /// ran the code.
    pub on_stack: usize,
    pub scanned_bytes: usize,
    /// Secret names of the stray fragments, deduplicated.
    pub stray_secrets: Vec<String>,
    /// Where each stray fragment was: the setup thread's stack, the scanning
    /// thread's stack, or the kind of region.
    pub stray_places: Vec<String>,
}

impl Snapshot {
    pub fn clean(&self) -> bool {
        self.stray.is_empty()
    }
}

/// The caller's key (from `turing::random::new_key`, so the OS generator
/// holds no copy of it) and the search list for everything derived from it.
struct Secrets {
    key: SecretBox<[u8; 32]>,
    needles: Needles,
    round_keys: std::ops::Range<usize>,
}

fn xor(a: &[u8], b: &[u8]) -> SecretBox<[u8; 16]> {
    let mut out: SecretBox<[u8; 16]> = SecretBox::zeroed();
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b)) {
        *o = x ^ y;
    }
    out
}

/// Not inlined, so its frame is below the caller's and the caller's
/// `burn_stack` wipes what computing the search list left there.
#[inline(never)]
fn secrets() -> Secrets {
    let key = random::new_key().expect("OS randomness");
    let mut needles = Needles::new();
    needles.add("key", &key[..]);
    let mut whitened: SecretBox<[u8; 32]> = SecretBox::zeroed();
    xof::cshake256_secret(KEY_LABEL, &key[..], &mut whitened[..]);
    needles.add("whitened key K'", &whitened[..]);
    let t = Turing::new(&key);
    for pair in 0..ROUND_KEYS.div_ceil(2) {
        needles.add(&format!("Feistel L at pair {pair}"), &xor(t.round_key(2 * pair), &whitened[..16])[..]);
        if 2 * pair + 1 < ROUND_KEYS {
            needles.add(&format!("Feistel R at pair {pair}"), &xor(t.round_key(2 * pair + 1), &whitened[16..])[..]);
        }
    }
    let first = needles.secrets();
    for i in 0..ROUND_KEYS {
        needles.add(&format!("round key {i}"), t.round_key(i));
    }
    let round_keys = first..needles.secrets();
    Secrets { key, needles, round_keys }
}

fn page_of(address: usize) -> (usize, usize) {
    (address & !4095, 4096)
}

fn snapshot(scenario: &'static str, s: &Secrets, scan: &Scan, allowed: &[(usize, usize)], stack: usize) -> Snapshot {
    let stray = scan.outside(allowed);
    let on_stack = stray.iter().filter(|h| h.base == stack && stack != 0).count();
    let here = 0u8;
    let own_stack = memscan::region_of(core::hint::black_box(&here) as *const u8 as usize).map_or(0, |r| r.base);
    let mut stray_secrets: Vec<String> = stray.iter().map(|h| s.needles.name(h.secret).to_string()).collect();
    stray_secrets.sort();
    stray_secrets.dedup();
    let stray_places = stray
        .iter()
        .map(|h| match h.base {
            b if b == stack && stack != 0 => format!("{} at {:#x}: setup thread's stack", s.needles.name(h.secret), h.address),
            b if b == own_stack => format!("{} at {:#x}: scanning thread's stack", s.needles.name(h.secret), h.address),
            _ => format!("{} at {:#x}: {} region based at {:#x}", s.needles.name(h.secret), h.address, h.kind, h.base),
        })
        .collect();
    Snapshot { scenario, expected: scan.hits.len() - stray.len(), stray, on_stack, scanned_bytes: scan.bytes, stray_secrets, stray_places }
}

/// The key buffer's address range: where the caller keeps the key.
fn key_range(s: &Secrets) -> (usize, usize) {
    (s.key.as_ptr() as usize, 32)
}

/// Control: a random secret planted in an ordinary heap buffer is found
/// there and nowhere else. Returns (hits, all four found at the address).
pub fn planted() -> (usize, bool) {
    let mut needles = Needles::new();
    let key = random::new_key().expect("OS randomness");
    let mut planted = Box::new([0u8; 64]); // on the heap
    planted[16..48].copy_from_slice(&key[..]);
    needles.add("planted", &key[..]);
    drop(key);
    let scan = memscan::scan(&needles);
    let at = planted.as_ptr() as usize + 16;
    let found_there = scan.hits.iter().filter(|h| h.address >= at && h.address < at + 32).count();
    (scan.hits.len(), found_there == 4)
}

/// Copies the key into a local and returns without wiping it. The copy sits
/// at the bottom of a 4 KB frame, below the few hundred bytes that parking
/// uses in an unoptimised build, where atomics are real calls.
#[inline(never)]
fn careless_copy(key: &[u8; 32]) {
    let mut frame = [0u8; 4096];
    frame[..32].copy_from_slice(key);
    core::hint::black_box(&frame);
}

/// Control: a copy of the key left in a dead stack frame by the worker is
/// found in the worker's stack; with `burn`, `burn_stack` runs after the
/// careless copy and nothing is left.
pub fn stack_plant(burn: bool) -> Snapshot {
    let s = secrets();
    burn_stack();
    let name = if burn { "a key copy in a dead stack frame, then burn_stack" } else { "control: a key copy left in a dead stack frame" };
    memscan::run_parked(
        |p: &Parker| {
            careless_copy(&s.key);
            if burn {
                burn_stack();
            }
            p.park(1);
        },
        1,
        |_, stack| snapshot(name, &s, &memscan::scan(&s.needles), &[key_range(&s)], stack),
    )
    .remove(0)
}

/// Keys fresh from the OS generator, scanned for copies outside their own
/// buffer: with `derived` false the key is the generator's raw output, with
/// `derived` true it comes from `turing::random::new_key`. Returns how many
/// of `runs` keys left a copy, and the fragments found.
pub fn generator_copies(derived: bool, runs: usize) -> (usize, usize) {
    let (mut dirty, mut fragments) = (0, 0);
    for _ in 0..runs {
        let key = if derived {
            random::new_key().expect("OS randomness")
        } else {
            let mut k: SecretBox<[u8; 32]> = SecretBox::zeroed();
            random::os_random(&mut k[..]).expect("OS randomness");
            k
        };
        let mut needles = Needles::new();
        needles.add("key", &key[..]);
        let at = key.as_ptr() as usize;
        let stray = memscan::scan(&needles).outside(&[(at, 32)]).len();
        dirty += usize::from(stray > 0);
        fragments += stray;
    }
    (dirty, fragments)
}

/// `Turing::new` (or the control without the stack burn), scanned straight
/// away, before later calls reuse the stack it left; then after some
/// encryptions and checked calls; then after the cipher is dropped.
pub fn plain(burn: bool) -> Vec<Snapshot> {
    let s = secrets();
    burn_stack();
    let keys_at = AtomicUsize::new(0);
    let names = if burn {
        ["Turing::new, scanned at once", "then encryptions and checked calls", "after the Turing is dropped"]
    } else {
        ["Turing::new without the stack burn, scanned at once", "then encryptions and checked calls", "after drop"]
    };
    memscan::run_parked(
        |p: &Parker| {
            let t = if burn { Turing::new(&s.key) } else { Turing::new_without_stack_burn(&s.key) };
            keys_at.store(t.round_key(0).as_ptr() as usize, Ordering::Release);
            p.park(1);
            let mut b: Block = [0x5a; 16];
            for _ in 0..3 {
                t.encrypt_block(&mut b);
            }
            let _ = t.encrypt_block_checked(&mut b);
            let _ = t.decrypt_block_checked(&mut b);
            t.decrypt_block(&mut b);
            p.park(2);
            drop(t);
            p.park(3);
        },
        3,
        |step, stack| {
            let scan = memscan::scan(&s.needles);
            let mut allowed = vec![key_range(&s)];
            if step < 3 {
                allowed.push(page_of(keys_at.load(Ordering::Acquire)));
            }
            snapshot(names[step - 1], &s, &scan, &allowed, stack)
        },
    )
}

/// `MaskedTuring::new` and masked encryptions: round keys exist only as
/// shares, so no round key should be found anywhere.
pub fn masked() -> Vec<Snapshot> {
    let s = secrets();
    burn_stack();
    memscan::run_parked(
        |p: &Parker| {
            let mut m = MaskedTuring::new(&s.key).expect("OS randomness");
            p.park(1);
            let mut b: Block = [0x3c; 16];
            for _ in 0..3 {
                m.encrypt_block(&mut b);
            }
            let _ = m.encrypt_block_checked(&mut b);
            let _ = m.decrypt_block_checked(&mut b);
            m.decrypt_block(&mut b);
            p.park(2);
            drop(m);
            p.park(3);
        },
        3,
        |step, stack| {
            let name = ["MaskedTuring::new, scanned at once", "then masked encryptions and checked calls", "after the MaskedTuring is dropped"][step - 1];
            snapshot(name, &s, &memscan::scan(&s.needles), &[key_range(&s)], stack)
        },
    )
}

/// A shielded key: the caller shields its key and wipes its own copy; then
/// a cipher is made from the shielded key and later dropped.
pub fn shielded() -> Vec<Snapshot> {
    let mut s = secrets();
    burn_stack();
    let keys_at = AtomicUsize::new(0);
    let key = std::sync::Mutex::new(std::mem::replace(&mut s.key, SecretBox::zeroed()));
    let out = memscan::run_parked(
        |p: &Parker| {
            let mut shielded = {
                let mut k = key.lock().expect("key");
                let shielded = ShieldedKey::new(&k).expect("OS randomness");
                zeroize::Zeroize::zeroize(&mut k[..]);
                shielded
            };
            p.park(1);
            let t = shielded.cipher();
            keys_at.store(t.round_key(0).as_ptr() as usize, Ordering::Release);
            p.park(2);
            let mut b: Block = [0x77; 16];
            t.encrypt_block(&mut b);
            drop(t);
            shielded.refresh().expect("OS randomness");
            drop(shielded.masked().expect("OS randomness"));
            p.park(3);
        },
        3,
        |step, stack| {
            let mut allowed = vec![];
            if step == 2 {
                allowed.push(page_of(keys_at.load(Ordering::Acquire)));
            }
            let name = ["ShieldedKey::new, then the caller wipes its key", "a cipher made from the shielded key", "after refresh() and a masked cipher"][step - 1];
            snapshot(name, &s, &memscan::scan(&s.needles), &allowed, stack)
        },
    );
    s.key = key.into_inner().expect("key");
    out
}

/// How many round-key fragments of a plain `Turing` the scan finds in its
/// locked page (all 50 if the scanner reads locked memory).
pub fn round_keys_found_in_their_page() -> (usize, usize) {
    let s = secrets();
    let t = Turing::new(&s.key);
    let page = page_of(t.round_key(0).as_ptr() as usize);
    let scan = memscan::scan(&s.needles);
    let found = scan.hits.iter().filter(|h| s.round_keys.contains(&h.secret) && h.address >= page.0 && h.address < page.0 + page.1).count();
    (found, 2 * ROUND_KEYS)
}

/// Stack bytes the secret-handling code uses below its caller, measured
/// without the burn (whose own 32 KB frame would dominate): the burn must
/// cover each of them.
pub fn stack_depths() -> Vec<(&'static str, usize)> {
    let key = [7u8; 32];
    let prekey = vec![9u8; turing::shield::PREKEY_BYTES];
    let dk = turing::turing1026::DecapsulationKey::from_seed(&key).expect("consistent");
    let (ct, _) = dk.encapsulation_key().encapsulate_with_no_burn(&[1; 32], &[2; 64]);
    vec![
        ("Turing-1026 key generation", memscan::stack_depth(|| drop(turing::turing1026::DecapsulationKey::from_seed_without_stack_burn(&key)))),
        ("Turing-1026 encapsulation", memscan::stack_depth(|| drop(dk.encapsulation_key().encapsulate_with_no_burn(&[1; 32], &[2; 64])))),
        ("Turing-1026 decapsulation", memscan::stack_depth(|| drop(dk.decapsulate_no_burn(&ct)))),
        ("key schedule (keyschedule::expand)", memscan::stack_depth(|| drop(turing::keyschedule::expand::<ROUND_KEYS>(&key)))),
        (
            "Turing-256 key schedule (keyschedule256::expand)",
            memscan::stack_depth(|| drop(turing::keyschedule256::expand::<{ 2 * turing::turing256::ROUND_KEYS }>(&key))),
        ),
        ("masked key setup (MaskedTuring::with_mask_seed)", memscan::stack_depth(|| drop(MaskedTuring::with_mask_seed(&key, &[1; 64])))),
        (
            "shield mask (cSHAKE256 of the 16 KB prekey)",
            memscan::stack_depth(|| {
                let mut out = [0u8; 32];
                xof::cshake256_secret("Turing v2 key shield", &prekey, &mut out);
            }),
        ),
    ]
}

/// Turing-256 (docs/15): the key, K' (64 bytes), the Feistel halves at each
/// round-key pair and the 25 round keys of 32 bytes, searched for after
/// `Turing256::new` (or the control without the stack burn), after
/// encryptions and checked calls, and after drop. Hits are expected only in
/// the caller's key buffer and the round keys' locked page.
pub fn plain256(burn: bool) -> Vec<Snapshot> {
    use turing::{Block256, Turing256};
    let s = secrets256();
    burn_stack();
    let keys_at = AtomicUsize::new(0);
    let names = if burn {
        ["Turing256::new, scanned at once", "then encryptions and checked calls", "after the Turing256 is dropped"]
    } else {
        ["Turing256::new without the stack burn, scanned at once", "then encryptions and checked calls", "after drop"]
    };
    memscan::run_parked(
        |p: &Parker| {
            let t = if burn { Turing256::new(&s.key) } else { Turing256::new_without_stack_burn(&s.key) };
            keys_at.store(t.stored_block(0).as_ptr() as usize, Ordering::Release);
            p.park(1);
            let mut b: Block256 = [0x5a; 32];
            for _ in 0..3 {
                t.encrypt_block(&mut b);
            }
            let _ = t.encrypt_block_checked(&mut b);
            let _ = t.decrypt_block_checked(&mut b);
            t.decrypt_block(&mut b);
            p.park(2);
            drop(t);
            p.park(3);
        },
        3,
        |step, stack| {
            let scan = memscan::scan(&s.needles);
            let mut allowed = vec![key_range(&s)];
            if step < 3 {
                allowed.push(page_of(keys_at.load(Ordering::Acquire)));
            }
            snapshot(names[step - 1], &s, &scan, &allowed, stack)
        },
    )
}

#[inline(never)]
fn secrets256() -> Secrets {
    use turing::turing256::ROUND_KEYS as KEYS256;
    let key = random::new_key().expect("OS randomness");
    let mut needles = Needles::new();
    needles.add("key", &key[..]);
    let mut whitened: SecretBox<[u8; 64]> = SecretBox::zeroed();
    xof::cshake256_secret(turing::keyschedule256::KEY_LABEL, &key[..], &mut whitened[..]);
    needles.add("whitened key K'", &whitened[..]);
    let t = turing::Turing256::new(&key);
    for i in 0..KEYS256 {
        let mut rk: SecretBox<[u8; 32]> = SecretBox::zeroed();
        rk.copy_from_slice(&t.round_key(i));
        let half = if i % 2 == 0 { &whitened[..32] } else { &whitened[32..] };
        let mut state: SecretBox<[u8; 32]> = SecretBox::zeroed();
        for (o, (a, b)) in state.iter_mut().zip(rk.iter().zip(half)) {
            *o = a ^ b;
        }
        needles.add(&format!("Feistel {} at pair {}", if i % 2 == 0 { "L" } else { "R" }, i / 2), &state[..]);
    }
    let first = needles.secrets();
    for i in 0..KEYS256 {
        let mut rk: SecretBox<[u8; 32]> = SecretBox::zeroed();
        rk.copy_from_slice(&t.round_key(i));
        needles.add(&format!("round key {i}"), &rk[..]);
    }
    let round_keys = first..needles.secrets();
    Secrets { key, needles, round_keys }
}

/// Turing-1026 (docs/16): the seed (from `random::new_key`), everything its
/// key generation derives that is never meant to be stored (the noise seed),
/// the stored rejection secret z, and for one encapsulation with a known
/// message: the message, the coins' seed, k and the shared key; and the
/// rejection key of a tampered ciphertext. S itself is left out: its 8-byte
/// fragments hold about 14 bits each, too few to tell a copy from chance.
/// Allowed: the caller's seed and message buffers, the decapsulation key's
/// own locked memory while it lives, and the keys the caller holds.
pub fn kem1026(burn: bool) -> Vec<Snapshot> {
    use turing::turing1026::DecapsulationKey;
    let seed = random::new_key().expect("OS randomness");
    let mu = random::new_key().expect("OS randomness");
    let salt = [0x33u8; 64];
    let mut needles = Needles::new();
    needles.add("seed", &seed[..]);
    let mut derived: SecretBox<[u8; 96]> = SecretBox::zeroed();
    xof::cshake256_secret("Turing-1026 v1 key generation", &seed[..], &mut derived[..]);
    needles.add("noise seed", &derived[32..64]);
    needles.add("rejection secret z", &derived[64..]);
    needles.add("message", &mu[..]);
    let check = DecapsulationKey::from_seed(&seed).expect("consistent");
    let mut pk_hash = [0u8; 32];
    sha3::digest::XofReader::read(&mut xof::cshake256("Turing-1026 v1 public key", check.encapsulation_key().as_bytes()), &mut pk_hash);
    let mut coins: SecretBox<[u8; 96]> = SecretBox::zeroed();
    let mut input: SecretBox<[u8; 128]> = SecretBox::zeroed();
    input[..32].copy_from_slice(&pk_hash);
    input[32..64].copy_from_slice(&mu[..]);
    input[64..].copy_from_slice(&salt);
    xof::cshake256_secret("Turing-1026 v1 coins", &input[..], &mut coins[..]);
    drop(input);
    needles.add("coin seed", &coins[..64]);
    needles.add("k", &coins[64..]);
    let (ct, key) = check.encapsulation_key().encapsulate_with(&mu, &salt);
    needles.add("shared key", &key[..]);
    let mut bad = ct.clone();
    bad[100] ^= 1;
    let rejected = check.decapsulate(&bad).expect("length");
    needles.add("rejection key", &rejected[..]);
    drop((check, key, rejected, derived, coins));
    burn_stack();
    let s = Secrets { key: seed, needles, round_keys: 0..0 };
    let (secret_at, held_at) = (AtomicUsize::new(0), [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)]);
    let names = if burn {
        ["Turing-1026 key from its seed, scanned at once", "then an encapsulation and two decapsulations", "after everything is dropped"]
    } else {
        ["Turing-1026 key without the stack burn, scanned at once", "then encapsulation and decapsulations", "after drop"]
    };
    let mu_range = (mu.as_ptr() as usize, 32);
    memscan::run_parked(
        |p: &Parker| {
            let dk = if burn { DecapsulationKey::from_seed(&s.key).expect("consistent") } else { DecapsulationKey::from_seed_without_stack_burn(&s.key) };
            secret_at.store(dk.secret_memory().0, Ordering::Release);
            p.park(1);
            let (ct, key) = dk.encapsulation_key().encapsulate_with(&mu, &salt);
            let back = dk.decapsulate(&ct).expect("length");
            let mut bad = ct.clone();
            bad[100] ^= 1;
            let rejected = dk.decapsulate(&bad).expect("length");
            for (slot, k) in held_at.iter().zip([&key, &back, &rejected]) {
                slot.store(k.as_ptr() as usize, Ordering::Release);
            }
            p.park(2);
            drop((dk, key, back, rejected));
            p.park(3);
        },
        3,
        |step, stack| {
            let scan = memscan::scan(&s.needles);
            let mut allowed = vec![key_range(&s), mu_range];
            if step < 3 {
                let at = secret_at.load(Ordering::Acquire);
                allowed.push((at, core::mem::size_of::<[u16; 1026 * 32]>() + 64));
            }
            if step == 2 {
                allowed.extend(held_at.iter().map(|a| page_of(a.load(Ordering::Acquire))));
            }
            snapshot(names[step - 1], &s, &scan, &allowed, stack)
        },
    )
}
