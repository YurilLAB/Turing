//! The residue sweep: every public operation of this crate that handles a
//! secret, run once each, and the stack it leaves behind searched for every
//! secret it handled: whole Keccak states of its secret sponges (recorded as
//! they are wiped) and every 8-byte piece of its keys, seeds, checksum
//! points and shared keys.
//!
//! The review of 2026-09-28 found three such leftovers, one operation at a
//! time: Turing-1026's seed in a sponge state after key generation (R1),
//! ML-KEM's K, r and J(z || c) state (R3), and the checksum's point after
//! the checked calls (R4). This runs all of them, in both builds: the tests
//! of a workspace build turn on the `analysis` feature, and `tools/ci.py`'s
//! `production` stage runs them without it, the build users get, where the
//! optimiser inlines differently (R1 only showed there).
//!
//! What it does not search for, and why: the state of a plain encryption or
//! decryption between layers (docs/11 concedes it: states are not keys, and
//! a burn per block would cost about 10%), the masks of the masked cipher (a
//! mask alone is independent of the key), and S (an 8-byte piece of it holds
//! about 14 bits, too few to tell a copy from chance).

use crate::memory::residue::{contains, contains_state, leave, run, snapshot, SCAN};
use crate::memory::{self, SecretBox};
use crate::xof::{self, recorded};
use crate::{keyschedule, keyschedule256, mlkem, random, turing1026, MaskedTuring, ShieldedKey, Turing, Turing256};
use sha3::digest::XofReader;
use sha3::{Digest, Sha3_256, Sha3_512};

struct Sweep {
    buf: Vec<u8>,
    name: String,
    operations: usize,
    found: Vec<String>,
}

impl Sweep {
    /// Runs `op` from a burned stack, snapshots the stack it used, and
    /// searches it for every sponge state the operation wiped.
    fn op(&mut self, name: &str, op: &mut dyn FnMut()) {
        memory::burn_stack();
        recorded::start();
        run(op);
        snapshot(&mut self.buf);
        let states = recorded::stop();
        self.name = name.to_string();
        self.operations += 1;
        if let Some(i) = states.iter().position(|st| contains_state(&self.buf, st)) {
            self.found.push(format!("{name}: sponge state {i} of {}", states.len()));
        }
    }

    /// No 8-byte piece of any of `secrets` is in the last operation's stack.
    fn absent(&mut self, secrets: &[&[u8]]) {
        for (n, s) in secrets.iter().enumerate() {
            if s.chunks_exact(8).any(|piece| contains(&self.buf, piece)) {
                self.found.push(format!("{}: secret {n} of {}", self.name, secrets.len()));
            }
        }
    }
}

fn whitened(label: &str, key: &[u8], len: usize) -> Vec<u8> {
    let mut k = vec![0u8; len];
    xof::cshake256(label, key).read(&mut k);
    k
}

fn blocks(v: &[[u8; 16]]) -> Vec<&[u8]> {
    v.iter().map(|b| &b[..]).collect()
}

#[test]
fn every_public_operation_leaves_no_secret_on_the_stack() {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            let mut s = Sweep { buf: vec![0u8; SCAN], name: String::new(), operations: 0, found: Vec::new() };
            // Controls: a planted secret and a planted state are found.
            let planted_key = [0x5au8; 32];
            s.op("control: a key copied into a callee's frame", &mut || leave(&planted_key));
            s.absent(&[&planted_key]);
            let planted_state: [u64; 25] = core::array::from_fn(|i| 0x7475_7269_6e67_0000 ^ ((i as u64) << 8));
            s.op("control: a state copied into a callee's frame", &mut || leave(&planted_state));
            let state_found = contains_state(&s.buf, &planted_state);
            assert_eq!(s.found.len(), 1, "control: the planted key must be found: {:?}", s.found);
            assert!(state_found, "control: the planted state must be found");
            s.found.clear();

            let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(77) ^ 0x3c);
            let kw = whitened(keyschedule::KEY_LABEL, &key, 32);
            let kw256 = whitened(keyschedule256::KEY_LABEL, &key, 64);

            // Turing: key setup and the checked calls.
            let mut t = None;
            s.op("Turing::new", &mut || t = Some(Turing::new(&key)));
            let t = t.expect("cipher");
            let tb = t.secret_blocks();
            s.absent(&[&[&kw[..]][..], &blocks(&tb)].concat());
            for (name, encrypt) in [("Turing::encrypt_block_checked", true), ("Turing::decrypt_block_checked", false)] {
                s.op(name, &mut || {
                    let mut b = [0x11u8; 16];
                    let r = if encrypt { t.encrypt_block_checked(&mut b) } else { t.decrypt_block_checked(&mut b) };
                    r.expect("intact");
                    core::hint::black_box(b);
                });
                s.absent(&blocks(&tb));
            }

            // Turing-256.
            let mut t2 = None;
            s.op("Turing256::new", &mut || t2 = Some(Turing256::new(&key)));
            let t2 = t2.expect("cipher");
            let t2b = t2.secret_blocks();
            s.absent(&[&[&kw256[..]][..], &blocks(&t2b)].concat());
            for (name, encrypt) in [("Turing256::encrypt_block_checked", true), ("Turing256::decrypt_block_checked", false)] {
                s.op(name, &mut || {
                    let mut b = [0x22u8; 32];
                    let r = if encrypt { t2.encrypt_block_checked(&mut b) } else { t2.decrypt_block_checked(&mut b) };
                    r.expect("intact");
                    core::hint::black_box(b);
                });
                s.absent(&blocks(&t2b));
            }

            // The masked cipher: no round key, checksum or point ever unshared.
            let mut m = None;
            s.op("MaskedTuring::new", &mut || m = Some(MaskedTuring::new(&key).expect("OS randomness")));
            let mut m = m.expect("cipher");
            let mb = m.secret_blocks();
            s.absent(&[&[&kw[..]][..], &blocks(&mb)].concat());
            for (name, which) in [("MaskedTuring::encrypt_block", 0), ("MaskedTuring::decrypt_block", 1), ("MaskedTuring::encrypt_block_checked", 2), ("MaskedTuring::decrypt_block_checked", 3)] {
                s.op(name, &mut || {
                    let mut b = [0x33u8; 16];
                    match which {
                        0 => m.encrypt_block(&mut b),
                        1 => m.decrypt_block(&mut b),
                        2 => core::hint::black_box(m.encrypt_block_checked(&mut b)).expect("intact"),
                        _ => core::hint::black_box(m.decrypt_block_checked(&mut b)).expect("intact"),
                    }
                    core::hint::black_box(b);
                });
                s.absent(&blocks(&m.secret_blocks()));
            }

            // The shielded key: its mask, the key, and what cipher() and masked() set up.
            let mut sh = None;
            s.op("ShieldedKey::new", &mut || sh = Some(ShieldedKey::new(&key).expect("OS randomness")));
            let mut sh = sh.expect("shielded");
            let [mask, _] = sh.secrets();
            s.absent(&[&mask, &kw]);
            s.op("ShieldedKey::refresh", &mut || sh.refresh().expect("OS randomness"));
            let [mask2, _] = sh.secrets();
            s.absent(&[&mask, &mask2, &kw]);
            let mut c = None;
            s.op("ShieldedKey::cipher", &mut || c = Some(sh.cipher()));
            let cb = c.expect("cipher").secret_blocks();
            s.absent(&[&[&mask2[..], &kw[..]][..], &blocks(&cb)].concat());
            let mut mc = None;
            s.op("ShieldedKey::masked", &mut || mc = Some(sh.masked().expect("OS randomness")));
            let mcb = mc.expect("masked").secret_blocks();
            s.absent(&[&[&mask2[..], &kw[..]][..], &blocks(&mcb)].concat());

            // Key generation.
            let mut k = None;
            s.op("random::new_key", &mut || k = Some(random::new_key().expect("OS randomness")));
            let k: SecretBox<[u8; 32]> = k.expect("key");
            s.absent(&[&k[..]]);

            // Turing-1026.
            let mut dk = None;
            s.op("DecapsulationKey::from_seed", &mut || dk = Some(turing1026::DecapsulationKey::from_seed(&[0x42; 32]).expect("consistent")));
            let dk = dk.expect("key");
            let [seed, z] = dk.secrets();
            s.absent(&[&seed, &z]);
            let mut g = None;
            s.op("DecapsulationKey::generate", &mut || g = Some(turing1026::DecapsulationKey::generate().expect("keygen")));
            let [gseed, gz] = g.expect("key").secrets();
            s.absent(&[&gseed, &gz]);
            let mut enc = None;
            s.op("EncapsulationKey::encapsulate", &mut || enc = Some(dk.encapsulation_key().encapsulate().expect("OS randomness")));
            let (ct, shared) = enc.expect("ciphertext");
            s.absent(&[&shared[..], &z]);
            let mut back = None;
            s.op("DecapsulationKey::decapsulate", &mut || back = Some(dk.decapsulate(&ct).expect("length")));
            s.absent(&[&shared[..], &seed, &z]);
            let mut bad = ct.clone();
            bad[7] ^= 1;
            s.op("DecapsulationKey::decapsulate (rejected)", &mut || back = Some(dk.decapsulate(&bad).expect("length")));
            let rejected = back.take().expect("key");
            s.absent(&[&rejected[..], &shared[..], &seed, &z]);

            // ML-KEM, the entry points the hybrid will call.
            for p in [mlkem::ML_KEM_512, mlkem::ML_KEM_768, mlkem::ML_KEM_1024] {
                let (mut ek, mut dkm) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
                let (d, zm, msg) = ([0x61u8; 32], [0x62u8; 32], [0x63u8; 32]);
                s.op("mlkem::keygen", &mut || mlkem::keygen(&p, &d, &zm, &mut ek, &mut dkm).expect("lengths"));
                s.absent(&[&d, &zm, &dkm[..64]]);
                let (mut c, mut kk, mut kb) = (vec![0u8; p.ct_bytes()], [0u8; 32], [0u8; 32]);
                s.op("mlkem::encapsulate", &mut || mlkem::encapsulate(&p, &ek, &msg, &mut c, &mut kk).expect("valid"));
                let mut gh = Sha3_512::new();
                Digest::update(&mut gh, msg);
                Digest::update(&mut gh, Sha3_256::digest(&ek));
                let r = gh.finalize()[32..].to_vec();
                s.absent(&[&kk, &r, &msg]);
                s.op("mlkem::decapsulate", &mut || mlkem::decapsulate(&p, &dkm, &c, &mut kb).expect("valid"));
                s.absent(&[&kk, &r, &msg, &zm]);
            }

            assert_eq!(s.operations, 32, "the sweep must run its 30 operations and two controls");
            assert!(s.found.is_empty(), "secrets left in dead stack:\n{}", s.found.join("\n"));
        })
        .expect("thread")
        .join()
        .expect("sweep thread");
}
