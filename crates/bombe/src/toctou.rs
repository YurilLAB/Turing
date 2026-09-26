//! Time-of-check to time-of-use, and concurrent use.
//!
//! The checked calls verify the round keys' checksum before computing. A
//! persistent fault that lands after that check, but before the computation
//! reads the key, corrupts encryption and decryption alike, so
//! decrypt-and-compare passes and a block computed under a wrong key would
//! be released: one faulty ciphertext of that kind, with the flipped bit in
//! round key 23, is a differential-fault pair on the last S-box layer
//! (fault.rs). The calls therefore check the keys again afterwards. These
//! experiments flip a key bit exactly inside that window, through the hook
//! the analysis build exposes, and confirm the second check catches it.
//!
//! In safe Rust a key cannot change under a running call by software means:
//! the cipher is borrowed for the call, so nothing else can hold `&mut` to
//! it, and the block is `&mut`, so no other thread can rewrite it between
//! reads (no double fetch). Only hardware faults, or unsafe code, reach the
//! window, and that is what is simulated here.

use crate::rng::Rng;
use turing::structure::ROUND_KEYS;
use turing::{Block, FaultDetected, MaskedTuring, Turing};

/// For `trials` random (round key, bit) pairs flipped between the first check
/// and the encryption: how many checked calls caught the flip and wiped the
/// block, and how many times decrypt-and-compare alone would have released a
/// ciphertext under the wrong key (the control).
pub fn plain_flip_in_window(trials: usize, label: &str) -> (usize, usize, usize) {
    let mut rng = Rng::new(label);
    let (mut caught, mut released) = (0, 0);
    for _ in 0..trials {
        let t = Turing::new(&rng.bytes());
        let p: Block = rng.bytes();
        let mut expected = p;
        t.encrypt_block(&mut expected);
        let (round, bit) = (rng.below(ROUND_KEYS as u64) as usize, rng.below(128) as usize);
        let mut b = p;
        // SAFETY: inside `between` no reference into the round keys is alive.
        let result = t.encrypt_block_checked_with(&mut b, || unsafe { t.flip_round_key_bit_in_use(round, bit) });
        caught += usize::from(result == Err(FaultDetected) && b == [0u8; 16]);
        let mut c = p;
        t.encrypt_block(&mut c);
        let mut back = c;
        t.decrypt_block(&mut back);
        released += usize::from(back == p && c != expected);
    }
    (caught, released, trials)
}

/// The same for the masked cipher, flipping a bit of one share.
pub fn masked_flip_in_window(trials: usize, label: &str) -> (usize, usize) {
    let mut rng = Rng::new(label);
    let mut caught = 0;
    for _ in 0..trials {
        let mut m = MaskedTuring::new(&rng.bytes()).expect("OS randomness");
        let (round, bit) = (rng.below(ROUND_KEYS as u64) as usize, rng.below(128) as usize);
        let mut b: Block = rng.bytes();
        let result = m.encrypt_block_checked_with(&mut b, |m| m.flip_share_bit(round, bit));
        caught += usize::from(result == Err(FaultDetected) && b == [0u8; 16]);
    }
    (caught, trials)
}

/// One `Turing` shared by `threads` threads, each encrypting and running
/// checked calls on its own blocks: how many results differ from a
/// single-threaded run.
pub fn shared_across_threads(threads: usize, per_thread: usize, label: &str) -> (usize, usize) {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let inputs: Vec<Block> = (0..threads * per_thread).map(|_| rng.bytes()).collect();
    let expected: Vec<Block> = inputs
        .iter()
        .map(|p| {
            let mut b = *p;
            t.encrypt_block(&mut b);
            b
        })
        .collect();
    let mismatches: usize = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let (t, inputs, expected) = (&t, &inputs, &expected);
                s.spawn(move || {
                    let mut bad = 0;
                    for k in i * per_thread..(i + 1) * per_thread {
                        let (mut a, mut b) = (inputs[k], inputs[k]);
                        t.encrypt_block(&mut a);
                        let ok = t.encrypt_block_checked(&mut b).is_ok();
                        let mut back = b;
                        let back_ok = t.decrypt_block_checked(&mut back).is_ok();
                        bad += usize::from(a != expected[k] || b != expected[k] || !ok || !back_ok || back != inputs[k]);
                    }
                    bad
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("thread")).sum()
    });
    (mismatches, threads * per_thread)
}

/// Encrypts one fixed block with the masked cipher in a fork child and in
/// the parent, and compares the first share after round 1: with masks drawn
/// afresh by each process they differ. `None` where there is no fork(2).
#[cfg(unix)]
pub fn fork_draws_fresh_masks() -> Option<bool> {
    let mut m = MaskedTuring::new(&[0x61; 32]).expect("OS randomness");
    let mut warm: Block = [0; 16];
    m.encrypt_block(&mut warm);
    let first_share = |m: &mut MaskedTuring| {
        let mut out = [0u8; 16];
        let mut b: Block = [0x11; 16];
        m.encrypt_probed(&mut b, &mut |round, s0, _| {
            if round == 1 {
                out = *s0;
            }
        });
        out
    };
    let mut fds = [0i32; 2];
    // SAFETY: pipe fills the two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the child only encrypts (no allocation), writes and exits.
    match unsafe { libc::fork() } {
        0 => {
            let out = first_share(&mut m);
            // SAFETY: plain system calls in the child.
            unsafe {
                libc::write(fds[1], out.as_ptr().cast(), out.len());
                libc::_exit(0);
            }
        }
        pid if pid > 0 => {
            let mine = first_share(&mut m);
            let mut theirs = [0u8; 16];
            // SAFETY: reads into `theirs`; waits for our own child.
            let n = unsafe { libc::read(fds[0], theirs.as_mut_ptr().cast(), theirs.len()) };
            unsafe {
                libc::waitpid(pid, core::ptr::null_mut(), 0);
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            (n == 16).then_some(mine != theirs)
        }
        _ => None,
    }
}

#[cfg(not(unix))]
pub fn fork_draws_fresh_masks() -> Option<bool> {
    None
}
