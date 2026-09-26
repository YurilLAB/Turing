//! Randomness for keys, masking and key shielding.
//!
//! Seeds come from the operating system through the getrandom crate
//! (ProcessPrng on Windows, getrandom(2) on Linux). A masked encryption needs
//! about 2.7 KB of fresh masks per block, so those come from a cSHAKE256
//! stream keyed with a 64-byte OS seed, one stream per object. Every
//! constructor fails closed: without OS randomness there is no masked cipher
//! and no shielded key, rather than a predictable one.
//!
//! Nothing secret is used as the OS returned it. Measured on Windows 11
//! (docs/13): after ProcessPrng returns, up to the last 16 bytes of its
//! output are often still readable elsewhere in the process until a later
//! request replaces them. Microsoft's description of the generator
//! (Ferguson, 2019) wipes the bytes its small-request buffer hands out, so
//! this copy is outside that design. A key taken straight from the OS could
//! leave half of itself there. So seeds are 64 bytes and only ever used
//! through cSHAKE256: the 16 bytes that may remain leave 384 bits unknown.
//!
//! Whoever knows the stream's state knows every future mask, so the state is
//! kept like a key: in its own locked allocation (memory.rs), with the seed
//! written straight into it and Keccak-f run in place, so no copy of the
//! state is moved around the stack. Two processes must never share it:
//! after fork(2) the parent and the child would draw the same masks, and an
//! attacker who watches both sees each mask used twice, which undoes masking
//! (Bombe's leakage tests show it). On Linux the state's pages are marked
//! MADV_WIPEONFORK, so a child finds them zeroed and reseeds before its first
//! mask. Beyond that, `check_fork` compares the process ID: every public
//! draw (`fill`, `u64`, `block`) runs it first, so a stream used directly is
//! fork-safe on every platform, whatever the kernel said to
//! MADV_WIPEONFORK. The masked cipher draws thousands of masks per block
//! through crate-private calls that skip the system call, and runs
//! `check_fork` once at the start of every operation instead.

use crate::memory::{SecretBox, Zeroable};
use zeroize::Zeroize;

/// The operating system could not supply random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomnessError;

/// Fills `buf` from the operating system's generator. For keys, use
/// `new_key`: bytes used as the OS returned them may have a copy left in
/// the generator's memory.
pub fn os_random(buf: &mut [u8]) -> Result<(), RandomnessError> {
    getrandom::fill(buf).map_err(|_| RandomnessError)
}

/// A new random 256-bit key in its own locked memory: cSHAKE256 of a
/// 64-byte OS seed (S = "Turing v2 key generation"). The seed is wiped and
/// so is the stack the hash used; Bombe's memory scan finds the key nowhere
/// but in the returned buffer.
pub fn new_key() -> Result<SecretBox<[u8; 32]>, RandomnessError> {
    let mut seed: SecretBox<[u8; SEED_BYTES]> = SecretBox::zeroed();
    os_random(&mut seed[..])?;
    let key = key_from_seed(&seed);
    drop(seed);
    crate::memory::burn_stack();
    Ok(key)
}

fn key_from_seed(seed: &[u8; SEED_BYTES]) -> SecretBox<[u8; 32]> {
    let mut key: SecretBox<[u8; 32]> = SecretBox::zeroed();
    crate::xof::cshake256_secret(KEY_LABEL, seed, &mut key[..]);
    key
}

const STREAM_LABEL: &str = "Turing v2 masks";
/// cSHAKE256's rate in bytes (capacity 512 bits).
const RATE: usize = 136;
const SEED_BYTES: usize = 64;
const KEY_LABEL: &str = "Turing v2 key generation";
const _: () = assert!(STREAM_LABEL.len() < 32, "the label's bit length must fit left_encode's one-byte form");

/// The stream's state, all in one locked allocation.
struct StreamState {
    lanes: [u64; 25],
    /// The current output block; also where the OS seed is written.
    block: [u8; RATE],
    used: u64,
    /// 1 once seeded. Reads 0 in a fork child on Linux (MADV_WIPEONFORK).
    seeded: u64,
    /// The process that seeded the stream.
    pid: u64,
}

impl Zeroize for StreamState {
    fn zeroize(&mut self) {
        self.lanes.zeroize();
        self.block.zeroize();
        self.used.zeroize();
        self.seeded.zeroize();
        self.pid.zeroize();
    }
}

// SAFETY: integers and byte arrays only; all zeroes is a valid value.
unsafe impl Zeroable for StreamState {}

/// XORs `bytes` (at most one rate block) into the lanes, little-endian.
fn absorb(lanes: &mut [u64; 25], bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        lanes[i / 8] ^= u64::from(*b) << (8 * (i % 8));
    }
}

/// A stream of mask bytes: cSHAKE256(seed, N = "", S = "Turing v2 masks")
/// from a fresh OS seed.
pub struct MaskStream {
    state: SecretBox<StreamState>,
}

impl MaskStream {
    pub fn new() -> Result<MaskStream, RandomnessError> {
        let mut stream = MaskStream { state: SecretBox::zeroed_fork_wiped() };
        stream.reseed()?;
        Ok(stream)
    }

    /// The stream for a given seed (tests and Bombe's controls replay one).
    #[cfg(any(test, feature = "analysis"))]
    pub(crate) fn from_seed(seed: &[u8; SEED_BYTES]) -> MaskStream {
        MaskStream::seeded_in(SecretBox::zeroed_fork_wiped(), seed)
    }

    #[cfg(any(test, feature = "analysis"))]
    fn seeded_in(state: SecretBox<StreamState>, seed: &[u8; SEED_BYTES]) -> MaskStream {
        let mut stream = MaskStream { state };
        stream.state.block[..SEED_BYTES].copy_from_slice(seed);
        stream.start();
        stream
    }

    fn reseed(&mut self) -> Result<(), RandomnessError> {
        os_random(&mut self.state.block[..SEED_BYTES])?;
        self.start();
        Ok(())
    }

    /// cSHAKE256 (NIST SP 800-185, section 3.3) over the seed at the start of
    /// `block`: absorbs bytepad(encode_string(N) || encode_string(S), 136),
    /// then the seed followed by cSHAKE's suffix 00 and the pad10*1 padding
    /// (the bytes 0x04 ... 0x80), then wipes the seed.
    fn start(&mut self) {
        let st = &mut *self.state;
        st.lanes = [0; 25];
        let label = STREAM_LABEL.as_bytes();
        // left_encode(136), encode_string(""), left_encode(8 * |S|), S.
        let mut prefix = [0u8; 6 + 31];
        prefix[..6].copy_from_slice(&[0x01, RATE as u8, 0x01, 0x00, 0x01, (8 * label.len()) as u8]);
        prefix[6..6 + label.len()].copy_from_slice(label);
        absorb(&mut st.lanes, &prefix[..6 + label.len()]);
        keccak::f1600(&mut st.lanes);
        absorb(&mut st.lanes, &st.block[..SEED_BYTES]);
        st.lanes[SEED_BYTES / 8] ^= 0x04 << (8 * (SEED_BYTES % 8));
        st.lanes[(RATE - 1) / 8] ^= 0x80 << (8 * ((RATE - 1) % 8));
        keccak::f1600(&mut st.lanes);
        st.block.zeroize();
        st.used = RATE as u64;
        st.seeded = 1;
        st.pid = u64::from(std::process::id());
    }

    /// Reseeds from the OS if this process did not seed the stream: a fork
    /// child. Panics if the OS has no randomness to give, since the only
    /// alternative is to reuse the parent's masks.
    pub fn check_fork(&mut self) {
        if self.state.seeded == 0 || self.state.pid != u64::from(std::process::id()) {
            self.reseed().expect("OS randomness failed after fork; refusing to reuse masks");
        }
    }

    /// Makes the stream look as if another process had seeded it, to test
    /// the process-ID check on systems that have MADV_WIPEONFORK.
    #[cfg(test)]
    pub(crate) fn pretend_other_process(&mut self) {
        self.state.pid ^= 1;
    }

    /// Whether the operating system agreed to zero the stream's state in a
    /// fork child (MADV_WIPEONFORK, Linux 4.14 and later). Either way the
    /// public draws check the process ID.
    pub fn wiped_on_fork(&self) -> bool {
        self.state.wiped_on_fork()
    }

    /// Mask bytes. Reseeds first if another process seeded the stream (a
    /// fork child), so the parent's masks are never drawn twice.
    pub fn fill(&mut self, out: &mut [u8]) {
        self.check_fork();
        self.draw(out);
    }

    pub fn u64(&mut self) -> u64 {
        self.check_fork();
        self.draw_u64()
    }

    pub fn block(&mut self) -> [u8; 16] {
        self.check_fork();
        self.draw_block()
    }

    /// `fill` without the process-ID check, a system call, for the masked
    /// cipher's thousands of draws per block. Callers must run `check_fork`
    /// themselves at the start of each operation, as `MaskedTuring` does.
    pub(crate) fn draw(&mut self, out: &mut [u8]) {
        // Free on Linux, where a fork child finds the state zeroed.
        if self.state.seeded == 0 {
            self.check_fork();
        }
        let st = &mut *self.state;
        for byte in out.iter_mut() {
            if st.used == RATE as u64 {
                for (chunk, lane) in st.block.chunks_exact_mut(8).zip(&st.lanes) {
                    chunk.copy_from_slice(&lane.to_le_bytes());
                }
                keccak::f1600(&mut st.lanes);
                st.used = 0;
            }
            *byte = st.block[st.used as usize];
            st.used += 1;
        }
    }

    /// `u64` without the process-ID check (see `draw`).
    pub(crate) fn draw_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.draw(&mut b);
        u64::from_le_bytes(b)
    }

    /// `block` without the process-ID check (see `draw`).
    pub(crate) fn draw_block(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.draw(&mut b);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // new_key is cSHAKE256 of the seed, as the sha3 crate computes it, not
    // the seed itself.
    #[test]
    fn keys_are_derived_from_the_seed() {
        let seed: [u8; 64] = core::array::from_fn(|i| (i * 3) as u8);
        let mut expected = [0u8; 32];
        sha3::digest::XofReader::read(&mut crate::xof::cshake256(KEY_LABEL, &seed), &mut expected);
        assert_eq!(*key_from_seed(&seed), expected);
    }

    #[test]
    fn check_fork_reseeds_for_another_process() {
        let seed = [8u8; 64];
        let (mut a, mut b) = (MaskStream::from_seed(&seed), MaskStream::from_seed(&seed));
        b.pretend_other_process();
        b.check_fork();
        a.check_fork();
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_ne!(x, y, "the other process reseeded");
        let mut c = MaskStream::from_seed(&seed);
        let mut z = [0u8; 32];
        c.fill(&mut z);
        assert_eq!(x, z, "control: the same process keeps its stream");
    }

    #[test]
    fn new_keys_are_random_and_locked() {
        let (a, b) = (new_key().unwrap(), new_key().unwrap());
        assert_ne!(*a, *b);
        assert_ne!(*a, [0u8; 32]);
        assert!(a.locked() || cfg!(not(windows)));
    }

    #[test]
    fn os_random_varies() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        os_random(&mut a).unwrap();
        os_random(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn streams_differ_and_look_balanced() {
        let (mut s1, mut s2) = (MaskStream::new().unwrap(), MaskStream::new().unwrap());
        let (mut x, mut y) = ([0u8; 4096], [0u8; 4096]);
        s1.fill(&mut x);
        s2.fill(&mut y);
        assert_ne!(x, y, "independent seeds");
        // 32768 fair bits: the count of ones is within 5 sigma (452) of half.
        let ones: u32 = x.iter().map(|b| b.count_ones()).sum();
        assert!((ones as i64 - 16384).abs() < 453, "{ones}");
    }

    // The same seed gives the same bytes however the reads are cut, and they
    // are cSHAKE256(seed, S = "Turing v2 masks") as the sha3 crate computes it.
    #[test]
    fn stream_is_cshake256_of_the_seed() {
        for seed in [[9u8; 64], core::array::from_fn(|i| i as u8)] {
            let mut whole = [0u8; 580];
            MaskStream::from_seed(&seed).fill(&mut whole);
            let mut s = MaskStream::from_seed(&seed);
            let mut parts = Vec::new();
            for len in [1usize, 135, 137, 7, 300] {
                let mut buf = vec![0u8; len];
                s.fill(&mut buf);
                parts.extend(buf);
            }
            assert_eq!(parts, whole);
            let mut expected = [0u8; 580];
            sha3::digest::XofReader::read(&mut crate::xof::cshake256(STREAM_LABEL, &seed), &mut expected);
            assert_eq!(whole, expected);
        }
    }

    #[test]
    fn the_seed_is_not_left_in_the_state() {
        let seed = [0xa5u8; 64];
        let s = MaskStream::from_seed(&seed);
        assert!(s.state.block.iter().all(|&b| b == 0));
        assert_eq!(s.state.seeded, 1);
    }

    /// Runs `child` in a forked child process and returns the 64 bytes it
    /// writes back. The child only touches memory that already exists and
    /// makes system calls, so forking from a multi-threaded test is safe.
    #[cfg(unix)]
    fn in_child(child: impl FnOnce() -> [u8; 64]) -> [u8; 64] {
        let mut fds = [0i32; 2];
        // SAFETY: pipe fills the two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child runs only `child`, write and _exit.
        match unsafe { libc::fork() } {
            0 => {
                let out = child();
                // SAFETY: plain system calls in the child.
                unsafe {
                    libc::write(fds[1], out.as_ptr().cast(), out.len());
                    libc::_exit(0);
                }
            }
            pid if pid > 0 => {
                let mut out = [0u8; 64];
                let mut got = 0;
                while got < out.len() {
                    // SAFETY: reads into the rest of `out`.
                    let n = unsafe { libc::read(fds[0], out[got..].as_mut_ptr().cast(), out.len() - got) };
                    assert!(n > 0, "child wrote nothing");
                    got += n as usize;
                }
                let mut status = 0;
                // SAFETY: waits for our own child; closes our descriptors.
                unsafe {
                    libc::waitpid(pid, &mut status, 0);
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                out
            }
            _ => panic!("fork failed"),
        }
    }

    // A child draws different masks from its parent, however the stream was
    // seeded.
    #[test]
    #[cfg(unix)]
    fn a_fork_child_draws_its_own_masks() {
        for mut s in [MaskStream::new().unwrap(), MaskStream::from_seed(&[4; 64])] {
            let mut warm = [0u8; 10];
            s.fill(&mut warm);
            let child = in_child(|| {
                s.check_fork();
                let mut b = [0u8; 64];
                s.fill(&mut b);
                b
            });
            let mut parent = [0u8; 64];
            s.fill(&mut parent);
            assert_ne!(child, parent);
            assert_ne!(child, [0u8; 64]);
        }
    }

    // Control: a stream in ordinary locked memory, drawn from in the child
    // without the process check, repeats the parent's masks exactly. This is
    // what the check and the wiped pages prevent.
    #[test]
    #[cfg(unix)]
    fn control_an_unprotected_stream_repeats_after_fork() {
        let mut s = MaskStream::seeded_in(SecretBox::zeroed(), &[4; 64]);
        let child = in_child(|| {
            let mut b = [0u8; 64];
            s.draw(&mut b);
            b
        });
        let mut parent = [0u8; 64];
        s.draw(&mut parent);
        assert_eq!(child, parent);
    }

    // The public draws are fork-safe where nothing wipes the state (every
    // Unix but Linux, or a kernel that refused MADV_WIPEONFORK): a stream in
    // ordinary memory, drawn from directly in a child, never repeats its
    // parent's masks, whichever call draws them.
    #[test]
    #[cfg(unix)]
    fn public_draws_in_a_fork_child_never_repeat_the_parent() {
        type Draw = fn(&mut MaskStream) -> [u8; 64];
        let draws: [(&str, Draw); 3] = [
            ("fill", |s| {
                let mut b = [0u8; 64];
                s.fill(&mut b);
                b
            }),
            ("u64", |s| {
                let mut b = [0u8; 64];
                b.chunks_exact_mut(8).for_each(|c| c.copy_from_slice(&s.u64().to_le_bytes()));
                b
            }),
            ("block", |s| {
                let mut b = [0u8; 64];
                b.chunks_exact_mut(16).for_each(|c| c.copy_from_slice(&s.block()));
                b
            }),
        ];
        for (name, draw) in draws {
            let mut s = MaskStream::seeded_in(SecretBox::zeroed(), &[4; 64]);
            assert!(!s.wiped_on_fork());
            let child = in_child(|| draw(&mut s));
            let parent = draw(&mut s);
            assert_ne!(child, parent, "{name}");
            assert_ne!(child, [0u8; 64], "{name}");
        }
    }

    // On Linux a child that never calls check_fork still reseeds, because
    // the unchecked draw finds the wiped state.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_a_child_that_skips_the_check_still_reseeds() {
        let mut s = MaskStream::from_seed(&[4; 64]);
        let child = in_child(|| {
            let mut b = [0u8; 64];
            s.draw(&mut b);
            b
        });
        let mut parent = [0u8; 64];
        s.draw(&mut parent);
        assert_ne!(child, parent);
        assert_ne!(child, [0u8; 64]);
    }

    // On Linux the child finds the state already wiped, before any check.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_fork_children_find_the_state_wiped() {
        let s = MaskStream::new().unwrap();
        assert!(s.wiped_on_fork(), "the kernel took MADV_WIPEONFORK");
        let child = in_child(|| {
            let mut b = [0u8; 64];
            b[0] = s.state.seeded as u8;
            b[1] = s.state.lanes.iter().any(|&l| l != 0) as u8;
            b
        });
        assert_eq!((child[0], child[1]), (0, 0));
        assert_eq!(s.state.seeded, 1);
    }
}
