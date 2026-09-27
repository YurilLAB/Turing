//! Memory for keys. Each secret gets its own page-aligned allocation that the
//! operating system keeps out of the page file (VirtualLock on Windows, mlock
//! on Unix) and, on Linux, out of core dumps (madvise MADV_DONTDUMP).
//! Microsoft documents that locked pages "are guaranteed not to be written to
//! the pagefile while they are locked"; mlock(2) that locked pages stay
//! resident in RAM. Page locks carry no count, so unlocking one allocation
//! would unlock any other secret on the same page: hence one allocation per
//! secret. Contents are wiped before the memory goes back to the system.
//!
//! Locking is limited: Windows lets a process lock about its minimum working
//! set (200 KB by default, measured: two Turing-1026 keys), Linux its
//! RLIMIT_MEMLOCK. When a lock is refused for that reason, the allocation
//! grows the limit and tries once more: on Windows the minimum and maximum
//! working set, as Microsoft's VirtualLock documentation says an application
//! that locks more pages must ("must first call the SetProcessWorkingSetSize
//! function"), by at most 64 MB in all; on Linux the soft RLIMIT_MEMLOCK, up
//! to the hard limit. Locking can still be refused (a hard limit, or no
//! memory to spare). The value then lives in ordinary memory, `locked()` says
//! so, `unlocked_allocations()` counts it for the whole process, and it is
//! still wiped. `dump_excluded()` and `wiped_on_fork()` report the kernel's
//! answer to the madvise calls the same way, false wherever the platform has
//! no such call. Hibernation writes all of RAM to disk, locked or not; only
//! full-disk encryption covers that. mlock(2) is not inherited across
//! fork(2): a child process that keeps using a cipher made before the fork
//! holds its keys in pages that may be swapped.
//!
//! Values computed on the way to a key (the whitened key, Feistel halves,
//! Keccak states) pass through the stack, and compiler temporaries there are
//! out of reach of `zeroize`. `burn_stack` overwrites the stack below the
//! caller after key setup, as libgcrypt's `_gcry_burn_stack` does after its
//! key schedules; Bombe's memory scan (docs/13) checks that nothing is left.
//! It reaches only the frames *below* its caller, so every public operation
//! that handles a secret is an outer function that calls an
//! `#[inline(never)]` worker and then burns: the worker's frame, and every
//! frame it called, lie below the burn.

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// Allocations the operating system refused to lock, since the process
/// started (see the module notes).
static UNLOCKED: AtomicU64 = AtomicU64::new(0);

/// How many `SecretBox` allocations, over the whole process so far, ended up
/// in memory the operating system would not lock (and may page out). Zero
/// means every secret, long-lived keys and per-operation scratch alike, was
/// locked. The per-box answer is `SecretBox::locked`.
pub fn unlocked_allocations() -> u64 {
    UNLOCKED.load(Ordering::Relaxed)
}

/// Plain data for which all-zero bytes are a valid value, so fresh zeroed
/// pages can hold it, and which contains no pointers.
///
/// # Safety
/// Implement only for such types.
pub unsafe trait Zeroable: Zeroize {}
unsafe impl Zeroable for u8 {}
unsafe impl Zeroable for u16 {}
unsafe impl Zeroable for u64 {}
unsafe impl<T: Zeroable, const N: usize> Zeroable for [T; N] where [T; N]: Zeroize {}

/// A value in its own locked, wiped-on-drop allocation.
pub struct SecretBox<T: Zeroable> {
    ptr: NonNull<T>,
    /// Bytes mapped from the OS, or 0 for the ordinary-heap fallback.
    mapped: usize,
    locked: bool,
    dump_excluded: bool,
    wiped_on_fork: bool,
}

/// A fresh mapping, and what the operating system granted for it.
struct Mapping {
    ptr: NonNull<u8>,
    size: usize,
    locked: bool,
    dump_excluded: bool,
    wiped_on_fork: bool,
}

// Owned like a Box: sending or sharing it is sending or sharing the T.
unsafe impl<T: Zeroable + Send> Send for SecretBox<T> {}
unsafe impl<T: Zeroable + Sync> Sync for SecretBox<T> {}

impl<T: Zeroable> SecretBox<T> {
    /// An all-zero value, in locked memory where the OS allows it.
    pub fn zeroed() -> SecretBox<T> {
        SecretBox::allocate(false)
    }

    /// The same, and on Linux the pages read as zeroes in a child created by
    /// fork(2) (MADV_WIPEONFORK, Linux 4.14). For state two processes must
    /// never share, such as the mask stream (random.rs).
    pub fn zeroed_fork_wiped() -> SecretBox<T> {
        SecretBox::allocate(true)
    }

    fn allocate(wipe_on_fork: bool) -> SecretBox<T> {
        let bytes = core::mem::size_of::<T>();
        assert!(bytes > 0 && core::mem::align_of::<T>() <= 4096);
        let b = match os::map(bytes, wipe_on_fork) {
            Some(m) => SecretBox { ptr: m.ptr.cast(), mapped: m.size, locked: m.locked, dump_excluded: m.dump_excluded, wiped_on_fork: m.wiped_on_fork },
            None => {
                let layout = std::alloc::Layout::new::<T>();
                // SAFETY: the layout has non-zero size; zeroed memory is a valid T (Zeroable).
                let raw = unsafe { std::alloc::alloc_zeroed(layout) };
                let ptr = NonNull::new(raw.cast::<T>()).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
                SecretBox { ptr, mapped: 0, locked: false, dump_excluded: false, wiped_on_fork: false }
            }
        };
        if !b.locked {
            UNLOCKED.fetch_add(1, Ordering::Relaxed);
        }
        b
    }

    /// Whether the operating system agreed to keep this memory out of the
    /// page file.
    pub fn locked(&self) -> bool {
        self.locked
    }

    /// Whether the operating system agreed to leave this memory out of core
    /// dumps (MADV_DONTDUMP, on Linux and Android). Always false elsewhere;
    /// Windows' full crash dumps, for one, include it (docs/13).
    pub fn dump_excluded(&self) -> bool {
        self.dump_excluded
    }

    /// Whether a fork child finds this memory zero-filled (MADV_WIPEONFORK,
    /// Linux 4.14 and later). Only `zeroed_fork_wiped` asks for it; where it
    /// is refused, the mask stream's process-ID check still catches the fork
    /// (random.rs).
    pub fn wiped_on_fork(&self) -> bool {
        self.wiped_on_fork
    }

    /// The allocation's address, for fault simulation that must write while
    /// only shared references to the owner exist (Bombe's TOCTOU tests).
    #[cfg(any(test, feature = "analysis"))]
    pub(crate) fn raw(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: Zeroable> Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: ptr is valid, aligned and initialised for the box's lifetime.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Zeroable> DerefMut for SecretBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and &mut self gives exclusive access.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: Zeroable> Drop for SecretBox<T> {
    fn drop(&mut self) {
        (**self).zeroize();
        // SAFETY: the value's bytes, read just before release; T is plain data.
        let bytes = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), core::mem::size_of::<T>()) };
        debug_assert!(bytes.iter().all(|&b| b == 0), "secret memory released unwiped");
        if self.mapped > 0 {
            // SAFETY: ptr and mapped come from os::map and are released once.
            unsafe { os::unmap(self.ptr.cast(), self.mapped, self.locked) };
        } else {
            // SAFETY: allocated with this layout by alloc_zeroed.
            unsafe { std::alloc::dealloc(self.ptr.as_ptr().cast(), std::alloc::Layout::new::<T>()) };
        }
    }
}

/// Bytes of stack `burn_stack` overwrites: several times the deepest key
/// setup (Turing::new peaks at a few kilobytes in a release build).
pub const BURN_BYTES: usize = 32 * 1024;

/// Overwrites the stack just below the caller's frame, where the functions
/// it called kept their temporaries. Not inlined, so its frame sits exactly
/// there. The buffer starts uninitialised and every word is written with a
/// volatile store, so the stores are the burn and cannot be optimised away.
#[inline(never)]
pub fn burn_stack() {
    let mut scratch = core::mem::MaybeUninit::<[u64; BURN_BYTES / 8]>::uninit();
    let words = scratch.as_mut_ptr().cast::<u64>();
    for i in 0..BURN_BYTES / 8 {
        // SAFETY: in bounds of the buffer; writing to uninitialised memory is allowed.
        unsafe { words.add(i).write_volatile(0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The most the lock limit is ever raised, in total, and the smallest step.
const MAX_LOCK_GROWTH: usize = 64 << 20;
const LOCK_GROWTH_STEP: usize = 1 << 20;

/// Test support for the residue tests: what an attacker who reads the stack
/// after an operation would see.
#[cfg(test)]
pub(crate) mod residue {
    /// Bytes of dead stack a snapshot covers: every public operation of
    /// this crate uses less (research/reviews/2026-09-28: 2.7 KB to 24 KB).
    pub const SCAN: usize = 24 * 1024;

    /// Runs `op` in a frame of its own, so that a `snapshot` taken next from
    /// the same caller reads exactly the stack `op` used.
    #[inline(never)]
    pub fn run(op: &mut dyn FnMut()) {
        op();
    }

    /// Copies the `out.len()` bytes just below this function's frame into
    /// `out` with volatile loads and no calls (not even a panic path, which
    /// would enlarge this frame over the region it reads), so nothing
    /// overwrites that region while it is read. Call it right after `run`,
    /// from the same function, with a buffer of `SCAN` bytes.
    #[inline(never)]
    pub fn snapshot(out: &mut [u8]) {
        let marker = 0u8;
        let top = core::hint::black_box(&marker as *const u8 as usize) & !7;
        let base = top - out.len();
        for (i, o) in out.iter_mut().enumerate() {
            // SAFETY: this thread's stack below the live frame, which stays
            // mapped (the tests run on threads with megabytes of stack).
            *o = unsafe { ((base + i) as *const u8).read_volatile() };
        }
    }

    /// Whether `needle` occurs anywhere in `hay`.
    pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Whether any of the lanes a Keccak state keeps out of every output
    /// (17..25, the capacity of a 136-byte rate and part of SHA3-512's) is
    /// in `hay`: a copy of the state, or of enough of it to invert.
    pub fn contains_state(hay: &[u8], lanes: &[u64; 25]) -> bool {
        lanes[17..].iter().any(|l| contains(hay, &l.to_le_bytes()))
    }

    /// Copies a value into a callee's frame, 32 times over a kilobyte-deep
    /// array as a real operation's deeper frames would hold it, and returns:
    /// the control that shows a snapshot finds what an operation left behind.
    #[inline(never)]
    pub fn leave<T: Copy>(value: &T) {
        let copies = [*value; 32];
        core::hint::black_box(&copies);
        let deeper = [0u8; 1024];
        core::hint::black_box(&deeper);
    }
}

#[cfg(windows)]
mod os {
    use super::{Mapping, LOCK_GROWTH_STEP, MAX_LOCK_GROWTH};
    use core::ptr::NonNull;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_WORKING_SET_QUOTA};
    use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize};

    /// Bytes this library has added to the working set so far. The lock also
    /// serialises growing, so two threads never read the same old sizes.
    static GROWN: Mutex<usize> = Mutex::new(0);

    /// Committed, zero-filled pages (VirtualAlloc zeroes them), locked if
    /// allowed. Windows has no fork(2), so there is nothing to wipe on fork,
    /// and no call that keeps pages out of every crash dump.
    pub fn map(bytes: usize, _wipe_on_fork: bool) -> Option<Mapping> {
        let size = bytes.div_ceil(4096) * 4096;
        // SAFETY: plain allocation call; the result is checked for null.
        let ptr = NonNull::new(unsafe { VirtualAlloc(core::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }.cast::<u8>())?;
        let locked = lock(ptr, size);
        Some(Mapping { ptr, size, locked, dump_excluded: false, wiped_on_fork: false })
    }

    /// VirtualLock on a region just committed.
    fn try_lock(ptr: NonNull<u8>, size: usize) -> bool {
        // SAFETY: the region is committed and owned by the caller.
        unsafe { VirtualLock(ptr.as_ptr().cast(), size) != 0 }
    }

    /// Locks the region; if the working-set quota refuses it, grows the
    /// minimum and maximum working set (by at least 1 MB, at most 64 MB in
    /// all) and tries once more. "The maximum number of pages that a process
    /// can lock is equal to the number of pages in its minimum working set
    /// minus a small overhead" (VirtualLock, Microsoft Learn).
    fn lock(ptr: NonNull<u8>, size: usize) -> bool {
        if try_lock(ptr, size) {
            return true;
        }
        // SAFETY: reads the calling thread's last error, set by VirtualLock.
        if unsafe { GetLastError() } != ERROR_WORKING_SET_QUOTA {
            return false;
        }
        let mut grown = GROWN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Another thread may have grown the working set while this one waited.
        if try_lock(ptr, size) {
            return true;
        }
        let step = (size + 16 * 4096).max(LOCK_GROWTH_STEP);
        if *grown + step > MAX_LOCK_GROWTH {
            return false;
        }
        let (mut min, mut max) = (0usize, 0usize);
        // SAFETY: the pseudo-handle of this process, which has every access
        // right (PROCESS_SET_QUOTA included); the out-pointers are live.
        let set = unsafe {
            let process = GetCurrentProcess();
            GetProcessWorkingSetSize(process, &mut min, &mut max) != 0 && SetProcessWorkingSetSize(process, min + step, max + step) != 0
        };
        if !set {
            return false;
        }
        *grown += step;
        try_lock(ptr, size)
    }

    /// # Safety
    /// `ptr` and `size` must come from `map`, released once.
    pub unsafe fn unmap(ptr: NonNull<u8>, size: usize, locked: bool) {
        if locked {
            VirtualUnlock(ptr.as_ptr().cast(), size);
        }
        VirtualFree(ptr.as_ptr().cast(), 0, MEM_RELEASE);
    }
}

#[cfg(unix)]
mod os {
    use super::Mapping;
    use core::ptr::NonNull;

    /// Anonymous private pages (zero-filled), locked if allowed and, on
    /// Linux, excluded from core dumps and optionally wiped in fork children.
    pub fn map(bytes: usize, wipe_on_fork: bool) -> Option<Mapping> {
        // SAFETY: sysconf has no preconditions.
        let page = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            p if p > 0 => p as usize,
            _ => 4096,
        };
        let size = bytes.div_ceil(page) * page;
        // SAFETY: a fresh anonymous mapping; the result is checked.
        let raw = unsafe { libc::mmap(core::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if raw == libc::MAP_FAILED {
            return None;
        }
        let locked = lock(raw, size);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: our own fresh private anonymous mapping, whose contents
        // neither advice changes. A kernel older than 4.14 refuses
        // MADV_WIPEONFORK; the process-ID check in random.rs still catches
        // the fork.
        let (dump_excluded, wiped_on_fork) = unsafe { (advise(raw, size, libc::MADV_DONTDUMP), wipe_on_fork && advise(raw, size, libc::MADV_WIPEONFORK)) };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let (dump_excluded, wiped_on_fork) = {
            let _ = wipe_on_fork;
            (false, false)
        };
        Some(Mapping { ptr: NonNull::new(raw.cast::<u8>())?, size, locked, dump_excluded, wiped_on_fork })
    }

    /// mlock(2) on a region just mapped.
    fn try_lock(raw: *mut libc::c_void, size: usize) -> bool {
        // SAFETY: the region was just mapped by the caller.
        unsafe { libc::mlock(raw, size) == 0 }
    }

    /// Bytes this library has added to RLIMIT_MEMLOCK so far; the lock also
    /// serialises raising it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static GROWN: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

    /// Locks the region; if RLIMIT_MEMLOCK refuses it (ENOMEM, or EPERM at a
    /// zero limit, mlock(2)), raises the soft limit towards the hard one (by
    /// at least 1 MB, at most 64 MB in all) and tries once more. An
    /// unprivileged process may raise its soft limit up to the hard limit
    /// (setrlimit(2)).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn lock(raw: *mut libc::c_void, size: usize) -> bool {
        use super::{LOCK_GROWTH_STEP, MAX_LOCK_GROWTH};
        if try_lock(raw, size) {
            return true;
        }
        let err = std::io::Error::last_os_error().raw_os_error();
        if err != Some(libc::ENOMEM) && err != Some(libc::EPERM) {
            return false;
        }
        let mut grown = GROWN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if try_lock(raw, size) {
            return true;
        }
        let step = (size + 16 * 4096).max(LOCK_GROWTH_STEP);
        if *grown + step > MAX_LOCK_GROWTH {
            return false;
        }
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit fills the struct it is given.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
            return false;
        }
        if limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur >= limit.rlim_max {
            return false;
        }
        let raised = libc::rlimit { rlim_cur: limit.rlim_cur.saturating_add(step as libc::rlim_t).min(limit.rlim_max), rlim_max: limit.rlim_max };
        // SAFETY: setrlimit reads the struct it is given.
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) } != 0 {
            return false;
        }
        *grown += step;
        try_lock(raw, size)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn lock(raw: *mut libc::c_void, size: usize) -> bool {
        try_lock(raw, size)
    }

    /// madvise(2), reporting whether the kernel took the advice. It refuses
    /// advice it does not know, such as MADV_WIPEONFORK before Linux 4.14.
    ///
    /// # Safety
    /// `raw` and `size` must describe a mapping made by `map`, and `advice`
    /// must leave its contents as they are.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub unsafe fn advise(raw: *mut libc::c_void, size: usize, advice: libc::c_int) -> bool {
        libc::madvise(raw, size, advice) == 0
    }

    /// # Safety
    /// `ptr` and `size` must come from `map`, released once.
    pub unsafe fn unmap(ptr: NonNull<u8>, size: usize, locked: bool) {
        if locked {
            libc::munlock(ptr.as_ptr().cast(), size);
        }
        libc::munmap(ptr.as_ptr().cast(), size);
    }
}

#[cfg(not(any(windows, unix)))]
mod os {
    use super::Mapping;
    use core::ptr::NonNull;

    pub fn map(_bytes: usize, _wipe_on_fork: bool) -> Option<Mapping> {
        None
    }

    /// # Safety
    /// Never called: `map` never succeeds here.
    pub unsafe fn unmap(_ptr: NonNull<u8>, _size: usize, _locked: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_zeroed_and_holds_values() {
        let mut b: SecretBox<[[u8; 16]; 25]> = SecretBox::zeroed();
        assert!(b.iter().flatten().all(|&x| x == 0));
        b[3][7] = 0x5a;
        assert_eq!(b[3][7], 0x5a);
    }

    // On this project's development machine (Windows), a small allocation is
    // locked; elsewhere the fallback is allowed but must still work.
    #[test]
    #[cfg(windows)]
    fn small_secrets_are_locked_on_windows() {
        let b: SecretBox<[u8; 32]> = SecretBox::zeroed();
        assert!(b.locked());
        // Windows has no call that keeps pages out of every crash dump, and
        // no fork, so both report false rather than a protection not given.
        let w: SecretBox<[u8; 32]> = SecretBox::zeroed_fork_wiped();
        assert!(!b.dump_excluded() && !w.dump_excluded() && !w.wiped_on_fork());
    }

    // More secret memory than the default quota covers (a 200 KB minimum
    // working set locks about 44 pages; these are 384) is all locked: the
    // allocation grows the working set when the quota refuses a lock.
    // Before, the third Turing-1026 key and every workspace after it were
    // left unlocked.
    #[test]
    #[cfg(windows)]
    fn secrets_beyond_the_default_quota_are_locked_on_windows() {
        let boxes: Vec<SecretBox<[u8; 64 * 1024]>> = (0..24).map(|_| SecretBox::zeroed()).collect();
        let unlocked = boxes.iter().filter(|b| !b.locked()).count();
        assert_eq!(unlocked, 0, "{unlocked} of 24 boxes of 64 KB unlocked");
    }

    // The same on Linux: with the soft RLIMIT_MEMLOCK lowered to 64 KB (in a
    // child process, so no other test sees the limit), 8 boxes of 64 KB are
    // still all locked, because the soft limit is raised towards the hard
    // one. Control: at a hard limit of 64 KB nothing can be raised, and the
    // refusals are counted.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_raises_the_soft_memlock_limit() {
        let run = |hard_too: bool| -> [u8; 3] {
            in_child(move || {
                let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                // SAFETY: plain limit calls on this child process.
                unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
                let low = 64 * 1024;
                let max = if hard_too { low } else { limit.rlim_max };
                // SAFETY: as above.
                let ok = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &libc::rlimit { rlim_cur: low, rlim_max: max }) } == 0;
                let before = unlocked_allocations();
                let boxes: Vec<SecretBox<[u8; 64 * 1024]>> = (0..8).map(|_| SecretBox::zeroed()).collect();
                let locked = boxes.iter().filter(|b| b.locked()).count() as u8;
                [u8::from(ok), locked, (unlocked_allocations() - before) as u8]
            })
        };
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: reads this process's limit.
        unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
        if limit.rlim_max != libc::RLIM_INFINITY && limit.rlim_max < 2 << 20 {
            eprintln!("hard RLIMIT_MEMLOCK below 2 MB: nothing to raise into, test skipped");
            return;
        }
        let [ok, locked, refused] = run(false);
        assert!(ok == 1 && locked == 8 && refused == 0, "soft limit 64 KB: {locked} of 8 locked, {refused} counted");
        let [ok, locked, refused] = run(true);
        assert!(ok == 1 && locked < 8 && u32::from(refused) == 8 - u32::from(locked), "control: hard limit 64 KB locked {locked}, counted {refused}");
    }

    /// Runs `child` in a forked child and returns the 3 bytes it writes back.
    #[cfg(target_os = "linux")]
    fn in_child(child: impl FnOnce() -> [u8; 3]) -> [u8; 3] {
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
                let mut out = [0u8; 3];
                // SAFETY: reads into `out`; waits for our own child.
                unsafe {
                    assert_eq!(libc::read(fds[0], out.as_mut_ptr().cast(), 3), 3, "child wrote nothing");
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                out
            }
            _ => panic!("fork failed"),
        }
    }

    #[test]
    fn many_boxes_do_not_share_locks() {
        let boxes: Vec<SecretBox<[u8; 64]>> = (0..8).map(|_| SecretBox::zeroed()).collect();
        let pages: std::collections::HashSet<usize> = boxes.iter().map(|b| b.ptr.as_ptr() as usize / 4096).collect();
        assert_eq!(pages.len(), boxes.len(), "one allocation per secret");
    }

    // The frame burn_stack wipes is the one a previous call used: a value left
    // there by a callee is gone afterwards. `leave` returns the address it
    // wrote to; reading it back after both calls return is reading dead stack,
    // done with a volatile read of memory that is still mapped.
    #[inline(never)]
    fn leave(marker: u64) -> usize {
        let slot = [marker; 64];
        core::hint::black_box(&slot);
        slot.as_ptr() as usize + 8 * 32
    }

    #[test]
    fn burn_stack_wipes_what_a_callee_left() {
        let marker = 0x7475_7269_6e67_2121;
        let addr = leave(marker);
        // SAFETY: addr is in this thread's stack, which stays mapped.
        let before = unsafe { (addr as *const u64).read_volatile() };
        assert_eq!(before, marker, "control: the callee's value is still there");
        let addr = leave(marker);
        burn_stack();
        // SAFETY: as above.
        let after = unsafe { (addr as *const u64).read_volatile() };
        assert_eq!(after, 0);
    }

    /// The VmFlags line of /proc/self/smaps for the mapping holding `addr`.
    #[cfg(target_os = "linux")]
    fn vm_flags(addr: usize) -> Vec<String> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").expect("smaps");
        let mut inside = false;
        for line in smaps.lines() {
            let range = line.split(' ').next().and_then(|r| r.split_once('-'));
            if let Some((a, b)) = range.and_then(|(a, b)| Some((usize::from_str_radix(a, 16).ok()?, usize::from_str_radix(b, 16).ok()?))) {
                inside = a <= addr && addr < b;
            } else if let (true, Some(flags)) = (inside, line.strip_prefix("VmFlags:")) {
                return flags.split_whitespace().map(String::from).collect();
            }
        }
        panic!("no mapping holds {addr:#x}");
    }

    // proc(5): "lo" pages are locked in memory, "dd" do not include area into
    // core dump, "wf" wipe on fork. What each box reports is what the kernel
    // shows.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_pages_are_locked_and_left_out_of_dumps() {
        let plain: SecretBox<[u8; 32]> = SecretBox::zeroed();
        let wiped: SecretBox<[u8; 32]> = SecretBox::zeroed_fork_wiped();
        let flags = vm_flags(plain.ptr.as_ptr() as usize);
        assert!(plain.locked() && flags.contains(&"lo".into()) && flags.contains(&"dd".into()), "{flags:?}");
        assert!(!flags.contains(&"wf".into()));
        assert!(plain.dump_excluded() && !plain.wiped_on_fork());
        let flags = vm_flags(wiped.ptr.as_ptr() as usize);
        assert!(flags.contains(&"wf".into()) && flags.contains(&"dd".into()), "{flags:?}");
        assert!(wiped.dump_excluded() && wiped.wiped_on_fork());
        // Control: ordinary heap memory has none of these.
        let heap = vec![0u8; 1 << 20];
        let flags = vm_flags(heap.as_ptr() as usize);
        assert!(!flags.contains(&"lo".into()) && !flags.contains(&"dd".into()), "{flags:?}");
    }

    // Advice the kernel refuses (here, advice it does not know, as a kernel
    // before 4.14 does not know MADV_WIPEONFORK) is reported as refused, so
    // a box never claims a protection it did not get.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn refused_advice_is_reported_as_refused() {
        let b: SecretBox<[u8; 32]> = SecretBox::zeroed();
        assert!(b.mapped > 0, "a mapping, not the heap fallback");
        let raw = b.ptr.as_ptr().cast::<libc::c_void>();
        // SAFETY: the box's own mapping; neither advice changes its contents.
        unsafe {
            assert!(!os::advise(raw, b.mapped, -1));
            assert!(os::advise(raw, b.mapped, libc::MADV_DONTDUMP));
        }
    }
}
