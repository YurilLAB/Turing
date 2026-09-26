//! Memory for keys. Each secret gets its own page-aligned allocation that the
//! operating system keeps out of the page file (VirtualLock on Windows, mlock
//! on Unix) and, on Linux, out of core dumps (madvise MADV_DONTDUMP).
//! Microsoft documents that locked pages "are guaranteed not to be written to
//! the pagefile while they are locked"; mlock(2) that locked pages stay
//! resident in RAM. Page locks carry no count, so unlocking one allocation
//! would unlock any other secret on the same page: hence one allocation per
//! secret. Contents are wiped before the memory goes back to the system.
//!
//! Locking can be refused (Windows allows about the minimum working set,
//! Unix RLIMIT_MEMLOCK). The value then lives in ordinary memory, `locked()`
//! says so, and it is still wiped. Hibernation writes all of RAM to disk,
//! locked or not; only full-disk encryption covers that. mlock(2) is not
//! inherited across fork(2): a child process that keeps using a cipher made
//! before the fork holds its keys in pages that may be swapped.
//!
//! Values computed on the way to a key (the whitened key, Feistel halves,
//! Keccak states) pass through the stack, and compiler temporaries there are
//! out of reach of `zeroize`. `burn_stack` overwrites the stack below the
//! caller after key setup, as libgcrypt's `_gcry_burn_stack` does after its
//! key schedules; Bombe's memory scan (docs/13) checks that nothing is left.

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use zeroize::Zeroize;

/// Plain data for which all-zero bytes are a valid value, so fresh zeroed
/// pages can hold it, and which contains no pointers.
///
/// # Safety
/// Implement only for such types.
pub unsafe trait Zeroable: Zeroize {}
unsafe impl Zeroable for u8 {}
unsafe impl Zeroable for u64 {}
unsafe impl<T: Zeroable, const N: usize> Zeroable for [T; N] where [T; N]: Zeroize {}

/// A value in its own locked, wiped-on-drop allocation.
pub struct SecretBox<T: Zeroable> {
    ptr: NonNull<T>,
    /// Bytes mapped from the OS, or 0 for the ordinary-heap fallback.
    mapped: usize,
    locked: bool,
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
        match os::map(bytes, wipe_on_fork) {
            Some((ptr, mapped, locked)) => SecretBox { ptr: ptr.cast(), mapped, locked },
            None => {
                let layout = std::alloc::Layout::new::<T>();
                // SAFETY: the layout has non-zero size; zeroed memory is a valid T (Zeroable).
                let raw = unsafe { std::alloc::alloc_zeroed(layout) };
                let ptr = NonNull::new(raw.cast::<T>()).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
                SecretBox { ptr, mapped: 0, locked: false }
            }
        }
    }

    /// Whether the operating system agreed to keep this memory out of the
    /// page file.
    pub fn locked(&self) -> bool {
        self.locked
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

#[cfg(windows)]
mod os {
    use core::ptr::NonNull;
    use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

    /// Committed, zero-filled pages (VirtualAlloc zeroes them), locked if
    /// allowed. Windows has no fork(2), so there is nothing to wipe on fork.
    pub fn map(bytes: usize, _wipe_on_fork: bool) -> Option<(NonNull<u8>, usize, bool)> {
        let size = bytes.div_ceil(4096) * 4096;
        // SAFETY: plain allocation call; the result is checked for null.
        let ptr = NonNull::new(unsafe { VirtualAlloc(core::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }.cast::<u8>())?;
        // SAFETY: the region was just committed.
        let locked = unsafe { VirtualLock(ptr.as_ptr().cast(), size) } != 0;
        Some((ptr, size, locked))
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
    use core::ptr::NonNull;

    /// Anonymous private pages (zero-filled), locked if allowed and, on
    /// Linux, excluded from core dumps and optionally wiped in fork children.
    pub fn map(bytes: usize, wipe_on_fork: bool) -> Option<(NonNull<u8>, usize, bool)> {
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
        // SAFETY: the region was just mapped.
        let locked = unsafe { libc::mlock(raw, size) } == 0;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: advisory calls on our own private anonymous mapping. If the
        // kernel predates MADV_WIPEONFORK the call fails and the process-ID
        // check in random.rs still catches the fork.
        unsafe {
            libc::madvise(raw, size, libc::MADV_DONTDUMP);
            if wipe_on_fork {
                libc::madvise(raw, size, libc::MADV_WIPEONFORK);
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = wipe_on_fork;
        Some((NonNull::new(raw.cast::<u8>())?, size, locked))
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
    use core::ptr::NonNull;

    pub fn map(_bytes: usize, _wipe_on_fork: bool) -> Option<(NonNull<u8>, usize, bool)> {
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
    // core dump, "wf" wipe on fork.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_pages_are_locked_and_left_out_of_dumps() {
        let plain: SecretBox<[u8; 32]> = SecretBox::zeroed();
        let wiped: SecretBox<[u8; 32]> = SecretBox::zeroed_fork_wiped();
        let flags = vm_flags(plain.ptr.as_ptr() as usize);
        assert!(plain.locked() && flags.contains(&"lo".into()) && flags.contains(&"dd".into()), "{flags:?}");
        assert!(!flags.contains(&"wf".into()));
        let flags = vm_flags(wiped.ptr.as_ptr() as usize);
        assert!(flags.contains(&"wf".into()) && flags.contains(&"dd".into()), "{flags:?}");
        // Control: ordinary heap memory has none of these.
        let heap = vec![0u8; 1 << 20];
        let flags = vm_flags(heap.as_ptr() as usize);
        assert!(!flags.contains(&"lo".into()) && !flags.contains(&"dd".into()), "{flags:?}");
    }
}
