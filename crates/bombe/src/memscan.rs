//! A memory-dump attacker. Cold-boot attacks (Halderman et al., USENIX
//! Security 2008) read a machine's RAM after power-off, a crash dump or
//! hibernation file holds a process's memory, and RAMBleed (Kwong et al.,
//! IEEE S&P 2020) reads it bit by bit from another process. Each is only as
//! good as what is still in memory, so this reads every readable page of the
//! running process and reports every place key material appears.
//!
//! Secrets are searched for as aligned 8-byte fragments, so a partial copy
//! of 15 or more bytes is found too. The search list holds each fragment
//! XORed with a random pad, and the comparison is done on memory XOR pad,
//! so the list itself contains no key material for the scan to find.
//!
//! The code under test runs on its own thread, which parks without making
//! any call after each step (`Parker`), and the scan runs from the main
//! thread: the dead stack below the worker's frame keeps whatever the step
//! left there, where a scan on the same thread would overwrite it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A readable stretch of the address space.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub start: usize,
    pub len: usize,
    /// Start of the allocation it belongs to (a thread's whole stack, say).
    pub base: usize,
    pub kind: &'static str,
}

/// Where a fragment of a secret was found.
#[derive(Clone, Copy, Debug)]
pub struct Hit {
    pub secret: usize,
    pub address: usize,
    pub base: usize,
    pub kind: &'static str,
}

/// Secrets to look for, as padded 8-byte fragments.
pub struct Needles {
    pad: u64,
    fragments: HashMap<u64, usize>,
    filter: Vec<u64>,
    names: Vec<String>,
}

impl Default for Needles {
    fn default() -> Self {
        Needles::new()
    }
}

impl Needles {
    pub fn new() -> Needles {
        let mut pad = [0u8; 8];
        turing::random::os_random(&mut pad).expect("OS randomness");
        Needles { pad: u64::from_le_bytes(pad), fragments: HashMap::new(), filter: vec![0; 1024], names: Vec::new() }
    }

    /// Adds every aligned 8-byte fragment of `secret` (a multiple of 8
    /// bytes long) under `name`, and returns the secret's index.
    pub fn add(&mut self, name: &str, secret: &[u8]) -> usize {
        assert!(secret.len().is_multiple_of(8) && !secret.is_empty());
        let index = self.names.len();
        self.names.push(name.to_string());
        for chunk in secret.chunks_exact(8) {
            let masked = u64::from_le_bytes(chunk.try_into().expect("8 bytes")) ^ self.pad;
            self.filter[(masked & 0xffff) as usize / 64] |= 1 << (masked % 64);
            self.fragments.insert(masked, index);
        }
        index
    }

    pub fn name(&self, secret: usize) -> &str {
        &self.names[secret]
    }

    pub fn secrets(&self) -> usize {
        self.names.len()
    }

    fn find(&self, window: u64) -> Option<usize> {
        let masked = window ^ self.pad;
        if self.filter[(masked & 0xffff) as usize / 64] >> (masked % 64) & 1 == 0 {
            return None;
        }
        self.fragments.get(&masked).copied()
    }
}

const CHUNK: usize = 1 << 20;

/// Every place in this process's readable memory where a fragment of one of
/// the needles appears.
pub struct Scan {
    pub hits: Vec<Hit>,
    pub bytes: usize,
    pub regions: usize,
}

impl Scan {
    /// Hits outside the given address ranges (where a secret belongs).
    pub fn outside(&self, allowed: &[(usize, usize)]) -> Vec<Hit> {
        self.hits.iter().copied().filter(|h| !allowed.iter().any(|&(start, len)| h.address >= start && h.address < start + len)).collect()
    }

    /// Hits of one secret.
    pub fn of(&self, secret: usize) -> Vec<Hit> {
        self.hits.iter().copied().filter(|h| h.secret == secret).collect()
    }
}

/// Reads all readable memory and records every needle fragment in it. The
/// read buffer is its own allocation, skipped, and wiped after each chunk.
pub fn scan(needles: &Needles) -> Scan {
    let buffer = os::Buffer::new(CHUNK + 7);
    let own = buffer.range();
    let regions = os::regions();
    let (mut hits, mut bytes) = (Vec::new(), 0);
    for r in &regions {
        if r.start < own.0 + own.1 && own.0 < r.start + r.len {
            continue;
        }
        let mut offset = 0;
        while offset < r.len {
            let n = (r.len - offset).min(CHUNK + 7);
            let buf = buffer.slice(n);
            let got = os::read(r.start + offset, buf);
            bytes += got.min(CHUNK);
            for i in 0..got.saturating_sub(7) {
                let window = u64::from_le_bytes(buf[i..i + 8].try_into().expect("8 bytes"));
                if let Some(secret) = needles.find(window) {
                    hits.push(Hit { secret, address: r.start + offset + i, base: r.base, kind: r.kind });
                }
            }
            buffer.wipe();
            offset += CHUNK;
        }
    }
    Scan { hits, bytes, regions: regions.len() }
}

/// The region holding `address`, if readable.
pub fn region_of(address: usize) -> Option<Region> {
    os::regions().into_iter().find(|r| address >= r.start && address < r.start + r.len)
}

/// A worker's handle for pausing between steps. `park` spins on an atomic
/// and is inlined, so parking writes nothing below the caller's frame.
pub struct Parker {
    reached: AtomicUsize,
    release: AtomicUsize,
    stack: AtomicUsize,
}

impl Parker {
    #[inline(always)]
    pub fn park(&self, step: usize) {
        let marker = 0u8;
        self.stack.store(core::hint::black_box(&marker) as *const u8 as usize, Ordering::Release);
        self.reached.store(step, Ordering::Release);
        while self.release.load(Ordering::Acquire) < step {
            core::hint::spin_loop();
        }
    }
}

/// Runs `worker` on a new thread. Each time it calls `park(step)` with
/// steps 1, 2, ..., `at_step(step, stack)` runs on this thread while the
/// worker waits; `stack` is the allocation base of the worker's stack.
pub fn run_parked<R>(worker: impl FnOnce(&Parker) + Send, steps: usize, mut at_step: impl FnMut(usize, usize) -> R) -> Vec<R> {
    let parker = Parker { reached: AtomicUsize::new(0), release: AtomicUsize::new(0), stack: AtomicUsize::new(0) };
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| worker(&parker));
        let mut out = Vec::new();
        for step in 1..=steps {
            while parker.reached.load(Ordering::Acquire) < step {
                assert!(!handle.is_finished(), "worker ended before step {step}");
                std::thread::yield_now();
            }
            let stack = region_of(parker.stack.load(Ordering::Acquire)).map_or(0, |r| r.base);
            out.push(at_step(step, stack));
            parker.release.store(step, Ordering::Release);
        }
        handle.join().expect("worker");
        out
    })
}

/// How many bytes of stack `f` uses below the caller: paint the stack below
/// this frame, run `f`, and find the deepest word that changed.
pub fn stack_depth(f: impl FnOnce()) -> usize {
    const PAINT: u64 = 0x5a5a_c3c3_a5a5_3c3c;
    const PAINT_BYTES: usize = 256 * 1024;
    #[inline(never)]
    fn paint() -> usize {
        let mut area = [PAINT; PAINT_BYTES / 8];
        core::hint::black_box(&mut area);
        area.as_ptr() as usize
    }
    // A local, not `&0u8`, which would be promoted to a static.
    let here = 0u8;
    let top = core::hint::black_box(&here) as *const u8 as usize;
    let low = paint();
    f();
    let mut addr = low;
    while addr < top {
        // SAFETY: [low, top) is this thread's stack, painted above and still
        // mapped; reading it disturbs nothing.
        if unsafe { (addr as *const u64).read_volatile() } != PAINT {
            return top - addr;
        }
        addr += 8;
    }
    0
}

#[cfg(windows)]
mod os {
    use super::Region;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    pub fn regions() -> Vec<Region> {
        let (mut out, mut addr) = (Vec::new(), 0usize);
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: VirtualQuery fills `info` for any address.
            if unsafe { VirtualQuery(addr as *const _, &mut info, core::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 {
                break;
            }
            let (start, len) = (info.BaseAddress as usize, info.RegionSize);
            let readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            if info.State == MEM_COMMIT && info.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0 && info.Protect & readable != 0 {
                let kind = match info.Type {
                    MEM_IMAGE => "image",
                    MEM_MAPPED => "mapped",
                    _ => "private",
                };
                out.push(Region { start, len, base: info.AllocationBase as usize, kind });
            }
            match start.checked_add(len) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }
        out
    }

    /// Copies from our own address space; a page that went away meanwhile
    /// makes the call fail instead of faulting.
    pub fn read(addr: usize, buf: &mut [u8]) -> usize {
        let mut got = 0usize;
        // SAFETY: the destination is our buffer; the source is only read.
        let ok = unsafe { ReadProcessMemory(GetCurrentProcess(), addr as *const _, buf.as_mut_ptr().cast(), buf.len(), &mut got) };
        if ok == 0 {
            0
        } else {
            got
        }
    }

    pub struct Buffer {
        ptr: *mut u8,
        len: usize,
    }

    impl Buffer {
        pub fn new(len: usize) -> Buffer {
            // SAFETY: plain allocation; checked below.
            let ptr = unsafe { VirtualAlloc(core::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }.cast::<u8>();
            assert!(!ptr.is_null(), "scan buffer");
            Buffer { ptr, len }
        }

        pub fn range(&self) -> (usize, usize) {
            (self.ptr as usize, self.len.div_ceil(4096) * 4096)
        }

        #[allow(clippy::mut_from_ref)]
        pub fn slice(&self, n: usize) -> &mut [u8] {
            // SAFETY: n <= len; the buffer is used by one thread at a time.
            unsafe { core::slice::from_raw_parts_mut(self.ptr, n.min(self.len)) }
        }

        pub fn wipe(&self) {
            zeroize::Zeroize::zeroize(self.slice(self.len));
        }
    }

    impl Drop for Buffer {
        fn drop(&mut self) {
            self.wipe();
            // SAFETY: allocated by VirtualAlloc above, released once.
            unsafe { VirtualFree(self.ptr.cast(), 0, MEM_RELEASE) };
        }
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::Region;
    use std::os::unix::fs::FileExt;

    pub fn regions() -> Vec<Region> {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
        let mut out = Vec::new();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let (Some(range), Some(perms)) = (fields.next(), fields.next()) else { continue };
            let path = fields.nth(3).unwrap_or("");
            let Some((a, b)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) = (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16)) else { continue };
            if !perms.starts_with('r') || path.starts_with("[vvar") || path == "[vsyscall]" {
                continue;
            }
            let kind = match path {
                "" => "private",
                "[heap]" => "heap",
                "[stack]" => "main stack",
                p if p.starts_with('[') => "special",
                _ => "file",
            };
            out.push(Region { start, len: end - start, base: start, kind });
        }
        out
    }

    pub fn read(addr: usize, buf: &mut [u8]) -> usize {
        let Ok(mem) = std::fs::File::open("/proc/self/mem") else { return 0 };
        mem.read_at(buf, addr as u64).unwrap_or(0)
    }

    pub struct Buffer {
        ptr: *mut u8,
        len: usize,
    }

    impl Buffer {
        pub fn new(len: usize) -> Buffer {
            // SAFETY: a fresh anonymous mapping; checked below.
            let ptr = unsafe { libc::mmap(core::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
            assert!(ptr != libc::MAP_FAILED, "scan buffer");
            Buffer { ptr: ptr.cast(), len }
        }

        pub fn range(&self) -> (usize, usize) {
            (self.ptr as usize, self.len.div_ceil(4096) * 4096)
        }

        #[allow(clippy::mut_from_ref)]
        pub fn slice(&self, n: usize) -> &mut [u8] {
            // SAFETY: n <= len; the buffer is used by one thread at a time.
            unsafe { core::slice::from_raw_parts_mut(self.ptr, n.min(self.len)) }
        }

        pub fn wipe(&self) {
            zeroize::Zeroize::zeroize(self.slice(self.len));
        }
    }

    impl Drop for Buffer {
        fn drop(&mut self) {
            self.wipe();
            // SAFETY: mapped above, unmapped once.
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }
}
