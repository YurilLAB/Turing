//! sc_rust_ct_probe.rs: the lattice-KEM timing bug classes written in Rust,
//! with Valgrind client requests issued from Rust itself (no C, no crates).
//!
//! Reproduces, for rustc/LLVM, the questions ct_bugclasses.c asks of gcc and
//! clang, for research/notes/pq/side-channels-faults-and-ct-verification.md:
//!   * does a division by the constant q = 3329 on secret data survive as a
//!     `div` instruction (KyberSlash, Bernstein et al., TCHES 2025(2)), and at
//!     which opt-level (cargo's default test profile is opt-level 0)?
//!   * does rustc turn the Kyber `poly_frommsg` mask into a branch
//!     (Clangover, Purnal 2024, for clang), and do the three barriers Rust
//!     code uses (core::hint::black_box, an empty asm!, subtle's
//!     read_volatile) prevent it?
//!   * `a == b` on byte slices (early exit, the FrodoKEM class of Guo,
//!     Johansson, Nilsson, CRYPTO 2020) versus a folded XOR.
//!   * rejection sampling on secret versus declassified (public) input.
//! The client-request encoding is copied from valgrind.h (amd64 Linux:
//! __SPECIAL_INSTRUCTION_PREAMBLE = rolq $3,$13,$61,$51 on %rdi, then
//! xchgq %rbx,%rbx with %rax -> 6-word argument block, result in %rdx) and
//! memcheck.h (VG_USERREQ__MAKE_MEM_UNDEFINED = VG_USERREQ_TOOL_BASE('M','C')
//! + 1, MAKE_MEM_DEFINED = + 2). Outside Valgrind the sequence does nothing.
//!
//! Built by sc_rust_ct_probe.py as a no_std staticlib for
//! x86_64-unknown-linux-gnu and linked statically with gcc inside WSL.
//! Usage of the binary: probe CASE   (see main for the case names)
#![no_std]
#![no_main]

use core::arch::asm;

const N: usize = 256;
const Q: i32 = 3329;

extern "C" {
    fn printf(fmt: *const u8, ...) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The precompiled `core` for x86_64-unknown-linux-gnu is built with
/// unwinding and references this symbol even under panic=abort; nothing
/// calls it here, so an empty definition satisfies the static link.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// ---- Valgrind client requests from Rust ------------------------------------

const MC_BASE: usize = ((b'M' as usize) << 24) | ((b'C' as usize) << 16);
const MAKE_MEM_UNDEFINED: usize = MC_BASE + 1;
const MAKE_MEM_DEFINED: usize = MC_BASE + 2;

#[inline(always)]
fn vg_request(request: usize, a1: usize, a2: usize) -> usize {
    let args: [usize; 6] = [request, a1, a2, 0, 0, 0];
    let result: usize;
    // Same bytes as VALGRIND_DO_CLIENT_REQUEST_EXPR in valgrind.h (amd64).
    // The four rotations add up to 128 bits, so rdi is unchanged; xchg rbx,rbx
    // is a no-op on real hardware. No `nomem`: Valgrind reads `args`.
    unsafe {
        asm!(
            "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") 0usize => result,
            options(nostack)
        );
    }
    result
}

fn secret<T>(p: &T) {
    vg_request(MAKE_MEM_UNDEFINED, p as *const T as usize, core::mem::size_of::<T>());
}

fn declassify<T>(p: &T) {
    vg_request(MAKE_MEM_DEFINED, p as *const T as usize, core::mem::size_of::<T>());
}

/// Declassify a scalar result and read it back from memory, so the value used
/// afterwards is the one Valgrind now considers defined (not a register copy
/// taken before the client request).
fn declassify_val<T: Copy>(x: T) -> T {
    let v = x;
    declassify(&v);
    unsafe { core::ptr::read_volatile(&v) }
}

// ---- the cases -------------------------------------------------------------

/// Pre-fix Kyber poly_tomsg (KyberSlash1), transcribed: `/ Q` on secret data.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_tomsg_div(msg: &mut [u8; 32], a: &[i16; N]) {
    for i in 0..N / 8 {
        msg[i] = 0;
        for j in 0..8 {
            let mut t = a[8 * i + j] as u16;
            t = t.wrapping_add(((t as i16 >> 15) as u16) & Q as u16);
            t = ((((t as u32) << 1) + Q as u32 / 2) / Q as u32) as u16 & 1;
            msg[i] |= (t as u8) << j;
        }
    }
}

/// Fixed poly_tomsg (pq-crystals commit dda29cc): multiply and shift.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_tomsg_mul(msg: &mut [u8; 32], a: &[i16; N]) {
    for i in 0..N / 8 {
        msg[i] = 0;
        for j in 0..8 {
            let mut t = a[8 * i + j] as i32 as u32;
            t <<= 1;
            t = t.wrapping_add(1665);
            t = t.wrapping_mul(80635);
            t >>= 28;
            t &= 1;
            msg[i] |= (t as u8) << j;
        }
    }
}

/// Pre-Clangover poly_frommsg: mask = -bit, coefficient = mask & (q+1)/2.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_frommsg_mask(r: &mut [i16; N], msg: &[u8; 32]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            let mask = -(((msg[i] >> j) & 1) as i16);
            r[8 * i + j] = mask & (((Q + 1) / 2) as i16);
        }
    }
}

/// The same with the bit passed through core::hint::black_box.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_frommsg_blackbox(r: &mut [i16; N], msg: &[u8; 32]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            let b = core::hint::black_box((msg[i] >> j) & 1);
            let mask = -(b as i16);
            r[8 * i + j] = mask & (((Q + 1) / 2) as i16);
        }
    }
}

/// The same with an empty asm! value barrier (the Rust form of the
/// `__asm__("" : "+r"(b))` in pq-crystals commit 7dff53d).
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_frommsg_asm(r: &mut [i16; N], msg: &[u8; 32]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            let mut b = ((msg[i] >> j) & 1) as u16;
            unsafe { asm!("/* {0} */", inout(reg) b, options(pure, nomem, nostack, preserves_flags)) };
            let mask = (b as i16).wrapping_neg();
            r[8 * i + j] = mask & (((Q + 1) / 2) as i16);
        }
    }
}

/// The same with subtle 2.6.1's default barrier: a read_volatile of the bit.
#[inline(never)]
fn volatile_box(x: u8) -> u8 {
    unsafe { core::ptr::read_volatile(&x) }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_frommsg_volatile(r: &mut [i16; N], msg: &[u8; 32]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            let b = volatile_box((msg[i] >> j) & 1);
            let mask = -(b as i16);
            r[8 * i + j] = mask & (((Q + 1) / 2) as i16);
        }
    }
}

/// `==` on slices: Rust lowers it to bcmp/memcmp, which may stop early.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_eq_slice(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a[..] == b[..]
}

/// OR of XORs, one test at the end (the pattern of Turing's `checked()`).
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_eq_fold(a: &[u8; 64], b: &[u8; 64]) -> bool {
    let d = core::hint::black_box(a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)));
    d == 0
}

/// ML-KEM-style rejection sampling of 12-bit values below q.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_rej_uniform(r: &mut [i16; N], buf: &[u8; 504]) -> usize {
    let (mut ctr, mut pos) = (0usize, 0usize);
    while ctr < N && pos + 3 <= buf.len() {
        let v0 = (buf[pos] as u16 | ((buf[pos + 1] as u16) << 8)) & 0xFFF;
        let v1 = ((buf[pos + 1] >> 4) as u16 | ((buf[pos + 2] as u16) << 4)) & 0xFFF;
        pos += 3;
        if (v0 as i32) < Q {
            r[ctr] = v0 as i16;
            ctr += 1;
        }
        if ctr < N && (v1 as i32) < Q {
            r[ctr] = v1 as i16;
            ctr += 1;
        }
    }
    ctr
}

// ---- driver ----------------------------------------------------------------

struct Rng(u32);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

fn fnv(bytes: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for k in 0..bytes.len() {
        let b = unsafe { core::ptr::read_volatile(bytes.as_ptr().add(k)) };
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    h
}

fn as_bytes<T>(x: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(x as *const T as *const u8, core::mem::size_of::<T>()) }
}

unsafe fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (k, &c) in s.iter().enumerate() {
        if *p.add(k) != c {
            return false;
        }
    }
    *p.add(s.len()) == 0
}

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    if argc < 2 {
        return 2;
    }
    let case = unsafe { *argv.add(1) };
    let mut rng = Rng(0x12345678);
    let mut a = [0i16; N];
    for c in a.iter_mut() {
        *c = (rng.next() % Q as u32) as i16 - ((Q - 1) / 2) as i16;
    }
    let mut msg = [0u8; 32];
    for m in msg.iter_mut() {
        *m = rng.next() as u8;
    }
    let mut x = [0u8; 64];
    for v in x.iter_mut() {
        *v = rng.next() as u8;
    }
    let mut y = x;
    y[40] ^= 1;
    let mut buf = [0u8; 504];
    for v in buf.iter_mut() {
        *v = rng.next() as u8;
    }
    let mut out32 = [0u8; 32];
    let mut poly = [0i16; N];
    let h: u32;
    let is = |s: &[u8]| unsafe { cstr_eq(case, s) };
    if is(b"tomsg_div") {
        secret(&a); rs_tomsg_div(&mut out32, &a); declassify(&out32); h = fnv(&out32);
    } else if is(b"tomsg_mul") {
        secret(&a); rs_tomsg_mul(&mut out32, &a); declassify(&out32); h = fnv(&out32);
    } else if is(b"frommsg_mask") {
        secret(&msg); rs_frommsg_mask(&mut poly, &msg); declassify(&poly); h = fnv(as_bytes(&poly));
    } else if is(b"frommsg_blackbox") {
        secret(&msg); rs_frommsg_blackbox(&mut poly, &msg); declassify(&poly); h = fnv(as_bytes(&poly));
    } else if is(b"frommsg_asm") {
        secret(&msg); rs_frommsg_asm(&mut poly, &msg); declassify(&poly); h = fnv(as_bytes(&poly));
    } else if is(b"frommsg_volatile") {
        secret(&msg); rs_frommsg_volatile(&mut poly, &msg); declassify(&poly); h = fnv(as_bytes(&poly));
    } else if is(b"eq_slice") {
        secret(&x); let e = declassify_val(rs_eq_slice(&x, &y)); h = e as u32;
    } else if is(b"eq_fold") {
        secret(&x); let e = declassify_val(rs_eq_fold(&x, &y)); h = e as u32;
    } else if is(b"rej_secret") {
        secret(&buf); let n = declassify_val(rs_rej_uniform(&mut poly, &buf)); declassify(&poly);
        h = n as u32 ^ fnv(as_bytes(&poly));
    } else if is(b"rej_public") {
        let n = rs_rej_uniform(&mut poly, &buf); h = n as u32 ^ fnv(as_bytes(&poly));
    } else if is(b"selftest") {
        // tomsg_div and tomsg_mul agree on every centred coefficient value.
        let mut bad = 0u32;
        let (mut m1, mut m2) = ([0u8; 32], [0u8; 32]);
        for v in -(Q - 1) / 2..=(Q - 1) / 2 {
            let p = [v as i16; N];
            rs_tomsg_div(&mut m1, &p);
            rs_tomsg_mul(&mut m2, &p);
            if m1 != m2 {
                bad += 1;
            }
        }
        unsafe { printf(b"selftest mismatches %u of 3329\n\0".as_ptr(), bad) };
        return (bad != 0) as i32;
    } else {
        return 2;
    }
    unsafe { printf(b"%s %08x\n\0".as_ptr(), case, h) };
    0
}
