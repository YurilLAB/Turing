//! sc_rust_cmov_probe.rs: does the RustCrypto `cmov` crate (0.5.4) give a
//! branch-free select in rustc output, and how does the Valgrind
//! secret-poisoning method (ctgrind / TIMECOP) see its CMOV instructions?
//!
//! The crate describes itself as "guaranteed on major platforms ... to
//! execute in constant-time and not be rewritten as branches" (crates.io).
//! Its x86 backend emits `test` + `cmovnz` in inline assembly
//! (cmov-0.5.4/src/backends/x86.rs). This probe runs one select per case on
//! a secret (Valgrind-undefined) condition:
//!   cmov_u32    u32::cmovnz from the crate
//!   cmov_arr    [u8; 32]::cmovnz from the crate
//!   mask_u32    hand-written mask select, x ^ (m & (x ^ y))  (the pattern of
//!               pq-crystals cmov and of Turing's own code)
//!   maskbar_u32 the same with the mask hidden behind an empty asm block
//!   branch_u32  an explicit branch on the secret (positive control)
//! Valgrind client requests are issued from Rust with the same inline
//! assembly as sc_rust_ct_probe.rs (bytes of VALGRIND_DO_CLIENT_REQUEST_EXPR
//! for amd64 from valgrind.h; MAKE_MEM_UNDEFINED/DEFINED from memcheck.h).
//! Built by sc_rust_cmov_probe.py as a no_std staticlib for
//! x86_64-unknown-linux-gnu, with the cmov crate compiled from the local
//! cargo cache as an rlib, and linked statically by gcc in WSL.
#![no_std]
#![no_main]

use cmov::Cmov;
use core::arch::asm;

extern "C" {
    fn printf(fmt: *const u8, ...) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

const MC_BASE: usize = ((b'M' as usize) << 24) | ((b'C' as usize) << 16);
const MAKE_MEM_UNDEFINED: usize = MC_BASE + 1;
const MAKE_MEM_DEFINED: usize = MC_BASE + 2;

#[inline(always)]
fn vg_request(request: usize, a1: usize, a2: usize) -> usize {
    let args: [usize; 6] = [request, a1, a2, 0, 0, 0];
    let result: usize;
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

#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_cmov_u32(x: &mut u32, y: &u32, cond: u8) {
    x.cmovnz(y, cond);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_cmov_arr(x: &mut [u8; 32], y: &[u8; 32], cond: u8) {
    x.cmovnz(y, cond);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_mask_u32(x: &mut u32, y: &u32, cond: u8) {
    let m = 0u32.wrapping_sub(((cond as u32) | (cond as u32).wrapping_neg()) >> 31);
    *x ^= m & (*x ^ *y);
}

/// The same mask select with the mask passed through an empty asm block (the
/// pq-crystals 7dff53d idea), so LLVM cannot see that it is 0 or all ones.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_maskbar_u32(x: &mut u32, y: &u32, cond: u8) {
    let mut m = 0u32.wrapping_sub(((cond as u32) | (cond as u32).wrapping_neg()) >> 31);
    unsafe { asm!("/* {0:e} */", inout(reg) m, options(pure, nomem, nostack)) };
    *x ^= m & (*x ^ *y);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rs_branch_u32(x: &mut u32, y: &u32, cond: u8) {
    if cond != 0 {
        unsafe { core::ptr::write_volatile(x, *y) };
    }
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
    if argc < 3 {
        return 2;
    }
    let case = unsafe { *argv.add(1) };
    let c = unsafe { **argv.add(2) } - b'0'; // condition 0 or 1 from the command line
    let mut cond = [c];
    let mut x: u32 = 0x1111_1111;
    let y: u32 = 0x2222_2222;
    let mut xa = [0x11u8; 32];
    let ya = [0x22u8; 32];
    secret(&cond);
    let cnd = unsafe { core::ptr::read_volatile(&cond[0]) };
    let is = |s: &[u8]| unsafe { cstr_eq(case, s) };
    let out: u32;
    if is(b"cmov_u32") {
        rs_cmov_u32(&mut x, &y, cnd); declassify(&x); out = x;
    } else if is(b"cmov_arr") {
        rs_cmov_arr(&mut xa, &ya, cnd); declassify(&xa); out = xa[0] as u32 | (xa[31] as u32) << 8;
    } else if is(b"mask_u32") {
        rs_mask_u32(&mut x, &y, cnd); declassify(&x); out = x;
    } else if is(b"maskbar_u32") {
        rs_maskbar_u32(&mut x, &y, cnd); declassify(&x); out = x;
    } else if is(b"branch_u32") {
        rs_branch_u32(&mut x, &y, cnd); declassify(&x); out = x;
    } else {
        return 2;
    }
    cond[0] = 0;
    unsafe { printf(b"%s %08x\n\0".as_ptr(), case, out) };
    0
}
