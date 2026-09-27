//! sc_fault_victim.rs: the Rust transcription of sc_fault_victim.c (the last
//! step of lattice-KEM decapsulation, three orders), so that the same
//! instruction-skip simulation (sc_fault_sim.c, driven by sc_fault_sim.py
//! with the "rust" option) runs on rustc output.
//!
//! literal  = FIPS 203 Algorithm 18 order: output holds K', overwritten by
//!            K-bar if c != c' (the order Xagawa et al., ASIACRYPT 2021,
//!            defeated by skipping the cmov).
//! ref      = pq-crystals ref/kem.c order: fail = verify; out = K-bar;
//!            cmov(out, K', !fail) ("default fail", Xagawa et al. Sec. 7).
//! hardened = default fail, select mask derived from the full difference
//!            (no 0/1 flag), then an independent recomputation of the
//!            difference that reverts to K-bar unless it is also zero.
//!            A design proposal written for these notes, not from a paper.
//!
//! Built as a no_std staticlib for x86_64-unknown-linux-gnu and linked with
//! sc_fault_victim_rs_main.c (data set-up and printing) inside WSL. All
//! victim functions are in the link section "victim_text".
#![no_std]

use core::arch::asm;

const CTLEN: usize = 64;
const KLEN: usize = 32;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Referenced by the precompiled `core`; never called (panic=abort).
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Hide a value from the optimiser (same idea as the pq-crystals asm barrier).
#[inline(always)]
fn barrier_u8(mut x: u8) -> u8 {
    unsafe { asm!("/* {0} */", inout(reg_byte) x, options(pure, nomem, nostack)) };
    x
}

#[inline(always)]
fn barrier_u32(mut x: u32) -> u32 {
    unsafe { asm!("/* {0:e} */", inout(reg) x, options(pure, nomem, nostack)) };
    x
}

/// Launder a pointer so that the compiler cannot prove it equals an earlier
/// one (forces the second difference pass to reload the ciphertexts).
#[inline(always)]
fn launder(mut p: *const u8) -> *const u8 {
    unsafe { asm!("/* {0} */", inout(reg) p, options(pure, nomem, nostack)) };
    p
}

/// ref/verify.c verify(): 0 if equal, 1 otherwise.
#[inline(never)]
#[link_section = "victim_text"]
fn verify(a: &[u8; CTLEN], b: &[u8; CTLEN]) -> u8 {
    let mut r: u8 = 0;
    for i in 0..CTLEN {
        r |= a[i] ^ b[i];
    }
    (0u64.wrapping_sub(r as u64) >> 63) as u8
}

/// ref/verify.c cmov(): r = x if b == 1.
#[inline(never)]
#[link_section = "victim_text"]
fn cmov(r: &mut [u8; KLEN], x: &[u8; KLEN], b: u8) {
    let m = barrier_u8(b).wrapping_neg();
    for i in 0..KLEN {
        r[i] ^= m & (r[i] ^ x[i]);
    }
}

#[no_mangle]
#[inline(never)]
#[link_section = "victim_text"]
pub extern "C" fn rs_tail_literal(ss: &mut [u8; KLEN], ct: &[u8; CTLEN], cmp: &[u8; CTLEN],
                                  kr: &[u8; KLEN], rk: &[u8; KLEN]) {
    *ss = *kr;
    let fail = verify(ct, cmp);
    cmov(ss, rk, fail);
}

#[no_mangle]
#[inline(never)]
#[link_section = "victim_text"]
pub extern "C" fn rs_tail_ref(ss: &mut [u8; KLEN], ct: &[u8; CTLEN], cmp: &[u8; CTLEN],
                              kr: &[u8; KLEN], rk: &[u8; KLEN]) {
    let fail = verify(ct, cmp);
    *ss = *rk;
    cmov(ss, kr, (fail == 0) as u8);
}

#[no_mangle]
#[inline(never)]
#[link_section = "victim_text"]
pub extern "C" fn rs_tail_hardened(ss: &mut [u8; KLEN], ct: &[u8; CTLEN], cmp: &[u8; CTLEN],
                                   kr: &[u8; KLEN], rk: &[u8; KLEN]) {
    *ss = *rk;
    let mut d1: u32 = 0;
    for i in 0..CTLEN {
        d1 |= (ct[i] ^ cmp[i]) as u32;
    }
    let d1 = barrier_u32(d1);
    let m1 = (0u32.wrapping_sub(d1) >> 31).wrapping_sub(1) as u8; // 0xff iff d1 == 0
    for i in 0..KLEN {
        ss[i] ^= m1 & (ss[i] ^ kr[i]);
    }
    let (p, q) = (launder(ct.as_ptr()), launder(cmp.as_ptr()));
    let mut d2: u32 = 0;
    for i in (0..CTLEN).rev() {
        d2 |= unsafe { (*q.add(i) ^ *p.add(i)) as u32 };
    }
    let d2 = barrier_u32(d2);
    let m2 = (0u32.wrapping_sub(d2) >> 31).wrapping_sub(1) as u8;
    for i in 0..KLEN {
        ss[i] ^= !m2 & (ss[i] ^ rk[i]);
    }
}
