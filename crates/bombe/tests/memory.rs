//! Keys in memory: the memory-dump attacker (memscan.rs, residue.rs) against
//! every way of holding a Turing key. Each scan reads the whole process, so
//! the tests take turns.

use bombe::residue::{self, Snapshot};
use std::sync::Mutex;

// Scans must not overlap: two tests scanning at once see each other's keys.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn turn() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn report(snaps: &[Snapshot]) {
    for s in snaps {
        println!("{}: {} expected, {} stray ({} on the setup thread's stack), {} MB scanned", s.scenario, s.expected, s.stray.len(), s.on_stack, s.scanned_bytes >> 20);
        for place in &s.stray_places {
            println!("    {place}");
        }
    }
}

#[test]
fn control_a_planted_secret_is_found_where_it_was_put() {
    let _turn = turn();
    let (hits, there) = residue::planted();
    assert!(there, "all four fragments at the planted address");
    assert_eq!(hits, 4, "and nowhere else");
}

#[test]
fn control_a_key_copy_in_a_dead_stack_frame_is_found() {
    let _turn = turn();
    let s = residue::stack_plant(false);
    report(std::slice::from_ref(&s));
    assert_eq!(s.on_stack, 4, "the four key fragments, in the worker's stack");
}

#[test]
fn the_stack_burn_removes_a_dead_frames_copy() {
    let _turn = turn();
    let s = residue::stack_plant(true);
    report(std::slice::from_ref(&s));
    assert!(s.clean());
}

#[test]
fn control_the_scanner_reads_locked_key_pages() {
    let _turn = turn();
    let (found, all) = residue::round_keys_found_in_their_page();
    assert_eq!(found, all);
}

#[test]
fn new_key_leaves_no_copy_in_the_generator() {
    let _turn = turn();
    let (dirty, fragments) = residue::generator_copies(true, 8);
    println!("new_key: {dirty} of 8 keys left {fragments} fragments elsewhere");
    assert_eq!(dirty, 0);
    let (dirty, fragments) = residue::generator_copies(false, 8);
    println!("raw OS output: {dirty} of 8 keys left {fragments} fragments elsewhere");
}

#[test]
fn plain_cipher_leaves_nothing_behind() {
    let _turn = turn();
    let snaps = residue::plain(true);
    report(&snaps);
    assert!(snaps[0].expected >= 50, "the round keys are in their page");
    assert!(snaps.iter().all(Snapshot::clean));
}

// Measurement, not a check, because it depends on the build: without the
// burn, the release build leaves two 8-byte pieces of K' in dead stack that
// survive later encryptions and the cipher's drop; the test profile
// (opt-level 2) leaves nothing; CARGO_PROFILE_TEST_OPT_LEVEL=0 leaves two
// copies of K' and pieces of round key 24, which later calls overwrite
// (docs/13). With the burn every build is clean
// (plain_cipher_leaves_nothing_behind).
#[test]
fn key_schedule_without_the_stack_burn() {
    let _turn = turn();
    report(&residue::plain(false));
}

#[test]
fn masked_cipher_holds_no_round_key() {
    let _turn = turn();
    let snaps = residue::masked();
    report(&snaps);
    assert!(snaps.iter().all(Snapshot::clean));
}

#[test]
fn shielded_key_is_nowhere_in_memory() {
    let _turn = turn();
    let snaps = residue::shielded();
    report(&snaps);
    assert_eq!(snaps[0].expected + snaps[2].expected, 0, "no key or round key outside a cipher");
    assert!(snaps.iter().all(Snapshot::clean));
}

#[test]
fn the_burn_covers_every_key_setup() {
    let _turn = turn();
    for (name, depth) in residue::stack_depths() {
        println!("{name}: {depth} bytes of stack");
        assert!(depth > 0 && depth < turing::memory::BURN_BYTES, "{name}: {depth}");
    }
}
