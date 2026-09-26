//! Validates the division-property engine against published integral
//! results for AES, then records what it predicts for Turing.

use bombe::division::{active, balanced_until, column_patterns};
use bombe::trail::Layer;

const A: Layer = Layer::ShiftMixColumns;
const M: Layer = Layer::MixState;

// AES: a set of 256 plaintexts with one active byte is balanced after three
// rounds, at the input of the fourth S-box layer (the Square distinguisher,
// Daemen, Knudsen, Rijmen, FSE 1997), which is what makes the 4-round Square
// attack work. With the four bytes of a diagonal active (2^32 plaintexts)
// the first round maps the set onto a full column, adding a round: balanced
// at the input of the fifth S-box layer (Ferguson et al., FSE 2000).
#[test]
fn reproduces_aes_integral_distinguishers() {
    assert_eq!(balanced_until(&active(&[0]), &[A; 8]), Some(4));
    assert_eq!(balanced_until(&active(&[0, 5, 10, 15]), &[A; 8]), Some(5));
}

// The four bytes of a column are not special for AES: ShiftRows scatters
// them in the first round, so they buy no extra round over a single byte.
#[test]
fn aes_column_is_no_better_than_one_byte() {
    assert_eq!(balanced_until(&active(&[0, 1, 2, 3]), &[A; 8]), Some(4));
}

// Per-column rule checked by hand: a column total of 1..=7 can always end
// up in one byte, giving a single 1; a total of 8 can stay as one 8 or split
// into two 1s, never a single 1.
#[test]
fn column_patterns_by_hand() {
    assert_eq!(column_patterns(0), vec![[0, 0, 0, 0]]);
    for t in 1..=7 {
        assert_eq!(column_patterns(t).len(), 4, "t = {t}: one 1 in any of 4 rows");
    }
    let eight = column_patterns(8);
    assert!(eight.contains(&[8, 0, 0, 0]));
    assert!(eight.contains(&[1, 1, 0, 0]));
    assert!(!eight.iter().any(|p| p.iter().map(|&x| x as u32).sum::<u32>() == 1));
    // A full column of 32 can only be all 8s.
    assert_eq!(column_patterns(32), vec![[8, 8, 8, 8]]);
}

// The full codebook is balanced forever (any permutation's outputs XOR to
// zero over all inputs), so the engine must never find a break.
#[test]
fn full_codebook_never_breaks() {
    assert_eq!(balanced_until(&[8; 16], &[M, A, M, A, M, A, M]), None);
}

/// Turing's first rounds: MixState in odd rounds, ShiftRows + MixColumns in
/// even rounds.
fn turing(rounds: usize) -> Vec<Layer> {
    turing::structure::schedule()[..rounds - 1].to_vec()
}

// What the division property says about Turing. One, two or three active
// bytes give balance up to the input of the third S-box layer (matching the
// measured square attack on 3 rounds). Four active bytes, 2^32 plaintexts,
// reach one round further: balanced at the input of the fourth S-box layer,
// so the square attack extends to 4 rounds.
#[test]
fn turing_integral_distinguishers() {
    let s = turing(16);
    for bytes in [&[0][..], &[0, 1], &[0, 1, 2]] {
        assert_eq!(balanced_until(&active(bytes), &s), Some(3), "{bytes:?}");
    }
    assert_eq!(balanced_until(&active(&[0, 1, 2, 3]), &s), Some(4));
    assert_eq!(balanced_until(&active(&[0, 5, 10, 15]), &s), Some(4));
}

// How far larger structures reach, up to 15 active bytes (2^120 plaintexts).
#[test]
fn turing_integral_reach_by_data() {
    let s = turing(16);
    let reach: Vec<Option<usize>> = (1..=15).map(|n| balanced_until(&active(&(0..n).collect::<Vec<_>>()), &s)).collect();
    // Never beyond the fifth S-box layer, far inside 16 rounds.
    assert!(reach.iter().all(|r| r.is_some_and(|r| r <= 5)), "{reach:?}");
}
