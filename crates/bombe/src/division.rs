//! Word-level division property (Todo, "Structural Evaluation by
//! Generalized Integral Property", EUROCRYPT 2015): the technique behind the
//! first attack on full MISTY1 (Todo, CRYPTO 2015).
//!
//! A set of plaintexts is described by vectors k in {0..8}^16: roughly, "the
//! XOR over the set of any product of fewer than k_i bits of byte i is
//! known". Propagation rules, all sound (they may lose information, never
//! invent it):
//!  - S-box layer (bijective, degree 7): k = 0 stays 0, k = 8 stays 8
//!    (a permutation of "all values" is "all values"), 1..7 become 1.
//!  - Linear layer where every output byte depends on every input byte of a
//!    group (MixColumns on a column, MixState on the state): the vector may
//!    be redistributed arbitrarily inside the group, keeping its total.
//!  - ShiftRows permutes; key addition changes nothing.
//!
//! Every output bit is balanced (XORs to zero over the set) as long as no
//! vector with a single 1 (a unit vector) is reachable.
//!
//! Only minimal vectors matter, and after MixState only the smallest total
//! does. The engine keeps explicit vector sets where positions matter
//! (ShiftRows + MixColumns) and a single number after MixState.

use crate::trail::Layer;
use std::collections::HashSet;

pub type Vector = [u8; 16];

fn s(k: u8) -> u8 {
    match k {
        0 => 0,
        8 => 8,
        _ => 1,
    }
}

/// For a column total t (0..=32) spread over 4 bytes by MixColumns, the
/// minimal S-box output patterns (entries 0, 1 or 8, by row) reachable from
/// some split of t. A pattern at least as large as another in every byte
/// adds nothing, so only minimal ones are kept; the product of per-column
/// minimal sets is then minimal too.
pub fn column_patterns(t: u32) -> Vec<[u8; 4]> {
    let mut all = HashSet::new();
    for d0 in 0..=8u32 {
        for d1 in 0..=8u32 {
            for d2 in 0..=8u32 {
                let rest = t as i32 - (d0 + d1 + d2) as i32;
                if (0..=8).contains(&rest) {
                    all.insert([s(d0 as u8), s(d1 as u8), s(d2 as u8), s(rest as u8)]);
                }
            }
        }
    }
    let dominated = |p: &[u8; 4]| all.iter().any(|q| q != p && q.iter().zip(p).all(|(a, b)| a <= b));
    let mut minimal: Vec<[u8; 4]> = all.iter().filter(|p| !dominated(p)).copied().collect();
    minimal.sort_unstable();
    minimal
}

/// A description of the plaintext set after an S-box layer.
#[derive(Clone, Debug)]
enum State {
    /// Explicit vectors (entries 0, 1 or 8).
    Explicit(HashSet<Vector>),
    /// After MixState then an S-box layer: every S-box output reachable from
    /// a vector with this total spread anywhere over the 16 bytes.
    Total(u32),
}

/// (ones, eights) shapes that an S-box layer can output from total t spread
/// over `words` bytes, keeping only the fewest ones for each number of eights.
fn shapes(t: u32, words: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for eights in 0..=words.min(t / 8) {
        let rest = t - 8 * eights;
        let ones = rest.div_ceil(7);
        if ones + eights <= words && (rest > 0 || ones == 0) {
            out.push((ones, eights));
        }
    }
    out
}

fn has_unit(state: &State) -> bool {
    match state {
        State::Explicit(set) => set.iter().any(|v| v.iter().map(|&x| x as u32).sum::<u32>() == 1),
        State::Total(t) => (1..=7).contains(t),
    }
}

fn smallest_total(state: &State) -> u32 {
    match state {
        State::Explicit(set) => set.iter().map(|v| v.iter().map(|&x| x as u32).sum::<u32>()).min().unwrap_or(0),
        State::Total(t) => shapes(*t, 16).iter().map(|&(ones, eights)| ones + 8 * eights).min().unwrap_or(0),
    }
}

/// ShiftRows, MixColumns and the next S-box layer applied to explicit vectors.
fn through_shift_mix(set: &HashSet<Vector>, patterns: &[Vec<[u8; 4]>]) -> HashSet<Vector> {
    let mut out = HashSet::new();
    for v in set {
        // Move bytes as ShiftRows does: byte at column (c + r) % 4 goes to c.
        let mut shifted = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                shifted[4 * c + r] = v[4 * ((c + r) % 4) + r];
            }
        }
        let options: Vec<&Vec<[u8; 4]>> =
            (0..4).map(|c| &patterns[shifted[4 * c..4 * c + 4].iter().map(|&x| x as usize).sum::<usize>()]).collect();
        for p0 in options[0] {
            for p1 in options[1] {
                for p2 in options[2] {
                    for p3 in options[3] {
                        let mut w = [0u8; 16];
                        w[0..4].copy_from_slice(p0);
                        w[4..8].copy_from_slice(p1);
                        w[8..12].copy_from_slice(p2);
                        w[12..16].copy_from_slice(p3);
                        out.insert(w);
                    }
                }
            }
        }
    }
    out
}

/// ShiftRows + MixColumns + S after MixState: positions are free, so place
/// each shape's ones and eights over the four columns (up to four bytes a
/// column) in every possible way, then expand each column.
fn total_through_shift_mix(t: u32, patterns: &[Vec<[u8; 4]>]) -> HashSet<Vector> {
    let mut out = HashSet::new();
    for (ones, eights) in shapes(t, 16) {
        let mut split = Vec::new();
        distribute(ones, eights, 0, &mut [(0, 0); 4], &mut split);
        for cols in split {
            let options: Vec<&Vec<[u8; 4]>> = cols.iter().map(|&(o, e)| &patterns[(o + 8 * e) as usize]).collect();
            for p0 in options[0] {
                for p1 in options[1] {
                    for p2 in options[2] {
                        for p3 in options[3] {
                            let mut w = [0u8; 16];
                            w[0..4].copy_from_slice(p0);
                            w[4..8].copy_from_slice(p1);
                            w[8..12].copy_from_slice(p2);
                            w[12..16].copy_from_slice(p3);
                            out.insert(w);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Every way to put `ones` and `eights` into 4 columns of 4 bytes.
fn distribute(ones: u32, eights: u32, col: usize, cur: &mut [(u32, u32); 4], out: &mut Vec<[(u32, u32); 4]>) {
    if col == 4 {
        if ones == 0 && eights == 0 {
            out.push(*cur);
        }
        return;
    }
    for o in 0..=ones.min(4) {
        for e in 0..=eights.min(4 - o) {
            cur[col] = (o, e);
            distribute(ones - o, eights - e, col + 1, cur, out);
        }
    }
    cur[col] = (0, 0);
}

/// Too many explicit vectors to continue: give up rather than guess.
const EXPLICIT_LIMIT: usize = 2_000_000;

/// For a plaintext set with division vector `input` (8 = byte takes all
/// values, 0 = constant) and the cipher's linear layers `schedule`
/// (schedule[i] follows S-box layer i + 1): the largest i such that every
/// output bit is balanced at the input of S-box layer i. So key recovery
/// that guesses the last round key byte by byte works on up to i rounds.
/// None if balance never breaks (the full codebook) or the search is too
/// large to finish.
pub fn balanced_until(input: &Vector, schedule: &[Layer]) -> Option<usize> {
    let patterns: Vec<Vec<[u8; 4]>> = (0..=32).map(column_patterns).collect();
    let first: Vector = input.map(s);
    let mut state = State::Explicit(HashSet::from([first]));
    if has_unit(&state) {
        return Some(1);
    }
    for (i, &layer) in schedule.iter().enumerate() {
        state = match (layer, &state) {
            (Layer::MixState, _) => State::Total(smallest_total(&state)),
            (Layer::ShiftMixColumns, State::Explicit(set)) => State::Explicit(through_shift_mix(set, &patterns)),
            (Layer::ShiftMixColumns, State::Total(t)) => State::Explicit(total_through_shift_mix(*t, &patterns)),
        };
        if has_unit(&state) {
            // Balance is lost at the output of S-box layer i + 2.
            return Some(i + 2);
        }
        if let State::Explicit(set) = &state {
            if set.len() > EXPLICIT_LIMIT {
                return None;
            }
        }
    }
    None
}

/// A plaintext set with the given bytes taking all values.
pub fn active(bytes: &[usize]) -> Vector {
    let mut v = [0u8; 16];
    for &b in bytes {
        v[b] = 8;
    }
    v
}
