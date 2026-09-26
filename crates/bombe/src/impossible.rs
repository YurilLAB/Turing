//! Truncated impossible-differential search ("miss in the middle").
//!
//! Each byte of a difference is tracked as certainly zero, certainly
//! non-zero, or unknown. From an input activity pattern we propagate forward
//! what is certain; from an output pattern, backward. If the two meet in a
//! contradiction (a byte certainly zero from one side and certainly non-zero
//! from the other, or a linear layer whose input and output cannot fit its
//! branch number), no pair of plaintexts with that input difference pattern
//! can give that output pattern, for any key: an impossible differential.
//!
//! The rules only ever claim what must be true, so every impossible
//! differential found is real. The search can miss impossible differentials
//! that depend on the S-box or on exact values; for AES it finds the known
//! 4-round ones and none over 5 rounds, which Sun et al. (EUROCRYPT 2016)
//! proved is the limit for S-box-independent impossible differentials.

use crate::trail::{shift_rows_pattern, Layer};
use std::collections::HashMap;

/// What is certain about each byte of a difference: bits of `nz` are
/// non-zero bytes, bits of `z` are zero bytes, the rest are unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Trunc {
    pub nz: u32,
    pub z: u32,
}

const ALL: u32 = 0xffff;

impl Trunc {
    /// A fully known pattern: `p` non-zero, the rest zero.
    pub fn definite(p: u32) -> Trunc {
        Trunc { nz: p, z: !p & ALL }
    }
}

fn inv_shift_rows_pattern(p: u32) -> u32 {
    let mut out = 0;
    for c in 0..4 {
        for r in 0..4 {
            if p >> (4 * c + r) & 1 == 1 {
                out |= 1 << (4 * ((c + r) % 4) + r);
            }
        }
    }
    out
}

/// An MDS matrix (or its inverse; both have no zero entries) applied to the
/// bytes in `block`: all zero in -> all zero out; exactly one non-zero byte
/// and the rest zero -> every output byte non-zero (each is that byte times
/// a non-zero entry); anything else -> unknown.
fn mds_block(t: Trunc, block: u32) -> Trunc {
    let nz = t.nz & block;
    let unknown = block & !(t.nz | t.z);
    if nz == 0 && unknown == 0 {
        Trunc { nz: 0, z: block }
    } else if nz.count_ones() == 1 && unknown == 0 {
        Trunc { nz: block, z: 0 }
    } else {
        Trunc { nz: 0, z: 0 }
    }
}

fn mds_columns(t: Trunc) -> Trunc {
    (0..4).fold(Trunc { nz: 0, z: 0 }, |acc, c| {
        let part = mds_block(t, 0xf << (4 * c));
        Trunc { nz: acc.nz | part.nz, z: acc.z | part.z }
    })
}

/// Propagate through a linear layer in the encryption direction.
pub fn forward(layer: Layer, t: Trunc) -> Trunc {
    match layer {
        Layer::ShiftMixColumns => {
            let s = Trunc { nz: shift_rows_pattern(t.nz), z: shift_rows_pattern(t.z) };
            mds_columns(s)
        }
        Layer::MixState => mds_block(t, ALL),
    }
}

/// Propagate through a linear layer in the decryption direction.
pub fn backward(layer: Layer, t: Trunc) -> Trunc {
    match layer {
        Layer::ShiftMixColumns => {
            let m = mds_columns(t);
            Trunc { nz: inv_shift_rows_pattern(m.nz), z: inv_shift_rows_pattern(m.z) }
        }
        Layer::MixState => mds_block(t, ALL),
    }
}

/// Could some difference matching `input` map through an MDS block of the
/// given branch number to one matching `output`?
fn block_feasible(input: Trunc, output: Trunc, block: u32, branch: u32) -> bool {
    let in_min = (input.nz & block).count_ones();
    let in_max = (block & !input.z).count_ones();
    let out_min = (output.nz & block).count_ones();
    let out_max = (block & !output.z).count_ones();
    let both_zero = in_min == 0 && out_min == 0;
    let non_zero = in_max >= 1 && out_max >= 1 && in_max + out_max >= branch;
    both_zero || non_zero
}

/// Is a forward state before `layer` compatible with a backward state after it?
pub fn consistent(layer: Layer, before: Trunc, after: Trunc) -> bool {
    match layer {
        Layer::ShiftMixColumns => {
            let s = Trunc { nz: shift_rows_pattern(before.nz), z: shift_rows_pattern(before.z) };
            (0..4).all(|c| block_feasible(s, after, 0xf << (4 * c), 5))
        }
        Layer::MixState => block_feasible(before, after, ALL, 17),
    }
}

fn clash(a: Trunc, b: Trunc) -> bool {
    (a.nz & b.z) | (a.z & b.nz) != 0
}

/// An impossible differential over S-box layers S_1 .. S_{m+1} with
/// `layers[i]` between S_{i+1} and S_{i+2}: an input activity pattern (at
/// S_1) and an output pattern (after S_{m+1}) that can never occur together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub input: u32,
    pub output: u32,
}

pub fn find(layers: &[Layer]) -> Option<Witness> {
    let m = layers.len();
    // Distinct states at each S-box layer, each with one pattern producing it.
    let definite: HashMap<Trunc, u32> = (1..=ALL).map(|p| (Trunc::definite(p), p)).collect();
    let mut fw = vec![definite.clone()];
    for &layer in layers {
        let next = fw.last().unwrap().iter().map(|(&t, &p)| (forward(layer, t), p)).collect();
        fw.push(next);
    }
    let mut bw = vec![definite];
    for &layer in layers.iter().rev() {
        let next = bw.last().unwrap().iter().map(|(&t, &q)| (backward(layer, t), q)).collect();
        bw.push(next);
    }
    bw.reverse();
    // Clash at an S-box layer (S-boxes keep zero and non-zero bytes).
    for k in 0..=m {
        for (&f, &p) in &fw[k] {
            for (&b, &q) in &bw[k] {
                if clash(f, b) {
                    return Some(Witness { input: p, output: q });
                }
            }
        }
    }
    // Inconsistent across a linear layer.
    for (k, &layer) in layers.iter().enumerate() {
        for (&f, &p) in &fw[k] {
            for (&b, &q) in &bw[k + 1] {
                if !consistent(layer, f, b) {
                    return Some(Witness { input: p, output: q });
                }
            }
        }
    }
    None
}

/// The longest window of consecutive rounds (S-box layers) of a cipher with
/// the given linear-layer schedule that has an impossible differential.
pub fn longest(schedule: &[Layer]) -> usize {
    let total = schedule.len() + 1;
    let mut best = 1; // one S-box layer: the pattern cannot change
    for rounds in 2..=total {
        let any = (0..=total - rounds).any(|start| find(&schedule[start..start + rounds - 1]).is_some());
        if !any {
            break;
        }
        best = rounds;
    }
    best
}
