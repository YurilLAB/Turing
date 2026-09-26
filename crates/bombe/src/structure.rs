//! Compares candidate round structures: where MixState goes and how that
//! changes the trail bounds, impossible differentials and diffusion.

use crate::impossible;
use crate::trail::{self, Layer};

/// A periodic schedule: MixState in rounds r with r % period == offset
/// (period 1 = every round, 0 = never), ShiftRows + MixColumns elsewhere.
pub fn periodic(rounds: usize, period: usize, offset: usize) -> Vec<Layer> {
    (1..rounds)
        .map(|r| if period != 0 && r % period == offset % period { Layer::MixState } else { Layer::ShiftMixColumns })
        .collect()
}

/// Named candidates for a cipher with `rounds` rounds: MixState every
/// `period` rounds, and the reverse (ShiftRows + MixColumns every `period`
/// rounds, MixState elsewhere).
pub fn candidates(rounds: usize) -> Vec<(String, Vec<Layer>)> {
    let mut out = vec![
        ("AES-like (no MixState)".to_string(), periodic(rounds, 0, 0)),
        ("MixState every round".to_string(), periodic(rounds, 1, 0)),
    ];
    let first = |period: usize, offset: usize| if offset == 0 { period } else { offset };
    for period in 2..=5 {
        for offset in 0..period {
            out.push((format!("MixState every {period}, from round {}", first(period, offset)), periodic(rounds, period, offset)));
        }
    }
    for period in 3..=4 {
        for offset in 0..period {
            let flipped = periodic(rounds, period, offset)
                .into_iter()
                .map(|l| if l == Layer::MixState { Layer::ShiftMixColumns } else { Layer::MixState })
                .collect();
            out.push((format!("MixCol every {period}, from round {}", first(period, offset)), flipped));
        }
    }
    out
}

/// Byte-dependency pattern after one linear layer.
fn diffuse(layer: Layer, p: u32) -> u32 {
    match layer {
        Layer::MixState => {
            if p != 0 {
                0xffff
            } else {
                0
            }
        }
        Layer::ShiftMixColumns => {
            let s = trail::shift_rows_pattern(p);
            (0..4).fold(0, |out, c| if s >> (4 * c) & 0xf != 0 { out | 0xf << (4 * c) } else { out })
        }
    }
}

/// Worst case over all windows and all single input bytes: how many rounds
/// until every byte depends on it (None if some window never gets there).
pub fn full_diffusion(schedule: &[Layer]) -> Option<usize> {
    let mut worst = 0;
    for start in 0..schedule.len() {
        for byte in 0..16 {
            let (mut p, mut rounds) = (1u32 << byte, 1);
            let mut layers = schedule[start..].iter();
            while p != 0xffff {
                match layers.next() {
                    Some(&l) => {
                        p = diffuse(l, p);
                        rounds += 1;
                    }
                    None if start == 0 => return None,
                    None => break,
                }
            }
            if p == 0xffff {
                worst = worst.max(rounds);
            }
        }
    }
    Some(worst)
}

/// The longest run of consecutive ShiftRows + MixColumns layers.
pub fn longest_aes_like_run(schedule: &[Layer]) -> usize {
    schedule
        .split(|&l| l == Layer::MixState)
        .map(<[Layer]>::len)
        .max()
        .unwrap_or(0)
}

/// Relative cost of one round (S-box layer + linear layer) in the
/// constant-time implementation, counting 8-step field multiplications:
/// an S-box is ~15 multiplications (x^254) plus two affine maps (~2), so a
/// layer of 16 is ~272; MixColumns is 64 multiplications, MixState 256.
pub fn round_cost(layer: Layer) -> u32 {
    272 + match layer {
        Layer::ShiftMixColumns => 64,
        Layer::MixState => 256,
    }
}

pub struct Evaluation {
    /// Weakest window of r rounds, for r = 1..=weakest.len().
    pub weakest: Vec<u32>,
    pub rounds_to_22: Option<usize>,
    pub rounds_to_43: Option<usize>,
    pub impossible: usize,
    pub diffusion: Option<usize>,
    pub aes_like_run: usize,
    pub mix_states: usize,
    pub cost: u32,
}

pub fn evaluate(schedule: &[Layer], window_rows: usize) -> Evaluation {
    Evaluation {
        weakest: (1..=window_rows.min(schedule.len() + 1)).map(|r| trail::weakest_window(schedule, r)).collect(),
        rounds_to_22: trail::rounds_to_reach(schedule, 22),
        rounds_to_43: trail::rounds_to_reach(schedule, 43),
        impossible: impossible::longest(schedule),
        diffusion: full_diffusion(schedule),
        aes_like_run: longest_aes_like_run(schedule),
        mix_states: schedule.iter().filter(|&&l| l == Layer::MixState).count(),
        cost: schedule.iter().map(|&l| round_cost(l)).sum::<u32>() + 272,
    }
}
