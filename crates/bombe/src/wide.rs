//! Trail bounds and the division property for alternating schedules on
//! states of any number of 4-byte columns: Turing (16 bytes) and Turing-256
//! (32 bytes, docs/15).
//!
//! When MixState and ShiftRows + MixColumns alternate, only the number of
//! active bytes matters at every S-box layer after a MixState: an MDS
//! matrix takes an input with a active bytes to every output support of
//! size at least n + 1 - a, so positions are free again. ShiftRows +
//! MixColumns always starts from free positions (after MixState or at the
//! start of a window), so its transitions reduce to how many columns the
//! active bytes occupy. That makes both computations exact over n + 1
//! counts instead of 2^n patterns. `trail::min_active_prefixes` and
//! `division::balanced_until` are the exact 16-byte references, and the
//! tests require the same answers from both.

use crate::division::column_patterns;
use crate::trail::Layer;

/// Whether ShiftRows + MixColumns can take p active bytes (placed freely) to
/// q active bytes on a state of `columns` columns: with m active columns,
/// each of 1 to 4 active bytes in, each column puts out between 5 minus its
/// input and 4 (branch number 5).
fn shift_mix_step(p: usize, q: usize, columns: usize) -> bool {
    if p == 0 {
        return q == 0;
    }
    (p.div_ceil(4)..=p.min(columns)).any(|m| 5 * m >= p && 5 * m - p <= q && q <= 4 * m)
}

/// Whether MixState on n bytes can take a active bytes to b.
fn mix_state_step(a: usize, b: usize, n: usize) -> bool {
    if a == 0 {
        b == 0
    } else {
        b >= 1 && a + b > n
    }
}

/// For windows of 1, 2, ... S-box layers with linear layers `layers`
/// between them (starting anywhere in the window), the minimum number of
/// active S-boxes on an n-byte state. ShiftMix must never follow ShiftMix.
pub fn min_active_prefixes(layers: &[Layer], n: usize) -> Vec<u32> {
    assert!(n.is_multiple_of(4));
    assert!(layers.windows(2).all(|w| w != [Layer::ShiftMixColumns; 2]), "alternating schedules only");
    const INF: u32 = u32::MAX / 2;
    let mut cost: Vec<u32> = (0..=n).map(|c| if c == 0 { INF } else { c as u32 }).collect();
    let mut out = vec![1];
    for &layer in layers {
        let mut next = vec![INF; n + 1];
        for (a, &paid) in cost.iter().enumerate().skip(1) {
            if paid == INF {
                continue;
            }
            for (b, slot) in next.iter_mut().enumerate().skip(1) {
                let ok = match layer {
                    Layer::MixState => mix_state_step(a, b, n),
                    Layer::ShiftMixColumns => shift_mix_step(a, b, n / 4),
                };
                if ok {
                    *slot = (*slot).min(paid + b as u32);
                }
            }
        }
        cost = next;
        out.push(*cost.iter().min().expect("n > 0"));
    }
    out
}

/// The smallest over both starting layers of an alternating schedule: the
/// guaranteed active S-boxes for any window of r rounds (index r - 1).
pub fn min_active_alternating(n: usize, rounds: usize) -> Vec<u32> {
    let schedule = |first: Layer| -> Vec<Layer> {
        (0..rounds.saturating_sub(1))
            .map(|i| if (i % 2 == 0) == (first == Layer::MixState) { Layer::MixState } else { Layer::ShiftMixColumns })
            .collect()
    };
    let a = min_active_prefixes(&schedule(Layer::MixState), n);
    let b = min_active_prefixes(&schedule(Layer::ShiftMixColumns), n);
    a.iter().zip(&b).map(|(x, y)| *x.min(y)).collect()
}

/// (ones, eights) shapes an S-box layer can output from a total t spread
/// over n bytes by MixState (as in `division`).
fn shapes(t: u32, n: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for eights in 0..=n.min(t / 8) {
        let rest = t - 8 * eights;
        let ones = rest.div_ceil(7);
        if ones + eights <= n && (rest > 0 || ones == 0) {
            out.push((ones, eights));
        }
    }
    out
}

fn column_minimum(t: u32) -> u32 {
    if t == 0 {
        0
    } else {
        column_patterns(t).iter().map(|p| p.iter().map(|&x| x as u32).sum::<u32>()).min().expect("a pattern")
    }
}

/// The division state after an S-box layer, reduced to what the next layer
/// of an alternating schedule reads.
enum After {
    /// The first S-box layer's output (entries 0, 1 or 8), positions known.
    Start(Vec<u32>),
    /// An explicit set after ShiftRows + MixColumns: whether it holds a
    /// unit vector, and its smallest total.
    Summary { unit: bool, smallest: u32 },
    /// After MixState then an S-box layer: the total before the S-box layer.
    Total(u32),
}

/// `division::balanced_until` for alternating schedules on n bytes whose
/// ShiftRows rotates row r left by `shifts[r]`: for a set with division
/// vector `input` (8 = byte takes all values, 0 = constant) at the input of
/// S-box layer 1, the largest i with every output bit balanced at the input
/// of S-box layer i. None if balance never breaks within the schedule.
pub fn balanced_until(input: &[u8], schedule: &[Layer], shifts: &[usize; 4]) -> Option<usize> {
    let n = input.len();
    let columns = n / 4;
    let s = |k: u8| -> u32 {
        match k {
            0 => 0,
            8 => 8,
            _ => 1,
        }
    };
    let smallest = |st: &After| -> u32 {
        match st {
            After::Start(v) => v.iter().sum(),
            After::Summary { smallest, .. } => *smallest,
            After::Total(t) => shapes(*t, n as u32).iter().map(|&(o, e)| o + 8 * e).min().unwrap_or(0),
        }
    };
    let unit = |st: &After| -> bool {
        match st {
            After::Start(v) => v.iter().sum::<u32>() == 1,
            After::Summary { unit, .. } => *unit,
            After::Total(t) => (1..=7).contains(t),
        }
    };
    let mut state = After::Start(input.iter().map(|&k| s(k)).collect());
    if unit(&state) {
        return Some(1);
    }
    for (i, &layer) in schedule.iter().enumerate() {
        state = match (layer, &state) {
            (Layer::MixState, _) => After::Total(smallest(&state)),
            (Layer::ShiftMixColumns, After::Start(v)) => {
                let totals: Vec<u32> = (0..columns).map(|c| (0..4).map(|r| v[4 * ((c + shifts[r]) % columns) + r]).sum()).collect();
                let nonzero: Vec<u32> = totals.iter().copied().filter(|&t| t > 0).collect();
                After::Summary {
                    unit: nonzero.len() == 1 && (1..=7).contains(&nonzero[0]),
                    smallest: totals.iter().map(|&t| column_minimum(t)).sum(),
                }
            }
            (Layer::ShiftMixColumns, After::Total(t)) => {
                let (mut unit, mut best) = (false, u32::MAX);
                for (ones, eights) in shapes(*t, n as u32) {
                    // All in one column, with no 8: a single 1 can come out.
                    unit |= eights == 0 && (1..=4).contains(&ones);
                    best = best.min(spread_minimum(ones as usize, eights as usize, columns));
                }
                After::Summary { unit, smallest: best }
            }
            (Layer::ShiftMixColumns, After::Summary { .. }) => panic!("alternating schedules only"),
        };
        if unit(&state) {
            return Some(i + 2);
        }
    }
    None
}

/// The smallest total after MixColumns and an S-box layer, over every way
/// of placing `ones` 1s and `eights` 8s in `columns` columns of 4 bytes.
fn spread_minimum(ones: usize, eights: usize, columns: usize) -> u32 {
    let mut best = vec![vec![u32::MAX; eights + 1]; ones + 1];
    best[0][0] = 0;
    for _ in 0..columns {
        let mut next = vec![vec![u32::MAX; eights + 1]; ones + 1];
        for o in 0..=ones {
            for e in 0..=eights {
                if best[o][e] == u32::MAX {
                    continue;
                }
                for co in 0..=4usize.min(ones - o) {
                    for ce in 0..=(4 - co).min(eights - e) {
                        let cell = &mut next[o + co][e + ce];
                        *cell = (*cell).min(best[o][e] + column_minimum((co + 8 * ce) as u32));
                    }
                }
            }
        }
        best = next;
    }
    best[ones][eights]
}

/// A set with the given bytes taking every value, the rest constant.
pub fn active(n: usize, bytes: &[usize]) -> Vec<u8> {
    let mut v = vec![0u8; n];
    for &b in bytes {
        v[b] = 8;
    }
    v
}

/// The alternating schedule of `layers` linear layers on either start.
pub fn alternating(first: Layer, layers: usize) -> Vec<Layer> {
    (0..layers)
        .map(|i| if (i % 2 == 0) == (first == Layer::MixState) { Layer::MixState } else { Layer::ShiftMixColumns })
        .collect()
}

/// The count-level impossible differential test: a window of S-box layers
/// with linear layers `layers` has an impossible differential with one
/// active byte in and one out if the active-byte counts reachable forward
/// from one byte and backward from one byte never meet at an S-box layer.
pub fn one_byte_impossible(layers: &[Layer], n: usize) -> bool {
    let step = |layer: Layer, from: &[bool]| -> Vec<bool> {
        (0..=n)
            .map(|b| {
                (1..=n).any(|a| {
                    from[a]
                        && match layer {
                            Layer::MixState => mix_state_step(a, b, n),
                            Layer::ShiftMixColumns => shift_mix_step(a, b, n / 4),
                        }
                })
            })
            .collect()
    };
    let one: Vec<bool> = (0..=n).map(|c| c == 1).collect();
    let mut forward = vec![one.clone()];
    for &l in layers {
        let next = step(l, forward.last().expect("start"));
        forward.push(next);
    }
    // Both layers are their own kind when inverted (MDS inverses are MDS).
    let mut backward = vec![one];
    for &l in layers.iter().rev() {
        let next = step(l, backward.last().expect("end"));
        backward.push(next);
    }
    backward.reverse();
    forward.iter().zip(&backward).any(|(f, b)| !f.iter().zip(b).any(|(x, y)| *x && *y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::division;
    use crate::trail;

    // Exact on Turing's 16-byte state: the pattern-level DP over all 2^16
    // activity patterns gives the same minimum for every window, from
    // either starting layer.
    #[test]
    fn counts_match_the_exact_16_byte_bounds() {
        let s = turing::structure::schedule();
        for start in 0..2 {
            let w = &s[start..start + 12];
            assert_eq!(min_active_prefixes(w, 16), trail::min_active_prefixes(w), "start {start}");
        }
    }

    // The same for the division property: every structure the 16-byte
    // engine was validated on, from both starting layers.
    #[test]
    fn division_matches_the_16_byte_engine() {
        let s = turing::structure::schedule();
        let mut structures: Vec<Vec<usize>> = (1..=15usize).map(|k| (0..k).collect()).collect();
        structures.extend([vec![0, 5, 10, 15], vec![0, 5], vec![0, 4, 8, 12], vec![0, 5, 10, 15, 4, 9, 14, 3], vec![3], vec![1, 6, 11], vec![2, 7, 8, 13]]);
        for start in 0..2 {
            for bytes in &structures {
                let reference = division::balanced_until(&division::active(bytes), &s[start..]);
                assert_eq!(balanced_until(&active(16, bytes), &s[start..], &[0, 1, 2, 3]), reference, "start {start} {bytes:?}");
            }
        }
    }

    // Turing-256's numbers (docs/15).
    #[test]
    fn turing_256_bounds() {
        let bounds = min_active_alternating(32, 8);
        assert_eq!(bounds, vec![1, 5, 34, 45, 67, 68, 100, 101]);
        // Every 4-round window: at least 45 active S-boxes, 2^-270 < 2^-256.
        assert!(bounds[3] * 6 > 256 && bounds[2] * 6 <= 256);
    }

    #[test]
    fn turing_256_division_reach() {
        let shifts = turing::linear256::SHIFTS;
        let ms = alternating(Layer::MixState, 30);
        let reach = |k: usize| balanced_until(&active(32, &(0..k).collect::<Vec<_>>()), &ms, &shifts);
        assert_eq!(reach(1), Some(3));
        assert_eq!(reach(4), Some(4));
        assert_eq!(reach(24), Some(4));
        assert_eq!(reach(25), Some(5));
        assert_eq!(reach(31), Some(6));
        // Never past layer 6 from the plaintext, whatever the size.
        assert!((1..=31).all(|k| reach(k).is_some_and(|r| r <= 6)));
    }

    // AES-like and Turing checks of the impossible-differential test: the
    // 4-round window ShiftMix, MixState, ShiftMix has one; 5 rounds do not.
    #[test]
    fn impossible_differentials_by_count() {
        use Layer::*;
        for n in [16, 32] {
            assert!(one_byte_impossible(&[ShiftMixColumns, MixState, ShiftMixColumns], n), "{n}");
            assert!(!one_byte_impossible(&[MixState, ShiftMixColumns, MixState], n), "{n}");
            assert!(!one_byte_impossible(&[ShiftMixColumns, MixState, ShiftMixColumns, MixState], n), "{n}");
            assert!(!one_byte_impossible(&[MixState, ShiftMixColumns, MixState, ShiftMixColumns], n), "{n}");
        }
    }
}
