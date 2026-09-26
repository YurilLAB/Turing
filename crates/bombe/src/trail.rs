//! Trail bounder: the minimum number of active S-boxes in any differential
//! or linear trail through several rounds of an SPN whose rounds use either
//! ShiftRows + MixColumns or MixState.
//!
//! The state is tracked as a 16-bit *activity pattern* (bit 4c + r = the
//! byte at row r, column c is active, i.e. has a non-zero difference). For an
//! MDS matrix with n inputs, a transition from input pattern X to output
//! pattern Y is possible exactly when both are zero, or both are non-zero and
//! wt(X) + wt(Y) >= n + 1. (Every support of that size is taken by some
//! codeword of an MDS code, so this is exact, not just a bound.) The S-box
//! layer keeps the pattern and costs wt(pattern) active S-boxes.
//!
//! Linear trails give the same numbers: masks move through ShiftRows in the
//! same direction as differences (a permutation matrix P has
//! (P^-1)^T = P), and through (M^-1)^T, which is MDS whenever M is, with
//! the same branch number.
//!
//! The minimum over all patterns is computed exactly by dynamic
//! programming over the 2^16 patterns, round by round.

pub use turing::structure::Layer;

const PATTERNS: usize = 1 << 16;
const INF: u32 = u32::MAX / 2;

/// A MixColumns transition from column pattern x to y (4 bits each).
fn column_allowed(x: u32, y: u32) -> bool {
    (x == 0 && y == 0) || (x != 0 && y != 0 && x.count_ones() + y.count_ones() >= 5)
}

/// ShiftRows on an activity pattern: row r rotates left by r, so the byte at
/// column (c + r) mod 4 moves to column c.
pub fn shift_rows_pattern(p: u32) -> u32 {
    let mut out = 0;
    for c in 0..4 {
        for r in 0..4 {
            if p >> (4 * ((c + r) % 4) + r) & 1 == 1 {
                out |= 1 << (4 * c + r);
            }
        }
    }
    out
}

/// Cheapest cost of reaching each output pattern through ShiftRows +
/// MixColumns. The column constraint is separable, so the minimum is taken
/// one column at a time (a min-plus product per column) instead of over all
/// input/output pairs at once.
fn through_shift_mix(paid: &[u32]) -> Vec<u32> {
    let mut a = vec![INF; PATTERNS];
    for (x, &cost) in paid.iter().enumerate() {
        let y = shift_rows_pattern(x as u32) as usize;
        a[y] = a[y].min(cost);
    }
    for c in 0..4 {
        let shift = 4 * c;
        let mut b = vec![INF; PATTERNS];
        for (idx, slot) in b.iter_mut().enumerate() {
            let y = (idx >> shift) as u32 & 0xf;
            let rest = idx & !(0xf << shift);
            for x in 0..16u32 {
                if column_allowed(x, y) {
                    *slot = (*slot).min(a[rest | (x as usize) << shift]);
                }
            }
        }
        a = b;
    }
    a
}

/// Cheapest cost of reaching each output pattern through MixState
/// (branch 17): only the weights matter.
fn through_mix_state(paid: &[u32]) -> Vec<u32> {
    let mut by_weight = [INF; 17];
    for (x, &cost) in paid.iter().enumerate().skip(1) {
        let w = (x as u32).count_ones() as usize;
        by_weight[w] = by_weight[w].min(cost);
    }
    // at_least[w] = cheapest input of weight >= w.
    let mut at_least = [INF; 18];
    for w in (1..=16).rev() {
        at_least[w] = at_least[w + 1].min(by_weight[w]);
    }
    let mut out = vec![INF; PATTERNS];
    for (y, slot) in out.iter_mut().enumerate().skip(1) {
        let wy = (y as u32).count_ones() as usize;
        *slot = at_least[(17 - wy).max(1)];
    }
    out
}

/// Minimum active S-boxes for a trail through S-box layers S_1 .. S_{k+1}
/// with `layers[i]` applied between S_{i+1} and S_{i+2}. Returns one value per
/// prefix: element k is the bound over the first k + 1 S-box layers.
pub fn min_active_prefixes(layers: &[Layer]) -> Vec<u32> {
    // cost[x]: cheapest trail reaching pattern x at the input of the next
    // S-box layer. The input difference may be any non-zero pattern.
    let mut cost = vec![0u32; PATTERNS];
    cost[0] = INF;
    let mut bounds = Vec::with_capacity(layers.len() + 1);
    for step in 0..=layers.len() {
        let paid: Vec<u32> = cost
            .iter()
            .enumerate()
            .map(|(x, &c)| if c >= INF { INF } else { c + (x as u32).count_ones() })
            .collect();
        bounds.push(*paid.iter().min().unwrap());
        if step == layers.len() {
            break;
        }
        cost = match layers[step] {
            Layer::ShiftMixColumns => through_shift_mix(&paid),
            Layer::MixState => through_mix_state(&paid),
        };
    }
    bounds
}

/// Straightforward version for cross-checking `min_active_prefixes`: for
/// ShiftRows + MixColumns it enumerates, for every input pattern, every
/// output pattern the column rule allows (about 7.8 * 10^7 pairs per layer),
/// instead of the column-by-column minimisation. MixState stays by weight,
/// which is its definition. Only practical for a few rounds.
pub fn min_active_naive(layers: &[Layer]) -> u32 {
    let allowed_outputs: Vec<Vec<u32>> =
        (0..16u32).map(|x| (0..16u32).filter(|&y| column_allowed(x, y)).collect()).collect();
    let mut cost = vec![0u32; PATTERNS];
    cost[0] = INF;
    for layer in layers {
        let paid: Vec<u32> = cost
            .iter()
            .enumerate()
            .map(|(x, &c)| if c >= INF { INF } else { c + (x as u32).count_ones() })
            .collect();
        let mut next = vec![INF; PATTERNS];
        match layer {
            Layer::ShiftMixColumns => {
                for (x, &p) in paid.iter().enumerate() {
                    if p >= INF {
                        continue;
                    }
                    let s = shift_rows_pattern(x as u32);
                    let cols: Vec<&Vec<u32>> = (0..4).map(|c| &allowed_outputs[(s >> (4 * c) & 0xf) as usize]).collect();
                    for &y0 in cols[0] {
                        for &y1 in cols[1] {
                            for &y2 in cols[2] {
                                for &y3 in cols[3] {
                                    let y = (y0 | y1 << 4 | y2 << 8 | y3 << 12) as usize;
                                    next[y] = next[y].min(p);
                                }
                            }
                        }
                    }
                }
            }
            Layer::MixState => {
                // Pair every output weight with every input weight directly.
                for wy in 1..=16u32 {
                    let best = paid
                        .iter()
                        .enumerate()
                        .filter(|&(x, _)| x != 0 && (x as u32).count_ones() + wy >= 17)
                        .map(|(_, &p)| p)
                        .min()
                        .unwrap_or(INF);
                    for (y, slot) in next.iter_mut().enumerate() {
                        if (y as u32).count_ones() == wy {
                            *slot = best;
                        }
                    }
                }
            }
        }
        cost = next;
    }
    cost.iter()
        .enumerate()
        .filter(|&(_, &c)| c < INF)
        .map(|(x, &c)| c + (x as u32).count_ones())
        .min()
        .unwrap()
}

/// For every window of `rounds` consecutive rounds inside a cipher with the
/// given linear-layer schedule (`schedule[i]` follows round i + 1), the
/// minimum active S-boxes; returns the weakest window's value.
pub fn weakest_window(schedule: &[Layer], rounds: usize) -> u32 {
    let total = schedule.len() + 1;
    assert!(rounds >= 1 && rounds <= total);
    (0..=total - rounds)
        .map(|start| *min_active_prefixes(&schedule[start..start + rounds - 1]).last().unwrap())
        .min()
        .unwrap()
}

/// Smallest window length whose weakest window reaches `target` active
/// S-boxes, if any window length up to the whole cipher does.
pub fn rounds_to_reach(schedule: &[Layer], target: u32) -> Option<usize> {
    let total = schedule.len() + 1;
    let mut weakest = vec![u32::MAX; total + 1];
    for start in 0..total {
        let prefixes = min_active_prefixes(&schedule[start..]);
        for (k, &b) in prefixes.iter().enumerate() {
            weakest[k + 1] = weakest[k + 1].min(b);
        }
    }
    (1..=total).find(|&r| weakest[r] >= target)
}
