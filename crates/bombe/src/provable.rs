//! Provable bounds on differentials and linear hulls with every trail
//! counted (clustering), in the standard model of independent, uniformly
//! random round keys (a Markov cipher).
//!
//! Park, Sung, Lee and Lim (FSE 2003, Theorems 1 and 2): for two rounds of an
//! SPN, an S-box layer, a linear layer of branch number B and an S-box layer,
//!   MEDP <= max over a != 0 of sum over b of DP_S(a, b)^B, over rows and
//!   columns of the difference table, and
//!   MELP <= max over a != 0 of sum over b of LP_S(a, b)^B.
//! Keliher and Sui (ePrint 2005/321) quote the AES values, 79/2^34 and
//! 192,773,764/2^54; the tests reproduce both.
//!
//! Longer windows. With independent keys, T rounds are never better for the
//! attacker than any 2-round window inside them: summing over the
//! differences before and after the window, the other rounds contribute
//! factors that add up to 1 (each row and column of a permutation's
//! difference table sums to 1; for correlations, Parseval). Every three
//! consecutive Turing rounds contain an S-box layer, MixState (B = 17) and an
//! S-box layer, so the B = 17 bound covers every T >= 3. Four rounds starting
//! with a ShiftRows+MixColumns round are two layers of four 32-bit super-boxes
//! with MixState between them. Over 32-bit words MixState has branch number
//! 5 (a active bytes in give at least 17 - a out), so Park et al.'s Theorem 1
//! applied to the super-boxes gives mu^4, where mu bounds the super-box: the
//! argument Keliher and Sui use for AES.
//!
//! Keliher and Sui's Theorem 1 gives a lower bound on mu: the largest
//! probability of a differential over minimal-weight activity patterns (5
//! active S-boxes), summed over all 255 characteristics. For AES it is
//! 53/2^34, which they prove is the exact 2-round MEDP.

use crate::gf256;
use std::sync::atomic::{AtomicU64, Ordering};

/// A probability bound: log2 of its value, and the exact fraction
/// numerator / 2^denominator_log2 when the numerator fits in 128 bits.
#[derive(Clone, Copy, Debug)]
pub struct Bound {
    pub log2: f64,
    pub exact: Option<(u128, u32)>,
}

fn ddt(table: &[u8; 256]) -> Vec<[u16; 256]> {
    let mut d = vec![[0u16; 256]; 256];
    for (a, row) in d.iter_mut().enumerate() {
        for x in 0..256 {
            row[(table[x] ^ table[x ^ a]) as usize] += 1;
        }
    }
    d
}

/// Walsh coefficients W[a][b] = sum over x of (-1)^(a.x ^ b.S(x)).
fn walsh(table: &[u8; 256]) -> Vec<[i32; 256]> {
    let mut w = vec![[0i32; 256]; 256];
    for (a, row) in w.iter_mut().enumerate() {
        for (b, cell) in row.iter_mut().enumerate() {
            *cell = (0..256usize).map(|x| if ((a & x) as u8 ^ (b as u8 & table[x])).count_ones().is_multiple_of(2) { 1 } else { -1 }).sum();
        }
    }
    w
}

/// max over the rows and the columns of sum of (entry / scale)^power, where
/// every entry is a non-negative integer.
fn power_sum_bound(rows: &[Vec<u64>], scale_log2: u32, power: u32) -> Bound {
    let mut best_f = 0f64;
    let mut best_exact: Option<u128> = Some(0);
    let mut consider = |values: &mut dyn Iterator<Item = u64>| {
        let values: Vec<u64> = values.collect();
        let f: f64 = values.iter().map(|&v| (v as f64 / (1u64 << scale_log2) as f64).powi(power as i32)).sum();
        best_f = best_f.max(f);
        let exact = values.iter().try_fold(0u128, |acc, &v| u128::from(v).checked_pow(power).and_then(|p| acc.checked_add(p)));
        best_exact = match (best_exact, exact) {
            (Some(b), Some(e)) => Some(b.max(e)),
            _ => None,
        };
    };
    for (a, row) in rows.iter().enumerate().skip(1) {
        consider(&mut row[1..].iter().copied());
        consider(&mut rows[1..].iter().map(|r| r[a]));
    }
    Bound { log2: best_f.log2(), exact: best_exact.map(|e| (e, scale_log2 * power)) }
}

/// Park et al.'s bound on the 2-round MEDP for an S-box and branch number B.
pub fn dp_bound(table: &[u8; 256], branch: u32) -> Bound {
    let rows: Vec<Vec<u64>> = ddt(table).iter().map(|r| r.iter().map(|&v| u64::from(v)).collect()).collect();
    power_sum_bound(&rows, 8, branch)
}

/// Park et al.'s bound on the 2-round MELP: LP = (W / 256)^2 = W^2 / 2^16.
pub fn lp_bound(table: &[u8; 256], branch: u32) -> Bound {
    let rows: Vec<Vec<u64>> = walsh(table).iter().map(|r| r.iter().map(|&w| (w * w) as u64).collect()).collect();
    power_sum_bound(&rows, 16, branch)
}

type Set = [u64; 4];

fn set_and(a: &Set, b: &Set) -> Set {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

fn set_len(a: &Set) -> u32 {
    a.iter().map(|w| w.count_ones()).sum()
}

fn set_has(a: &Set, i: usize) -> bool {
    a[i / 64] >> (i % 64) & 1 == 1
}

/// One minimal-weight activity pattern: the 255 characteristics, as the
/// inner difference of each of the 5 active S-boxes, and which of them are
/// in round 1 (the attacker picks their input difference) or round 2 (the
/// attacker picks their output difference).
struct Pattern {
    inner: [[u8; 255]; 5],
    round1: [bool; 5],
    input_bytes: Vec<usize>,
    output_bytes: Vec<usize>,
}

fn mat_vec(m: &[[u8; 4]; 4], x: &[u8; 4]) -> [u8; 4] {
    std::array::from_fn(|i| (0..4).fold(0, |acc, j| acc ^ gf256::fast_mul(m[i][j], x[j])))
}

/// The vectors supported exactly on `mask` with a 1 in their first active
/// position (at most 256 of them when at most 2 positions are active).
fn normalised(mask: u8) -> Vec<[u8; 4]> {
    let active: Vec<usize> = (0..4).filter(|&i| mask >> i & 1 == 1).collect();
    let free = active.len() - 1;
    (0..(1u32 << (8 * free)))
        .map(|guess| {
            let mut v = [0u8; 4];
            v[active[0]] = 1;
            for (k, &i) in active[1..].iter().enumerate() {
                v[i] = (guess >> (8 * k)) as u8;
            }
            v
        })
        .filter(|v| active.iter().all(|&i| v[i] != 0))
        .collect()
}

fn support(v: &[u8; 4]) -> u8 {
    (0..4).filter(|&i| v[i] != 0).fold(0, |acc, i| acc | 1 << i)
}

/// All minimal-weight pattern pairs (|in| + |out| = 5) of an MDS 4x4 matrix.
fn patterns(m: &[[u8; 4]; 4]) -> Vec<Pattern> {
    let inverse = crate::matrix::invert(&crate::matrix::from_array(m)).expect("MDS matrices are invertible");
    let m_inv: [[u8; 4]; 4] = std::array::from_fn(|i| std::array::from_fn(|j| inverse[i][j]));
    let mut out = Vec::new();
    for in_mask in 1u8..16 {
        for out_mask in 1u8..16 {
            if in_mask.count_ones() + out_mask.count_ones() != 5 {
                continue;
            }
            let ins: Vec<usize> = (0..4).filter(|&i| in_mask >> i & 1 == 1).collect();
            let outs: Vec<usize> = (0..4).filter(|&i| out_mask >> i & 1 == 1).collect();
            // Base solution: x supported exactly on `ins` with M x supported
            // exactly on `outs`, unique up to scale for an MDS matrix. Search
            // the side with fewer active bytes (at most 2, so 256 guesses).
            let solutions: Vec<[u8; 4]> = if ins.len() <= outs.len() {
                normalised(in_mask).into_iter().filter(|x| support(&mat_vec(m, x)) == out_mask).collect()
            } else {
                normalised(out_mask).into_iter().map(|y| mat_vec(&m_inv, &y)).filter(|x| support(x) == in_mask).collect()
            };
            assert_eq!(solutions.len(), 1, "an MDS matrix has one solution per scale");
            let x = solutions[0];
            // Characteristic w is the base solution scaled by w + 1: its
            // inner differences at the 5 active S-boxes.
            let columns: Vec<[u8; 5]> = (1..=255u8)
                .map(|scale| {
                    let xs: [u8; 4] = std::array::from_fn(|i| gf256::fast_mul(scale, x[i]));
                    let ys = mat_vec(m, &xs);
                    let mut col = [0u8; 5];
                    for (p, &i) in ins.iter().enumerate() {
                        col[p] = xs[i];
                    }
                    for (q, &j) in outs.iter().enumerate() {
                        col[ins.len() + q] = ys[j];
                    }
                    col
                })
                .collect();
            let inner: [[u8; 255]; 5] = std::array::from_fn(|p| std::array::from_fn(|w| columns[w][p]));
            let round1: [bool; 5] = std::array::from_fn(|p| p < ins.len());
            out.push(Pattern { inner, round1, input_bytes: ins, output_bytes: outs });
        }
    }
    out
}

/// Search state: the characteristics still contributing, and the few that
/// hit a DDT entry of 4 (counted in `doubled`).
#[derive(Clone)]
struct Node {
    alive: Set,
    doubled: Vec<(usize, u32)>,
}

impl Node {
    /// Sum of 2^f over live characteristics (units of 2^-35).
    fn sum(&self) -> u64 {
        u64::from(set_len(&self.alive)) + self.doubled.iter().filter(|&&(w, _)| set_has(&self.alive, w)).map(|&(_, f)| (1u64 << f) - 1).sum::<u64>()
    }

    fn largest(&self) -> u64 {
        self.doubled.iter().filter(|&&(w, _)| set_has(&self.alive, w)).map(|&(_, f)| 1u64 << f).max().unwrap_or(1)
    }
}

struct Tables {
    /// alive[p][alpha]: characteristics with a non-zero DDT entry at position p.
    alive: Vec<Vec<Set>>,
    /// four[p][alpha]: the characteristic whose DDT entry there is 4.
    four: Vec<Vec<Option<usize>>>,
}

fn tables(d: &[[u16; 256]], pat: &Pattern, alphas: u32) -> Tables {
    let mut alive = vec![vec![[0u64; 4]; 256]; 5];
    let mut four = vec![vec![None; 256]; 5];
    for p in 0..5 {
        for alpha in 1..=alphas as usize {
            for w in 0..255 {
                let z = pat.inner[p][w] as usize;
                let v = if pat.round1[p] { d[alpha][z] } else { d[z][alpha] };
                assert!(v == 0 || v == 2 || v == 4, "search assumes a differentially 4-uniform S-box with entries 0, 2, 4");
                if v > 0 {
                    alive[p][alpha][w / 64] |= 1 << (w % 64);
                }
                if v == 4 {
                    assert!(four[p][alpha].is_none(), "at most one entry 4 per row and column");
                    four[p][alpha] = Some(w);
                }
            }
        }
    }
    Tables { alive, four }
}

fn search(t: &Tables, level: usize, node: &Node, alphas: u32, best: &AtomicU64) {
    if level == 5 {
        best.fetch_max(node.sum(), Ordering::Relaxed);
        return;
    }
    for alpha in 1..=alphas as usize {
        let mut next = Node { alive: set_and(&node.alive, &t.alive[level][alpha]), doubled: node.doubled.clone() };
        if let Some(w) = t.four[level][alpha] {
            if set_has(&next.alive, w) {
                match next.doubled.iter_mut().find(|(x, _)| *x == w) {
                    Some(entry) => entry.1 += 1,
                    None => next.doubled.push((w, 1)),
                }
            }
        }
        // Each remaining level can at most double one characteristic.
        let remaining = 5 - (level + 1);
        let bound = next.sum() + ((1u64 << remaining) - 1) * next.largest();
        if bound > best.load(Ordering::Relaxed) {
            search(t, level + 1, &next, alphas, best);
        }
    }
}

pub struct LowerBound {
    /// max over patterns of sum over characteristics of 2^f: the EDP is
    /// this / 2^35.
    pub units: u64,
    pub log2: f64,
    /// The activity pattern that reaches it (input bytes, output bytes).
    pub pattern: (Vec<usize>, Vec<usize>),
}

/// Keliher and Sui's lower bound on the 2-round MEDP of the super-box
/// S-box layer, 4x4 matrix `m`, S-box layer. `alphas` limits the outer
/// differences searched (255 for the real bound; smaller for tests).
pub fn ks_lower_bound(table: &[u8; 256], m: &[[u8; 4]; 4], alphas: u32) -> LowerBound {
    let d = ddt(table);
    let mut result = LowerBound { units: 0, log2: f64::NEG_INFINITY, pattern: (Vec::new(), Vec::new()) };
    for pat in patterns(m) {
        let t = tables(&d, &pat, alphas);
        let best = AtomicU64::new(0);
        let full: Set = [u64::MAX, u64::MAX, u64::MAX, (1u64 << 63) - 1];
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let next_alpha = AtomicU64::new(1);
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| loop {
                    let alpha = next_alpha.fetch_add(1, Ordering::Relaxed) as usize;
                    if alpha > alphas as usize {
                        break;
                    }
                    let mut node = Node { alive: set_and(&full, &t.alive[0][alpha]), doubled: Vec::new() };
                    if let Some(w) = t.four[0][alpha] {
                        node.doubled.push((w, 1));
                    }
                    search(&t, 1, &node, alphas, &best);
                });
            }
        });
        let units = best.load(Ordering::Relaxed);
        if units > result.units {
            result = LowerBound { units, log2: (units as f64).log2() - 35.0, pattern: (pat.input_bytes.clone(), pat.output_bytes.clone()) };
        }
    }
    result
}

/// Exhaustive version of the same maximum (tests only: no pruning).
pub fn ks_exhaustive(table: &[u8; 256], m: &[[u8; 4]; 4], alphas: u32) -> u64 {
    let d = ddt(table);
    let mut best = 0u64;
    for pat in patterns(m) {
        let weight = |p: usize, alpha: usize, w: usize| -> u64 {
            let z = pat.inner[p][w] as usize;
            u64::from(if pat.round1[p] { d[alpha][z] } else { d[z][alpha] })
        };
        let a = alphas as usize;
        for a0 in 1..=a {
            for a1 in 1..=a {
                for a2 in 1..=a {
                    for a3 in 1..=a {
                        for a4 in 1..=a {
                            let sum: u64 = (0..255).map(|w| weight(0, a0, w) * weight(1, a1, w) * weight(2, a2, w) * weight(3, a3, w) * weight(4, a4, w)).sum();
                            best = best.max(sum / 32);
                        }
                    }
                }
            }
        }
    }
    best
}

/// The AES MixColumns matrix (FIPS-197), for validation.
pub const AES_MIX_COLUMNS: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

#[cfg(test)]
mod tests {
    use super::*;

    // Keliher and Sui (ePrint 2005/321): the AES 2-round MEDP was known to
    // lie between 53/2^34 and 79/2^34, and the MELP below 192,773,764/2^54
    // (Park et al.'s bounds).
    #[test]
    fn park_bounds_reproduce_the_aes_values() {
        let aes = gf256::aes_sbox();
        let dp = dp_bound(&aes, 5);
        assert_eq!(dp.exact, Some((79 << 6, 40)), "79/2^34 = 5056/2^40");
        let lp = lp_bound(&aes, 5);
        assert_eq!(lp.exact, Some((192_773_764u128 << 26, 80)), "192,773,764/2^54");
    }

    #[test]
    fn pruned_search_equals_exhaustive_on_a_small_range() {
        let aes = gf256::aes_sbox();
        for alphas in [5u32, 7] {
            assert_eq!(ks_lower_bound(&aes, &AES_MIX_COLUMNS, alphas).units, ks_exhaustive(&aes, &AES_MIX_COLUMNS, alphas), "{alphas} outer differences");
        }
    }

    #[test]
    fn patterns_are_consistent() {
        let pats = patterns(&AES_MIX_COLUMNS);
        assert_eq!(pats.len(), 56, "Keliher and Sui: 5-LIST(1) has size 56");
        for pat in &pats {
            for p in 0..5 {
                let mut seen = [false; 256];
                for w in 0..255 {
                    let z = pat.inner[p][w] as usize;
                    assert!(z != 0 && !seen[z], "Lemma 1: distinct non-zero values in every position");
                    seen[z] = true;
                }
            }
        }
    }
}
