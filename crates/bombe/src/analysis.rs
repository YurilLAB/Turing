//! Measurements of an 8-bit S-box. Each function is one attack's view of it.

use crate::sbox::{Sbox, N};
use std::collections::BTreeMap;

fn parity(x: u8) -> bool {
    x.count_ones() & 1 == 1
}

fn histogram(values: impl Iterator<Item = u16>) -> BTreeMap<u16, usize> {
    let mut h = BTreeMap::new();
    for v in values {
        *h.entry(v).or_insert(0) += 1;
    }
    h
}

// ---------------------------------------------------------------------------
// Differential cryptanalysis
// ---------------------------------------------------------------------------

/// Difference Distribution Table: DDT[dx][dy] = #{x : S(x) ^ S(x ^ dx) = dy}.
/// A large entry means input difference dx produces output difference dy
/// unusually often, which a differential attack chains across rounds.
pub struct Ddt {
    counts: Vec<u16>,
}

pub fn ddt(s: &Sbox) -> Ddt {
    let mut counts = vec![0u16; N * N];
    for dx in 0..N {
        for x in 0..N {
            let dy = s.get(x as u8) ^ s.get((x ^ dx) as u8);
            counts[dx * N + dy as usize] += 1;
        }
    }
    Ddt { counts }
}

impl Ddt {
    pub fn get(&self, dx: u8, dy: u8) -> u16 {
        self.counts[dx as usize * N + dy as usize]
    }

    /// Largest entry over dx != 0 (row 0 is trivially DDT[0][0] = 256).
    /// A differential passes one S-box with probability at most this / 256.
    pub fn uniformity(&self) -> u16 {
        self.counts[N..].iter().copied().max().unwrap_or(0)
    }

    /// How often each value occurs over dx != 0.
    pub fn spectrum(&self) -> BTreeMap<u16, usize> {
        histogram(self.counts[N..].iter().copied())
    }

    pub fn raw(&self) -> &[u16] {
        &self.counts
    }
}

// ---------------------------------------------------------------------------
// Linear cryptanalysis
// ---------------------------------------------------------------------------

/// Walsh coefficients W(a, b) = sum over x of (-1)^(a·x XOR b·S(x)).
///
/// The linear approximation "a·x = b·S(x)" holds with probability
/// 1/2 + W/512, so W/256 is its correlation. W = 0 is perfect; |W| = 256 means
/// the approximation always (or never) holds and the S-box is linear.
pub struct Lat {
    walsh: Vec<i16>,
}

/// In-place fast Walsh-Hadamard transform: v[a] <- sum_x v[x] (-1)^(a·x).
fn fwht(v: &mut [i32; N]) {
    let mut h = 1;
    while h < N {
        for i in (0..N).step_by(h * 2) {
            for j in i..i + h {
                let (x, y) = (v[j], v[j + h]);
                v[j] = x + y;
                v[j + h] = x - y;
            }
        }
        h *= 2;
    }
}

pub fn lat(s: &Sbox) -> Lat {
    let mut walsh = vec![0i16; N * N];
    for b in 0..N {
        let mut f = [0i32; N];
        for (x, fx) in f.iter_mut().enumerate() {
            *fx = if parity(b as u8 & s.get(x as u8)) { -1 } else { 1 };
        }
        fwht(&mut f);
        for (a, &w) in f.iter().enumerate() {
            walsh[a * N + b] = w as i16;
        }
    }
    Lat { walsh }
}

impl Lat {
    pub fn get(&self, a: u8, b: u8) -> i16 {
        self.walsh[a as usize * N + b as usize]
    }

    fn nontrivial(&self) -> impl Iterator<Item = u16> + '_ {
        (0..N).flat_map(move |a| (1..N).map(move |b| self.walsh[a * N + b].unsigned_abs()))
    }

    /// Largest |W(a, b)| over output masks b != 0. Max correlation = this / 256.
    pub fn linearity(&self) -> u16 {
        self.nontrivial().max().unwrap_or(0)
    }

    /// Hamming distance from the nearest affine function: 128 - linearity / 2.
    pub fn nonlinearity(&self) -> u16 {
        128 - self.linearity() / 2
    }

    /// How often each |W| occurs over b != 0.
    pub fn spectrum(&self) -> BTreeMap<u16, usize> {
        histogram(self.nontrivial())
    }

    pub fn raw(&self) -> &[i16] {
        &self.walsh
    }
}

// ---------------------------------------------------------------------------
// Boomerang attacks
// ---------------------------------------------------------------------------

/// Largest entry of the Boomerang Connectivity Table (Cid et al., 2018):
/// BCT[di][do] = #{x : S⁻¹(S(x) ^ do) ^ S⁻¹(S(x ^ di) ^ do) = di}.
/// A boomerang attack glues two short differentials together at an S-box
/// layer; this bounds how well that joint works. None if S is not bijective.
pub fn boomerang_uniformity(s: &Sbox) -> Option<u16> {
    let inv = s.inverse()?;
    let mut worst = 0u16;
    for di in 1..N {
        for dout in 1..N {
            let mut count = 0u16;
            for x in 0..N {
                let a = inv.get(s.get(x as u8) ^ dout as u8);
                let b = inv.get(s.get((x ^ di) as u8) ^ dout as u8);
                if (a ^ b) as usize == di {
                    count += 1;
                }
            }
            worst = worst.max(count);
        }
    }
    Some(worst)
}

// ---------------------------------------------------------------------------
// Algebraic attacks
// ---------------------------------------------------------------------------

/// Algebraic degree of a Boolean function given by its truth table, via the
/// Möbius transform to algebraic normal form (ANF).
fn anf_degree(mut t: [u8; N]) -> u32 {
    for i in 0..8 {
        let bit = 1 << i;
        for x in 0..N {
            if x & bit != 0 {
                t[x] ^= t[x ^ bit];
            }
        }
    }
    (0..N).filter(|&x| t[x] == 1).map(|x| (x as u32).count_ones()).max().unwrap_or(0)
}

/// Degrees of the output bits (coordinates) and of every non-zero XOR
/// combination of output bits (components). Low degree lets an attacker write
/// the cipher as small polynomial equations and solve them.
pub struct Degrees {
    pub coordinates: [u32; 8],
    pub component_min: u32,
    pub component_max: u32,
}

pub fn degrees(s: &Sbox) -> Degrees {
    let component = |b: u8| {
        let mut t = [0u8; N];
        for (x, tx) in t.iter_mut().enumerate() {
            *tx = parity(b & s.get(x as u8)) as u8;
        }
        anf_degree(t)
    };
    let mut coordinates = [0u32; 8];
    for (i, d) in coordinates.iter_mut().enumerate() {
        *d = component(1 << i);
    }
    let all: Vec<u32> = (1..=255u8).map(component).collect();
    Degrees {
        coordinates,
        component_min: *all.iter().min().unwrap(),
        component_max: *all.iter().max().unwrap(),
    }
}

/// Number of linearly independent implicit equations relating the input bits
/// x and output bits y that hold for all 256 inputs.
/// `quadratic`: all monomials of degree <= 2 in (x, y).
/// `bi_affine`: only 1, x_i, y_j and x_i·y_j.
/// Many such equations are what algebraic attacks (e.g. XSL) try to exploit.
pub struct Equations {
    pub quadratic: usize,
    pub bi_affine: usize,
}

pub fn implicit_equations(s: &Sbox) -> Equations {
    let mut quadratic: Vec<Vec<usize>> = vec![vec![]];
    let mut bi_affine: Vec<Vec<usize>> = vec![vec![]];
    for i in 0..16 {
        quadratic.push(vec![i]);
        bi_affine.push(vec![i]);
    }
    for i in 0..16 {
        for j in i + 1..16 {
            quadratic.push(vec![i, j]);
            if i < 8 && j >= 8 {
                bi_affine.push(vec![i, j]);
            }
        }
    }
    // Variables 0..8 are the input bits, 8..16 the output bits.
    let var = |x: usize, v: usize| -> bool {
        if v < 8 {
            (x >> v) & 1 == 1
        } else {
            (s.get(x as u8) >> (v - 8)) & 1 == 1
        }
    };
    let null_space = |monomials: &[Vec<usize>]| {
        let words = monomials.len().div_ceil(64);
        let rows: Vec<Vec<u64>> = (0..N)
            .map(|x| {
                let mut row = vec![0u64; words];
                for (col, m) in monomials.iter().enumerate() {
                    if m.iter().all(|&v| var(x, v)) {
                        row[col / 64] |= 1 << (col % 64);
                    }
                }
                row
            })
            .collect();
        monomials.len() - gf2_rank(rows, monomials.len())
    };
    Equations {
        quadratic: null_space(&quadratic),
        bi_affine: null_space(&bi_affine),
    }
}

fn gf2_rank(mut rows: Vec<Vec<u64>>, ncols: usize) -> usize {
    let mut rank = 0;
    for col in 0..ncols {
        let (w, bit) = (col / 64, 1u64 << (col % 64));
        let Some(p) = (rank..rows.len()).find(|&r| rows[r][w] & bit != 0) else {
            continue;
        };
        rows.swap(rank, p);
        let pivot = rows[rank].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r != rank && row[w] & bit != 0 {
                for (a, b) in row.iter_mut().zip(&pivot) {
                    *a ^= b;
                }
            }
        }
        rank += 1;
    }
    rank
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

pub fn fixed_points(s: &Sbox) -> usize {
    (0..N).filter(|&x| s.get(x as u8) as usize == x).count()
}

/// Points where S(x) = NOT x.
pub fn opposite_fixed_points(s: &Sbox) -> usize {
    (0..N).filter(|&x| s.get(x as u8) == !(x as u8)).count()
}

/// Cycle lengths of the permutation, longest first. Short cycles are a
/// warning sign of structure. None if S is not bijective.
pub fn cycles(s: &Sbox) -> Option<Vec<usize>> {
    if !s.is_bijective() {
        return None;
    }
    let mut seen = [false; N];
    let mut lengths = Vec::new();
    for start in 0..N {
        let (mut x, mut len) = (start, 0);
        while !seen[x] {
            seen[x] = true;
            x = s.get(x as u8) as usize;
            len += 1;
        }
        if len > 0 {
            lengths.push(len);
        }
    }
    lengths.sort_unstable_by(|a, b| b.cmp(a));
    Some(lengths)
}

/// Differential branch number: min over a != b of wt(a^b) + wt(S(a)^S(b)).
/// The fewest bits an input difference and its output difference can touch.
pub fn differential_branch_number(s: &Sbox) -> u32 {
    let mut best = u32::MAX;
    for a in 0..N {
        for b in a + 1..N {
            let w = ((a ^ b) as u32).count_ones() + (s.get(a as u8) ^ s.get(b as u8)).count_ones();
            best = best.min(w);
        }
    }
    best
}

/// Linear branch number: min wt(a) + wt(b) over masks (a, b) != (0, 0)
/// whose correlation is non-zero.
pub fn linear_branch_number(lat: &Lat) -> u32 {
    let mut best = u32::MAX;
    for a in 0..N {
        for b in 0..N {
            if (a, b) != (0, 0) && lat.get(a as u8, b as u8) != 0 {
                best = best.min(((a | b << 8) as u32).count_ones());
            }
        }
    }
    best
}
