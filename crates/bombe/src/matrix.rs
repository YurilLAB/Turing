//! Analysis of the linear (mixing) layers: matrices over GF(2^8).
//!
//! A mixing matrix is **MDS** (maximum distance separable) when every square
//! submatrix is invertible. Then for any non-zero input x,
//! (active bytes of x) + (active bytes of M·x) >= n + 1, the best possible
//! **branch number**. That number is what forces attacks through many S-boxes.

use crate::gf256::{fast_inv as inv, fast_mul as mul};

pub type Matrix = Vec<Vec<u8>>;

pub fn from_array<const N: usize>(m: &[[u8; N]; N]) -> Matrix {
    m.iter().map(|row| row.to_vec()).collect()
}

pub fn mat_vec(m: &Matrix, x: &[u8]) -> Vec<u8> {
    m.iter().map(|row| row.iter().zip(x).fold(0, |acc, (&a, &b)| acc ^ mul(a, b))).collect()
}

pub fn mat_mul(a: &Matrix, b: &Matrix) -> Matrix {
    let n = a.len();
    (0..n)
        .map(|i| (0..n).map(|j| (0..n).fold(0, |acc, k| acc ^ mul(a[i][k], b[k][j]))).collect())
        .collect()
}

pub fn identity(n: usize) -> Matrix {
    (0..n).map(|i| (0..n).map(|j| (i == j) as u8).collect()).collect()
}

/// Gaussian elimination over GF(2^8).
pub fn nonsingular(mut m: Matrix) -> bool {
    let n = m.len();
    for col in 0..n {
        let Some(p) = (col..n).find(|&r| m[r][col] != 0) else {
            return false;
        };
        m.swap(col, p);
        let pivot_inv = inv(m[col][col]);
        let pivot = m[col].clone();
        for row in m.iter_mut().skip(col + 1) {
            if row[col] != 0 {
                let f = mul(row[col], pivot_inv);
                for (x, &p) in row.iter_mut().zip(&pivot).skip(col) {
                    *x ^= mul(f, p);
                }
            }
        }
    }
    true
}

/// Gauss-Jordan inverse over GF(2^8). None if singular.
pub fn invert(m: &Matrix) -> Option<Matrix> {
    let n = m.len();
    let mut a: Matrix = m.iter().zip(identity(n)).map(|(row, id)| [row.clone(), id].concat()).collect();
    for col in 0..n {
        let p = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, p);
        let pivot_inv = inv(a[col][col]);
        for x in a[col].iter_mut() {
            *x = mul(*x, pivot_inv);
        }
        let pivot = a[col].clone();
        for (r, row) in a.iter_mut().enumerate() {
            if r != col && row[col] != 0 {
                let f = row[col];
                for (x, &p) in row.iter_mut().zip(&pivot) {
                    *x ^= mul(f, p);
                }
            }
        }
    }
    Some(a.into_iter().map(|row| row[n..].to_vec()).collect())
}

fn submatrix(m: &Matrix, rows: &[usize], cols: &[usize]) -> Matrix {
    rows.iter().map(|&r| cols.iter().map(|&c| m[r][c]).collect()).collect()
}

/// All k-element subsets of 0..n (n <= 16), in increasing order.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    (0u32..1 << n)
        .filter(|m| m.count_ones() as usize == k)
        .map(|m| (0..n).filter(|&i| m >> i & 1 == 1).collect())
        .collect()
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn subset(&mut self, n: usize, k: usize) -> Vec<usize> {
        let mut all: Vec<usize> = (0..n).collect();
        for i in 0..k {
            let j = i + (self.next() % (n - i) as u64) as usize;
            all.swap(i, j);
        }
        let mut s = all[..k].to_vec();
        s.sort_unstable();
        s
    }
}

/// Result of checking every (or a sample of) k x k submatrices.
pub struct SubmatrixCheck {
    pub size: usize,
    pub checked: u64,
    pub exhaustive: bool,
    /// The first singular submatrix found, as (rows, columns).
    pub singular: Option<(Vec<usize>, Vec<usize>)>,
}

/// Checks k x k submatrices: all of them if there are at most `limit`
/// row-subset x column-subset pairs, otherwise `limit` random ones.
pub fn check_submatrices(m: &Matrix, k: usize, limit: u64, seed: u64) -> SubmatrixCheck {
    let n = m.len();
    let sets = subsets(n, k);
    let total = (sets.len() as u64).pow(2);
    let mut result = SubmatrixCheck { size: k, checked: 0, exhaustive: total <= limit, singular: None };
    let test = |rows: &[usize], cols: &[usize], result: &mut SubmatrixCheck| {
        result.checked += 1;
        if result.singular.is_none() && !nonsingular(submatrix(m, rows, cols)) {
            result.singular = Some((rows.to_vec(), cols.to_vec()));
        }
    };
    if result.exhaustive {
        for rows in &sets {
            for cols in &sets {
                test(rows, cols, &mut result);
            }
        }
    } else {
        let mut rng = Rng(seed | 1);
        for _ in 0..limit {
            let (rows, cols) = (rng.subset(n, k), rng.subset(n, k));
            test(&rows, &cols, &mut result);
        }
    }
    result
}

/// Whether `m` is a Cauchy matrix M[i][j] = 1/(x_i + y_j) over distinct
/// points. The theorem: every square submatrix of a Cauchy matrix is itself
/// Cauchy, and Cauchy matrices have non-zero determinant, so it is MDS.
pub fn is_cauchy(m: &Matrix, xs: &[u8], ys: &[u8]) -> bool {
    let mut points: Vec<u8> = xs.iter().chain(ys).copied().collect();
    points.sort_unstable();
    points.dedup();
    points.len() == xs.len() + ys.len()
        && m.iter().enumerate().all(|(i, row)| row.iter().enumerate().all(|(j, &v)| v == inv(xs[i] ^ ys[j])))
}

fn weight(v: &[u8]) -> usize {
    v.iter().filter(|&&b| b != 0).count()
}

/// Smallest wt(x) + wt(M·x) over every input with exactly `w` active bytes,
/// exhaustively if there are at most `limit` such inputs, else sampled.
/// Independent of the submatrix test: it measures the property directly.
pub fn min_branch_at_weight(m: &Matrix, w: usize, limit: u64, seed: u64) -> (usize, u64, bool) {
    let n = m.len();
    let positions = subsets(n, w);
    let total = positions.len() as u64 * 255u64.pow(w as u32);
    let mut best = usize::MAX;
    let mut record = |pos: &[usize], vals: &[u8]| {
        let mut x = vec![0u8; n];
        for (&p, &v) in pos.iter().zip(vals) {
            x[p] = v;
        }
        best = best.min(w + weight(&mat_vec(m, &x)));
    };
    if total <= limit {
        for pos in &positions {
            let mut vals = vec![1u8; w];
            loop {
                record(pos, &vals);
                // Odometer over 1..=255 in each active position.
                let mut i = 0;
                while i < w && vals[i] == 255 {
                    vals[i] = 1;
                    i += 1;
                }
                if i == w {
                    break;
                }
                vals[i] += 1;
            }
        }
        (best, total, true)
    } else {
        let mut rng = Rng(seed | 1);
        for _ in 0..limit {
            let pos = &positions[(rng.next() % positions.len() as u64) as usize];
            let vals: Vec<u8> = (0..w).map(|_| 1 + (rng.next() % 255) as u8).collect();
            record(pos, &vals);
        }
        (best, limit, false)
    }
}

/// Byte-activity propagation: bit 4c + r of a pattern is the byte in row r,
/// column c (the cipher's column-major state layout).
pub fn shift_rows_pattern(p: u16) -> u16 {
    let mut out = 0u16;
    for c in 0..4 {
        for r in 0..4 {
            if p >> (4 * ((c + r) % 4) + r) & 1 == 1 {
                out |= 1 << (4 * c + r);
            }
        }
    }
    out
}

/// An MDS column mix makes a whole column depend on any byte in it.
pub fn mix_columns_pattern(p: u16) -> u16 {
    (0..4).fold(0, |out, c| if p >> (4 * c) & 0xf != 0 { out | 0xf << (4 * c) } else { out })
}

/// An MDS whole-state mix makes every byte depend on any byte.
pub fn mix_state_pattern(p: u16) -> u16 {
    if p != 0 {
        0xffff
    } else {
        0
    }
}

/// Worst case, over every single starting byte, of the number of rounds
/// until every output byte depends on it.
pub fn rounds_to_full_diffusion(round: impl Fn(u16) -> u16) -> usize {
    (0..16)
        .map(|b| {
            let (mut p, mut rounds) = (1u16 << b, 0);
            while p != 0xffff && rounds < 64 {
                p = round(p);
                rounds += 1;
            }
            rounds
        })
        .max()
        .unwrap()
}

/// Full MDS verdict for an n x n matrix (n = 4 or 16).
pub struct MdsReport {
    pub n: usize,
    pub submatrices: Vec<SubmatrixCheck>,
    /// (input weight, min branch found, inputs tested, exhaustive)
    pub branch: Vec<(usize, usize, u64, bool)>,
    pub inverse_ok: bool,
}

impl MdsReport {
    /// Budget: exhaustive where the count of submatrices / inputs is at most
    /// the limits below, sampled elsewhere.
    pub fn new(m: &Matrix, m_inv: &Matrix) -> MdsReport {
        let n = m.len();
        let submatrices = (1..=n).map(|k| check_submatrices(m, k, 400_000, 0x5eed + k as u64)).collect();
        let branch = (1..=n.min(3))
            .map(|w| {
                let (b, tested, ex) = min_branch_at_weight(m, w, 2_000_000, 0xb7a + w as u64);
                (w, b, tested, ex)
            })
            .collect();
        let inverse_ok = mat_mul(m, m_inv) == identity(n) && mat_mul(m_inv, m) == identity(n);
        MdsReport { n, submatrices, branch, inverse_ok }
    }

    pub fn passed(&self) -> bool {
        self.submatrices.iter().all(|s| s.singular.is_none())
            && self.branch.iter().all(|&(_, b, _, _)| b > self.n)
            && self.inverse_ok
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for s in &self.submatrices {
            let how = if s.exhaustive { "all" } else { "sampled" };
            let verdict = match &s.singular {
                None => "all invertible".to_string(),
                Some((r, c)) => format!("SINGULAR at rows {r:?} cols {c:?}"),
            };
            out += &format!("    {:>2}x{:<2} submatrices  {how:>7} {:>9}  {verdict}\n", s.size, s.size, s.checked);
        }
        for &(w, b, tested, ex) in &self.branch {
            let how = if ex { "all" } else { "sampled" };
            out += &format!(
                "    inputs with {w} active byte(s)  {how:>7} {tested:>9}  min in+out active = {b} (need {})\n",
                self.n + 1
            );
        }
        out += &format!("    M x M^-1 = I                         {}\n", if self.inverse_ok { "yes" } else { "NO" });
        out
    }
}
