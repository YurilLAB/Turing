//! Lattice reduction (LLL and BKZ) and the primal attack on LWE, run
//! against Turing-1026's own key generation at small dimension (docs/16).
//!
//! The attack is the one docs/16's cost estimate prices: the public key
//! B = A S + E gives, for each column s of S, m = n samples b = A s + e mod q;
//! the lattice {(x, y, t) : y = t b - A x mod q} contains the unusually
//! short vector (s, e, 1) (Kannan's embedding), and BKZ with a large enough
//! block size finds it. At n = 1026 the estimate needs block size 868; here
//! n is small enough for LLL and BKZ-10 to 20 on one core, and the point is
//! that the secret comes out of the real implementation's public key, and
//! that the block size it takes grows with n as the estimate's success
//! condition says.
//!
//! LLL is the textbook floating-point algorithm (Cohen, Algorithm 2.6.3)
//! on an integer basis. BKZ enumerates each block's shortest vector
//! (Schnorr-Euchner, no pruning) and, rather than inserting it and removing
//! the resulting dependency, turns the block basis into one that starts
//! with it by Euclid's algorithm on the coefficients (every step is
//! unimodular, so the lattice never changes).

pub type Basis = Vec<Vec<i64>>;

fn dot(a: &[i64], b: &[i64]) -> f64 {
    a.iter().zip(b).map(|(&x, &y)| x as f64 * y as f64).sum()
}

/// Gram-Schmidt: mu[i][j] for j < i, and the squared norms |b*_i|^2.
pub fn gso(b: &Basis) -> (Vec<Vec<f64>>, Vec<f64>) {
    let d = b.len();
    let mut mu = vec![vec![0.0; d]; d];
    let mut star: Vec<Vec<f64>> = Vec::with_capacity(d);
    let mut norms = vec![0.0; d];
    for i in 0..d {
        let mut v: Vec<f64> = b[i].iter().map(|&x| x as f64).collect();
        for j in 0..i {
            mu[i][j] = b[i].iter().zip(&star[j]).map(|(&x, &y)| x as f64 * y).sum::<f64>() / norms[j];
            for (a, &s) in v.iter_mut().zip(&star[j]) {
                *a -= mu[i][j] * s;
            }
        }
        norms[i] = v.iter().map(|x| x * x).sum();
        star.push(v);
    }
    (mu, norms)
}

/// LLL with parameter delta (0.99 here), in place.
pub fn lll(b: &mut Basis, delta: f64) {
    let d = b.len();
    if d < 2 {
        return;
    }
    let (mut mu, mut bn) = gso(b);
    let mut k = 1;
    while k < d {
        for j in (0..k).rev() {
            let r = mu[k][j].round();
            if r != 0.0 {
                let ri = r as i64;
                let (low, high) = b.split_at_mut(k);
                for (x, &y) in high[0].iter_mut().zip(&low[j]) {
                    *x -= ri * y;
                }
                let (rows_below, rows_from_k) = mu.split_at_mut(k);
                for (x, &y) in rows_from_k[0][..j].iter_mut().zip(&rows_below[j][..j]) {
                    *x -= r * y;
                }
                mu[k][j] -= r;
            }
        }
        if bn[k] >= (delta - mu[k][k - 1] * mu[k][k - 1]) * bn[k - 1] {
            k += 1;
        } else {
            b.swap(k, k - 1);
            let m = mu[k][k - 1];
            let new = bn[k] + m * m * bn[k - 1];
            mu[k][k - 1] = m * bn[k - 1] / new;
            bn[k] = bn[k - 1] * bn[k] / new;
            bn[k - 1] = new;
            let (rows_below, rows_from_k) = mu.split_at_mut(k);
            rows_below[k - 1][..k - 1].swap_with_slice(&mut rows_from_k[0][..k - 1]);
            for i in k + 1..d {
                let t = mu[i][k];
                mu[i][k] = mu[i][k - 1] - m * t;
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k];
            }
            k = (k - 1).max(1);
        }
    }
}

/// Whether b is size-reduced and satisfies Lovász's condition (with a
/// small tolerance for floating point).
pub fn is_lll_reduced(b: &Basis, delta: f64) -> bool {
    let (mu, bn) = gso(b);
    let d = b.len();
    (1..d).all(|i| (0..i).all(|j| mu[i][j].abs() <= 0.5 + 1e-6)) && (1..d).all(|i| bn[i] >= (delta - mu[i][i - 1].powi(2)) * bn[i - 1] * (1.0 - 1e-9))
}

/// The shortest nonzero vector of the projected block [k, end), as
/// integer coefficients on b_k..b_end, if one is shorter than `radius`
/// (squared). Schnorr-Euchner enumeration: depth first, each level's
/// candidates in order of distance from its centre, the first level's
/// sign fixed to halve the work.
pub fn enumerate(mu: &[Vec<f64>], bn: &[f64], k: usize, end: usize, radius: f64) -> Option<Vec<i64>> {
    struct Search<'a> {
        mu: &'a [Vec<f64>],
        bn: &'a [f64],
        k: usize,
        x: Vec<i64>,
        radius: f64,
        best: Option<Vec<i64>>,
    }
    impl Search<'_> {
        // `top`: every coordinate above this level is zero, so only one
        // sign of this one needs trying (v and -v have the same length).
        fn go(&mut self, level: usize, partial: f64, top: bool) {
            let n = self.x.len();
            let centre = -(level + 1..n).map(|j| self.x[j] as f64 * self.mu[self.k + j][self.k + level]).sum::<f64>();
            let first = centre.round() as i64;
            let side = if centre >= first as f64 { 1 } else { -1 };
            // first, first + side, first - side, first + 2 side, ...: in
            // order of distance from the centre, so the first candidate out
            // of range ends the level.
            for step in 0i64.. {
                let t = (step + 1) / 2;
                let xi = first + if step % 2 == 1 { side * t } else { -side * t };
                let dist = (xi as f64 - centre).powi(2) * self.bn[self.k + level];
                if partial + dist >= self.radius {
                    break;
                }
                if top && xi < 0 {
                    continue;
                }
                self.x[level] = xi;
                if level == 0 {
                    if self.x.iter().any(|&v| v != 0) {
                        self.radius = partial + dist;
                        self.best = Some(self.x.clone());
                    }
                } else {
                    self.go(level - 1, partial + dist, top && xi == 0);
                }
            }
            self.x[level] = 0;
        }
    }
    let mut search = Search { mu, bn, k, x: vec![0; end - k], radius, best: None };
    search.go(end - k - 1, 0.0, true);
    search.best
}

/// Makes b[k] equal to sum x_i b[k + i] by unimodular steps inside the
/// block: Euclid's algorithm on the coefficients, mirrored on the vectors.
fn install(b: &mut Basis, k: usize, x: &[i64]) {
    let mut x = x.to_vec();
    loop {
        let nonzero: Vec<usize> = (0..x.len()).filter(|&i| x[i] != 0).collect();
        if nonzero.len() == 1 {
            let i = nonzero[0];
            // x[i] is +-1: the gcd of a shortest vector's coefficients is 1.
            debug_assert_eq!(x[i].abs(), 1);
            if x[i] < 0 {
                b[k + i].iter_mut().for_each(|v| *v = -*v);
            }
            let v = b.remove(k + i);
            b.insert(k, v);
            return;
        }
        // The two entries of smallest magnitude: reduce the larger by the
        // smaller. v = x_i b_i + x_j b_j = (x_i - c x_j) b_i + x_j (b_j + c b_i).
        let mut by_size = nonzero.clone();
        by_size.sort_by_key(|&i| x[i].abs());
        let (j, i) = (by_size[0], by_size[1]);
        let c = x[i] / x[j];
        x[i] -= c * x[j];
        let bi = b[k + i].clone();
        for (y, &z) in b[k + j].iter_mut().zip(&bi) {
            *y += c * z;
        }
    }
}

/// BKZ with block size beta: tours until one changes nothing, at most
/// `max_tours`. Returns the number of tours run.
pub fn bkz(b: &mut Basis, beta: usize, max_tours: usize) -> usize {
    lll(b, 0.99);
    let d = b.len();
    for tour in 1..=max_tours {
        let mut changed = false;
        for k in 0..d - 1 {
            let end = (k + beta).min(d);
            let (mu, bn) = gso(b);
            if let Some(x) = enumerate(&mu, &bn, k, end, 0.999 * bn[k]) {
                install(b, k, &x);
                lll(b, 0.99);
                changed = true;
            }
        }
        if !changed {
            return tour;
        }
    }
    max_tours
}

/// Kannan's embedding of b = A s + e mod q (A: m x n, rows of the basis):
/// [e_i | -A^T row i mod q | 0] for i < n, [0 | q e_j | 0] for j < m, and
/// [0 | b | 1]. It contains (s, e, 1).
pub fn embedding(a: &[Vec<i64>], b: &[i64], q: i64) -> Basis {
    let (m, n) = (a.len(), a[0].len());
    let mut rows = Vec::with_capacity(n + m + 1);
    for i in 0..n {
        let mut r = vec![0i64; n + m + 1];
        r[i] = 1;
        for (j, row) in a.iter().enumerate() {
            r[n + j] = (-row[i]).rem_euclid(q);
        }
        rows.push(r);
    }
    for j in 0..m {
        let mut r = vec![0i64; n + m + 1];
        r[n + j] = q;
        rows.push(r);
    }
    let mut last = vec![0i64; n + m + 1];
    last[n..n + m].copy_from_slice(b);
    last[n + m] = 1;
    rows.push(last);
    rows
}

/// The root Hermite factor a basis reaches: (|b_1| / vol^(1/d))^(1/d).
pub fn root_hermite(b: &Basis) -> f64 {
    let (_, bn) = gso(b);
    let d = b.len() as f64;
    let log_vol: f64 = bn.iter().map(|x| 0.5 * x.ln()).sum();
    ((0.5 * dot(&b[0], &b[0]).ln() - log_vol / d) / d).exp()
}

/// The success condition docs/16's estimate uses (ADPS16, eq. (1)), for
/// the embedding here (m = n samples, dimension d = 2n + 1, volume q^n):
/// BKZ-beta reaching root Hermite factor `delta` finds (s, e, 1) when
/// sigma sqrt(beta) <= delta^(2 beta - d - 1) q^(n / d).
pub fn predicts_success(n: usize, log_q: u32, sigma: f64, beta: usize, delta: f64) -> bool {
    let d = (2 * n + 1) as f64;
    sigma.ln() + 0.5 * (beta as f64).ln() <= (2.0 * beta as f64 - d - 1.0) * delta.ln() + n as f64 / d * f64::from(log_q) * std::f64::consts::LN_2
}

/// The root Hermite factor BKZ-beta (2: LLL) reaches here on random
/// embedding lattices of the attack's shape: the average of `samples` runs.
pub fn measured_delta(n: usize, log_q: u32, beta: usize, samples: usize, label: &str) -> f64 {
    let mut rng = crate::rng::Rng::new(label);
    let q = 1i64 << log_q;
    (0..samples)
        .map(|_| {
            let a: Vec<Vec<i64>> = (0..n).map(|_| (0..n).map(|_| rng.below(q as u64) as i64).collect()).collect();
            let b: Vec<i64> = (0..n).map(|_| rng.below(q as u64) as i64).collect();
            let mut basis = embedding(&a, &b, q);
            if beta <= 2 {
                lll(&mut basis, 0.99);
            } else {
                bkz(&mut basis, beta, 8);
            }
            root_hermite(&basis)
        })
        .sum::<f64>()
        / samples as f64
}

/// One primal attack on column 0 of a Turing-1026 key at dimension n.
#[derive(Clone, Debug)]
pub struct Attack {
    pub n: usize,
    pub log_q: u32,
    pub eta: u32,
    /// The smallest reduction that exposed (s, e, 1): 0 for none of those
    /// tried, 2 for LLL, else the BKZ block size.
    pub broken_by: usize,
    pub seconds: f64,
}

/// Makes a key with the real implementation (`turing::lwe::keygen`),
/// rebuilds A from its seed, and runs LLL, then BKZ with each block size in
/// `betas`, until the embedding's basis holds +-(s, e, 1) for column 0 of S.
pub fn attack_turing_key(n: usize, log_q: u32, eta: u32, betas: &[usize], label: &str) -> Attack {
    let p = turing::lwe::Params { n, nbar: 8, mbar: 1, log_q, eta };
    let mut rng = crate::rng::Rng::new(label);
    let seed_a: [u8; 32] = rng.bytes();
    let mut noise = turing::xof::SecretXof::new("Bombe lattice attack");
    noise.absorb(&rng.bytes::<32>());
    let (mut s, mut bm) = (vec![0u16; n * 8], vec![0u16; n * 8]);
    turing::lwe::keygen(&p, &seed_a, &mut noise, &mut s, &mut bm);
    let q = 1i64 << log_q;
    let mut row = vec![0u16; n];
    let a: Vec<Vec<i64>> = (0..n)
        .map(|i| {
            turing::lwe::matrix_row(&p, &seed_a, i, &mut row);
            row.iter().map(|&v| i64::from(v)).collect()
        })
        .collect();
    let b: Vec<i64> = (0..n).map(|i| i64::from(bm[i * 8])).collect();
    let secret: Vec<i64> = (0..n).map(|k| i64::from(s[k * 8] as i16)).collect();
    let error: Vec<i64> = (0..n).map(|i| (b[i] - (0..n).map(|k| a[i][k] * secret[k]).sum::<i64>()).rem_euclid(q)).map(|e| if e > q / 2 { e - q } else { e }).collect();
    let target: Vec<i64> = secret.iter().chain(&error).copied().chain([1]).collect();
    let found = |basis: &Basis| basis.iter().any(|v| *v == target || v.iter().zip(&target).all(|(x, y)| *x == -*y));
    let start = std::time::Instant::now();
    let mut basis = embedding(&a, &b, q);
    lll(&mut basis, 0.99);
    let mut broken_by = if found(&basis) { 2 } else { 0 };
    for &beta in betas {
        if broken_by != 0 {
            break;
        }
        bkz(&mut basis, beta, 8);
        if found(&basis) {
            broken_by = beta;
        }
    }
    Attack { n, log_q, eta, broken_by, seconds: start.elapsed().as_secs_f64() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn random_qary(n: usize, m: usize, q: i64, rng: &mut Rng) -> (Vec<Vec<i64>>, Basis) {
        let a: Vec<Vec<i64>> = (0..m).map(|_| (0..n).map(|_| rng.below(q as u64) as i64).collect()).collect();
        let b: Vec<i64> = (0..m).map(|_| rng.below(q as u64) as i64).collect();
        let basis = embedding(&a, &b, q);
        (a, basis)
    }

    // Every vector of the embedding lattice satisfies y + A x - t b = 0 mod q.
    fn in_lattice(v: &[i64], a: &[Vec<i64>], b: &[i64], q: i64) -> bool {
        let (m, n) = (a.len(), a[0].len());
        (0..m).all(|j| (v[n + j] + (0..n).map(|i| a[j][i] * v[i]).sum::<i64>() - v[n + m] * b[j]).rem_euclid(q) == 0)
    }

    #[test]
    fn lll_reduces_and_keeps_the_lattice() {
        let mut rng = Rng::new("lattice lll");
        let q = 97;
        let (a, mut basis) = random_qary(10, 12, q, &mut rng);
        let b: Vec<i64> = basis.last().expect("row")[10..22].to_vec();
        let log_vol: f64 = gso(&basis).1.iter().map(|x| 0.5 * x.ln()).sum();
        lll(&mut basis, 0.99);
        assert!(is_lll_reduced(&basis, 0.99));
        assert!(basis.iter().all(|v| in_lattice(v, &a, &b, q)));
        let after: f64 = gso(&basis).1.iter().map(|x| 0.5 * x.ln()).sum();
        assert!((log_vol - after).abs() < 1e-6, "volume {log_vol} -> {after}");
    }

    // Enumeration finds the true shortest vector: brute force over all
    // coefficient vectors in a box on a 5-dimensional LLL-reduced basis.
    #[test]
    fn enumeration_finds_the_shortest_vector() {
        let mut rng = Rng::new("lattice enum");
        for _ in 0..10 {
            let mut basis: Basis = (0..5).map(|_| (0..5).map(|_| rng.below(41) as i64 - 20).collect()).collect();
            lll(&mut basis, 0.99);
            let (mu, bn) = gso(&basis);
            let found = enumerate(&mu, &bn, 0, 5, f64::INFINITY).expect("a vector");
            let len = |x: &[i64]| -> i64 {
                let v: Vec<i64> = (0..5).map(|t| (0..5).map(|i| x[i] * basis[i][t]).sum()).collect();
                v.iter().map(|y| y * y).sum()
            };
            let mut best = i64::MAX;
            let r = 4i64;
            let mut x = [-r; 5];
            loop {
                if x.iter().any(|&v| v != 0) {
                    best = best.min(len(&x));
                }
                let mut i = 0;
                while i < 5 && x[i] == r {
                    x[i] = -r;
                    i += 1;
                }
                if i == 5 {
                    break;
                }
                x[i] += 1;
            }
            assert_eq!(len(&found), best);
        }
        // A basis whose shortest vector needs coefficients of both signs:
        // b1 - b2 = (0, 1, -1, 0), length^2 2, where every combination with
        // coefficients of one sign is at least 10 long.
        let basis: Basis = vec![vec![10, 1, 0, 0], vec![10, 0, 1, 0], vec![0, 0, 0, 13], vec![5, 5, 5, 5]];
        let (mu, bn) = gso(&basis);
        let x = enumerate(&mu, &bn, 0, 4, f64::INFINITY).expect("a vector");
        let v: Vec<i64> = (0..4).map(|t| (0..4).map(|i| x[i] * basis[i][t]).sum()).collect();
        assert_eq!(v.iter().map(|y| y * y).sum::<i64>(), 2, "{x:?}");
    }

    // BKZ keeps the lattice and reaches a shorter first vector than LLL.
    #[test]
    fn bkz_improves_on_lll() {
        let mut rng = Rng::new("lattice bkz");
        let q = 1021;
        let (a, basis) = random_qary(20, 20, q, &mut rng);
        let b: Vec<i64> = basis.last().expect("row")[20..40].to_vec();
        let (mut l, mut k) = (basis.clone(), basis);
        lll(&mut l, 0.99);
        bkz(&mut k, 12, 8);
        assert!(k.iter().all(|v| in_lattice(v, &a, &b, q)));
        assert!(is_lll_reduced(&k, 0.99));
        assert!(root_hermite(&k) <= root_hermite(&l) + 1e-9, "{} vs {}", root_hermite(&k), root_hermite(&l));
    }

    // The attack recovers a small Turing-1026 key's secret column.
    #[test]
    fn recovers_a_small_key() {
        let a = attack_turing_key(12, 11, 18, &[10], "lattice test key");
        assert!(a.broken_by != 0, "{a:?}");
    }
}
