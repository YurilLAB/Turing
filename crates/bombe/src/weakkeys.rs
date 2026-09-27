//! The decryption-failure probability of one fixed Turing-1026 key, and how
//! it is spread over keys (docs/16).
//!
//! The average over keys, 2^-266.06, is what the Fujisaki-Okamoto bounds use
//! (delta-correctness averages over key generation). A decapsulation key is
//! used many times, though, so the question here is how bad an unlucky key
//! can be.
//!
//! For a fixed key, the error of coefficient (i, j) of a ciphertext is
//! X = sum_k E[k][j] S'[i][k] - S[k][j] E'[i][k] + E''[i][j], the key's
//! entries times fresh CBD(eta) samples. Only the histogram of the absolute
//! values in column j of E and S (2n entries) matters, since the fresh
//! samples are symmetric, and values v with multiplicity c contribute
//! v CBD(c eta). Three tools:
//!
//! - `Column::exact_failure`: the conditional law by exact convolution.
//! - `Column::chernoff_log2`: a proven bound. CBD(eta) has moment generating
//!   function cosh(t/2)^(2 eta), so P(X >= h) <= min_l exp(K(l) - l h) with
//!   K(l) = 2 eta [sum_v c_v ln cosh(l v / 2) + ln cosh(l / 2)].
//! - `Column::saddlepoint_log2`: Lugannani and Rice's approximation with the
//!   continuity correction for integer variables; checked against the exact
//!   law in the tests, it is what makes 100,000 keys affordable.
//!
//! Two proven statements over all keys, for a key's failure bound D (the
//! union bound over its 256 coefficients, which is what every figure here
//! is):
//!
//! - Markov: D averages exactly to delta = 2^-266.06 over keys (each term's
//!   average is the unconditional per-coefficient rate), so at most
//!   delta / tau of keys have D >= tau.
//! - Norms: ln cosh(sqrt(u)) is concave in u, so by Jensen a column's
//!   Chernoff bound is at most that of a column whose 2n entries all have
//!   the same square, which depends only on the column's squared norm N; the
//!   law of N (a sum of 2n squared CBD(eta) samples) is computed exactly by
//!   convolution. Hence P_keys[D > 512 B(T)] <= 32 P(N > T), with
//!   512 = 8 rows x 32 columns x 2 sides.
//!
//! Markov is the stronger near the average, the norms far from it.

use crate::dfr::Law;

/// Turing-1026's decoding window half-width, q/4.
pub const WINDOW: i64 = 1 << 13;

/// The absolute values of one column of E and the same column of S.
#[derive(Clone, Debug)]
pub struct Column {
    pub eta: u32,
    /// counts[v] = how many of the 2n entries have |value| = v.
    pub counts: Vec<u64>,
}

fn ln_cosh(x: f64) -> f64 {
    let a = x.abs();
    a + (-2.0 * a).exp().ln_1p() - std::f64::consts::LN_2
}

impl Column {
    pub fn from_values(eta: u32, values: impl IntoIterator<Item = i64>) -> Column {
        let mut counts = vec![0u64; eta as usize + 1];
        for v in values {
            counts[v.unsigned_abs() as usize] += 1;
        }
        Column { eta, counts }
    }

    /// A column whose `entries` values all have square N / entries: the
    /// worst case, by Jensen, for the Chernoff bound at squared norm N. Only
    /// used through `flat_chernoff_log2`, which takes the norm directly.
    pub fn norm(&self) -> u64 {
        self.counts.iter().enumerate().map(|(v, &c)| c * (v * v) as u64).sum()
    }

    /// K(l), K'(l), K''(l) of the column's error coefficient (the extra
    /// E'' sample included).
    fn cgf(&self, l: f64) -> (f64, f64, f64) {
        let two_eta = 2.0 * f64::from(self.eta);
        let mut k = (0.0, 0.0, 0.0);
        let mut add = |v: f64, c: f64| {
            let x = l * v / 2.0;
            let t = x.tanh();
            k.0 += c * ln_cosh(x);
            k.1 += c * v / 2.0 * t;
            k.2 += c * v * v / 4.0 * (1.0 - t * t);
        };
        for (v, &c) in self.counts.iter().enumerate().skip(1) {
            add(v as f64, c as f64);
        }
        add(1.0, 1.0);
        (two_eta * k.0, two_eta * k.1, two_eta * k.2)
    }

    /// The l > 0 with K'(l) = x, by bisection (K' is increasing).
    fn solve(&self, x: f64) -> f64 {
        let (mut lo, mut hi) = (0.0, 1.0);
        while self.cgf(hi).1 < x {
            hi *= 2.0;
        }
        for _ in 0..200 {
            let mid = (lo + hi) / 2.0;
            if self.cgf(mid).1 < x {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        (lo + hi) / 2.0
    }

    /// log2 of a proven bound on P(X outside [-h, h)): 2 min_l exp(K(l) - l h).
    pub fn chernoff_log2(&self, h: i64) -> f64 {
        let l = self.solve(h as f64);
        let (k, _, _) = self.cgf(l);
        (k - l * h as f64) / std::f64::consts::LN_2 + 1.0
    }

    /// log2 of Lugannani and Rice's approximation of P(X outside [-h, h)) =
    /// P(X >= h) + P(X >= h + 1), each with the continuity correction for an
    /// integer variable (saddlepoint at h - 1/2, u = 2 sinh(l/2) sqrt(K'')).
    pub fn saddlepoint_log2(&self, h: i64) -> f64 {
        let one = |x: i64| -> f64 {
            let y = x as f64 - 0.5;
            let l = self.solve(y);
            let (k, _, k2) = self.cgf(l);
            let w = (2.0 * (l * y - k)).sqrt();
            let u = 2.0 * (l / 2.0).sinh() * k2.sqrt();
            // 1 - Phi(w) + phi(w) (1/u - 1/w) = phi(w) (1/u + R(w) - 1/w), with
            // Mills' ratio R(w) - 1/w = -1/w^3 + 3/w^5 - 15/w^7 + ... (w > 8).
            assert!(w > 8.0, "the far-tail series needs w > 8, got {w}");
            let correction = -1.0 / w.powi(3) + 3.0 / w.powi(5) - 15.0 / w.powi(7) + 105.0 / w.powi(9);
            let ln_phi = -w * w / 2.0 - 0.5 * (2.0 * std::f64::consts::PI).ln();
            ln_phi + (1.0 / u + correction).ln()
        };
        let (a, b) = (one(h), one(h + 1));
        let top = a.max(b);
        (top + ((a - top).exp() + (b - top).exp()).ln()) / std::f64::consts::LN_2
    }

    /// The exact P(X outside [-h, h)) by convolution: v CBD(c_v eta) for
    /// every value v with multiplicity c_v, and one CBD(eta).
    pub fn exact_failure(&self, h: i64) -> f64 {
        let chi = Law::cbd(self.eta);
        let mut law = chi.clone();
        for (v, &c) in self.counts.iter().enumerate().skip(1) {
            if c > 0 {
                // the sparse factor outside, so conv skips its zeros
                law = chi.power(c).scaled(v as i64).conv(&law);
            }
        }
        law.sum_where(|x| x < -h || x >= h)
    }
}

/// log2 of the Chernoff bound of a column whose `entries` values all have
/// square N / entries (Jensen: no column of squared norm N has a larger
/// bound). Two-sided.
pub fn flat_chernoff_log2(norm: f64, entries: u64, eta: u32, h: i64) -> f64 {
    let two_eta = 2.0 * f64::from(eta);
    let a = (norm / entries as f64).sqrt();
    let cgf = |l: f64| -> (f64, f64) {
        let (x, y) = (l * a / 2.0, l / 2.0);
        (two_eta * (entries as f64 * ln_cosh(x) + ln_cosh(y)), two_eta * (entries as f64 * a / 2.0 * x.tanh() + 0.5 * y.tanh()))
    };
    let (mut lo, mut hi) = (0.0, 1.0);
    while cgf(hi).1 < h as f64 {
        hi *= 2.0;
    }
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if cgf(mid).1 < h as f64 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let l = (lo + hi) / 2.0;
    (cgf(l).0 - l * h as f64) / std::f64::consts::LN_2 + 1.0
}

/// The exact law of the squared norm of `entries` independent CBD(eta)
/// samples.
pub fn norm_law(eta: u32, entries: u64) -> Law {
    let chi = Law::cbd(eta);
    let mut p = vec![0.0; (eta * eta) as usize + 1];
    for (v, &pv) in chi.support().zip(&chi.p) {
        p[(v * v) as usize] += pv;
    }
    Law { lo: 0, p }.power(entries)
}

/// One line of the proven statement: the fraction of keys whose failure
/// bound can exceed 2^`failure_log2`.
#[derive(Clone, Copy, Debug)]
pub struct Tail {
    pub failure_log2: f64,
    /// The squared-norm threshold T with 512 B(T) = 2^failure_log2.
    pub norm: i64,
    /// log2 of 32 P(N > T).
    pub norm_log2: f64,
    /// log2 of delta / 2^failure_log2 (Markov).
    pub markov_log2: f64,
}

impl Tail {
    /// log2 of the proven fraction: the smaller of the two bounds.
    pub fn fraction_log2(&self) -> f64 {
        self.norm_log2.min(self.markov_log2)
    }
}

/// For each failure level, the fraction of Turing-1026 keys that could
/// exceed it, proven: Markov on the exact average, and Chernoff, Jensen and
/// the exact law of N with a union bound over the 32 columns.
pub fn proven_tails(levels: &[f64]) -> Vec<Tail> {
    let p = turing::turing1026::PARAMS;
    let delta = crate::dfr::turing_1026_rate().message;
    let entries = 2 * p.n as u64;
    let law = norm_law(p.eta, entries);
    let columns = p.nbar as f64;
    let factor = (2 * p.mbar * p.nbar) as f64; // 512 with the two sides
    levels
        .iter()
        .map(|&level| {
            // the largest integer norm whose bound stays at or below the level
            let (mut lo, mut hi) = (1i64, 200_000i64);
            while hi - lo > 1 {
                let mid = (lo + hi) / 2;
                if flat_chernoff_log2(mid as f64, entries, p.eta, WINDOW) - 1.0 + factor.log2() <= level {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            let tail = law.sum_where(|x| x > lo);
            Tail { failure_log2: level, norm: lo, norm_log2: (columns * tail).log2(), markov_log2: delta - level }
        })
        .collect()
}

/// S and E of a Turing-1026 key as signed values (n x nbar, row-major),
/// drawn as key generation draws them: S, then E, from cSHAKE256(r,
/// "Turing-1026 v1 key noise") for the key's noise seed r.
pub fn key_noise(r: &[u8; 32]) -> (Vec<i64>, Vec<i64>) {
    let p = turing::turing1026::PARAMS;
    let mut noise = turing::xof::SecretXof::new("Turing-1026 v1 key noise");
    noise.absorb(r);
    let (mut s, mut e) = (vec![0u16; p.n * p.nbar], vec![0u16; p.n * p.nbar]);
    turing::lwe::add_noise(p.eta, &mut noise, &mut s);
    turing::lwe::add_noise(p.eta, &mut noise, &mut e);
    let signed = |v: Vec<u16>| v.into_iter().map(|x| i64::from(x as i16)).collect();
    (signed(s), signed(e))
}

/// The noise seed of the key with this 32-byte secret key: bytes 32..64 of
/// cSHAKE256(seed, "Turing-1026 v1 key generation").
pub fn noise_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut derived = [0u8; 96];
    turing::xof::cshake256_secret("Turing-1026 v1 key generation", seed, &mut derived);
    derived[32..64].try_into().expect("32 bytes")
}

/// Column j of E with column j of S, for each of the key's 32 columns.
pub fn key_columns(r: &[u8; 32]) -> Vec<Column> {
    let p = turing::turing1026::PARAMS;
    let (s, e) = key_noise(r);
    (0..p.nbar).map(|j| Column::from_values(p.eta, (0..p.n).flat_map(|k| [s[k * p.nbar + j], e[k * p.nbar + j]]))).collect()
}

/// log2 of a key's failure bound, the union bound over its 8 x 32
/// coefficients (the 8 rows of a column share its law), from log2 of each
/// column's failure probability.
pub fn key_log2(columns: &[Column], column_log2: impl Fn(&Column) -> f64) -> f64 {
    let p = turing::turing1026::PARAMS;
    (p.mbar as f64).log2() + log2_sum(&columns.iter().map(column_log2).collect::<Vec<_>>())
}

/// The same with every column's law computed exactly (about 0.1 s a column).
pub fn exact_key_log2(r: &[u8; 32]) -> f64 {
    key_log2(&key_columns(r), |c| c.exact_failure(WINDOW).log2())
}

/// One key of a sample.
#[derive(Clone, Copy, Debug)]
pub struct SampledKey {
    pub noise_seed: [u8; 32],
    /// log2 of its failure bound, each column by the saddlepoint approximation.
    pub saddlepoint_log2: f64,
    /// The same with each column's proven Chernoff bound.
    pub chernoff_log2: f64,
}

/// A sample of keys with uniformly random noise seeds (in the random-oracle
/// model the same law as key generation's r), each bounded both ways.
pub fn sample_keys(keys: usize, label: &str) -> Vec<SampledKey> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let seeds: Vec<[u8; 32]> = {
        let mut rng = crate::rng::Rng::new(label);
        (0..keys).map(|_| rng.bytes()).collect()
    };
    let per = keys.div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let workers: Vec<_> = seeds
            .chunks(per)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|r| {
                            let columns = key_columns(r);
                            SampledKey {
                                noise_seed: *r,
                                saddlepoint_log2: key_log2(&columns, |c| c.saddlepoint_log2(WINDOW)),
                                chernoff_log2: key_log2(&columns, |c| c.chernoff_log2(WINDOW)),
                            }
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers.into_iter().flat_map(|w| w.join().expect("worker")).collect()
    })
}

/// The heaviest sampled keys recomputed exactly: (saddlepoint, Chernoff,
/// exact) log2 failure bounds.
pub fn recheck_heaviest(sample: &[SampledKey], count: usize) -> Vec<(f64, f64, f64)> {
    let mut order: Vec<&SampledKey> = sample.iter().collect();
    order.sort_by(|a, b| b.saddlepoint_log2.total_cmp(&a.saddlepoint_log2));
    order.iter().take(count).map(|k| (k.saddlepoint_log2, k.chernoff_log2, exact_key_log2(&k.noise_seed))).collect()
}

/// `bombe weak-keys`: the proven fractions, a sample of `keys` keys, and its
/// `recheck` heaviest keys recomputed exactly. The report, and whether every
/// recomputation agreed with the saddlepoint approximation within 0.05 bit
/// and stayed below its Chernoff bound.
pub fn report(keys: usize, recheck: usize, label: &str) -> (String, bool) {
    use std::fmt::Write;
    let mut out = String::new();
    let delta = crate::dfr::turing_1026_rate().message;
    let weakest = crate::coresvp::turing_1026()
        .iter()
        .filter_map(|(_, lwe)| crate::coresvp::estimate(lwe, crate::coresvp::Convention::NewHope))
        .map(|e| e.classical())
        .fold(f64::INFINITY, f64::min);
    let _ = writeln!(out, "Turing-1026: the decryption failures of individual keys (docs/16)\n");
    let _ = writeln!(out, "Average over keys, what the Fujisaki-Okamoto theorems use: 2^{delta:.2} per ciphertext.");
    let _ = writeln!(out, "Weakest lattice attack (classical core-SVP): 2^{weakest:.1}; the failure rule asks for 2^-{weakest:.1}.\n");
    let _ = writeln!(out, "Proven, for all keys: at most this fraction of keys has a failure bound above the level");
    let _ = writeln!(out, "  level       Markov     column norms  proven");
    let mut levels = vec![-200.0, -220.0, -240.0, -weakest, -260.0];
    levels.sort_by(f64::total_cmp);
    for t in proven_tails(&levels) {
        let _ = writeln!(out, "  2^{:<9.1} 2^{:<8.1} 2^{:<11.1} 2^{:.1}", t.failure_log2, t.markov_log2, t.norm_log2, t.fraction_log2());
    }
    let timer = std::time::Instant::now();
    let mut sample = sample_keys(keys, label);
    sample.sort_by(|a, b| b.saddlepoint_log2.total_cmp(&a.saddlepoint_log2));
    let _ = writeln!(out, "\n{keys} keys drawn as key generation draws them (\"{label}\"), each column by the saddlepoint approximation [{:.0} s]:", timer.elapsed().as_secs_f64());
    if keys == 0 {
        return (out, true);
    }
    let quantile = |f: f64| sample[((keys - 1) as f64 * f) as usize].saddlepoint_log2;
    let _ = writeln!(
        out,
        "  worst 2^{:.2}, 1 in 10,000 2^{:.2}, 1 in 1,000 2^{:.2}, 1 in 100 2^{:.2}, median 2^{:.2}, best 2^{:.2}",
        sample[0].saddlepoint_log2,
        quantile(1e-4),
        quantile(1e-3),
        quantile(1e-2),
        quantile(0.5),
        sample[keys - 1].saddlepoint_log2
    );
    let mean = log2_sum(&sample.iter().map(|k| k.saddlepoint_log2).collect::<Vec<_>>()) - (keys as f64).log2();
    let _ = writeln!(out, "  sample mean 2^{mean:.2} (the rare heavy keys that set the true average 2^{delta:.2} are mostly missing from a sample)");
    for level in [-weakest, -255.0, -260.0] {
        let above = |f: fn(&SampledKey) -> f64| sample.iter().filter(|k| f(k) > level).count();
        let _ = writeln!(out, "  above 2^{level:.1}: {} keys (their proven Chernoff bounds: {})", above(|k| k.saddlepoint_log2), above(|k| k.chernoff_log2));
    }
    let timer = std::time::Instant::now();
    let rechecked = recheck_heaviest(&sample, recheck);
    let _ = writeln!(out, "\nThe {} heaviest recomputed exactly, every column's law by convolution [{:.0} s]:", rechecked.len(), timer.elapsed().as_secs_f64());
    let mut ok = true;
    for &(saddle, chernoff, exact) in &rechecked {
        let good = (saddle - exact).abs() < 0.05 && chernoff >= exact;
        ok &= good;
        let _ = writeln!(out, "  exact 2^{exact:.3}, saddlepoint 2^{saddle:.3} ({:+.3} bits), Chernoff 2^{chernoff:.2}{}", saddle - exact, if good { "" } else { "  DISAGREES" });
    }
    (out, ok)
}

/// log2 of the sum of 2^x over the list.
pub fn log2_sum(v: &[f64]) -> f64 {
    let top = v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    top + v.iter().map(|x| (x - top).exp2()).sum::<f64>().log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small column (n = 64 entries of CBD(18)) where the exact law is quick:
    // the Chernoff bound is above the exact probability, and the saddlepoint
    // approximation is within a tenth of a bit of it, at several windows.
    #[test]
    fn bounds_and_approximation_against_the_exact_law() {
        let mut rng = crate::rng::Rng::new("weakkeys exact");
        for _ in 0..4 {
            let values: Vec<i64> = (0..128).map(|_| (0..18).map(|_| rng.below(2) as i64).sum::<i64>() - (0..18).map(|_| rng.below(2) as i64).sum::<i64>()).collect();
            let col = Column::from_values(18, values);
            for h in [1000i64, 1400, 1800] {
                let exact = col.exact_failure(h).log2();
                let chernoff = col.chernoff_log2(h);
                let saddle = col.saddlepoint_log2(h);
                assert!(chernoff >= exact, "h {h}: Chernoff {chernoff} below exact {exact}");
                assert!((saddle - exact).abs() < 0.1, "h {h}: saddlepoint {saddle} vs exact {exact}");
            }
        }
    }

    // Jensen: no column's bound exceeds the flat column's at the same norm.
    #[test]
    fn flat_column_dominates() {
        let mut rng = crate::rng::Rng::new("weakkeys flat");
        for _ in 0..20 {
            let values: Vec<i64> = (0..2052).map(|_| (0..18).map(|_| rng.below(2) as i64).sum::<i64>() - (0..18).map(|_| rng.below(2) as i64).sum::<i64>()).collect();
            let col = Column::from_values(18, values);
            assert!(flat_chernoff_log2(col.norm() as f64, 2052, 18, WINDOW) >= col.chernoff_log2(WINDOW) - 1e-9);
        }
    }

    // The sampled noise is key generation's: S from a real key's seed.
    #[test]
    fn key_noise_is_key_generation() {
        let seed = [0x6b; 32];
        let dk = turing::turing1026::DecapsulationKey::from_seed(&seed).expect("consistent");
        let (s, _) = key_noise(&noise_seed(&seed));
        assert!(s.iter().zip(dk.secret_matrix()).all(|(&a, &b)| a == i64::from(b as i16)));
        assert!(s.iter().all(|v| v.abs() <= 18) && s.iter().any(|&v| v != 0));
    }

    // Markov's premise: the conditional failure probabilities of random
    // columns average to the unconditional rate. At a small size (128
    // entries of CBD(3), window 50, about 3 standard deviations) the mean
    // over 4,000 columns is within 5% of the exact law's value.
    #[test]
    fn column_laws_average_to_the_unconditional_rate() {
        let (eta, entries, h) = (3u32, 128usize, 50i64);
        let law = crate::dfr::error_law(&Law::cbd(eta), entries as u64 / 2);
        let unconditional = law.sum_where(|x| x < -h || x >= h);
        let mut rng = crate::rng::Rng::new("weakkeys markov");
        let columns = 4000;
        let mean = (0..columns)
            .map(|_| {
                let values: Vec<i64> = (0..entries).map(|_| (0..eta).map(|_| rng.below(2) as i64).sum::<i64>() - (0..eta).map(|_| rng.below(2) as i64).sum::<i64>()).collect();
                Column::from_values(eta, values).exact_failure(h)
            })
            .sum::<f64>()
            / columns as f64;
        assert!((mean / unconditional - 1.0).abs() < 0.05, "mean {mean} against {unconditional}");
    }

    // A full-size column: the saddlepoint approximation within 0.01 bit of
    // the exact law, the Chernoff bound above it.
    #[test]
    fn full_size_column() {
        let columns = key_columns(&[42; 32]);
        for c in &columns[..2] {
            let exact = c.exact_failure(WINDOW).log2();
            assert!((c.saddlepoint_log2(WINDOW) - exact).abs() < 0.01, "{exact}");
            assert!(c.chernoff_log2(WINDOW) >= exact);
        }
    }

    #[test]
    fn norm_law_has_the_right_moments() {
        let law = norm_law(18, 2052);
        let mean: f64 = law.support().zip(&law.p).map(|(v, &p)| v as f64 * p).sum();
        assert!((mean - 2052.0 * 9.0).abs() < 1e-6, "{mean}");
        assert!((law.total() - 1.0).abs() < 1e-9);
    }
}
