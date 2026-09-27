//! The decryption error of real Turing-1026 ciphertexts, measured at the
//! real parameters on every CPU thread and compared with the exact law of
//! docs/16 (tools/CI.md, "noise").
//!
//! `dfr::monte_carlo` checks the real encryption at n = 64, where failures
//! are common enough to count; at Turing-1026's n = 1026 a failure is a
//! 2^-274 event and will never be seen. The error itself can be:
//! C - B'S = Encode(m) + X with X = S'E - E'S + E'', the quantity whose law
//! `dfr::error_law` computes, so every coefficient of every real ciphertext
//! is one sample of the real code's X. This compares those samples with the
//! exact law: its distribution function at a grid of points across the bulk
//! and as far into the tails as the samples reach, its mean (0, since the
//! law is symmetric: the most sensitive test of a shift) and its second
//! moment.
//! It also checks that the real `lwe::decrypt` gets a bit right exactly when
//! its X lies in the decoding window [-q/4, q/4).
//!
//! Coefficients of one key share S and E, so they are not independent: the
//! unit of independence is the key, and each statistic's standard error
//! comes from the spread of its per-key averages over many keys (as in
//! `dfr::monte_carlo`). A statistic is judged only once it rests on
//! `MIN_KEYS` keys and, for a probability, `MIN_EVENTS` expected events, so
//! that the normal approximation behind its z-score holds; the critical
//! value is Bonferroni-corrected over the statistics judged, for a false
//! alarm rate of `ALPHA` per run.
//!
//! The same samples must reject two wrong laws (CBD(eta - 1) noise, and n
//! products instead of 2n), and the negative control runs the real code
//! with CBD(eta - 1) noise, which the right law must then reject.
//!
//! Evidence accumulates across runs in a state file (per-key means and sums
//! of squared deviations, merged exactly), so long runs keep tightening it.

use crate::dfr::{error_law, Law};
use crate::nist::erfc;
use crate::rng::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use turing::lwe::{self, Params};
use turing::xof::SecretXof;

/// Grid points per law: -6 to +6 standard deviations in steps of a half.
pub const POINTS: usize = 25;
/// Statistics: one per grid point, then the mean E[X] and the second
/// moment E[X^2].
pub const STATS: usize = POINTS + 2;

/// False alarm rate of one run's verdict on the right law.
pub const ALPHA: f64 = 1e-6;
/// Keys a statistic needs before it is judged.
pub const MIN_KEYS: u64 = 200;
/// Expected events a probability needs before it is judged.
pub const MIN_EVENTS: f64 = 200.0;

/// The points g where the distribution function is compared, for a law of
/// standard deviation `sd`. Statistic i is P(X < g) for g <= 0 and
/// P(X >= g) for g > 0, so no tail is computed as 1 minus something close
/// to 1. Turing-1026's error has standard deviation 407.7, so its grid
/// reaches +-2446.
pub fn grid(sd: f64) -> [i64; POINTS] {
    std::array::from_fn(|i| ((i as f64 - 12.0) * 0.5 * sd).round() as i64)
}

/// The exact values of the statistics at `grid` under the law of 2n
/// products of CBD(eta) plus one more sample.
pub fn exact(eta: u32, n: u64, grid: &[i64; POINTS]) -> Vec<f64> {
    let law = error_law(&Law::cbd(eta), n);
    let mut v: Vec<f64> = grid.iter().map(|&g| if g <= 0 { law.sum_where(|x| x < g) } else { law.sum_where(|x| x >= g) }).collect();
    v.push(law.support().zip(&law.p).map(|(x, &p)| x as f64 * p).sum());
    v.push(law.support().zip(&law.p).map(|(x, &p)| (x * x) as f64 * p).sum());
    v
}

/// The standard deviation of the law of 2n products of CBD(eta) plus one
/// more sample: sqrt(2n (eta/2)^2 + eta/2).
pub fn sd(eta: u32, n: u64) -> f64 {
    let v = f64::from(eta) / 2.0;
    (2.0 * n as f64 * v * v + v).sqrt()
}

pub fn stat_name(grid: &[i64; POINTS], i: usize) -> String {
    match grid.get(i) {
        Some(&g) if g <= 0 => format!("P(X < {g})"),
        Some(&g) => format!("P(X >= {g})"),
        None if i == POINTS => "E[X]".into(),
        None => "E[X^2]".into(),
    }
}

/// Accumulated per-key statistics: for each statistic, the number of keys,
/// the mean of the per-key values and the sum of squared deviations from
/// it (Welford; merged exactly with Chan, Golub and LeVeque's formula).
#[derive(Clone, Debug)]
pub struct Tally {
    pub keys: u64,
    pub mean: Vec<f64>,
    pub m2: Vec<f64>,
    /// Coefficients per key.
    pub per_key: u64,
    /// Coefficients the real decryption got wrong, and coefficients whose
    /// decryption disagreed with their measured error (both must be 0).
    pub failures: u64,
    pub inconsistent: u64,
}

impl Tally {
    pub fn new(per_key: u64) -> Tally {
        Tally { keys: 0, mean: vec![0.0; STATS], m2: vec![0.0; STATS], per_key, failures: 0, inconsistent: 0 }
    }

    fn push(&mut self, values: &[f64]) {
        self.keys += 1;
        let k = self.keys as f64;
        for ((m, s), &v) in self.mean.iter_mut().zip(&mut self.m2).zip(values) {
            let d = v - *m;
            *m += d / k;
            *s += d * (v - *m);
        }
    }

    pub fn merge(&mut self, other: &Tally) {
        assert_eq!(self.per_key, other.per_key, "tallies of different shapes");
        if other.keys == 0 {
            return;
        }
        let (a, b) = (self.keys as f64, other.keys as f64);
        let n = a + b;
        for i in 0..STATS {
            let d = other.mean[i] - self.mean[i];
            self.mean[i] += d * b / n;
            self.m2[i] += other.m2[i] + d * d * a * b / n;
        }
        self.keys += other.keys;
        self.failures += other.failures;
        self.inconsistent += other.inconsistent;
    }

    /// z-score of statistic i against the value `exact`, if it may be
    /// judged.
    pub fn z(&self, i: usize, exact: f64) -> Option<f64> {
        if self.keys < MIN_KEYS {
            return None;
        }
        let events = exact * (self.keys * self.per_key) as f64;
        if i < POINTS && events < MIN_EVENTS {
            return None;
        }
        let k = self.keys as f64;
        let se = (self.m2[i] / (k - 1.0) / k).sqrt();
        (se > 0.0).then(|| (self.mean[i] - exact) / se)
    }

    pub fn to_text(&self, fingerprint: &str) -> String {
        let mut s = format!("bombe noise state v1\n{fingerprint}\nkeys {}\nfailures {}\ninconsistent {}\n", self.keys, self.failures, self.inconsistent);
        for i in 0..STATS {
            s += &format!("stat {i} {:e} {:e}\n", self.mean[i], self.m2[i]);
        }
        s
    }

    /// Parses `to_text`'s output; None if it is for a different fingerprint
    /// or malformed.
    pub fn from_text(text: &str, fingerprint: &str, per_key: u64) -> Option<Tally> {
        let mut lines = text.lines();
        if lines.next()? != "bombe noise state v1" || lines.next()? != fingerprint {
            return None;
        }
        let mut t = Tally::new(per_key);
        let mut seen = [false; STATS];
        for line in lines {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                ["keys", k] => t.keys = k.parse().ok()?,
                ["failures", k] => t.failures = k.parse().ok()?,
                ["inconsistent", k] => t.inconsistent = k.parse().ok()?,
                ["stat", i, m, s] => {
                    let i: usize = i.parse().ok()?;
                    *seen.get_mut(i)? = true;
                    t.mean[i] = m.parse().ok()?;
                    t.m2[i] = s.parse().ok()?;
                }
                [] => {}
                _ => return None,
            }
        }
        seen.iter().all(|&s| s).then_some(t)
    }
}

/// What a state file must match: the code that makes the samples (the
/// encryption, its randomness and this measurement, hashed with line ends
/// normalised), the parameters, the shape of a key's sample and the grid.
/// Evidence gathered from other code starts afresh.
pub fn fingerprint(p: &Params, encryptions_per_key: usize, grid: &[i64; POINTS]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut code = Sha3_256::new();
    for source in [include_str!("../../turing/src/lwe.rs"), include_str!("../../turing/src/xof.rs"), include_str!("noise1026.rs")] {
        code.update(source.replace('\r', "").as_bytes());
    }
    let code: String = code.finalize()[..8].iter().map(|b| format!("{b:02x}")).collect();
    let g: Vec<String> = grid.iter().map(i64::to_string).collect();
    format!("code={code} n={} nbar={} mbar={} log_q={} eta={} encryptions_per_key={} grid={}", p.n, p.nbar, p.mbar, p.log_q, p.eta, encryptions_per_key, g.join(","))
}

/// One key and `encryptions` real ciphertexts under it: the key's per-
/// coefficient averages of every statistic, its decryption failures and
/// its inconsistencies.
fn one_key(p: &Params, grid: &[i64; POINTS], encryptions: usize, label: &str, index: u64) -> (Vec<f64>, u64, u64) {
    let mut rng = Rng::new(&format!("{label} key {index}"));
    let stream = |seed: [u8; 32]| {
        let mut x = SecretXof::new("Bombe noise measurement");
        x.absorb(&seed);
        x
    };
    let seed_a: [u8; 32] = rng.bytes();
    let (mut s, mut b) = (vec![0u16; p.n * p.nbar], vec![0u16; p.n * p.nbar]);
    lwe::keygen(p, &seed_a, &mut stream(rng.bytes()), &mut s, &mut b);
    let (mut sp, mut bp, mut c) = (vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.nbar]);
    let (mut msg, mut back) = (vec![0u8; p.message_bytes()], vec![0u8; p.message_bytes()]);
    let (mask, half, quarter) = (i64::from(p.q_mask()), 1i64 << (p.log_q - 1), 1i64 << (p.log_q - 2));
    let mut counts = [0u64; POINTS];
    let (mut sum, mut squares, mut failures, mut inconsistent) = (0i64, 0u64, 0u64, 0u64);
    for _ in 0..encryptions {
        rng.fill(&mut msg);
        lwe::encrypt(p, &seed_a, &b, &msg, &mut stream(rng.bytes()), &mut sp, &mut bp, &mut c);
        lwe::decrypt(p, &s, &bp, &c, &mut back);
        for r in 0..p.mbar {
            for j in 0..p.nbar {
                let i = r * p.nbar + j;
                let bit = (msg[i / 8] >> (i % 8)) & 1;
                // C - B'S - Encode(m), centred into [-q/2, q/2).
                let mut v = c[i];
                for k in 0..p.n {
                    v = v.wrapping_sub(bp[r * p.n + k].wrapping_mul(s[k * p.nbar + j]));
                }
                v = v.wrapping_sub(u16::from(bit) << (p.log_q - 1));
                let x = ((i64::from(v) + half) & mask) - half;
                for (&g, n) in grid.iter().zip(&mut counts) {
                    *n += u64::from(if g <= 0 { x < g } else { x >= g });
                }
                sum += x;
                squares += (x * x) as u64;
                let right = (back[i / 8] >> (i % 8)) & 1 == bit;
                failures += u64::from(!right);
                inconsistent += u64::from(right != (-quarter..quarter).contains(&x));
            }
        }
    }
    let total = (encryptions * p.mbar * p.nbar) as f64;
    let mut values: Vec<f64> = counts.iter().map(|&n| n as f64 / total).collect();
    values.push(sum as f64 / total);
    values.push(squares as f64 / total);
    (values, failures, inconsistent)
}

/// Measures keys `first..first + keys`, `encryptions` ciphertexts each, on
/// every thread. The label and key number name each key's randomness, so a
/// run is reproducible and runs with a fresh label never repeat a key.
pub fn measure(p: &Params, grid: &[i64; POINTS], first: u64, keys: usize, encryptions: usize, label: &str) -> Tally {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).min(keys.max(1));
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(keys));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= keys {
                    break;
                }
                let result = one_key(p, grid, encryptions, label, first + index as u64);
                results.lock().expect("no worker panics while holding the lock").push((index, result));
            });
        }
    });
    let mut results = results.into_inner().expect("workers finished");
    results.sort_by_key(|(index, _)| *index);
    let mut tally = Tally::new((encryptions * p.mbar * p.nbar) as u64);
    for (_, (values, failures, inconsistent)) in results {
        tally.push(&values);
        tally.failures += failures;
        tally.inconsistent += inconsistent;
    }
    tally
}

/// Bonferroni critical value: |z| beyond it has two-sided probability
/// alpha / tests under the normal law.
pub fn critical(alpha: f64, tests: usize) -> f64 {
    let target = alpha / tests.max(1) as f64;
    let (mut lo, mut hi) = (0.0f64, 40.0f64);
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if erfc(mid / std::f64::consts::SQRT_2) > target {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// A tally judged against one law: the z-scores of the statistics that may
/// be judged, and the Bonferroni critical value over them.
pub struct Verdict {
    pub z: Vec<Option<f64>>,
    pub critical: f64,
    pub judged: usize,
}

impl Verdict {
    pub fn rejected(&self) -> bool {
        self.z.iter().flatten().any(|z| z.abs() >= self.critical)
    }

    pub fn worst(&self) -> Option<(usize, f64)> {
        self.z.iter().enumerate().filter_map(|(i, z)| z.map(|z| (i, z))).max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
    }
}

pub fn judge(tally: &Tally, exact: &[f64]) -> Verdict {
    let z: Vec<Option<f64>> = (0..STATS).map(|i| tally.z(i, exact[i])).collect();
    let judged = z.iter().flatten().count();
    Verdict { critical: critical(ALPHA, judged), z, judged }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Merging two tallies gives what pushing every key into one gives.
    #[test]
    fn merge_is_exact() {
        let mut rng = Rng::new("noise merge test");
        let rows: Vec<Vec<f64>> = (0..300).map(|_| (0..STATS).map(|_| rng.below(1_000_000) as f64 / 7.0).collect()).collect();
        let (mut all, mut a, mut b) = (Tally::new(8), Tally::new(8), Tally::new(8));
        for (i, row) in rows.iter().enumerate() {
            all.push(row);
            if i < 117 { &mut a } else { &mut b }.push(row);
        }
        a.merge(&b);
        assert_eq!(a.keys, all.keys);
        for i in 0..STATS {
            assert!((a.mean[i] - all.mean[i]).abs() <= 1e-9 * all.mean[i].abs().max(1.0), "mean {i}");
            assert!((a.m2[i] - all.m2[i]).abs() <= 1e-9 * all.m2[i].abs().max(1.0), "m2 {i}");
        }
    }

    // The state file round-trips exactly, and a different fingerprint or a
    // missing statistic is refused.
    #[test]
    fn state_round_trips() {
        let mut t = Tally::new(1024);
        let mut rng = Rng::new("noise state test");
        for _ in 0..50 {
            let row: Vec<f64> = (0..STATS).map(|_| rng.below(1 << 40) as f64 / 3.0).collect();
            t.push(&row);
        }
        t.failures = 3;
        let text = t.to_text("fp");
        let back = Tally::from_text(&text, "fp", 1024).expect("parses");
        assert_eq!((back.keys, back.failures), (t.keys, t.failures));
        assert_eq!(back.mean, t.mean);
        assert_eq!(back.m2, t.m2);
        assert!(Tally::from_text(&text, "other", 1024).is_none());
        let short: String = text.lines().filter(|l| !l.starts_with("stat 7 ")).map(|l| format!("{l}\n")).collect();
        assert!(Tally::from_text(&short, "fp", 1024).is_none());
    }

    // The exact mean is 0 and the second moment 2n (eta/2)^2 + eta/2, the
    // law's variance; the grid is symmetric, and so are the probabilities on
    // it: P(X < -g) = P(X > g) = P(X >= g) - P(X = g).
    #[test]
    fn exact_values_are_right() {
        let (eta, n) = (2, 16);
        let g = grid(sd(eta, n));
        let v = exact(eta, n, &g);
        assert!(v[POINTS].abs() < 1e-12, "mean {}", v[POINTS]);
        assert!((v[STATS - 1] - sd(eta, n).powi(2)).abs() < 1e-9 && (sd(eta, n).powi(2) - 33.0).abs() < 1e-12);
        let law = error_law(&Law::cbd(eta), n);
        for i in 0..POINTS {
            assert_eq!(g[i], -g[POINTS - 1 - i]);
        }
        for i in POINTS / 2 + 1..POINTS {
            let at = law.sum_where(|x| x == g[i]);
            assert!((v[POINTS - 1 - i] - (v[i] - at)).abs() < 1e-15, "g = {}", g[i]);
        }
        assert_eq!(grid(sd(18, 1026))[POINTS - 1], 2446);
    }

    #[test]
    fn critical_values() {
        // Two-sided 1e-6 for one test is 4.8916; spread over 26 tests,
        // 5.4978 (both from Python's math.erfc).
        assert!((critical(1e-6, 1) - 4.8916).abs() < 1e-3);
        assert!((critical(1e-6, 26) - 5.4978).abs() < 1e-3);
    }

    // At a small parameter set, the real code's error agrees with its law,
    // decryption agrees with the measured error, and the same samples reject
    // the law with the wrong noise and the law with half the products.
    #[test]
    fn small_parameters_agree_and_controls_are_rejected() {
        let p = Params { n: 64, nbar: 8, mbar: 8, log_q: 12, eta: 3 };
        let g = grid(sd(p.eta, p.n as u64));
        let tally = measure(&p, &g, 0, 400, 4, "noise unit test");
        assert_eq!((tally.keys, tally.failures, tally.inconsistent), (400, 0, 0));
        let right = judge(&tally, &exact(p.eta, p.n as u64, &g));
        assert!(right.judged >= 10 && !right.rejected(), "judged {}, worst {:?}", right.judged, right.worst());
        for (eta, n) in [(p.eta - 1, p.n as u64), (p.eta, p.n as u64 / 2)] {
            let wrong = judge(&tally, &exact(eta, n, &g));
            assert!(wrong.rejected(), "eta {eta} n {n}: worst {:?}", wrong.worst());
        }
    }

    // A window small enough for failures: every failure the real decryption
    // makes is one whose measured error left the window, and vice versa.
    #[test]
    fn failures_match_the_measured_error() {
        let p = Params { n: 64, nbar: 8, mbar: 8, log_q: 7, eta: 3 };
        let g = grid(sd(p.eta, p.n as u64));
        let tally = measure(&p, &g, 0, 50, 20, "noise failure test");
        assert!(tally.failures > 100, "{} failures", tally.failures);
        assert_eq!(tally.inconsistent, 0);
    }
}
