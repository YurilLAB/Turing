//! Exact decryption-failure probabilities of plain-LWE encryption (docs/16).
//!
//! Decryption computes Encode(m) + S'E - E'S + E'' and rounds, so one
//! coefficient decodes wrongly exactly when its error S'E - E'S + E'' leaves
//! the decoding window. That error is a sum of 2n independent products of
//! two noise samples plus one more sample; its law is built exactly by
//! convolution (the law of a sum of independent integers is the convolution
//! of their laws), and the message's failure probability is bounded by the
//! union bound over its coefficients, which needs no independence. This is
//! the method of the FrodoKEM specification and of the research note
//! research/notes/pq/decryption-failures.md (`dfr.py`), whose published
//! values `frodo_published` reproduces before anything of ours is trusted.
//!
//! Arithmetic is f64 with direct convolution: every term is non-negative,
//! so rounding errors stay relative (about 1e-12) even at 2^-270, where an
//! FFT would drown the tail in its absolute error. Entries below 2^-600 are
//! dropped along the way; what that removes is below 2^-580 and cannot move
//! any figure printed here.

/// P(X = lo + i) = p[i].
#[derive(Clone, Debug)]
pub struct Law {
    pub lo: i64,
    pub p: Vec<f64>,
}

/// 2^-600: exponent field 1023 - 600, mantissa zero.
const TRIM: f64 = f64::from_bits((1023 - 600) << 52);

impl Law {
    pub fn point(v: i64) -> Law {
        Law { lo: v, p: vec![1.0] }
    }

    /// The centred binomial law CBD(eta): C(2 eta, eta + v) / 4^eta.
    pub fn cbd(eta: u32) -> Law {
        let n = 2 * eta as usize;
        let mut row = vec![1.0f64];
        for _ in 0..n {
            let mut next = vec![0.0; row.len() + 1];
            for (i, &v) in row.iter().enumerate() {
                next[i] += v / 2.0;
                next[i + 1] += v / 2.0;
            }
            row = next;
        }
        Law { lo: -(eta as i64), p: row }
    }

    /// A symmetric law from a FrodoKEM table of P(0), P(+-1), ... in units
    /// of 2^-16.
    pub fn frodo_table(half: &[u32]) -> Law {
        let m = half.len() as i64 - 1;
        Law { lo: -m, p: (-m..=m).map(|v| f64::from(half[v.unsigned_abs() as usize]) / 65536.0).collect() }
    }

    fn trim(mut self) -> Law {
        let first = self.p.iter().position(|&x| x > TRIM);
        let last = self.p.iter().rposition(|&x| x > TRIM);
        match (first, last) {
            (Some(a), Some(b)) => {
                self.p = self.p[a..=b].to_vec();
                self.lo += a as i64;
                self
            }
            _ => Law::point(0),
        }
    }

    /// The law of X + Y for independent X ~ self, Y ~ other.
    pub fn conv(&self, other: &Law) -> Law {
        let mut out = vec![0.0f64; self.p.len() + other.p.len() - 1];
        for (i, &a) in self.p.iter().enumerate() {
            if a == 0.0 {
                continue;
            }
            for (o, &b) in out[i..].iter_mut().zip(&other.p) {
                *o += a * b;
            }
        }
        Law { lo: self.lo + other.lo, p: out }.trim()
    }

    /// The law of the sum of k independent copies.
    pub fn power(&self, mut k: u64) -> Law {
        let mut result = Law::point(0);
        let mut base = self.clone();
        while k > 0 {
            if k & 1 == 1 {
                result = result.conv(&base);
            }
            k >>= 1;
            if k > 0 {
                base = base.conv(&base);
            }
        }
        result
    }

    /// The law of X Y for independent X ~ self, Y ~ other.
    pub fn product(&self, other: &Law) -> Law {
        let values: Vec<i64> = self.support().flat_map(|a| other.support().map(move |b| a * b)).collect();
        let (lo, hi) = (*values.iter().min().expect("non-empty"), *values.iter().max().expect("non-empty"));
        let mut p = vec![0.0; (hi - lo + 1) as usize];
        for (a, &pa) in self.support().zip(&self.p) {
            for (b, &pb) in other.support().zip(&other.p) {
                p[(a * b - lo) as usize] += pa * pb;
            }
        }
        Law { lo, p }.trim()
    }

    pub fn support(&self) -> impl Iterator<Item = i64> + '_ {
        (0..self.p.len() as i64).map(move |i| self.lo + i)
    }

    pub fn total(&self) -> f64 {
        self.sum_where(|_| true)
    }

    pub fn variance(&self) -> f64 {
        let mean: f64 = self.support().zip(&self.p).map(|(v, &p)| v as f64 * p).sum();
        self.support().zip(&self.p).map(|(v, &p)| (v as f64 - mean).powi(2) * p).sum()
    }

    /// The sum of P(X = x) over the x where `keep` holds, smallest terms
    /// first.
    pub fn sum_where(&self, keep: impl Fn(i64) -> bool) -> f64 {
        let mut terms: Vec<f64> = self.support().zip(&self.p).filter(|(v, _)| keep(*v)).map(|(_, &p)| p).collect();
        terms.sort_by(f64::total_cmp);
        terms.iter().sum()
    }
}

/// The law of one error coefficient of plain-LWE encryption with secrets
/// and noise all drawn from `chi`: 2n products plus one more sample.
pub fn error_law(chi: &Law, n: u64) -> Law {
    chi.product(chi).power(2 * n).conv(chi)
}

/// A decryption-failure figure.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    /// log2 of one coefficient's failure probability, exact decoding window
    /// [-h, h).
    pub per_coefficient: f64,
    /// log2 of the union bound over the message's coefficients.
    pub message: f64,
    /// The same with the symmetric rule |e| >= h, which FrodoKEM's published
    /// figures use.
    pub message_symmetric: f64,
    /// Standard deviation of the error.
    pub sd: f64,
}

/// Failure rate of one coefficient decoded with window [-h, h), for a
/// message spread over `coefficients` coefficients.
pub fn rate(law: &Law, h: i64, coefficients: u64) -> Rate {
    let exact = law.sum_where(|x| x < -h || x >= h);
    let symmetric = law.sum_where(|x| x.abs() >= h);
    let n = coefficients as f64;
    Rate { per_coefficient: exact.log2(), message: (n * exact).log2(), message_symmetric: (n * symmetric).log2(), sd: law.variance().sqrt() }
}

/// Name, n, log2 q, bits per coefficient B, the error table, and the
/// published failure rate (log2).
pub type FrodoSet = (&'static str, u64, u32, u32, &'static [u32], f64);

/// FrodoKEM round 3 (Tables 1-3 of its specification; the rates are its
/// Table 2).
pub const FRODO: [FrodoSet; 3] = [
    ("FrodoKEM-640", 640, 15, 2, &[9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1], -138.7),
    ("FrodoKEM-976", 976, 16, 3, &[11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1], -199.6),
    ("FrodoKEM-1344", 1344, 16, 4, &[18286, 14320, 6876, 2023, 364, 40, 2], -252.5),
];

/// FrodoKEM's rate with its own rule: 64 coefficients, window q / 2^(B+1).
pub fn frodo_rate(n: u64, log_q: u32, bits: u32, table: &[u32]) -> Rate {
    let chi = Law::frodo_table(table);
    rate(&error_law(&chi, n), 1 << (log_q - bits - 1), 64)
}

/// Turing-1026's rate: CBD(18), 2n = 2052 products, one bit per coefficient
/// (window q/4 = 8192), 256 coefficients.
pub fn turing_1026_rate() -> Rate {
    let p = turing::turing1026::PARAMS;
    rate(&error_law(&Law::cbd(p.eta), p.n as u64), 1 << (p.log_q - 2), (p.mbar * p.nbar) as u64)
}

/// The real encryption code (`turing::lwe`) at a small parameter set where
/// failures are frequent enough to count, against the exact law.
pub struct MonteCarlo {
    pub params: turing::lwe::Params,
    pub keys: usize,
    /// Coefficients decrypted.
    pub trials: u64,
    /// Coefficients that decrypted to the wrong bit.
    pub failures: u64,
    /// The exact law's probability for one coefficient.
    pub expected: f64,
    /// (observed - expected) / standard error, the standard error taken
    /// from the spread of the per-key failure fractions (coefficients of one
    /// key are not independent; keys are).
    pub z: f64,
}

impl MonteCarlo {
    pub fn agrees(&self) -> bool {
        self.z.abs() < 4.0 && self.failures > 100
    }
}

pub fn monte_carlo(p: turing::lwe::Params, keys: usize, per_key: usize, label: &str) -> MonteCarlo {
    use turing::lwe;
    use turing::xof::SecretXof;
    let stream = |seed: [u8; 32]| {
        let mut x = SecretXof::new("Bombe failure-rate trial");
        x.absorb(&seed);
        x
    };
    let law = error_law(&Law::cbd(p.eta), p.n as u64);
    let h = 1i64 << (p.log_q - 2);
    let expected = law.sum_where(|x| x < -h || x >= h);
    let mut rng = crate::rng::Rng::new(label);
    let per_trial = (p.mbar * p.nbar) as u64;
    let mut fractions = Vec::with_capacity(keys);
    let mut failures = 0u64;
    let (mut s, mut b) = (vec![0u16; p.n * p.nbar], vec![0u16; p.n * p.nbar]);
    let (mut sp, mut bp, mut c) = (vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.n], vec![0u16; p.mbar * p.nbar]);
    let mut msg = vec![0u8; p.message_bytes()];
    let mut back = vec![0u8; p.message_bytes()];
    for _ in 0..keys {
        let seed_a: [u8; 32] = rng.bytes();
        lwe::keygen(&p, &seed_a, &mut stream(rng.bytes()), &mut s, &mut b);
        let mut key_failures = 0u64;
        for _ in 0..per_key {
            msg.iter_mut().for_each(|m| *m = rng.bytes::<1>()[0]);
            lwe::encrypt(&p, &seed_a, &b, &msg, &mut stream(rng.bytes()), &mut sp, &mut bp, &mut c);
            lwe::decrypt(&p, &s, &bp, &c, &mut back);
            key_failures += msg.iter().zip(&back).map(|(x, y)| u64::from((x ^ y).count_ones())).sum::<u64>();
        }
        failures += key_failures;
        fractions.push(key_failures as f64 / (per_key as u64 * per_trial) as f64);
    }
    let mean = fractions.iter().sum::<f64>() / keys as f64;
    let sd = (fractions.iter().map(|f| (f - mean).powi(2)).sum::<f64>() / (keys - 1) as f64).sqrt();
    let z = (mean - expected) / (sd / (keys as f64).sqrt()).max(f64::MIN_POSITIVE);
    MonteCarlo { params: p, keys, trials: (keys * per_key) as u64 * per_trial, failures, expected, z }
}

/// The two small sets Monte-Carlo runs: CBD(3) with the window at 3.8
/// standard deviations (the tail), and Turing-1026's CBD(18) at 2.5.
pub const TRIAL_SETS: [turing::lwe::Params; 2] = [
    turing::lwe::Params { n: 64, nbar: 8, mbar: 8, log_q: 8, eta: 3 },
    turing::lwe::Params { n: 64, nbar: 8, mbar: 8, log_q: 10, eta: 18 },
];

#[cfg(test)]
mod tests {
    use super::*;

    // The law code against brute-force enumeration: all 3^4 * 3 outcomes of
    // two products of CBD(1) samples plus one CBD(1) sample.
    #[test]
    fn laws_match_enumeration() {
        let chi = Law::cbd(1);
        let law = error_law(&chi, 1);
        let values = [(-1i64, 0.25), (0, 0.5), (1, 0.25)];
        let mut expected = std::collections::BTreeMap::new();
        for &(a, pa) in &values {
            for &(b, pb) in &values {
                for &(c, pc) in &values {
                    for &(d, pd) in &values {
                        for &(e, pe) in &values {
                            *expected.entry(a * b + c * d + e).or_insert(0.0) += pa * pb * pc * pd * pe;
                        }
                    }
                }
            }
        }
        for (v, p) in law.support().zip(&law.p) {
            assert!((p - expected.get(&v).copied().unwrap_or(0.0)).abs() < 1e-15, "value {v}");
        }
        assert!((law.total() - 1.0).abs() < 1e-12);
        assert!((Law::cbd(18).variance() - 9.0).abs() < 1e-9);
    }

    #[test]
    fn power_is_repeated_convolution() {
        let chi = Law::cbd(2);
        let direct = (0..5).fold(Law::point(0), |acc, _| acc.conv(&chi));
        let fast = chi.power(5);
        assert_eq!(direct.lo, fast.lo);
        for (a, b) in direct.p.iter().zip(&fast.p) {
            assert!((a - b).abs() < 1e-15);
        }
    }

    // FrodoKEM's published failure rates, to the published precision.
    #[test]
    fn reproduces_frodo() {
        for (name, n, log_q, bits, table, published) in FRODO {
            let r = frodo_rate(n, log_q, bits, table);
            assert!((r.message_symmetric - published).abs() < 0.05, "{name}: {} vs {published}", r.message_symmetric);
            assert!(r.message <= r.message_symmetric + 1e-9, "{name}: the exact window is at most the symmetric rule");
        }
    }

    // The implementation fails as often as the law says, and a law with the
    // wrong noise (CBD(2) instead of CBD(3)) is rejected by the same test.
    #[test]
    fn implementation_fails_as_the_law_predicts() {
        let mc = monte_carlo(TRIAL_SETS[0], 300, 40, "dfr test trial");
        assert!(mc.agrees(), "{} failures in {} (expected {:.3e} each), z {:.2}", mc.failures, mc.trials, mc.expected, mc.z);
        let p = TRIAL_SETS[0];
        let wrong = error_law(&Law::cbd(2), p.n as u64).sum_where(|x| x.abs() >= 1 << (p.log_q - 2));
        let observed = mc.failures as f64 / mc.trials as f64;
        assert!(observed > 5.0 * wrong, "{observed} vs {wrong}");
    }

    // Changing a parameter moves the figure far from the published one.
    #[test]
    fn negative_controls_fail() {
        let (_, n, log_q, bits, table, published) = FRODO[1];
        assert!((frodo_rate(n + 40, log_q, bits, table).message_symmetric - published).abs() > 1.0);
        assert!((frodo_rate(n, log_q, bits + 1, table).message_symmetric - published).abs() > 1.0);
        assert!((frodo_rate(n, log_q, bits, FRODO[0].4).message_symmetric - published).abs() > 1.0);
    }
}
