//! The NIST SP 800-22 battery applied to keystreams: Turing in counter mode
//! (E_K(counter), E_K(counter + 1), ...) with random keys and with the
//! all-zero key, reduced-round Turing to find where the tests stop seeing
//! structure, and baselines. Each sequence is 2^20 bits, tested on its own
//! CPU core. Judged by NIST's two criteria (section 4.2): enough sequences
//! pass each test, and (from 55 sequences) the P-values are uniform. "Enough"
//! is an exact binomial bound rather than NIST's three-sigma rule, which is
//! built for about 1000 sequences (see `minimum_passing`).

use crate::nist::{self, igamc, Bits, Outcome};
use crate::rng::Rng;
use turing::Turing;

pub const SEQUENCE_BITS: usize = 1 << 20;

#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// Turing with `rounds` rounds in counter mode, random key and counter.
    Turing { rounds: usize },
    /// Full Turing, all-zero key, counter starting at zero: low-entropy input.
    TuringZeroKey,
    /// Turing-256 with `rounds` rounds in counter mode (256-bit blocks), random
    /// key and counter (docs/15).
    Turing256 { rounds: usize },
    /// cSHAKE256 output: a known-good baseline.
    Cshake,
    /// The counter itself, unencrypted: a known-bad control.
    Counter,
}

impl Source {
    pub fn name(&self) -> String {
        match self {
            Source::Turing { rounds } => format!("Turing, {rounds} round(s), random keys"),
            Source::TuringZeroKey => "Turing, all-zero key, counter from 0".into(),
            Source::Turing256 { rounds } => format!("Turing-256, {rounds} round(s), random keys"),
            Source::Cshake => "cSHAKE256 (known good)".into(),
            Source::Counter => "plain counter (known bad)".into(),
        }
    }
}

/// Sequence `index` of a source, as bits.
pub fn sequence(source: Source, index: usize, label: &str) -> Bits {
    let blocks = SEQUENCE_BITS / 128;
    let mut rng = Rng::new(&format!("{label} / {} / {index}", source.name()));
    let mut bytes = Vec::with_capacity(SEQUENCE_BITS / 8);
    match source {
        Source::Turing { rounds } => {
            let t = Turing::new(&rng.bytes());
            let start = u128::from_le_bytes(rng.bytes());
            for i in 0..blocks as u128 {
                let mut b = start.wrapping_add(i).to_le_bytes();
                t.encrypt_rounds(&mut b, rounds);
                bytes.extend_from_slice(&b);
            }
        }
        Source::TuringZeroKey => {
            let t = Turing::new(&[0u8; 32]);
            let start = (index as u128) * blocks as u128;
            for i in 0..blocks as u128 {
                let mut b = (start + i).to_le_bytes();
                t.encrypt_block(&mut b);
                bytes.extend_from_slice(&b);
            }
        }
        Source::Turing256 { rounds } => {
            let t = turing::Turing256::new(&rng.bytes());
            let start = u128::from_le_bytes(rng.bytes());
            let high: [u8; 16] = rng.bytes();
            for i in 0..(SEQUENCE_BITS / 256) as u128 {
                let mut b = [0u8; 32];
                b[..16].copy_from_slice(&start.wrapping_add(i).to_le_bytes());
                b[16..].copy_from_slice(&high);
                t.encrypt_rounds(&mut b, rounds);
                bytes.extend_from_slice(&b);
            }
        }
        Source::Cshake => {
            bytes.resize(SEQUENCE_BITS / 8, 0);
            rng.fill(&mut bytes);
        }
        Source::Counter => {
            let start = (index as u128) * blocks as u128;
            for i in 0..blocks as u128 {
                bytes.extend_from_slice(&(start + i).to_le_bytes());
            }
        }
    }
    Bits::from_bytes(&bytes)
}

pub struct TestSummary {
    pub name: &'static str,
    pub passed: usize,
    /// NIST's uniformity P-value of the P-values (meaningful from 55
    /// sequences upward).
    pub uniformity: f64,
}

pub struct BatteryResult {
    pub source: String,
    pub sequences: usize,
    pub min_pass: usize,
    pub tests: Vec<TestSummary>,
}

impl BatteryResult {
    /// NIST's criteria: every test passed by at least `min_pass` sequences,
    /// and (with enough sequences to judge) uniform P-values.
    pub fn passed(&self) -> bool {
        self.tests.iter().all(|t| t.passed >= self.min_pass && (self.sequences < 55 || t.uniformity >= 0.0001))
    }

    pub fn failing_tests(&self) -> Vec<&'static str> {
        self.tests
            .iter()
            .filter(|t| t.passed < self.min_pass || (self.sequences >= 55 && t.uniformity < 0.0001))
            .map(|t| t.name)
            .collect()
    }
}

/// NIST 4.2.1: the fewest passing sequences (out of m, at alpha = 0.01)
/// consistent with randomness: m * (0.99 - 3 sqrt(0.99 * 0.01 / m)).
/// This three-sigma rule is meant for around 1000 sequences; with a few
/// dozen it rejects a perfect generator too often (at m = 8 it demands that
/// all 88 P-values pass, which happens only 41% of the time), so the
/// campaign uses `max_failures` instead.
pub fn minimum_passing(m: usize) -> usize {
    let p = 0.99;
    let lower = p - 3.0 * (p * (1.0 - p) / m as f64).sqrt();
    (lower * m as f64).ceil() as usize
}

/// False-alarm rate for a whole battery run: a perfect generator is
/// rejected by some statistic in at most 1 run in 1000.
pub const FAMILY_ALPHA: f64 = 0.001;

/// The most sequences (out of m) that may fail one statistic before it is
/// judged non-random: the smallest f with P(Binomial(m, 0.01) > f) below
/// FAMILY_ALPHA / 11, splitting the false-alarm rate over the 11 statistics.
pub fn max_failures(m: usize) -> usize {
    let (p, alpha) = (0.01f64, FAMILY_ALPHA / 11.0);
    let ln_choose = |k: usize| nist::ln_gamma(m as f64 + 1.0) - nist::ln_gamma(k as f64 + 1.0) - nist::ln_gamma((m - k) as f64 + 1.0);
    let mut tail = 1.0; // P(X > f), starting at f = -1
    for f in 0..=m {
        tail -= (ln_choose(f) + f as f64 * p.ln() + (m - f) as f64 * (1.0 - p).ln()).exp();
        if tail < alpha {
            return f;
        }
    }
    m
}

/// NIST 4.2.2: chi-square of the P-values over 10 equal bins.
pub fn uniformity(p_values: &[f64]) -> f64 {
    let mut bins = [0usize; 10];
    for &p in p_values {
        bins[((p * 10.0) as usize).min(9)] += 1;
    }
    let expected = p_values.len() as f64 / 10.0;
    let chi2: f64 = bins.iter().map(|&b| (b as f64 - expected).powi(2) / expected).sum();
    igamc(9.0 / 2.0, chi2 / 2.0)
}

pub fn run(source: Source, sequences: usize, label: &str) -> BatteryResult {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut results: Vec<Vec<Outcome>> = vec![Vec::new(); sequences];
    std::thread::scope(|scope| {
        for (worker, chunk) in results.chunks_mut(sequences.div_ceil(threads)).enumerate() {
            let first = worker * sequences.div_ceil(threads);
            scope.spawn(move || {
                for (offset, slot) in chunk.iter_mut().enumerate() {
                    *slot = nist::battery(&sequence(source, first + offset, label));
                }
            });
        }
    });
    let names: Vec<&'static str> = results[0].iter().map(|o| o.name).collect();
    let tests = names
        .iter()
        .enumerate()
        .map(|(i, &name)| {
            let p: Vec<f64> = results.iter().map(|r| r[i].p).collect();
            TestSummary { name, passed: p.iter().filter(|&&x| x >= 0.01).count(), uniformity: uniformity(&p) }
        })
        .collect();
    BatteryResult { source: source.name(), sequences, min_pass: sequences - max_failures(sequences), tests }
}
