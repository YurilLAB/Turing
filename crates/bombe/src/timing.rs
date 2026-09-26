//! Timing side-channel test in the style of dudect (Reparaz, Balasch,
//! Verbauwhede, "Dude, is my code constant time?", DATE 2017): time the code
//! on two classes of input, fixed and random, interleaved at random, and
//! compare the two timing distributions with Welch's t-test. In the paper's
//! words, "a t value larger than 4.5 provides strong statistical evidence
//! that the distributions are different", i.e. the running time depends on
//! the data. As in dudect, the test also runs on measurements cropped below
//! several percentiles, so rare interrupts cannot hide or fake a difference.

use crate::rng::Rng;

/// A cycle counter where available, nanoseconds otherwise.
fn now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rdtsc has no preconditions; it only reads a counter.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::sync::OnceLock;
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        START.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
    }
}

/// Welch's t statistic for two samples.
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let stats = |x: &[f64]| {
        let n = x.len() as f64;
        let mean = x.iter().sum::<f64>() / n;
        let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (n, mean, var)
    };
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

pub struct TimingResult {
    pub name: String,
    pub measurements: usize,
    /// Largest |t| over the uncropped data and every crop.
    pub max_t: f64,
    /// Median time of one call, in counter ticks.
    pub median_ticks: f64,
}

impl TimingResult {
    pub fn leaks(&self) -> bool {
        self.max_t > 4.5
    }
}

/// Times `f` on `measurements` inputs of `len` bytes: class 0 is all zeros,
/// class 1 random. Inputs and classes are generated before timing starts.
pub fn dudect(name: &str, measurements: usize, len: usize, mut f: impl FnMut(&[u8])) -> TimingResult {
    let mut rng = Rng::new(&format!("timing {name}"));
    let classes: Vec<bool> = (0..measurements).map(|_| rng.below(2) == 1).collect();
    let mut inputs = vec![0u8; measurements * len];
    for (i, &random) in classes.iter().enumerate() {
        if random {
            rng.fill(&mut inputs[i * len..(i + 1) * len]);
        }
    }
    for i in 0..measurements.min(1000) {
        f(&inputs[i * len..(i + 1) * len]); // warm up caches and branch predictors
    }
    let mut times = vec![0f64; measurements];
    for (i, t) in times.iter_mut().enumerate() {
        let input = &inputs[i * len..(i + 1) * len];
        let start = now();
        f(input);
        let end = now();
        *t = end.wrapping_sub(start) as f64;
    }
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let percentile = |p: f64| sorted[((sorted.len() - 1) as f64 * p) as usize];
    let mut max_t: f64 = 0.0;
    for crop in [1.0, 0.99, 0.95, 0.9, 0.75, 0.5] {
        let limit = percentile(crop);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for (&t, &random) in times.iter().zip(&classes) {
            if t <= limit {
                if random {
                    b.push(t);
                } else {
                    a.push(t);
                }
            }
        }
        if a.len() > 100 && b.len() > 100 {
            max_t = max_t.max(welch_t(&a, &b).abs());
        }
    }
    TimingResult { name: name.to_string(), measurements, max_t, median_ticks: percentile(0.5) }
}

/// A deliberately leaky S-box layer for the negative control: the field
/// inverse computed with the textbook multiply whose loop stops as soon as
/// the multiplier runs out of bits, so its running time depends on the data.
pub fn leaky_sub_bytes(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        let x = *b;
        let (mut result, mut base, mut e) = (1u8, x, 254u8);
        while e > 0 {
            if e & 1 == 1 {
                result = crate::gf256::mul(result, base);
            }
            base = crate::gf256::mul(base, base);
            e >>= 1;
        }
        *b = std::hint::black_box(if x == 0 { 0 } else { result });
    }
}
