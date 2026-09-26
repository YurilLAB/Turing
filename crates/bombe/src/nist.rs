//! Statistical tests from NIST SP 800-22 rev. 1a, "A Statistical Test Suite
//! for Random and Pseudorandom Number Generators for Cryptographic
//! Applications" (2010): nine of its fifteen tests, and the special
//! functions they need.
//!
//! Each test returns a P-value: the probability that a truly random
//! sequence would look at least this non-random. NIST's decision rule is
//! P < 0.01 means non-random. The implementations follow the document and,
//! where the document's prose and its reference code differ (class
//! probabilities, spectral-test indexing), the reference code, because the
//! published reference results were produced by it. They are checked against
//! every worked example in the document and against its reference results
//! for 1,000,000 bits of e (tests/nist.rs).

use std::f64::consts::PI;

// ---------------------------------------------------------------------------
// Special functions
// ---------------------------------------------------------------------------

/// ln Γ(x) for x > 0 (Lanczos approximation, g = 7, about 15 digits).
pub fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (PI / (PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let t = x + 7.5;
    let mut a = C[0];
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// The upper regularized incomplete gamma function Q(a, x), called igamc in
/// NIST's code. Series for x < a + 1, continued fraction otherwise
/// (Numerical Recipes, gammq).
pub fn igamc(a: f64, x: f64) -> f64 {
    assert!(a > 0.0 && x >= 0.0, "igamc({a}, {x})");
    if x == 0.0 {
        return 1.0;
    }
    let prefactor = (-x + a * x.ln() - ln_gamma(a)).exp();
    if x < a + 1.0 {
        let (mut ap, mut sum) = (a, 1.0 / a);
        let mut del = sum;
        for _ in 0..10_000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-17 {
                break;
            }
        }
        (1.0 - sum * prefactor).max(0.0)
    } else {
        const TINY: f64 = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / TINY;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..10_000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < TINY {
                d = TINY;
            }
            c = b + an / c;
            if c.abs() < TINY {
                c = TINY;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-17 {
                break;
            }
        }
        prefactor * h
    }
}

/// The complementary error function, erfc(x) = Q(1/2, x^2) for x >= 0.
pub fn erfc(x: f64) -> f64 {
    if x >= 0.0 {
        igamc(0.5, x * x)
    } else {
        2.0 - igamc(0.5, x * x)
    }
}

/// The standard normal cumulative distribution function Φ.
pub fn normal_cdf(x: f64) -> f64 {
    0.5 * erfc(-x / std::f64::consts::SQRT_2)
}

// ---------------------------------------------------------------------------
// Bit sequences
// ---------------------------------------------------------------------------

/// A sequence of bits, one per byte (0 or 1).
pub struct Bits(pub Vec<u8>);

impl Bits {
    /// Bytes unpacked most significant bit first.
    pub fn from_bytes(bytes: &[u8]) -> Bits {
        Bits(bytes.iter().flat_map(|&b| (0..8).rev().map(move |k| (b >> k) & 1)).collect())
    }

    /// From a string of '0' and '1' (other characters, e.g. spaces, ignored).
    pub fn parse(s: &str) -> Bits {
        Bits(s.bytes().filter_map(|c| match c {
            b'0' => Some(0),
            b'1' => Some(1),
            _ => None,
        }).collect())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The tests (section numbers refer to SP 800-22 rev. 1a)
// ---------------------------------------------------------------------------

/// 2.1 Frequency (monobit): the balance of ones and zeros.
pub fn frequency(e: &Bits) -> f64 {
    let n = e.len() as f64;
    let s: i64 = e.0.iter().map(|&b| 2 * b as i64 - 1).sum();
    erfc((s.abs() as f64 / n.sqrt()) / std::f64::consts::SQRT_2)
}

/// 2.2 Frequency within blocks of `m` bits.
pub fn block_frequency(e: &Bits, m: usize) -> f64 {
    let blocks = e.len() / m;
    let chi2: f64 = e.0.chunks_exact(m)
        .take(blocks)
        .map(|block| {
            let pi = block.iter().map(|&b| b as f64).sum::<f64>() / m as f64;
            (pi - 0.5).powi(2)
        })
        .sum::<f64>()
        * 4.0
        * m as f64;
    igamc(blocks as f64 / 2.0, chi2 / 2.0)
}

/// 2.3 Runs: the number of uninterrupted runs of identical bits. Returns 0
/// when the frequency prerequisite fails, as the reference code does.
pub fn runs(e: &Bits) -> f64 {
    let n = e.len() as f64;
    let pi = e.0.iter().map(|&b| b as f64).sum::<f64>() / n;
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        return 0.0;
    }
    let v = 1 + e.0.windows(2).filter(|w| w[0] != w[1]).count();
    let expected = 2.0 * n * pi * (1.0 - pi);
    erfc((v as f64 - expected).abs() / (2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi)))
}

/// 2.4 Longest run of ones in a block. Block size, classes and class
/// probabilities as in the reference code (sts-2.1.2).
pub fn longest_run(e: &Bits) -> f64 {
    let n = e.len();
    let (m, lower, probs): (usize, usize, &[f64]) = if n < 6272 {
        (8, 1, &[0.21484375, 0.3671875, 0.23046875, 0.1875])
    } else if n < 750_000 {
        (128, 4, &[0.1174035788, 0.242955959, 0.249363483, 0.17517706, 0.102701071, 0.112398847])
    } else {
        (10_000, 10, &[0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727])
    };
    let k = probs.len() - 1;
    let blocks = n / m;
    let mut counts = vec![0usize; probs.len()];
    for block in e.0.chunks_exact(m).take(blocks) {
        let (mut run, mut longest) = (0usize, 0usize);
        for &b in block {
            run = if b == 1 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        counts[longest.saturating_sub(lower).min(k)] += 1;
    }
    let chi2: f64 = counts
        .iter()
        .zip(probs)
        .map(|(&v, &p)| (v as f64 - blocks as f64 * p).powi(2) / (blocks as f64 * p))
        .sum();
    igamc(k as f64 / 2.0, chi2 / 2.0)
}

/// Probability that a random 32 x 32 binary matrix has rank `r` (r >= 30
/// is all the test needs; 30 stands for "30 or less").
fn rank_probability(r: i32) -> f64 {
    let exact = |r: i32| -> f64 {
        let mut product = 1.0;
        for i in 0..r {
            let a = 1.0 - 2f64.powi(i - 32);
            product *= a * a / (1.0 - 2f64.powi(i - r));
        }
        2f64.powi(r * (32 + 32 - r) - 32 * 32) * product
    };
    if r >= 31 {
        exact(r)
    } else {
        1.0 - exact(32) - exact(31)
    }
}

fn gf2_rank_32(mut rows: [u32; 32]) -> u32 {
    let mut rank = 0;
    for bit in (0..32).rev() {
        let Some(p) = (rank as usize..32).find(|&r| rows[r] >> bit & 1 == 1) else { continue };
        rows.swap(rank as usize, p);
        let pivot = rows[rank as usize];
        for (r, row) in rows.iter_mut().enumerate() {
            if r != rank as usize && *row >> bit & 1 == 1 {
                *row ^= pivot;
            }
        }
        rank += 1;
    }
    rank
}

/// 2.5 Binary matrix rank of disjoint 32 x 32 matrices.
pub fn rank(e: &Bits) -> f64 {
    let matrices = e.len() / 1024;
    let mut counts = [0usize; 3]; // full rank, full - 1, lower
    for block in e.0.chunks_exact(1024).take(matrices) {
        let mut rows = [0u32; 32];
        for (i, row) in rows.iter_mut().enumerate() {
            *row = block[32 * i..32 * i + 32].iter().fold(0u32, |acc, &b| acc << 1 | b as u32);
        }
        match gf2_rank_32(rows) {
            32 => counts[0] += 1,
            31 => counts[1] += 1,
            _ => counts[2] += 1,
        }
    }
    let n = matrices as f64;
    let chi2: f64 = counts
        .iter()
        .zip([32, 31, 30])
        .map(|(&f, r)| {
            let expected = n * rank_probability(r);
            (f as f64 - expected).powi(2) / expected
        })
        .sum();
    (-chi2 / 2.0).exp()
}

// Complex numbers as (re, im) pairs, enough for the spectral test.
type Complex = (f64, f64);

fn fft_pow2(a: &mut [Complex], inverse: bool) {
    let n = a.len();
    assert!(n.is_power_of_two());
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let angle = 2.0 * PI / len as f64 * if inverse { 1.0 } else { -1.0 };
        for start in (0..n).step_by(len) {
            for k in 0..len / 2 {
                let (s, c) = (angle * k as f64).sin_cos();
                let (ur, ui) = a[start + k];
                let (vr, vi) = a[start + k + len / 2];
                let (tr, ti) = (vr * c - vi * s, vr * s + vi * c);
                a[start + k] = (ur + tr, ui + ti);
                a[start + k + len / 2] = (ur - tr, ui - ti);
            }
        }
        len <<= 1;
    }
}

/// The discrete Fourier transform of real input, any length: radix-2 when
/// the length is a power of two, otherwise Bluestein's algorithm (the
/// transform written as a convolution computed with power-of-two FFTs).
pub fn dft(x: &[f64]) -> Vec<Complex> {
    let n = x.len();
    if n.is_power_of_two() {
        let mut a: Vec<Complex> = x.iter().map(|&v| (v, 0.0)).collect();
        fft_pow2(&mut a, false);
        return a;
    }
    // chirp[k] = exp(-i pi k^2 / n); k^2 is reduced mod 2n exactly first.
    let chirp: Vec<Complex> = (0..n)
        .map(|k| {
            let angle = PI * ((k as u128 * k as u128) % (2 * n as u128)) as f64 / n as f64;
            (angle.cos(), -angle.sin())
        })
        .collect();
    let size = (2 * n - 1).next_power_of_two();
    let mut a = vec![(0.0, 0.0); size];
    for k in 0..n {
        a[k] = (x[k] * chirp[k].0, x[k] * chirp[k].1);
    }
    let mut b = vec![(0.0, 0.0); size];
    b[0] = (chirp[0].0, -chirp[0].1);
    for k in 1..n {
        let conj = (chirp[k].0, -chirp[k].1);
        b[k] = conj;
        b[size - k] = conj;
    }
    fft_pow2(&mut a, false);
    fft_pow2(&mut b, false);
    for (u, v) in a.iter_mut().zip(&b) {
        *u = (u.0 * v.0 - u.1 * v.1, u.0 * v.1 + u.1 * v.0);
    }
    fft_pow2(&mut a, true);
    (0..n)
        .map(|k| {
            let (re, im) = (a[k].0 / size as f64, a[k].1 / size as f64);
            (re * chirp[k].0 - im * chirp[k].1, re * chirp[k].1 + im * chirp[k].0)
        })
        .collect()
}

/// The direct O(n^2) transform, to check `dft` against.
pub fn dft_naive(x: &[f64]) -> Vec<Complex> {
    let n = x.len();
    (0..n)
        .map(|j| {
            x.iter().enumerate().fold((0.0, 0.0), |(re, im), (k, &v)| {
                let angle = -2.0 * PI * ((j * k) % n) as f64 / n as f64;
                (re + v * angle.cos(), im + v * angle.sin())
            })
        })
        .collect()
}

/// 2.6 Discrete Fourier transform (spectral): too many or too few periodic
/// peaks. Counts |S_j| < T for j = 0 .. n/2 - 1, as the reference code does.
pub fn spectral(e: &Bits) -> f64 {
    let n = e.len();
    let x: Vec<f64> = e.0.iter().map(|&b| 2.0 * b as f64 - 1.0).collect();
    let s = dft(&x);
    let threshold = ((1.0f64 / 0.05).ln() * n as f64).sqrt();
    let below = s[..n / 2].iter().filter(|(re, im)| (re * re + im * im).sqrt() < threshold).count();
    let expected = 0.95 * n as f64 / 2.0;
    let d = (below as f64 - expected) / (n as f64 * 0.95 * 0.05 / 4.0).sqrt();
    erfc(d.abs() / std::f64::consts::SQRT_2)
}

/// Frequencies of every overlapping m-bit pattern, wrapping around the end.
fn pattern_counts(e: &Bits, m: usize) -> Vec<u64> {
    let n = e.len();
    let mut counts = vec![0u64; 1 << m];
    if m == 0 {
        return counts;
    }
    let mut value = 0usize;
    for i in 0..m - 1 {
        value = (value << 1) | e.0[i] as usize;
    }
    let mask = (1usize << m) - 1;
    for i in 0..n {
        value = ((value << 1) | e.0[(i + m - 1) % n] as usize) & mask;
        counts[value] += 1;
    }
    counts
}

fn psi_squared(e: &Bits, m: usize) -> f64 {
    if m == 0 {
        return 0.0;
    }
    let n = e.len() as f64;
    let sum: f64 = pattern_counts(e, m).iter().map(|&c| (c * c) as f64).sum();
    sum * (1u64 << m) as f64 / n - n
}

/// 2.11 Serial: frequencies of all overlapping m-bit patterns. Returns the
/// two P-values (first and second differences of ψ²).
pub fn serial(e: &Bits, m: usize) -> (f64, f64) {
    assert!(m >= 2);
    let (p0, p1, p2) = (psi_squared(e, m), psi_squared(e, m - 1), psi_squared(e, m - 2));
    let d1 = p0 - p1;
    let d2 = p0 - 2.0 * p1 + p2;
    (igamc(2f64.powi(m as i32 - 2), d1 / 2.0), igamc(2f64.powi(m as i32 - 3), d2 / 2.0))
}

/// 2.12 Approximate entropy with pattern length m.
pub fn approximate_entropy(e: &Bits, m: usize) -> f64 {
    let n = e.len() as f64;
    let phi = |m: usize| -> f64 {
        pattern_counts(e, m)
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                p * p.ln()
            })
            .sum()
    };
    let apen = phi(m) - phi(m + 1);
    let chi2 = 2.0 * n * (2f64.ln() - apen);
    igamc(2f64.powi(m as i32 - 1), chi2 / 2.0)
}

/// 2.13 Cumulative sums: the largest excursion of the ±1 random walk,
/// forward or backward. Summation limits use C integer division, as in the
/// reference code.
pub fn cumulative_sums(e: &Bits, forward: bool) -> f64 {
    let n = e.len() as i64;
    let mut s = 0i64;
    let mut z = 0i64;
    let steps: Box<dyn Iterator<Item = &u8>> = if forward { Box::new(e.0.iter()) } else { Box::new(e.0.iter().rev()) };
    for &b in steps {
        s += 2 * b as i64 - 1;
        z = z.max(s.abs());
    }
    let root_n = (n as f64).sqrt();
    let zf = z as f64;
    let mut sum1 = 0.0;
    for k in ((-n / z + 1) / 4)..=((n / z - 1) / 4) {
        sum1 += normal_cdf((4 * k + 1) as f64 * zf / root_n) - normal_cdf((4 * k - 1) as f64 * zf / root_n);
    }
    let mut sum2 = 0.0;
    for k in ((-n / z - 3) / 4)..=((n / z - 1) / 4) {
        sum2 += normal_cdf((4 * k + 3) as f64 * zf / root_n) - normal_cdf((4 * k + 1) as f64 * zf / root_n);
    }
    1.0 - sum1 + sum2
}

/// One test's result on one sequence.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub name: &'static str,
    pub p: f64,
}

/// The nine tests with the parameters NIST used for its reference results
/// on 1,000,000-bit sequences (block frequency M = 128, serial m = 16,
/// approximate entropy m = 10), for sequences of at least 1,000,000 bits.
pub fn battery(e: &Bits) -> Vec<Outcome> {
    let (s1, s2) = serial(e, 16);
    vec![
        Outcome { name: "frequency", p: frequency(e) },
        Outcome { name: "block frequency", p: block_frequency(e, 128) },
        Outcome { name: "cusum forward", p: cumulative_sums(e, true) },
        Outcome { name: "cusum backward", p: cumulative_sums(e, false) },
        Outcome { name: "runs", p: runs(e) },
        Outcome { name: "longest run", p: longest_run(e) },
        Outcome { name: "rank", p: rank(e) },
        Outcome { name: "spectral", p: spectral(e) },
        Outcome { name: "approximate entropy", p: approximate_entropy(e, 10) },
        Outcome { name: "serial 1", p: s1 },
        Outcome { name: "serial 2", p: s2 },
    ]
}
