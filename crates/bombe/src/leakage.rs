//! Leakage of the masked cipher, simulated in the probing model of Ishai,
//! Sahai and Wagner (CRYPTO 2003): the device leaks the Hamming weight of
//! each byte of each share it handles, plus Gaussian noise, and
//! `MaskedTuring::encrypt_probed` hands Bombe both shares after every S-box
//! layer. First-order masking claims that no single value leaks; two values
//! combined may.
//!
//! - First-order CPA (power.rs) on one share at a time, with the Hamming
//!   weight and all eight single bits of S(p ^ k) as predictions: must fail.
//! - Control: the same attack on the XOR of the shares, which is the
//!   unmasked value, must succeed, or the attack is too weak to mean anything.
//! - Second-order CPA on the centred product of the two shares' leaks
//!   (Prouff, Rivain and Bevan, IEEE Trans. Computers 2009): expected to
//!   succeed, since first-order masking does not claim order 2.
//! - TVLA (Goodwill et al., NIST NIAT 2011): Welch's t between a fixed and
//!   random plaintexts at every leak point, |t| > 4.5 in two independent
//!   groups counting as leakage; univariate on each share (must stay below),
//!   on the unmasked values (control), on the shares of a cipher whose masks
//!   repeat in every trace (control: a fixed mask seed, which is what broken
//!   randomness or a mask stream shared across fork(2) amounts to), and
//!   bivariate on the centred products (Schneider and Moradi, CHES 2015),
//!   which order-1 masking cannot hide.
//!
//! Masks that repeat do not make the key fall to the CPA above: the output
//! shares are nonlinear functions of p ^ k and the fixed masks, which a
//! prediction of S(p ^ k) does not match. They do make every share depend
//! on the data, and TVLA sees that at once.

use crate::rng::Rng;
use turing::structure::ROUNDS;
use turing::{sbox, Block, MaskedTuring};

/// A standard normal sample (Box-Muller).
fn normal(rng: &mut Rng) -> f64 {
    let unit = |x: u64| ((x >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    let (u1, u2) = (unit(rng.u64()), unit(rng.u64()));
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// What an attacker observes at one byte position of one trace.
#[derive(Clone, Copy)]
pub enum View {
    /// One share alone.
    Share(usize),
    /// The XOR of both shares: the unmasked value (control).
    Unmasked,
    /// The centred product of both shares' leaks (second order).
    Product,
}

/// Round-1 S-box outputs of `n` encryptions, as both shares, with the
/// plaintexts.
pub struct Traces {
    pub plaintexts: Vec<Block>,
    pub shares: Vec<[Block; 2]>,
    pub round_key: Block,
}

pub fn collect(key: &[u8; 32], n: usize, rng: &mut Rng) -> Traces {
    let mut m = MaskedTuring::new(key).expect("OS randomness");
    let (mut plaintexts, mut shares) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for _ in 0..n {
        let p: Block = rng.bytes();
        let mut b = p;
        let mut first = [[0u8; 16]; 2];
        m.encrypt_probed(&mut b, &mut |round, s0, s1| {
            if round == 1 {
                first = [*s0, *s1];
            }
        });
        plaintexts.push(p);
        shares.push(first);
    }
    Traces { plaintexts, shares, round_key: *turing::Turing::new(key).round_key(0) }
}

/// The simulated measurement of every trace at byte `j`.
fn measure(t: &Traces, j: usize, view: View, sigma: f64, rng: &mut Rng) -> Vec<f64> {
    let hw = |b: u8| f64::from(b.count_ones());
    let leaks: Vec<[f64; 2]> = t.shares.iter().map(|s| [hw(s[0][j]) + sigma * normal(rng), hw(s[1][j]) + sigma * normal(rng)]).collect();
    match view {
        View::Share(i) => leaks.iter().map(|l| l[i]).collect(),
        View::Unmasked => t.shares.iter().map(|s| hw(s[0][j] ^ s[1][j]) + sigma * normal(rng)).collect(),
        View::Product => {
            let n = leaks.len() as f64;
            let m0 = leaks.iter().map(|l| l[0]).sum::<f64>() / n;
            let m1 = leaks.iter().map(|l| l[1]).sum::<f64>() / n;
            leaks.iter().map(|l| (l[0] - m0) * (l[1] - m1)).collect()
        }
    }
}

/// Correlation-power analysis on byte `j`: for every key guess, the best
/// |correlation| over nine predictions of S(p ^ k) (its Hamming weight and
/// each bit). Every prediction depends on the plaintext byte alone, so the
/// traces are first summed per plaintext value. Returns the top guess.
fn cpa_byte(plaintexts: &[Block], j: usize, y: &[f64]) -> u8 {
    let (mut count, mut sum) = ([0f64; 256], [0f64; 256]);
    for (p, &v) in plaintexts.iter().zip(y) {
        count[p[j] as usize] += 1.0;
        sum[p[j] as usize] += v;
    }
    let n = y.len() as f64;
    let (sy, syy) = (y.iter().sum::<f64>(), y.iter().map(|v| v * v).sum::<f64>());
    let var_y = syy - sy * sy / n;
    let score = |k: u8| -> f64 {
        (0..9)
            .map(|model| {
                let f = |v: usize| -> f64 {
                    let s = sbox::TABLE[v ^ k as usize];
                    if model == 8 {
                        f64::from(s.count_ones())
                    } else {
                        f64::from((s >> model) & 1)
                    }
                };
                let (mut sx, mut sxx, mut sxy) = (0.0, 0.0, 0.0);
                for v in 0..256 {
                    let x = f(v);
                    sx += count[v] * x;
                    sxx += count[v] * x * x;
                    sxy += sum[v] * x;
                }
                let var_x = sxx - sx * sx / n;
                if var_x <= 0.0 || var_y <= 0.0 {
                    0.0
                } else {
                    ((sxy - sx * sy / n) / (var_x * var_y).sqrt()).abs()
                }
            })
            .fold(0.0, f64::max)
    };
    (0..=255u8).max_by(|&a, &b| score(a).total_cmp(&score(b))).expect("256 guesses")
}

/// Bytes of round key 0 the attack ranks first, of 16.
pub fn cpa(t: &Traces, view: View, sigma: f64, label: &str) -> usize {
    let mut rng = Rng::new(label);
    (0..16).filter(|&j| cpa_byte(&t.plaintexts, j, &measure(t, j, view, sigma, &mut rng)) == t.round_key[j]).count()
}

/// Running mean and variance (Welford).
#[derive(Clone, Copy, Default)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn add(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }

    fn t(&self, other: &Moments) -> f64 {
        let (va, vb) = (self.m2 / (self.n - 1.0), other.m2 / (other.n - 1.0));
        let se = (va / self.n + vb / other.n).sqrt();
        if se == 0.0 {
            0.0
        } else {
            (self.mean - other.mean) / se
        }
    }
}

/// One kind of leak point in a TVLA run.
#[derive(Clone, Copy, Debug)]
pub struct TvlaKind {
    pub points: usize,
    /// Points where both independent groups give |t| > 4.5 with the same
    /// sign: Goodwill et al.'s criterion for a leak.
    pub confirmed: usize,
    /// The largest |t| seen in either group.
    pub max_t: f64,
}

impl TvlaKind {
    pub fn leaks(&self) -> bool {
        self.confirmed > 0
    }
}

pub struct Tvla {
    pub traces: usize,
    /// Univariate, each byte of each share after every S-box layer.
    pub shares: TvlaKind,
    /// Univariate on the unmasked values (control).
    pub unmasked: TvlaKind,
    /// Bivariate: the product of both shares' leaks at one byte, centred on
    /// the known mean 4 of a uniformly random byte's weight.
    pub product: TvlaKind,
}

/// Fixed-versus-random TVLA over all 24 rounds, as Goodwill et al. specify
/// it: the traces are split into two disjoint groups, Welch's t is computed
/// in each, and a point leaks only if both exceed 4.5 in the same direction
/// ("if the t-test statistic exceeded +/- C at a particular instance in time
/// purely by chance, this rare occurrence is unlikely to repeat"). `n`
/// traces, classes interleaved at random, noise `sigma` on every leak.
/// `repeat_masks` rebuilds the cipher from one fixed mask seed before every
/// trace, so that every trace uses the same masks.
pub fn tvla(key: &[u8; 32], n: usize, sigma: f64, repeat_masks: bool, label: &str) -> Tvla {
    let mut rng = Rng::new(label);
    let mut m = MaskedTuring::new(key).expect("OS randomness");
    let fixed: Block = rng.bytes();
    const POINTS: usize = ROUNDS * 16;
    // [group][point][class]
    let mut shares = vec![vec![[Moments::default(); 2]; 2 * POINTS]; 2];
    let mut unmasked = vec![vec![[Moments::default(); 2]; POINTS]; 2];
    let mut product = vec![vec![[Moments::default(); 2]; POINTS]; 2];
    let mut noise: Vec<f64> = Vec::with_capacity(3 * POINTS);
    for trace in 0..n {
        let (group, class) = (trace % 2, rng.below(2) as usize);
        let mut b: Block = if class == 0 { fixed } else { rng.bytes() };
        if repeat_masks {
            m = MaskedTuring::with_mask_seed(key, &[0x5c; 64]);
        }
        noise.clear();
        noise.extend((0..3 * POINTS).map(|_| sigma * normal(&mut rng)));
        m.encrypt_probed(&mut b, &mut |round, s0, s1| {
            for j in 0..16 {
                let point = (round - 1) * 16 + j;
                let l0 = f64::from(s0[j].count_ones()) + noise[point];
                let l1 = f64::from(s1[j].count_ones()) + noise[POINTS + point];
                shares[group][point][class].add(l0);
                shares[group][POINTS + point][class].add(l1);
                unmasked[group][point][class].add(f64::from((s0[j] ^ s1[j]).count_ones()) + noise[2 * POINTS + point]);
                product[group][point][class].add((l0 - 4.0) * (l1 - 4.0));
            }
        });
    }
    let judge = |groups: &[Vec<[Moments; 2]>]| {
        let (mut confirmed, mut max_t) = (0, 0f64);
        for (g1, g2) in groups[0].iter().zip(&groups[1]) {
            let (t1, t2) = (g1[0].t(&g1[1]), g2[0].t(&g2[1]));
            max_t = max_t.max(t1.abs()).max(t2.abs());
            confirmed += usize::from(t1.abs() > 4.5 && t2.abs() > 4.5 && t1.signum() == t2.signum());
        }
        TvlaKind { points: groups[0].len(), confirmed, max_t }
    };
    Tvla { traces: n, shares: judge(&shares), unmasked: judge(&unmasked), product: judge(&product) }
}

/// Fixed-versus-random TVLA on every value the masked S-boxes compute in
/// rounds 1 and 2 (`MaskedTuring::encrypt_recorded`): each product, each
/// refreshed share and each share of the S-box's input and output, every
/// byte lane a leak point. This is the probing model at the level of single
/// operations: an intermediate that combines both shares of a secret, or a
/// product of values sharing a mask (a missing refresh), leaks here even if
/// the state between layers looks clean. Same two-group rule as `tvla`.
pub fn tvla_intermediates(key: &[u8; 32], n: usize, sigma: f64, repeat_masks: bool, label: &str) -> TvlaKind {
    let mut rng = Rng::new(label);
    let mut m = MaskedTuring::new(key).expect("OS randomness");
    let fixed: Block = rng.bytes();
    let per_round = m.encrypt_recorded(&mut fixed.clone()).len() / ROUNDS;
    let values = 2 * per_round;
    let mut stats = vec![vec![[Moments::default(); 2]; 8 * values]; 2];
    for trace in 0..n {
        let (group, class) = (trace % 2, rng.below(2) as usize);
        let mut b: Block = if class == 0 { fixed } else { rng.bytes() };
        if repeat_masks {
            m = MaskedTuring::with_mask_seed(key, &[0x5c; 64]);
        }
        let recorded = m.encrypt_recorded(&mut b);
        for (i, v) in recorded[..values].iter().enumerate() {
            for lane in 0..8 {
                let noise = if sigma > 0.0 { sigma * normal(&mut rng) } else { 0.0 };
                stats[group][8 * i + lane][class].add(f64::from(((v >> (8 * lane)) as u8).count_ones()) + noise);
            }
        }
    }
    let (mut confirmed, mut max_t) = (0, 0f64);
    for (g1, g2) in stats[0].iter().zip(&stats[1]) {
        let (t1, t2) = (g1[0].t(&g1[1]), g2[0].t(&g2[1]));
        max_t = max_t.max(t1.abs()).max(t2.abs());
        confirmed += usize::from(t1.abs() > 4.5 && t2.abs() > 4.5 && t1.signum() == t2.signum());
    }
    TvlaKind { points: 8 * values, confirmed, max_t }
}
