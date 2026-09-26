//! Correlation power analysis (Brier, Clavier and Olivier, CHES 2004), the
//! side-channel attack behind the practical breaks of KeeLoq remote keyless
//! entry (Eisenbarth et al., CRYPTO 2008) and the Mifare DESFire MF3ICD40
//! card (Oswald and Paar, CHES 2011). A chip's power draw depends on the
//! Hamming weight of the values it handles. For each guess of a key byte the
//! attacker predicts HW(S(p ^ k)) for every trace and keeps the guess whose
//! prediction correlates best with the measurements.
//!
//! Simulated here: the device leaks the Hamming weight of each first-round
//! S-box output plus Gaussian noise. The attack recovers round key 0; with it
//! known, the same attack one round deeper gives round key 1, and so on, so
//! an unprotected implementation loses every round key. The countermeasure
//! is masking. Turing computes x^254 with the addition chain Rivain and
//! Prouff mask at any order (CHES 2010, Algorithm 2: 4 multiplications,
//! which they show is the minimum), and its affine layers mask for free.

use crate::rng::Rng;
use turing::{sbox, Block, Turing};

/// A standard normal sample (Box-Muller).
fn normal(rng: &mut Rng) -> f64 {
    let unit = |x: u64| ((x >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    let (u1, u2) = (unit(rng.u64()), unit(rng.u64()));
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

fn correlation(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let (mx, my) = (x.iter().sum::<f64>() / n, y.iter().sum::<f64>() / n);
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for (a, b) in x.iter().zip(y) {
        sxy += (a - mx) * (b - my);
        sxx += (a - mx) * (a - mx);
        syy += (b - my) * (b - my);
    }
    if sxx == 0.0 || syy == 0.0 {
        0.0
    } else {
        sxy / (sxx * syy).sqrt()
    }
}

pub struct Cpa {
    pub sigma: f64,
    pub traces: usize,
    /// Bytes of round key 0 ranked first by the attack.
    pub bytes_correct: usize,
}

/// Runs CPA with `traces` simulated traces at noise level `sigma` (in units
/// of one bit of Hamming weight; a random byte's weight has variance 2, so
/// the signal-to-noise ratio is 2 / sigma^2).
pub fn attack(sigma: f64, traces: usize, label: &str) -> Cpa {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let rk0 = *t.round_key(0);
    let plaintexts: Vec<Block> = (0..traces).map(|_| rng.bytes()).collect();
    // The device: S-box outputs of round 1, leaked as weight + noise.
    let leaks: Vec<[f64; 16]> = plaintexts
        .iter()
        .map(|p| {
            let mut s: Block = std::array::from_fn(|j| p[j] ^ rk0[j]);
            sbox::sub_bytes(&mut s);
            std::array::from_fn(|j| f64::from(s[j].count_ones()) + sigma * normal(&mut rng))
        })
        .collect();
    // The attacker: the S-box is public, the key is not.
    let mut bytes_correct = 0;
    for j in 0..16 {
        let measured: Vec<f64> = leaks.iter().map(|l| l[j]).collect();
        let best = (0..=255u8)
            .map(|k| {
                let predicted: Vec<f64> = plaintexts.iter().map(|p| f64::from(sbox::TABLE[(p[j] ^ k) as usize].count_ones())).collect();
                (correlation(&predicted, &measured).abs(), k)
            })
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, k)| k);
        bytes_correct += usize::from(best == Some(rk0[j]));
    }
    Cpa { sigma, traces, bytes_correct }
}

/// Smallest trace count in 10, 20, 40, ... (up to `max`) at which all 16 key
/// bytes come out on top.
pub fn traces_needed(sigma: f64, max: usize, label: &str) -> Option<usize> {
    let mut n = 10;
    while n <= max {
        if attack(sigma, n, label).bytes_correct == 16 {
            return Some(n);
        }
        n *= 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_samples_have_unit_variance() {
        let mut rng = Rng::new("test normal");
        let xs: Vec<f64> = (0..20_000).map(|_| normal(&mut rng)).collect();
        let mean = xs.iter().sum::<f64>() / xs.len() as f64;
        let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / xs.len() as f64;
        assert!(mean.abs() < 0.05 && (var - 1.0).abs() < 0.05, "mean {mean}, variance {var}");
    }

    #[test]
    fn correlation_basics() {
        let x = [1.0, 2.0, 3.0, 4.0];
        assert!((correlation(&x, &[2.0, 4.0, 6.0, 8.0]) - 1.0).abs() < 1e-12);
        assert!((correlation(&x, &[8.0, 6.0, 4.0, 2.0]) + 1.0).abs() < 1e-12);
        assert_eq!(correlation(&x, &[5.0; 4]), 0.0);
    }
}
