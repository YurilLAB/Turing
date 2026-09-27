//! The core-SVP cost of lattice attacks on LWE (docs/16): the primal attack
//! (unique-SVP by BKZ) and the dual attack (a short dual vector as a
//! distinguisher), in the model of Alkim, Ducas, Pöppelmann and Schwabe
//! (NewHope, USENIX 2016, section 6) that Kyber, FrodoKEM and NewHope used
//! for their tables. A port of research/scripts/pq/coresvp.py's "newhope"
//! and "frodo" conventions, which reproduce those tables; the tests here
//! reproduce them again before the numbers are trusted on Turing-1026.
//!
//! BKZ with block size b reaches root Hermite factor
//! delta = ((pi b)^(1/b) b / (2 pi e))^(1/(2(b-1))) (Chen's formula); under
//! the geometric series assumption the primal attack on LWE(n, q) with m
//! samples succeeds when sigma sqrt(b) <= delta^(2b-d-1) Vol^(1/d),
//! d = n + m. The cost is one SVP call in dimension b: 2^(0.292 b)
//! classically (sieving, BDGL16), 2^(0.265 b) quantumly, 2^(0.2075 b) as a
//! "plausible" floor. Every polynomial factor is left out, which is why the
//! figure is conservative (it favours the attacker); the lattice-estimator's
//! gate counts for the same attacks are 15-35 bits higher (docs/16).

/// Sieving exponents: classical [BDGL16], quantum [Laarhoven 2016],
/// plausible floor (the list size).
pub const CLASSICAL: f64 = 0.292_481_250_360_578_3; // log2(sqrt(3/2))
pub const QUANTUM: f64 = 0.265_257_634_239_804_9; // log2(sqrt(13/9))
pub const PLAUSIBLE: f64 = 0.207_518_749_639_421_7; // log2(sqrt(4/3))

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convention {
    /// NewHope's scripts: no polynomial factor, dual advantage exp(...).
    NewHope,
    /// FrodoKEM's: + log2(b) per SVP call, dual advantage 4 exp(...).
    Frodo,
}

impl Convention {
    fn svp(self, b: usize, c: f64) -> f64 {
        c * b as f64 + if self == Convention::Frodo { (b as f64).log2() } else { 0.0 }
    }

    fn eps_factor(self) -> f64 {
        if self == Convention::Frodo {
            4.0
        } else {
            1.0
        }
    }
}

/// LWE with n secret coordinates of standard deviation `sigma_s`, errors of
/// standard deviation `sigma_e`, modulus q and at most `m_max` samples.
#[derive(Clone, Copy, Debug)]
pub struct Lwe {
    pub n: usize,
    pub q: f64,
    pub sigma_s: f64,
    pub sigma_e: f64,
    pub m_max: usize,
}

pub fn delta(b: usize) -> f64 {
    let b = b as f64;
    ((std::f64::consts::PI * b).powf(1.0 / b) * b / (2.0 * std::f64::consts::PI * std::f64::consts::E)).powf(1.0 / (2.0 * b - 2.0))
}

/// Whether BKZ-b finds the planted vector with m samples (GSA, secret
/// rescaled to the error's standard deviation as Bai and Galbraith do).
pub fn primal_succeeds(lwe: &Lwe, b: usize, m: usize) -> bool {
    let d = (lwe.n + m) as f64;
    let log_vol = m as f64 * lwe.q.ln() + lwe.n as f64 * (lwe.sigma_e / lwe.sigma_s).ln();
    let rhs = (2.0 * b as f64 - d - 1.0) * delta(b).ln() + log_vol / d;
    lwe.sigma_e.ln() + 0.5 * (b as f64).ln() < rhs
}

/// The primal attack: the smallest block size b for which some sample
/// count succeeds, with the smallest such m.
#[derive(Clone, Copy, Debug)]
pub struct Primal {
    pub b: usize,
    pub m: usize,
}

pub fn primal(lwe: &Lwe) -> Option<Primal> {
    for b in 50..lwe.n + lwe.m_max + 2 {
        let lo = (b.saturating_sub(lwe.n)).max(1);
        if lo > lwe.m_max {
            break;
        }
        if let Some(m) = (lo..=lwe.m_max).find(|&m| primal_succeeds(lwe, b, m)) {
            return Some(Primal { b, m });
        }
    }
    None
}

/// The dual attack's cheapest (cost, b, m) for sieve exponent c:
/// cost = svp(b) + max(0, -2 log2(eps) - 0.2075 b), where a dual vector of
/// length l has advantage eps = F exp(-2 pi^2 (l sigma_e / q)^2), 1/eps^2
/// of them are needed and one sieve call is assumed to give 2^(0.2075 b),
/// all as short as the shortest (attacker-favourable).
pub fn dual(lwe: &Lwe, c: f64, conv: Convention) -> (f64, usize, usize) {
    let mut best = (f64::INFINITY, 0, 0);
    for b in 50..lwe.n + lwe.m_max + 2 {
        let base = conv.svp(b, c);
        if base > best.0 {
            break;
        }
        let lo = (b.saturating_sub(lwe.n)).max(1);
        if lo > lwe.m_max {
            break;
        }
        let ld = delta(b).ln();
        for m in lo..=lwe.m_max {
            let d = (lwe.n + m) as f64;
            let lvol = lwe.n as f64 * (lwe.q.ln() + (lwe.sigma_s / lwe.sigma_e).ln());
            let tau = (d * ld + lvol / d).exp() * lwe.sigma_e / lwe.q;
            let log2_eps = conv.eps_factor().log2() - 2.0 * std::f64::consts::PI.powi(2) * tau * tau / std::f64::consts::LN_2;
            let cost = base + (-2.0 * log2_eps - PLAUSIBLE * b as f64).max(0.0);
            if cost < best.0 {
                best = (cost, b, m);
            }
        }
    }
    best
}

/// Classical, quantum and plausible core-SVP of both attacks.
#[derive(Clone, Copy, Debug)]
pub struct Estimate {
    pub primal: Primal,
    pub primal_cost: [f64; 3],
    pub dual_cost: [f64; 3],
    /// The dual attack's block size at the quantum exponent (the one the
    /// published tables print).
    pub dual_b: usize,
}

impl Estimate {
    pub fn classical(&self) -> f64 {
        self.primal_cost[0].min(self.dual_cost[0])
    }

    pub fn quantum(&self) -> f64 {
        self.primal_cost[1].min(self.dual_cost[1])
    }
}

pub fn estimate(lwe: &Lwe, conv: Convention) -> Option<Estimate> {
    let p = primal(lwe)?;
    let exps = [CLASSICAL, QUANTUM, PLAUSIBLE];
    let duals = exps.map(|c| dual(lwe, c, conv));
    Some(Estimate { primal: p, primal_cost: exps.map(|c| conv.svp(p.b, c)), dual_cost: duals.map(|d| d.0), dual_b: duals[1].1 })
}

/// One published row: name, convention, LWE instance, primal and dual
/// (b or 0 if not printed, classical, quantum, plausible), and whether the
/// table floors (true) or rounds to one decimal.
pub struct Published {
    pub name: &'static str,
    pub conv: Convention,
    pub lwe: Lwe,
    pub primal: (usize, f64, f64, f64),
    pub dual: (usize, f64, f64, f64),
    pub floor: bool,
}

const fn lwe(n: usize, q: f64, sigma: f64, m_max: usize) -> Lwe {
    Lwe { n, q, sigma_s: sigma, sigma_e: sigma, m_max }
}

/// FrodoKEM round-3 Table 10 (m_max = n + 8, the setting that reproduces
/// every entry) and NewHope round-2 Table 12 / ADPS16 Table 1.
pub fn published() -> Vec<Published> {
    use Convention::*;
    vec![
        Published { name: "FrodoKEM-640", conv: Frodo, lwe: lwe(640, 32768.0, 2.8, 648), primal: (0, 150.8, 137.6, 109.6), dual: (0, 149.6, 136.5, 108.7), floor: false },
        Published { name: "FrodoKEM-976", conv: Frodo, lwe: lwe(976, 65536.0, 2.3, 984), primal: (0, 216.0, 196.7, 156.0), dual: (0, 214.5, 195.4, 154.9), floor: false },
        Published { name: "FrodoKEM-1344", conv: Frodo, lwe: lwe(1344, 65536.0, 1.4, 1352), primal: (0, 281.6, 256.3, 202.6), dual: (0, 279.8, 254.7, 201.4), floor: false },
        Published { name: "NewHope512", conv: NewHope, lwe: lwe(512, 12289.0, 2.0, 1023), primal: (384, 112.0, 101.0, 79.0), dual: (383, 112.0, 101.0, 79.0), floor: true },
        Published { name: "NewHope1024", conv: NewHope, lwe: lwe(1024, 12289.0, 2.0, 2047), primal: (886, 259.0, 235.0, 183.0), dual: (881, 257.0, 233.0, 182.0), floor: true },
        Published { name: "NewHope (USENIX)", conv: NewHope, lwe: lwe(1024, 12289.0, std::f64::consts::SQRT_2 * 2.0, 2047), primal: (967, 282.0, 256.0, 200.0), dual: (962, 281.0, 255.0, 199.0), floor: true },
        Published { name: "JarJar (USENIX)", conv: NewHope, lwe: lwe(512, 12289.0, 3.464_101_615_137_754_6, 1023), primal: (449, 131.0, 119.0, 93.0), dual: (448, 131.0, 118.0, 92.0), floor: true },
    ]
}

/// Whether the estimate reproduces a published row: floored rows exactly,
/// one-decimal rows to the printed digit, block sizes where printed.
pub fn reproduces(row: &Published, est: &Estimate) -> bool {
    let round = |x: f64| if row.floor { (x + 1e-9).floor() } else { (x * 10.0).round() / 10.0 };
    let close = |got: [f64; 3], want: (usize, f64, f64, f64)| got.iter().zip([want.1, want.2, want.3]).all(|(&g, w)| (round(g) - w).abs() < 1e-6);
    close(est.primal_cost, row.primal)
        && close(est.dual_cost, row.dual)
        && (row.primal.0 == 0 || row.primal.0 == est.primal.b)
        && (row.dual.0 == 0 || row.dual.0 == est.dual_b)
}

/// Turing-1026's two LWE instances: the key (B = A S + E, n samples per
/// column of S) and a ciphertext (B' = S' A + E' and C = S' B + E'', n +
/// nbar samples per row of S').
pub fn turing_1026() -> [(&'static str, Lwe); 2] {
    let p = turing::turing1026::PARAMS;
    let sigma = (f64::from(p.eta) / 2.0).sqrt();
    let q = f64::from(1u32 << p.log_q);
    [("key (m = n)", lwe(p.n, q, sigma, p.n)), ("ciphertext (m = n + 32)", lwe(p.n, q, sigma, p.n + p.nbar))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproduces_the_published_tables() {
        for row in published() {
            let est = estimate(&row.lwe, row.conv).expect("an attack");
            assert!(reproduces(&row, &est), "{}: {est:?}", row.name);
        }
    }

    // Perturbing q, sigma or n breaks the match, so the check has teeth.
    #[test]
    fn negative_controls_fail() {
        let rows = published();
        let base = &rows[0];
        for lwe in [
            Lwe { q: 65536.0, ..base.lwe },
            Lwe { sigma_s: 2.6, sigma_e: 2.6, ..base.lwe },
            Lwe { n: 632, ..base.lwe },
        ] {
            let est = estimate(&lwe, base.conv).expect("an attack");
            assert!(!reproduces(base, &est), "{lwe:?}");
        }
    }

    #[test]
    fn cost_rises_with_n_and_sigma_and_falls_with_q() {
        let c = |n, q, s| estimate(&lwe(n, q, s, n + 8), Convention::NewHope).expect("an attack").primal_cost[0];
        assert!(c(700, 32768.0, 2.8) < c(800, 32768.0, 2.8));
        assert!(c(800, 32768.0, 2.0) < c(800, 32768.0, 2.8));
        assert!(c(800, 65536.0, 2.8) < c(800, 32768.0, 2.8));
    }

    #[test]
    fn delta_matches_chen() {
        // Kyber spec round 3, section 5.1: BKZ-406 gives delta ~ 1.003941.
        assert!((delta(406) - 1.003_941).abs() < 5e-7);
    }
}
