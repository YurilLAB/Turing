//! Differential-linear cryptanalysis (Langford and Hellman, CRYPTO 1994;
//! Biham, Dunkelman and Keller, ASIACRYPT 2002): a short differential
//! followed by a short linear approximation. Encrypt pairs with a fixed input
//! difference and test whether some mask of the output difference,
//! lambda . (C ^ C'), is biased. It reached further than either technique
//! alone on DES and many later designs.
//!
//! Two rounds of Turing have an exact prediction. Round 1's S-box turns the
//! input difference alpha into gamma (probability DDT[alpha][gamma] / 256),
//! MixState sends it to m_j gamma in byte j, and the last S-box layer maps
//! input difference d to an output difference whose mask-lambda parity has
//! correlation AC_lambda(d) / 256, the autocorrelation of the component
//! lambda . S. The input to that S-box is uniform and independent of gamma
//! (it mixes all 16 bytes), so
//!   correlation(j, lambda) = sum over gamma of DDT[alpha][gamma] / 256
//!                            * AC_lambda(m_j gamma) / 256.

use crate::rng::Rng;
use turing::{sbox, Block, Turing};

pub struct DiffLinear {
    pub rounds: usize,
    pub pairs: usize,
    /// Largest |correlation| over the 16 x 255 single-byte output masks.
    pub max_correlation: f64,
    pub byte: usize,
    pub mask: u8,
}

impl DiffLinear {
    /// The largest of 4080 correlations of pure noise is about
    /// sqrt(2 ln 8160 / pairs), 4.25 / sqrt(pairs); 6 / sqrt(pairs) is
    /// comfortably above it.
    pub fn threshold(&self) -> f64 {
        6.0 / (self.pairs as f64).sqrt()
    }

    pub fn distinguishes(&self) -> bool {
        self.max_correlation > self.threshold()
    }
}

/// In-place Walsh-Hadamard transform of 256 counts.
fn fwht(v: &mut [i64; 256]) {
    let mut h = 1;
    while h < 256 {
        for i in (0..256).step_by(2 * h) {
            for j in i..i + h {
                let (x, y) = (v[j], v[j + h]);
                v[j] = x + y;
                v[j + h] = x - y;
            }
        }
        h *= 2;
    }
}

/// Measures the best single-byte differential-linear correlation through
/// `rounds` rounds, with input difference `alpha` in byte 0.
pub fn measure(rounds: usize, alpha: u8, pairs: usize, label: &str) -> DiffLinear {
    let mut rng = Rng::new(label);
    let t = Turing::new(&rng.bytes());
    let mut hist = vec![[0i64; 256]; 16];
    for _ in 0..pairs {
        let p: Block = rng.bytes();
        let mut p2 = p;
        p2[0] ^= alpha;
        let (mut c, mut c2) = (p, p2);
        t.encrypt_rounds(&mut c, rounds);
        t.encrypt_rounds(&mut c2, rounds);
        for (j, h) in hist.iter_mut().enumerate() {
            h[(c[j] ^ c2[j]) as usize] += 1;
        }
    }
    let mut best = DiffLinear { rounds, pairs, max_correlation: 0.0, byte: 0, mask: 0 };
    for (j, h) in hist.iter_mut().enumerate() {
        fwht(h);
        for (mask, &count) in h.iter().enumerate().skip(1) {
            let corr = (count as f64 / pairs as f64).abs();
            if corr > best.max_correlation {
                best.max_correlation = corr;
                best.byte = j;
                best.mask = mask as u8;
            }
        }
    }
    best
}

/// The exact 2-round correlation for every (byte, mask), as above.
pub fn predict_two_rounds(alpha: u8) -> Vec<[f64; 256]> {
    assert_eq!(turing::structure::layer(1), Some(turing::structure::Layer::MixState));
    let s = &sbox::TABLE;
    let ddt_row: Vec<u32> = (0..256usize).map(|g| (0..256usize).filter(|&x| (s[x] ^ s[x ^ alpha as usize]) as usize == g).count() as u32).collect();
    // ac[d][lambda] = sum over y of (-1)^(lambda . (S(y) ^ S(y ^ d))).
    let mut ac = vec![[0i64; 256]; 256];
    for (d, row) in ac.iter_mut().enumerate() {
        for y in 0..256 {
            row[(s[y] ^ s[y ^ d]) as usize] += 1;
        }
        fwht(row);
    }
    (0..16)
        .map(|j| {
            let m = turing::linear::MIX_STATE[j][0];
            let mut out = [0f64; 256];
            for (lambda, cell) in out.iter_mut().enumerate() {
                *cell = (1..256usize)
                    .filter(|&g| ddt_row[g] > 0)
                    .map(|g| ddt_row[g] as f64 / 256.0 * ac[turing::gf::mul(m, g as u8) as usize][lambda] as f64 / 256.0)
                    .sum();
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walsh_transform_of_a_point() {
        let mut v = [0i64; 256];
        v[3] = 1;
        fwht(&mut v);
        assert_eq!((v[0], v[1], v[2], v[3]), (1, -1, -1, 1));
    }

    #[test]
    fn one_round_leaves_other_bytes_unchanged() {
        let d = measure(1, 0x01, 1 << 12, "test dl 1");
        assert_eq!(d.max_correlation, 1.0);
        assert_ne!(d.byte, 0);
    }
}
