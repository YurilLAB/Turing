//! Reproducible randomness for experiments: a cSHAKE256 stream named by a
//! label, so every experiment can be rerun with exactly the same inputs.
//! (cSHAKE output is cryptographic-quality, which keeps the sampling itself
//! from introducing structure into the statistics.)

use sha3::digest::XofReader;
use sha3::CShake256Reader;

pub struct Rng {
    reader: CShake256Reader,
}

impl Rng {
    pub fn new(label: &str) -> Rng {
        Rng { reader: turing::xof::cshake256("Bombe experiment randomness", label.as_bytes()) }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        self.reader.read(buf);
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }

    /// Uniform in 0..n (rejection sampling, no modulo bias).
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        let zone = u64::MAX - u64::MAX % n;
        loop {
            let x = self.u64();
            if x < zone {
                return x % n;
            }
        }
    }
}
