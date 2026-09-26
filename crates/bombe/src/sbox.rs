//! An 8-bit S-box: a table of 256 output bytes.

use std::fmt;

pub const N: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sbox {
    table: [u8; N],
}

#[derive(Debug)]
pub enum ParseError {
    Count(usize),
    Byte(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::Count(n) => write!(f, "expected 256 bytes, found {n}"),
            ParseError::Byte(s) => write!(f, "not a hex byte: {s:?}"),
        }
    }
}

impl Sbox {
    pub fn new(table: [u8; N]) -> Self {
        Sbox { table }
    }

    pub fn aes() -> Self {
        Sbox::new(crate::gf256::aes_sbox())
    }

    /// S(x) = x. Negative control: fails every criterion.
    pub fn identity() -> Self {
        let mut table = [0u8; N];
        for (x, out) in table.iter_mut().enumerate() {
            *out = x as u8;
        }
        Sbox::new(table)
    }

    /// A seeded random permutation (xorshift64* + Fisher-Yates).
    /// For testing the tools only; Turing's S-box is derived with SHAKE256.
    pub fn random(seed: u64) -> Self {
        let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
        if state == 0 {
            state = 1;
        }
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut table = Sbox::identity().table;
        for i in (1..N).rev() {
            let j = (next() % (i as u64 + 1)) as usize;
            table.swap(i, j);
        }
        Sbox::new(table)
    }

    /// Parses 256 hex bytes separated by whitespace or commas. `0x` prefixes
    /// are optional and `#` starts a comment.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut bytes = Vec::with_capacity(N);
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            for token in line.split(|c: char| c.is_whitespace() || c == ',') {
                if token.is_empty() {
                    continue;
                }
                let digits = token.trim_start_matches("0x").trim_start_matches("0X");
                let byte = u8::from_str_radix(digits, 16).map_err(|_| ParseError::Byte(token.to_string()))?;
                bytes.push(byte);
            }
        }
        let table: [u8; N] = bytes.try_into().map_err(|v: Vec<u8>| ParseError::Count(v.len()))?;
        Ok(Sbox::new(table))
    }

    pub fn get(&self, x: u8) -> u8 {
        self.table[x as usize]
    }

    pub fn table(&self) -> &[u8; N] {
        &self.table
    }

    pub fn is_bijective(&self) -> bool {
        let mut seen = [false; N];
        for &y in &self.table {
            if std::mem::replace(&mut seen[y as usize], true) {
                return false;
            }
        }
        true
    }

    pub fn inverse(&self) -> Option<Sbox> {
        if !self.is_bijective() {
            return None;
        }
        let mut table = [0u8; N];
        for (x, &y) in self.table.iter().enumerate() {
            table[y as usize] = x as u8;
        }
        Some(Sbox::new(table))
    }
}
