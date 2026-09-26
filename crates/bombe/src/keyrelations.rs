//! Linear relations in the key schedule. If some XOR of master-key and
//! round-key bits were the same for every key, an attacker who learns some
//! round-key bits (by a side channel, a fault or a partial attack) would get
//! others for free, and related-key and algebraic attacks would gain a
//! foothold. AES-128's schedule is mostly linear: most words satisfy
//! w[i] = w[i-4] ^ w[i-1] for every key (FIPS-197 section 5.2), which makes it
//! the control.
//!
//! Method: the bits of (key, every round key, constant 1) are the columns and
//! each random key is a row. Relations that hold for every key are exactly
//! the linear dependencies between columns, counted as columns - rank once
//! there are comfortably more rows than columns (with 128 extra rows, a
//! dependency is missed with probability below 2^-100).

use crate::rng::Rng;
use turing::keyschedule::{expand, expand_whitened};
use turing::structure::ROUND_KEYS;

pub struct Relations {
    pub columns: usize,
    pub samples: usize,
    pub rank: usize,
}

impl Relations {
    /// Linear (affine) relations that hold for every key.
    pub fn count(&self) -> usize {
        self.columns - self.rank
    }
}

/// Rank over GF(2) of rows given as bit vectors.
fn rank(mut rows: Vec<Vec<u64>>, columns: usize) -> usize {
    let mut rank = 0;
    for col in 0..columns {
        let (word, bit) = (col / 64, 1u64 << (col % 64));
        let Some(pivot) = (rank..rows.len()).find(|&r| rows[r][word] & bit != 0) else { continue };
        rows.swap(rank, pivot);
        let pivot_row = rows[rank].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r != rank && row[word] & bit != 0 {
                for (a, b) in row.iter_mut().zip(&pivot_row) {
                    *a ^= b;
                }
            }
        }
        rank += 1;
    }
    rank
}

/// Draws `samples` rows of `bytes` bytes each (plus the constant column).
fn measure(samples: usize, bytes: usize, label: &str, row: impl Fn(&mut Rng) -> Vec<u8>) -> Relations {
    let columns = 8 * bytes + 1;
    let mut rng = Rng::new(label);
    let rows: Vec<Vec<u64>> = (0..samples)
        .map(|_| {
            let data = row(&mut rng);
            assert_eq!(data.len(), bytes);
            let mut bits = vec![0u64; columns.div_ceil(64)];
            for (i, &byte) in data.iter().enumerate() {
                for b in 0..8 {
                    if byte >> b & 1 == 1 {
                        let col = 8 * i + b;
                        bits[col / 64] |= 1 << (col % 64);
                    }
                }
            }
            bits[(columns - 1) / 64] |= 1 << ((columns - 1) % 64);
            bits
        })
        .collect();
    Relations { columns, samples, rank: rank(rows, columns) }
}

/// Turing: the 256-bit key and all 17 round keys.
pub fn turing(extra_samples: usize, label: &str) -> Relations {
    let bytes = 32 + 16 * ROUND_KEYS;
    measure(8 * bytes + 1 + extra_samples, bytes, label, |rng| {
        let key: [u8; 32] = rng.bytes();
        let rk = expand::<ROUND_KEYS>(&key);
        key.iter().chain(rk.all().iter().flatten()).copied().collect()
    })
}

/// The Feistel stage alone: K' = (L, R) and all 17 round keys.
pub fn turing_feistel(extra_samples: usize, label: &str) -> Relations {
    let bytes = 32 + 16 * ROUND_KEYS;
    measure(8 * bytes + 1 + extra_samples, bytes, label, |rng| {
        let (l, r): ([u8; 16], [u8; 16]) = (rng.bytes(), rng.bytes());
        let rk = expand_whitened::<ROUND_KEYS>(&l, &r);
        l.iter().chain(&r).chain(rk.all().iter().flatten()).copied().collect()
    })
}

/// AES-128 key expansion (FIPS-197 section 5.2): 11 round keys.
pub fn aes128_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let sbox = crate::gf256::aes_sbox();
    let rcon = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [[0u8; 4]; 44];
    for (i, word) in w.iter_mut().take(4).enumerate() {
        word.copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [sbox[t[1] as usize] ^ rcon[i / 4 - 1], sbox[t[2] as usize], sbox[t[3] as usize], sbox[t[0] as usize]];
        }
        w[i] = std::array::from_fn(|b| w[i - 4][b] ^ t[b]);
    }
    std::array::from_fn(|r| std::array::from_fn(|k| w[4 * r + k / 4][k % 4]))
}

/// AES-128: the key and its 11 round keys (the control).
pub fn aes128(extra_samples: usize, label: &str) -> Relations {
    let bytes = 16 + 16 * 11;
    measure(8 * bytes + 1 + extra_samples, bytes, label, |rng| {
        let key: [u8; 16] = rng.bytes();
        key.iter().chain(aes128_expand(&key).iter().flatten()).copied().collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 Appendix A.1: key 2b7e1516..., last round key d014f9a8...
    #[test]
    fn aes_key_expansion_matches_fips_197() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let rk = aes128_expand(&key);
        assert_eq!(rk[0], key);
        assert_eq!(rk[1][..4], [0xa0, 0xfa, 0xfe, 0x17]);
        assert_eq!(rk[10], [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6]);
    }

    #[test]
    fn rank_counts_dependencies() {
        // Columns: a, b, a ^ b, constant: one dependency.
        let rows: Vec<Vec<u64>> = (0..16u64).map(|x| vec![(x & 1) | (x >> 1 & 1) << 1 | ((x ^ x >> 1) & 1) << 2 | 1 << 3]).collect();
        assert_eq!(rank(rows, 4), 3);
    }
}
