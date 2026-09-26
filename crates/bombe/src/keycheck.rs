//! Key checks on the real key schedule: suspicious keys, repeated or zero
//! round keys, and equivalent keys (two keys that encrypt identically).

use std::collections::HashSet;
use turing::structure::ROUND_KEYS;
use turing::Turing;

pub struct KeyScan {
    pub keys: usize,
    pub round_keys: usize,
    pub zero_round_keys: usize,
    /// Round keys equal to another round key, of the same or another key.
    pub repeated_round_keys: usize,
    /// Keys whose encryption of the zero block equals another key's.
    pub ciphertext_collisions: usize,
}

impl KeyScan {
    pub fn clean(&self) -> bool {
        self.zero_round_keys == 0 && self.repeated_round_keys == 0 && self.ciphertext_collisions == 0
    }
}

/// Keys a careless user or a weak-key search would try first: all zero, all
/// ones, repeating patterns, counting bytes, and every key with exactly one
/// bit set.
pub fn suspicious_keys() -> Vec<[u8; 32]> {
    let mut keys = vec![
        [0x00; 32],
        [0xff; 32],
        [0x55; 32],
        [0xaa; 32],
        [0x01; 32],
        [0x80; 32],
        std::array::from_fn(|i| i as u8),
        std::array::from_fn(|i| 31 - i as u8),
        std::array::from_fn(|i| if i < 16 { 0x00 } else { 0xff }),
        std::array::from_fn(|i| if i % 2 == 0 { 0x00 } else { 0xff }),
    ];
    for bit in 0..256 {
        let mut k = [0u8; 32];
        k[bit / 8] = 1 << (bit % 8);
        keys.push(k);
    }
    keys
}

pub fn scan(keys: &[[u8; 32]]) -> KeyScan {
    let mut seen_round_keys = HashSet::new();
    let mut seen_ciphertexts = HashSet::new();
    let mut result = KeyScan {
        keys: keys.len(),
        round_keys: keys.len() * ROUND_KEYS,
        zero_round_keys: 0,
        repeated_round_keys: 0,
        ciphertext_collisions: 0,
    };
    for k in keys {
        let t = Turing::new(k);
        for i in 0..ROUND_KEYS {
            let rk = *t.round_key(i);
            result.zero_round_keys += usize::from(rk == [0u8; 16]);
            result.repeated_round_keys += usize::from(!seen_round_keys.insert(rk));
        }
        let mut c = [0u8; 16];
        t.encrypt_block(&mut c);
        result.ciphertext_collisions += usize::from(!seen_ciphertexts.insert(c));
    }
    result
}

/// 2^16 keys that differ only in their first two bytes all encrypt the zero
/// block differently: no equivalent keys among close neighbours.
pub fn neighbouring_keys() -> KeyScan {
    let keys: Vec<[u8; 32]> = (0..=u16::MAX)
        .map(|i| {
            let mut k = [0x3c; 32];
            k[..2].copy_from_slice(&i.to_le_bytes());
            k
        })
        .collect();
    scan(&keys)
}
