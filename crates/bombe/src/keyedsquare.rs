//! The square attack pushed to 6 and 7 rounds by guessing all of round key 0
//! (docs/14).
//!
//! Round 1 ends with MixState, so no set of plaintexts keeps a byte
//! structure through it. Guess round key 0, though, and any set can be
//! placed at the input of round 2's S-box layer: the plaintext for a target
//! z is S^-1(MixState^-1(z)) ⊕ RK0, and round 2 then starts from z ⊕ RK1.
//! Round 2 mixes with ShiftRows + MixColumns, so a diagonal taking all 2^32
//! values there fills one column after a round, and the division property
//! keeps the set balanced up to the input of S-box layer 6: four rounds,
//! where 2^32 plaintexts chosen at round 1 stay balanced for three.
//!
//! - 6 rounds: guess RK0, then each byte of RK6 on its own, as the square
//!   attack's last step does.
//! - 7 rounds: guess RK0, then for a byte of the S-box layer 6 input one
//!   column of RK7 and one byte of the equivalent round key 6,
//!   ShiftRows^-1(MixColumns^-1(RK6)), with the partial sums of Ferguson et
//!   al. (FSE 2000, section 2.3).
//!
//! Each RK0 guess asks for its own plaintexts, so over 2^128 guesses both
//! attacks need the full codebook. They cost far less than 2^256 trial
//! keys and far more than anyone can run. What can be run is the test every
//! guess faces: with the right RK0 the set must be balanced and the right
//! round-key bytes must survive; with a wrong RK0 the balance must go.

use crate::fast::{self, Fast};
use crate::gf256;
use turing::structure::Layer;
use turing::{Block, Turing};

/// The bytes of the diagonal that round 2's ShiftRows moves into column 0.
pub const DIAGONAL: [usize; 4] = [0, 5, 10, 15];

/// The plaintext that puts z ⊕ RK1 at the input of round 2's S-box layer
/// when round key 0 is `rk0`.
pub fn plaintext_for(z: u128, rk0: u128) -> u128 {
    fast::inv_sub(fast::invert(Layer::MixState, z)) ^ rk0
}

/// A byte of the S-box layer 6 input, seen from a 7-round ciphertext.
/// Round 6 is S-box layer, ShiftRows + MixColumns, RK6; round 7 is S-box
/// layer, RK7. So with X7 = S^-1(C ⊕ RK7), byte j of the layer 6 input is
/// S^-1(Σ_i M^-1[row][i] · X7[4·column + i] ⊕ e_j), where e =
/// ShiftRows^-1(MixColumns^-1(RK6)) is the equivalent round key: four
/// bytes of RK7 and one byte of e.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub byte: usize,
    pub column: usize,
    pub row: usize,
}

impl Target {
    pub fn new(byte: usize) -> Target {
        // ShiftRows^-1 puts byte 4((c - r) mod 4) + r of its input at 4c + r.
        let (c, r) = (byte / 4, byte % 4);
        let p = 4 * ((c + 4 - r) % 4) + r;
        Target { byte, column: p / 4, row: p % 4 }
    }

    /// The four bytes of the S-box layer 6 input that depend on column
    /// `column` of RK7: ShiftRows^-1 spreads that column over a diagonal,
    /// one byte per row.
    pub fn sharing_column(column: usize) -> [Target; 4] {
        std::array::from_fn(|r| Target::new(4 * ((column + r) % 4) + r))
    }

    /// S_i(v) = M^-1[row][i] · S^-1(v) for i = 0..4, the bijections of
    /// Ferguson et al.'s equation (1).
    pub fn tables(&self) -> [[u8; 256]; 4] {
        let inv = fast::inv_sbox();
        let m = turing::linear::MIX_COLUMNS_INV[self.row];
        std::array::from_fn(|i| std::array::from_fn(|v| gf256::mul(m[i], inv[v])))
    }

    /// The target byte, computed directly from `tables` (this target's
    /// `tables()`): the tests' reference.
    pub fn value(&self, tables: &[[u8; 256]; 4], c7: u128, rk7: u128, e: u8) -> u8 {
        let (c, k) = (fast::to_block(c7), fast::to_block(rk7));
        let x = (0..4).fold(e, |acc, i| acc ^ tables[i][(c[4 * self.column + i] ^ k[4 * self.column + i]) as usize]);
        fast::inv_sbox()[x as usize]
    }
}

/// One structure: the diagonal of round 2's S-box input takes all 2^32
/// values, the other 12 bytes are fixed.
pub struct Structure {
    pub texts: u64,
    /// XOR over the structure of the input to S-box layers 2 to 7
    /// (`sums[l - 2]` for layer l). The distinguisher: zero in every byte
    /// up to layer 6 when RK0 is right.
    pub sums: [Block; 6],
    /// For each byte of the 6-round ciphertexts, the values taken an odd
    /// number of times: all the 6-round attack's last step needs.
    pub parity6: [[u64; 4]; 16],
    /// For each byte sharing column `column` of RK7 (`Target::sharing_column`),
    /// with the column's first two key bytes known: the parity of each
    /// (x1, c2, c3), x1 = S_0(c0 ⊕ k0) ⊕ S_1(c1 ⊕ k1), over the 7-round
    /// ciphertexts (2^24 bits each).
    pub partial: Vec<Vec<u64>>,
    /// Blocks encrypted again by the real cipher (6 and 7 rounds) and
    /// compared with the table-driven rounds.
    pub checked: usize,
    pub mismatches: usize,
}

/// Encrypts one structure through 6 and 7 rounds on every thread. `rk0` is
/// the guess used to build the plaintexts, `z` fixes the 12 bytes outside
/// the diagonal, and `known` gives the first two bytes of RK7's column
/// `column` for the partial sums. `bits` (at most 32) limits how many of the
/// diagonal's bits vary, for the tests.
pub fn structure(t: &Turing, rk0: &Block, z: &Block, column: usize, known: [u8; 2], bits: u32) -> Structure {
    assert!(bits <= 32);
    let f = Fast::new(t);
    let rk0 = fast::to_u128(rk0);
    let mut base = *z;
    for &b in &DIAGONAL {
        base[b] = 0;
    }
    let base = fast::to_u128(&base);
    let targets = Target::sharing_column(column);
    let tables: Vec<[[u8; 256]; 4]> = targets.iter().map(Target::tables).collect();
    let total: u64 = 1 << bits;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    // About 4096 blocks rechecked by the real cipher per structure.
    let stride = (total >> 12).max(1);
    let mut out = Structure {
        texts: total,
        sums: [[0; 16]; 6],
        parity6: [[0; 4]; 16],
        partial: vec![vec![0; 1 << 18]; 4],
        checked: 0,
        mismatches: 0,
    };
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|w| {
                let (f, tables) = (&f, &tables);
                scope.spawn(move || {
                    let mut sums = [0u128; 6];
                    let mut parity6 = [[0u64; 4]; 16];
                    let mut partial = vec![vec![0u64; 1 << 18]; 4];
                    let (mut checked, mut mismatches) = (0, 0);
                    let col = 4 * column;
                    for index in total * w / threads..total * (w + 1) / threads {
                        let d = index.to_le_bytes();
                        let z = base
                            | (d[0] as u128) << (8 * DIAGONAL[0])
                            | (d[1] as u128) << (8 * DIAGONAL[1])
                            | (d[2] as u128) << (8 * DIAGONAL[2])
                            | (d[3] as u128) << (8 * DIAGONAL[3]);
                        let p = plaintext_for(z, rk0);
                        let mut x = f.before_sbox(p, 2);
                        sums[0] ^= x;
                        for layer in 3..=6 {
                            x = f.forward(x, layer - 1, layer);
                            sums[layer - 2] ^= x;
                        }
                        let x6 = x;
                        let c6 = f.finish(x6, 6);
                        let x7 = fast::sub_then(Layer::ShiftMixColumns, x6) ^ f.key(6);
                        let c7 = f.finish(x7, 7);
                        sums[5] ^= x7;
                        for (j, &c) in c6.to_le_bytes().iter().enumerate() {
                            parity6[j][(c >> 6) as usize] ^= 1 << (c & 63);
                        }
                        let c = c7.to_le_bytes();
                        for (bits, s) in partial.iter_mut().zip(tables) {
                            let x1 = s[0][(c[col] ^ known[0]) as usize] ^ s[1][(c[col + 1] ^ known[1]) as usize];
                            let at = (x1 as usize) << 16 | (c[col + 2] as usize) << 8 | c[col + 3] as usize;
                            bits[at >> 6] ^= 1 << (at & 63);
                        }
                        if index % stride == 0 {
                            let block = fast::to_block(p);
                            let (mut r6, mut r7) = (block, block);
                            t.encrypt_rounds(&mut r6, 6);
                            t.encrypt_rounds(&mut r7, 7);
                            checked += 1;
                            mismatches += usize::from(r6 != fast::to_block(c6) || r7 != fast::to_block(c7));
                        }
                    }
                    (sums, parity6, partial, checked, mismatches)
                })
            })
            .collect();
        let mut sums = [0u128; 6];
        for worker in workers {
            let (s, p6, part, checked, mismatches) = worker.join().expect("worker");
            for (a, b) in sums.iter_mut().zip(s) {
                *a ^= b;
            }
            for (a, b) in out.parity6.iter_mut().zip(p6) {
                for (x, y) in a.iter_mut().zip(b) {
                    *x ^= y;
                }
            }
            for (a, b) in out.partial.iter_mut().zip(part) {
                for (x, y) in a.iter_mut().zip(b) {
                    *x ^= y;
                }
            }
            out.checked += checked;
            out.mismatches += mismatches;
        }
        out.sums = sums.map(fast::to_block);
    });
    out
}

/// The 6-round attack's last step: for each byte of RK6, the guesses k for
/// which S^-1(c ⊕ k) sums to zero over every structure given.
pub fn rk6_candidates(structures: &[&Structure]) -> [Vec<u8>; 16] {
    let inv = fast::inv_sbox();
    std::array::from_fn(|j| {
        (0..=255u8)
            .filter(|&k| {
                structures.iter().all(|s| {
                    (0..=255u8).filter(|&c| s.parity6[j][(c >> 6) as usize] >> (c & 63) & 1 == 1).fold(0u8, |acc, c| acc ^ inv[(c ^ k) as usize]) == 0
                })
            })
            .collect()
    })
}

/// Partial sums from (x1, c2, c3) parities: every (k2, k3, e) for which
/// S^-1(x1 ⊕ S_2(c2 ⊕ k2) ⊕ S_3(c3 ⊕ k3) ⊕ e) sums to zero. The work is
/// 2^8 · 2^24 + 2^16 · 2^16 + 2^24 · 2^8 steps, where trying every guess on
/// every text would take 2^24 · 2^32 (Ferguson et al., FSE 2000).
pub fn partial_sums(bits: &[u64], target: Target) -> Vec<[u8; 3]> {
    let s = target.tables();
    let inv = fast::inv_sbox();
    let ones: Vec<u32> = bits
        .iter()
        .enumerate()
        .flat_map(|(w, &word)| (0..64).filter(move |b| word >> b & 1 == 1).map(move |b| (64 * w + b) as u32))
        .collect();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut out = Vec::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|w| {
                let (ones, s) = (&ones, &s);
                scope.spawn(move || {
                    let mut found = Vec::new();
                    for k2 in (0..256usize).filter(|k| k % threads == w) {
                        let mut two = vec![0u64; 1 << 10];
                        for &at in ones {
                            let (x1, c2, c3) = (at >> 16, (at >> 8) & 255, at & 255);
                            let x2 = x1 as u8 ^ s[2][c2 as usize ^ k2];
                            let i = (x2 as usize) << 8 | c3 as usize;
                            two[i >> 6] ^= 1 << (i & 63);
                        }
                        let pairs: Vec<(u8, u8)> = (0..1usize << 16).filter(|&i| two[i >> 6] >> (i & 63) & 1 == 1).map(|i| ((i >> 8) as u8, i as u8)).collect();
                        for k3 in 0..256usize {
                            let mut three = [0u64; 4];
                            for &(x2, c3) in &pairs {
                                let x3 = x2 ^ s[3][c3 as usize ^ k3];
                                three[(x3 >> 6) as usize] ^= 1 << (x3 & 63);
                            }
                            let values: Vec<u8> = (0..=255u8).filter(|&x| three[(x >> 6) as usize] >> (x & 63) & 1 == 1).collect();
                            for e in 0..=255u8 {
                                if values.iter().fold(0u8, |acc, &x| acc ^ inv[(x ^ e) as usize]) == 0 {
                                    found.push([k2 as u8, k3 as u8, e]);
                                }
                            }
                        }
                    }
                    found
                })
            })
            .collect();
        for worker in workers {
            out.extend(worker.join().expect("worker"));
        }
    });
    out.sort_unstable();
    out
}

/// What the 7-round step recovers from structures: the (k2, k3) of RK7's
/// column for which every one of the four bytes sharing it keeps some e,
/// with those e. Each candidate list comes from `partial_sums` on one
/// structure; a guess must survive them all.
pub fn column_candidates(per_structure: &[[Vec<[u8; 3]>; 4]]) -> Vec<([u8; 2], [Vec<u8>; 4])> {
    // One bit per (k2, k3, e) for each target: the guesses kept by every
    // structure.
    let kept: Vec<Vec<u64>> = (0..4)
        .map(|t| {
            let mut all = vec![u64::MAX; 1 << 18];
            for lists in per_structure {
                let mut bits = vec![0u64; 1 << 18];
                for g in &lists[t] {
                    let i = (g[0] as usize) << 16 | (g[1] as usize) << 8 | g[2] as usize;
                    bits[i >> 6] |= 1 << (i & 63);
                }
                for (a, b) in all.iter_mut().zip(bits) {
                    *a &= b;
                }
            }
            all
        })
        .collect();
    let mut out = Vec::new();
    for k in 0..1usize << 16 {
        let es: [Vec<u8>; 4] = std::array::from_fn(|t| (0..=255u8).filter(|&e| kept[t][k << 2 | (e as usize >> 6)] >> (e & 63) & 1 == 1).collect());
        if es.iter().all(|e| !e.is_empty()) {
            out.push(([(k >> 8) as u8, k as u8], es));
        }
    }
    out
}

/// The equivalent round key e = ShiftRows^-1(MixColumns^-1(RK6)).
pub fn equivalent_rk6(t: &Turing) -> Block {
    turing::linear::invert_layer(Layer::ShiftMixColumns, t.round_key(6))
}

/// The last S-box layer whose input the structure keeps balanced (every
/// byte of the XOR zero), counting from layer 2; 1 if not even layer 2.
pub fn balanced_to(s: &Structure) -> usize {
    1 + s.sums.iter().take_while(|sum| sum.iter().all(|&b| b == 0)).count()
}

/// The last steps of the 6- and 7-round attacks, run as the right guess of
/// round key 0 runs them.
pub struct Attack {
    pub structures: Vec<Structure>,
    /// Guesses left for each byte of RK6.
    pub rk6: [Vec<u8>; 16],
    /// (k2, k3) of RK7's column 0 left, with the e bytes of the four
    /// targets sharing it; k0 and k1 are given.
    pub column: Vec<([u8; 2], [Vec<u8>; 4])>,
    /// Whether each byte of RK6 came out unique and right.
    pub rk6_right: bool,
    /// Whether one (k2, k3) and one e per target are left, all right.
    pub column_right: bool,
}

/// Encrypts structures (the diagonal at round 2, 2^32 texts each, built
/// with round key 0 = `rk0`) until round key 6 and the column of round key
/// 7 come out unique, using at least 2 and at most `max_structures`.
pub fn attack(t: &Turing, rk0: &Block, max_structures: usize, label: &str) -> Attack {
    let mut rng = crate::rng::Rng::new(label);
    let rk7 = *t.round_key(7);
    let e = equivalent_rk6(t);
    let targets = Target::sharing_column(0);
    let mut structures = Vec::new();
    let mut lists = Vec::new();
    loop {
        let s = structure(t, rk0, &rng.bytes(), 0, [rk7[0], rk7[1]], 32);
        lists.push(std::array::from_fn(|k| partial_sums(&s.partial[k], targets[k])));
        structures.push(s);
        let refs: Vec<&Structure> = structures.iter().collect();
        let rk6 = rk6_candidates(&refs);
        let column = column_candidates(&lists);
        let rk6_right = (0..16).all(|j| rk6[j] == [t.round_key(6)[j]]);
        let column_right = column.len() == 1 && column[0].0 == [rk7[2], rk7[3]] && (0..4).all(|k| column[0].1[k] == [e[targets[k].byte]]);
        let unique = rk6.iter().all(|c| c.len() <= 1) && column.len() <= 1 && column.iter().all(|(_, es)| es.iter().all(|e| e.len() == 1));
        if (structures.len() >= 2 && unique) || structures.len() >= max_structures {
            return Attack { structures, rk6, column, rk6_right, column_right };
        }
    }
}

/// Costs of the full attacks, in log2 (docs/14).
pub struct Costs {
    /// 6 rounds: 2^128 RK0 guesses, each one structure of 2^32 codebook
    /// lookups; almost every wrong guess fails its first structure.
    pub six_lookups: f64,
    /// 7 rounds: 2^128 RK0 guesses, each about six structures of partial
    /// sums at 2^50 S-box lookups (5 key bytes, Ferguson et al.).
    pub seven_sbox_lookups: f64,
    /// The same in 7-round encryptions (112 S-box lookups each).
    pub seven_encryptions: f64,
}

pub fn costs() -> Costs {
    let seven = 128.0 + (6.0f64).log2() + 50.0;
    Costs { six_lookups: 128.0 + 32.0, seven_sbox_lookups: seven, seven_encryptions: seven - (112.0f64).log2() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn plaintexts_land_on_the_chosen_round_2_input() {
        let mut rng = Rng::new("keyed square construction");
        for _ in 0..20 {
            let t = Turing::new(&rng.bytes());
            let z = fast::to_u128(&rng.bytes());
            let p = fast::to_block(plaintext_for(z, fast::to_u128(t.round_key(0))));
            // One round without its linear layer, then MixState and RK1 by hand.
            let mut after = p;
            t.encrypt_rounds(&mut after, 1);
            let rk1 = t.round_key(1);
            let y: Block = std::array::from_fn(|i| after[i] ^ rk1[i]);
            let x2 = turing::linear::mix_state(&y);
            let x2: Block = std::array::from_fn(|i| x2[i] ^ rk1[i]);
            let want: Block = std::array::from_fn(|i| fast::to_block(z)[i] ^ rk1[i]);
            assert_eq!(x2, want);
        }
    }

    #[test]
    fn targets_read_the_layer_6_input() {
        let mut rng = Rng::new("keyed square targets");
        for _ in 0..20 {
            let t = Turing::new(&rng.bytes());
            let f = Fast::new(&t);
            let e = equivalent_rk6(&t);
            let p = fast::to_u128(&rng.bytes());
            let x6 = fast::to_block(f.before_sbox(p, 6));
            let c7 = f.encrypt(p, 7);
            for byte in 0..16 {
                let target = Target::new(byte);
                assert_eq!(target.value(&target.tables(), c7, f.key(7), e[byte]), x6[byte], "byte {byte}");
            }
        }
        for column in 0..4 {
            let targets = Target::sharing_column(column);
            assert!(targets.iter().all(|t| t.column == column));
            let rows: Vec<usize> = targets.iter().map(|t| t.row).collect();
            assert_eq!(rows, [0, 1, 2, 3]);
        }
        assert_eq!(Target::sharing_column(0).map(|t| t.byte), DIAGONAL);
    }

    // Small structures through the whole pipeline: one byte (or two bytes
    // of the diagonal) at round 2 stays balanced to S-box layer 4, as the
    // division property says, when round key 0 is right, and not when it is
    // one byte off; the table-driven rounds match the real cipher.
    #[test]
    fn small_keyed_structures_follow_the_division_property() {
        let mut rng = Rng::new("keyed square small");
        let t = Turing::new(&rng.bytes());
        let z: Block = rng.bytes();
        let rk0 = *t.round_key(0);
        let mut wrong = rk0;
        wrong[3] ^= 0x5a;
        for bits in [8, 16] {
            let s = structure(&t, &rk0, &z, 0, [0, 0], bits);
            assert_eq!(balanced_to(&s), 4, "{bits} bits");
            assert!(s.checked > 0 && s.mismatches == 0);
            assert!(balanced_to(&structure(&t, &wrong, &z, 0, [0, 0], bits)) < 4, "{bits} bits, wrong key");
        }
    }

    // A structure where S^-1(c ⊕ k) sums to zero for k = `key` at byte j.
    fn zero_sum_structure(j: usize, key: u8, rng: &mut Rng) -> Structure {
        let inv = fast::inv_sbox();
        let sbox = turing::sbox::TABLE;
        let mut parity6 = [[0u64; 4]; 16];
        let (a, b) = loop {
            let [a, b] = rng.bytes::<2>();
            let c = sbox[(inv[(a ^ key) as usize] ^ inv[(b ^ key) as usize]) as usize] ^ key;
            if a != b && c != a && c != b {
                break (a, b);
            }
        };
        let c = sbox[(inv[(a ^ key) as usize] ^ inv[(b ^ key) as usize]) as usize] ^ key;
        for v in [a, b, c] {
            parity6[j][(v >> 6) as usize] ^= 1 << (v & 63);
        }
        Structure { texts: 3, sums: [[0; 16]; 6], parity6, partial: Vec::new(), checked: 0, mismatches: 0 }
    }

    // A guess of a round key 6 byte must survive every structure.
    #[test]
    fn rk6_candidates_need_every_structure() {
        let mut rng = Rng::new("keyed square rk6");
        let one = zero_sum_structure(5, 0x3c, &mut rng);
        let two = zero_sum_structure(5, 0xa1, &mut rng);
        let (a, b) = (rk6_candidates(&[&one])[5].clone(), rk6_candidates(&[&two])[5].clone());
        assert!(a.contains(&0x3c) && b.contains(&0xa1));
        let both = rk6_candidates(&[&one, &two])[5].clone();
        assert_eq!(both, a.iter().copied().filter(|k| b.contains(k)).collect::<Vec<_>>());
        assert!(!both.contains(&0x3c) || b.contains(&0x3c));
    }

    // A (k2, k3) survives only if every target keeps some e in every
    // structure.
    #[test]
    fn column_candidates_need_every_target_and_structure() {
        let right = |t: u8| vec![[1, 2, 3 + t]];
        let one: [Vec<[u8; 3]>; 4] = std::array::from_fn(|t| {
            let mut l = right(t as u8);
            l.push([9, 9, 9]); // kept by structure 1 only
            if t < 3 {
                l.push([7, 7, t as u8]); // missing for target 3
            }
            l.sort_unstable();
            l
        });
        let two: [Vec<[u8; 3]>; 4] = std::array::from_fn(|t| {
            let mut l = right(t as u8);
            l.push([7, 7, t as u8]);
            l.push([1, 2, 200]); // a second e for (1, 2), in structure 2 only
            l.sort_unstable();
            l
        });
        let found = column_candidates(&[one, two]);
        assert_eq!(found, vec![([1, 2], [vec![3], vec![4], vec![5], vec![6]])]);
    }

    // The partial sums must agree with the plain sum for every guess: on a
    // small set of random ciphertexts, the plain sum is zero exactly for
    // the guesses `partial_sums` returns.
    #[test]
    fn partial_sums_agree_with_the_plain_sum() {
        let mut rng = Rng::new("keyed square partial sums");
        let target = Target::new(rng.below(16) as usize);
        let s = target.tables();
        let known: [u8; 2] = rng.bytes();
        let texts: Vec<Block> = (0..300).map(|_| rng.bytes()).collect();
        let col = 4 * target.column;
        let mut bits = vec![0u64; 1 << 18];
        for c in &texts {
            let x1 = s[0][(c[col] ^ known[0]) as usize] ^ s[1][(c[col + 1] ^ known[1]) as usize];
            let at = (x1 as usize) << 16 | (c[col + 2] as usize) << 8 | c[col + 3] as usize;
            bits[at >> 6] ^= 1 << (at & 63);
        }
        let found = partial_sums(&bits, target);
        let plain = |k2: u8, k3: u8, e: u8| {
            let mut key = [0u8; 16];
            key[col..col + 4].copy_from_slice(&[known[0], known[1], k2, k3]);
            texts.iter().fold(0u8, |acc, c| acc ^ target.value(&s, fast::to_u128(c), fast::to_u128(&key), e))
        };
        // About 2^16 of the 2^24 guesses pass; all of them must sum to zero.
        assert!((50_000..80_000).contains(&found.len()), "{}", found.len());
        for g in found.iter().step_by(97) {
            assert_eq!(plain(g[0], g[1], g[2]), 0, "{g:?}");
        }
        // And random guesses pass exactly when listed.
        for _ in 0..3000 {
            let g: [u8; 3] = rng.bytes();
            assert_eq!(plain(g[0], g[1], g[2]) == 0, found.binary_search(&g).is_ok(), "{g:?}");
        }
    }
}
