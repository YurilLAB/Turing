//! The yoyo game (Rønjom, Bardeh, Helleseth, "Yoyo Tricks with AES",
//! ASIACRYPT 2017, ePrint 2017/980).
//!
//! For E = S ∘ L ∘ S, with S layers of independent word-wise permutations
//! and L linear (keys anywhere), take plaintexts p0, p1 whose difference is
//! zero in some words, encrypt them, swap words between the two
//! ciphertexts, and decrypt. The new plaintexts p0', p1' differ in exactly
//! the same words as p0, p1, always: swapping ciphertext words commutes
//! with the last S layer and keeps the XOR of the pair, L^-1 keeps it too,
//! and the first S layer keeps which words are zero (their Theorem 2). The
//! words at the two ends need not be the same: they are the words of the
//! first and of the last S layer.
//!
//! For AES, two rounds are one super-box layer (SubBytes, MixColumns,
//! SubBytes on each column), so 4 rounds are S ∘ L ∘ S on columns, and the
//! game holds with one pair of plaintexts and one pair of ciphertexts (their
//! Algorithm 3). Three rounds fall to one pair and one new ciphertext
//! (Algorithm 2).
//!
//! Turing: rounds 1-2 are S ∘ MixState ∘ S on bytes. Rounds 1-3 are S (bytes)
//! ∘ ShiftRows ∘ MixState ∘ super-box (columns), because round 2's
//! MixColumns joins rounds 2 and 3 into super-boxes. Four rounds from round
//! 1 have MixState on both sides of a super-box layer: no such form. Rounds
//! 2-5 are super-box ∘ ShiftRows ∘ MixState ∘ super-box, so the game holds
//! there, but only with round key 0 guessed to reach round 2 (docs/14).

use crate::rng::Rng;

pub type Block = [u8; 16];

/// Byte positions of each word.
pub type Words = Vec<Vec<usize>>;

/// Sixteen one-byte words.
pub fn bytes() -> Words {
    (0..16).map(|i| vec![i]).collect()
}

/// The four columns (bytes 4c..4c + 4).
pub fn columns() -> Words {
    (0..4).map(|c| (4 * c..4 * c + 4).collect()).collect()
}

/// The four diagonals ShiftRows moves into columns: diagonal c holds the
/// byte of row r in column c + r.
pub fn diagonals() -> Words {
    (0..4).map(|c| (0..4).map(|r| 4 * ((c + r) % 4) + r).collect()).collect()
}

/// Which words of a ⊕ b are zero.
pub fn zero_pattern(a: &Block, b: &Block, words: &Words) -> Vec<bool> {
    words.iter().map(|w| w.iter().all(|&i| a[i] == b[i])).collect()
}

/// Algorithm 1 (SimpleSWAP): a copy of b with the first word where a and b
/// differ taken from a. None unless they differ in at least two words (with
/// one, the swap only exchanges the pair).
pub fn simple_swap(a: &Block, b: &Block, words: &Words) -> Option<Block> {
    let zeros = zero_pattern(a, b, words);
    if zeros.iter().filter(|&&z| !z).count() < 2 {
        return None;
    }
    let first = zeros.iter().position(|&z| !z)?;
    let mut out = *b;
    for &i in &words[first] {
        out[i] = a[i];
    }
    Some(out)
}

/// Two plaintexts that differ in exactly one word (chosen at random).
fn pair(rng: &mut Rng, words: &Words) -> (Block, Block) {
    let p0: Block = rng.bytes();
    let w = &words[rng.below(words.len() as u64) as usize];
    loop {
        let mut p1 = p0;
        for &i in w {
            p1[i] = rng.bytes::<1>()[0];
        }
        if p1 != p0 {
            return (p0, p1);
        }
    }
}

pub struct Game {
    pub trials: usize,
    /// Trials whose returned plaintexts kept the zero pattern.
    pub kept: usize,
}

impl Game {
    /// Kept every time: the property is deterministic.
    pub fn always(&self) -> bool {
        self.trials > 0 && self.kept == self.trials
    }
}

/// Theorem 2 / Algorithm 3: encrypt a pair differing in one plaintext word,
/// swap the first differing ciphertext word between the two ciphertexts,
/// decrypt both, and check the new pair's zero pattern.
pub fn pair_game(
    encrypt: impl Fn(&Block) -> Block,
    decrypt: impl Fn(&Block) -> Block,
    plain: &Words,
    cipher: &Words,
    trials: usize,
    label: &str,
) -> Game {
    let mut rng = Rng::new(label);
    let mut game = Game { trials: 0, kept: 0 };
    while game.trials < trials {
        let (p0, p1) = pair(&mut rng, plain);
        let (c0, c1) = (encrypt(&p0), encrypt(&p1));
        let (Some(d0), Some(d1)) = (simple_swap(&c0, &c1, cipher), simple_swap(&c1, &c0, cipher)) else {
            continue;
        };
        game.trials += 1;
        game.kept += usize::from(zero_pattern(&decrypt(&d0), &decrypt(&d1), plain) == zero_pattern(&p0, &p1, plain));
    }
    game
}

/// Algorithm 2: one new ciphertext made from the pair's words; its
/// plaintext differs from p0 in exactly the words p1 does.
pub fn single_game(
    encrypt: impl Fn(&Block) -> Block,
    decrypt: impl Fn(&Block) -> Block,
    plain: &Words,
    cipher: &Words,
    trials: usize,
    label: &str,
) -> Game {
    let mut rng = Rng::new(label);
    let mut game = Game { trials: 0, kept: 0 };
    while game.trials < trials {
        let (p0, p1) = pair(&mut rng, plain);
        let (c0, c1) = (encrypt(&p0), encrypt(&p1));
        let Some(d) = simple_swap(&c0, &c1, cipher) else {
            continue;
        };
        game.trials += 1;
        game.kept += usize::from(zero_pattern(&decrypt(&d), &p0, plain) == zero_pattern(&p0, &p1, plain));
    }
    game
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_layouts() {
        for words in [bytes(), columns(), diagonals()] {
            let mut all: Vec<usize> = words.concat();
            all.sort_unstable();
            assert_eq!(all, (0..16).collect::<Vec<_>>());
        }
        // ShiftRows moves diagonal c into column c.
        for (c, d) in diagonals().iter().enumerate() {
            let mut s = [0u8; 16];
            for &i in d {
                s[i] = 1;
            }
            let moved = turing::linear::shift_rows(&s);
            assert_eq!(moved.iter().enumerate().filter(|(_, &b)| b == 1).map(|(i, _)| i).collect::<Vec<_>>(), columns()[c]);
        }
    }

    #[test]
    fn zero_patterns_by_hand() {
        let a = [0u8; 16];
        let mut b = a;
        b[5] = 1;
        assert_eq!(zero_pattern(&a, &b, &columns()), [true, false, true, true]);
        assert_eq!(zero_pattern(&a, &b, &diagonals()), [false, true, true, true]);
        assert_eq!(zero_pattern(&a, &b, &bytes()).iter().filter(|&&z| !z).count(), 1);
    }

    #[test]
    fn swap_keeps_the_pair_difference() {
        let mut rng = Rng::new("yoyo swap");
        for _ in 0..100 {
            let (a, b): (Block, Block) = (rng.bytes(), rng.bytes());
            let (x, y) = (simple_swap(&a, &b, &columns()).unwrap(), simple_swap(&b, &a, &columns()).unwrap());
            assert!(x != a && x != b);
            let d: Vec<u8> = (0..16).map(|i| x[i] ^ y[i]).collect();
            assert_eq!(d, (0..16).map(|i| a[i] ^ b[i]).collect::<Vec<_>>());
        }
        let a = [0u8; 16];
        let mut b = a;
        b[3] = 1;
        assert_eq!(simple_swap(&a, &b, &columns()), None, "one differing word: nothing new");
        // The first word that differs is taken, not the first word: here
        // columns 1 and 2 differ, so column 1 comes from a.
        let a: Block = rng.bytes();
        let mut c = a;
        c[4] ^= 1;
        c[9] ^= 2;
        let x = simple_swap(&a, &c, &columns()).unwrap();
        assert_eq!((&x[..4], &x[4..8], &x[8..]), (&c[..4], &a[4..8], &c[8..]));
    }
}
