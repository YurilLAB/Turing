//! Demirci-Selçuk meet-in-the-middle (FSE 2008), the family behind the best
//! single-key attacks on AES-192 and AES-256 (Dunkelman, Keller, Shamir,
//! ASIACRYPT 2010; Derbez, Fouque, Jean, EUROCRYPT 2013).
//!
//! Take a δ-set, 256 states equal except in one byte, which takes every
//! value, just after an S-box layer. Through a few rounds, the ordered
//! sequence of 256 values of one output byte is a function of a few
//! intermediate bytes of one state of the set (the parameters): the bytes
//! of each S-box layer in between that are both active (differ across the
//! set) and needed (the output byte depends on them). Knowing their values
//! for one state, the differences go through every S-box. An attacker
//! tabulates all 2^(8·parameters) sequences offline, then guesses outer
//! round keys and looks sequences up; the attack needs the table smaller
//! than the key space.
//!
//! Derbez and Fouque (FSE 2013, Property 5) count 25 parameters for 4 AES
//! rounds (24 for sequences of differences, which skip the output byte),
//! which `parameters` reproduces. Dunkelman et al.'s differential enumeration
//! then keeps only δ-sets holding a pair that follows a sparse truncated
//! differential, which cuts AES's 4-round table to 10 bytes (2^80); the
//! trail's probability is the price, paid in data.

use crate::trail::Layer;

/// Which input bytes each output byte of a linear layer depends on.
fn sources(layer: Layer, out: usize) -> u16 {
    match layer {
        Layer::MixState => 0xffff,
        // Output column c of ShiftRows + MixColumns reads the diagonal
        // ShiftRows moves into column c: row r from column c + r.
        Layer::ShiftMixColumns => {
            let c = out / 4;
            (0..4).fold(0, |acc, r| acc | 1 << (4 * ((c + r) % 4) + r))
        }
    }
}

/// Output bytes a layer's input bytes reach.
fn spread(layer: Layer, active: u16) -> u16 {
    (0..16).filter(|&o| sources(layer, o) & active != 0).fold(0, |acc, o| acc | 1 << o)
}

/// Input bytes the given output bytes depend on.
fn needs(layer: Layer, outputs: u16) -> u16 {
    (0..16).filter(|&o| outputs >> o & 1 == 1).fold(0, |acc, o| acc | sources(layer, o))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Count {
    /// Parameters at each S-box layer the δ-set's differences cross.
    pub per_layer: Vec<u32>,
    /// Their sum: parameters of a sequence of differences.
    pub differences: u32,
    /// Plus the output byte itself: parameters of a sequence of values.
    pub values: u32,
}

/// Parameters of the δ-set property: the δ-set's active byte `input` sits
/// after an S-box layer and before `layers[0]`; then S-box layer, layers[1],
/// and so on; the observed byte `output` is taken after the last linear
/// layer (the input of the next S-box layer). `layers.len()` rounds.
pub fn parameters(layers: &[Layer], input: usize, output: usize) -> Count {
    assert!(!layers.is_empty() && input < 16 && output < 16);
    // Active bytes at the input of each S-box layer after the δ-set.
    let mut active = Vec::new();
    let mut a = spread(layers[0], 1 << input);
    for &layer in &layers[1..] {
        active.push(a);
        a = spread(layer, a);
    }
    // Needed bytes at the input of each of those S-box layers, backwards.
    let mut needed = vec![0u16; active.len()];
    let mut n: u16 = 1 << output;
    for (i, &layer) in layers[1..].iter().enumerate().rev() {
        n = needs(layer, n);
        needed[i] = n;
    }
    let per_layer: Vec<u32> = active.iter().zip(&needed).map(|(a, n)| (a & n).count_ones()).collect();
    let differences = per_layer.iter().sum();
    Count { per_layer, differences, values: differences + 1 }
}

/// Differential enumeration (Dunkelman, Keller, Shamir 2010), counted the
/// way Derbez, Fouque and Jean count AES's 4-round table (10 bytes, 2^80;
/// FSE 2013 cites it as "described by 10 parameters").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enumerated {
    /// Bytes of difference the table depends on: the δ-set's, the S-box
    /// outputs before the layer where the two halves of the trail meet, the
    /// S-box inputs after it, and the output byte's. Each S-box of the
    /// meeting layer has about one solution per pair of differences.
    pub free: u32,
    /// log2 of 1 / the probability that a pair follows the trail: 8 bits
    /// for every byte the trail forces to zero after the meeting layer.
    pub cost: u32,
}

/// Keeps only δ-sets holding a pair that follows the sparsest trail: it
/// spreads forward from the δ-set up to a meeting S-box layer, and is active
/// after it only where the output byte depends on it. The best meeting
/// layer is the one with the fewest free bytes.
pub fn enumerated(layers: &[Layer], input: usize, output: usize) -> Enumerated {
    assert!(layers.len() >= 2 && input < 16 && output < 16);
    let n = layers.len() - 1; // S-box layers between δ-set and output
    let mut forward = vec![spread(layers[0], 1 << input)];
    for k in 1..n {
        forward.push(spread(layers[k], forward[k - 1]));
    }
    let mut backward = vec![0u16; n];
    let mut b: u16 = 1 << output;
    for k in (0..n).rev() {
        b = needs(layers[k + 1], b);
        backward[k] = b;
    }
    (0..n)
        .map(|m| {
            let before: u32 = forward[..m].iter().map(|a| a.count_ones()).sum();
            let after: u32 = backward[m + 1..].iter().map(|b| b.count_ones()).sum();
            // The trail: forward sets up to m, backward sets after, the
            // output byte last. Forced zeros: what each set would spread
            // to, minus what the trail keeps.
            let trail: Vec<u16> = (0..n).map(|k| if k <= m { forward[k] } else { backward[k] }).chain([1u16 << output]).collect();
            let cost = (m..n).map(|k| 8 * (spread(layers[k + 1], trail[k]) & !trail[k + 1]).count_ones()).sum();
            Enumerated { free: 2 + before + after, cost }
        })
        .min_by_key(|e| (e.free, e.cost))
        .expect("at least one S-box layer")
}

/// The smallest count over every choice of active and observed byte.
pub fn best(layers: &[Layer]) -> Count {
    (0..16)
        .flat_map(|i| (0..16).map(move |o| (i, o)))
        .map(|(i, o)| parameters(layers, i, o))
        .min_by_key(|c| c.differences)
        .expect("16 x 16 choices")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Layer = Layer::ShiftMixColumns;
    const M: Layer = Layer::MixState;

    // Derbez-Fouque FSE 2013, Property 5: four full AES rounds, δ-set and
    // observed byte both at position 0: the first column of x_{i+1} (4),
    // the full x_{i+2} (16), the first column of z_{i+3} (4) and x_{i+4}[0]
    // (1) = 25; 24 for differences.
    #[test]
    fn reproduces_property_5_for_aes() {
        let c = parameters(&[A; 4], 0, 0);
        assert_eq!(c.per_layer, vec![4, 16, 4]);
        assert_eq!((c.differences, c.values), (24, 25));
        // Every position gives the same for AES.
        assert_eq!(best(&[A; 4]).differences, 24);
    }

    // Derbez, Fouque and Jean's 4-round table: 10 bytes (2^80), for a pair
    // following 1 -> 4 -> 16 -> 4 -> 1, which costs 2^-96 in the third round
    // and 2^-24 in the fourth.
    #[test]
    fn reproduces_the_10_byte_table_for_aes() {
        assert_eq!(enumerated(&[A; 4], 0, 0), Enumerated { free: 10, cost: 120 });
    }

    // Turing: after round 1's S-boxes the δ-set meets MixState at once, and
    // any 3 rounds need 32 parameters; after round 2's, 3 rounds need 8, as
    // AES, but every 4-round window needs 36 (AES 24): MixState makes each
    // S-box layer it touches count in full.
    #[test]
    fn turing_windows() {
        let s = turing::structure::schedule();
        assert_eq!(best(&s[..3]).differences, 32);
        assert_eq!(best(&s[1..4]).differences, 8);
        assert_eq!(best(&s[..4]).differences, 36);
        assert_eq!(best(&s[1..5]), Count { per_layer: vec![4, 16, 16], differences: 36, values: 37 });
        assert_eq!(best(&[A; 3]).differences, 8);
        // Enumeration: 1 -> 4 -> 16 -> 16 -> 1 leaves 22 free bytes (2^176),
        // and MixState's 16 -> 1 costs 2^-120.
        assert_eq!(enumerated(&s[1..5], 0, 0), Enumerated { free: 22, cost: 120 });
    }

    #[test]
    fn dependencies_by_hand() {
        // ShiftRows + MixColumns: output column 0 reads bytes 0, 5, 10, 15.
        assert_eq!(sources(A, 0), 1 | 1 << 5 | 1 << 10 | 1 << 15);
        assert_eq!(spread(A, 1), 0x000f);
        assert_eq!(spread(M, 1), 0xffff);
        assert_eq!(needs(A, 1 << 4), 1 << 4 | 1 << 9 | 1 << 14 | 1 << 3);
    }
}
