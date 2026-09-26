//! Validates the trail bounder and the impossible-differential search against
//! published AES results and theorems, then checks Turing's round structure.

use bombe::impossible::{self, Trunc};
use bombe::trail::{self, Layer};

const A: Layer = Layer::ShiftMixColumns;
const M: Layer = Layer::MixState;

// Mouha, Wang, Gu, Preneel, "Differential and Linear Cryptanalysis using
// Mixed-Integer Linear Programming" (Inscrypt 2011), Table 4: the minimum
// number of differentially or linearly active S-boxes in 1..14 AES rounds.
const AES_PUBLISHED: [u32; 14] = [1, 5, 9, 25, 26, 30, 34, 50, 51, 55, 59, 75, 76, 80];

#[test]
fn trail_bounder_reproduces_aes_table() {
    assert_eq!(trail::min_active_prefixes(&[A; 13]), AES_PUBLISHED.to_vec());
}

// Daemen-Rijmen two-round propagation: two rounds around a linear layer of
// branch B have at least B active S-boxes, and alternating 1 and 16 active
// bytes meets it exactly for MixState: 1, 17, 18, 34, ...
#[test]
fn trail_bounder_mix_state_only() {
    let bounds = trail::min_active_prefixes(&[M; 9]);
    let expected: Vec<u32> = (1..=10u32).map(|r| 17 * (r / 2) + r % 2).collect();
    assert_eq!(bounds, expected);
}

// The column-by-column minimisation must agree with enumerating every
// allowed (input, output) pattern pair, on every mix of layers up to three
// linear layers (four rounds).
#[test]
fn fast_bounder_agrees_with_naive_enumeration() {
    let mut cases: Vec<Vec<Layer>> = Vec::new();
    for len in 1..=3usize {
        for bits in 0..(1u32 << len) {
            cases.push((0..len).map(|i| if bits >> i & 1 == 1 { M } else { A }).collect());
        }
    }
    for layers in cases {
        let fast = *trail::min_active_prefixes(&layers).last().unwrap();
        assert_eq!(fast, trail::min_active_naive(&layers), "{layers:?}");
    }
}

// Every two consecutive rounds meet the branch number of the layer between
// them, in any mixed schedule (checked on all schedules of 6 layers).
#[test]
fn two_round_theorem_holds_in_mixed_schedules() {
    for bits in 0..64u32 {
        let layers: Vec<Layer> = (0..6).map(|i| if bits >> i & 1 == 1 { M } else { A }).collect();
        for (i, &l) in layers.iter().enumerate() {
            let two = *trail::min_active_prefixes(&layers[i..=i]).last().unwrap();
            assert_eq!(two, if l == M { 17 } else { 5 });
        }
    }
}

// The classic AES impossible differential (Biham-Keller): one active byte at
// the input cannot give, four S-box layers later, an output whose column 0 is
// zero before the last ShiftRows+MixColumns -- here: a pattern with column 0
// inactive. Sun et al. (EUROCRYPT 2016) proved no S-box-independent
// impossible differential covers 5 AES rounds.
#[test]
fn impossible_differentials_match_aes_results() {
    assert!(impossible::find(&[A; 3]).is_some(), "4-round AES impossible differential");
    assert!(impossible::find(&[A; 4]).is_none(), "no 5-round one");
    assert_eq!(impossible::longest(&[A; 9]), 4);
    // The specific classic one: byte 0 active in, column 0 inactive out.
    let forward = [A; 2].iter().fold(Trunc::definite(1), |t, &l| impossible::forward(l, t));
    let backward = impossible::backward(A, Trunc::definite(0xfff0));
    assert_eq!(forward, Trunc { nz: 0xffff, z: 0 }, "all 16 bytes certainly active after 2 rounds");
    assert_eq!(backward.z & 0x8421, 0x8421, "the diagonal is certainly inactive going back");
}

// With MixState in every round, one active byte makes all 16 active, so no
// single-byte output can follow a single-byte input two rounds later; three
// rounds leave nothing certain in the middle.
#[test]
fn impossible_differentials_mix_state_only() {
    assert_eq!(impossible::longest(&[M; 9]), 2);
}

// Every reported impossible differential must be sound. Recheck each witness
// found on short AES and mixed windows by exhaustively enumerating all
// truncated trails between the two patterns with the trail bounder's rules.
#[test]
fn impossible_witnesses_have_no_trail() {
    let schedules: [&[Layer]; 4] = [&[A, A, A], &[A, M], &[M, A], &[A, A]];
    for layers in schedules {
        let w = impossible::find(layers).expect("expected an impossible differential");
        assert!(!trail_exists(layers, w.input, w.output), "{layers:?}: {w:?}");
    }
}

#[test]
fn turing_layer_schedule() {
    use turing::structure::{layer, schedule, ROUNDS, ROUND_KEYS};
    assert_eq!((ROUNDS, ROUND_KEYS), (24, 25));
    assert_eq!(layer(0), None);
    assert_eq!(layer(ROUNDS), None, "the last round has no linear layer");
    assert_eq!(layer(1), Some(M), "MixState first");
    assert_eq!(layer(ROUNDS - 1), Some(M), "and last");
    let s = schedule();
    assert!(s.windows(2).all(|w| w[0] != w[1]), "the layers alternate");
    assert_eq!(s.iter().filter(|&&l| l == M).count(), 12);
}

// The measured security of the chosen structure, over every window of
// consecutive rounds inside the 24-round cipher.
#[test]
fn turing_structure_bounds() {
    let s = turing::structure::schedule();
    let e = bombe::structure::evaluate(&s, 8);
    assert_eq!(e.weakest, vec![1, 5, 18, 25, 35, 36, 52, 53]);
    assert_eq!(e.rounds_to_22, Some(4));
    assert_eq!(e.rounds_to_43, Some(7));
    assert_eq!(e.impossible, 4);
    assert_eq!(e.diffusion, Some(3));
    assert_eq!(e.aes_like_run, 1);
    // The whole cipher: the 24 rounds split into 12 pairs (1-2, 3-4, ...),
    // each around one MixState layer, so the two-round theorem gives
    // 12 x 17 = 204; the bounder shows that is also the exact minimum.
    assert_eq!(trail::weakest_window(&s, 24), 204);
    // Version 1's 16 rounds, now a window that can start on either layer: a
    // window starting with ShiftRows+MixColumns holds one pair fewer.
    assert_eq!(trail::weakest_window(&s, 16), 121);
}

// The round-count rule (docs/09): the longest attack we can build from these
// distinguishers is the longest usable one plus 2 rounds of key guessing at
// each end, and the cipher has at least twice that many rounds.
//  - Differential/linear: a trail is usable only while it has fewer than 22
//    active S-boxes (probability above 2^-132, within the 2^128 codebook).
//  - Impossible differentials: the longest one found.
#[test]
fn round_count_rule() {
    use turing::structure::ROUNDS;
    let s = turing::structure::schedule();
    let e = bombe::structure::evaluate(&s, 8);
    let usable_trail = e.rounds_to_22.unwrap() - 1;
    let longest_attack = usable_trail.max(e.impossible) + 4;
    assert_eq!(longest_attack, 8);
    assert!(ROUNDS >= 2 * longest_attack);
    // Even trails that a 2^256 budget could not use run out long before.
    assert!(e.rounds_to_43.unwrap() + 4 < ROUNDS);
}

/// Is there any sequence of activity patterns from `input` to `output`
/// allowed by the truncated rules (S-boxes keep patterns; MDS layers need
/// in + out >= branch)?
fn trail_exists(layers: &[Layer], input: u32, output: u32) -> bool {
    let mut reachable = vec![false; 1 << 16];
    reachable[input as usize] = true;
    for &layer in layers {
        let mut next = vec![false; 1 << 16];
        for x in (1..1u32 << 16).filter(|&x| reachable[x as usize]) {
            for y in 1..1u32 << 16 {
                let ok = match layer {
                    Layer::MixState => x.count_ones() + y.count_ones() >= 17,
                    Layer::ShiftMixColumns => {
                        let s = trail::shift_rows_pattern(x);
                        (0..4).all(|c| {
                            let (a, b) = (s >> (4 * c) & 0xf, y >> (4 * c) & 0xf);
                            (a == 0 && b == 0) || (a != 0 && b != 0 && a.count_ones() + b.count_ones() >= 5)
                        })
                    }
                };
                if ok {
                    next[y as usize] = true;
                }
            }
        }
        reachable = next;
    }
    reachable[output as usize]
}

// The propagation rules are sound on real differences, including patterns
// that mix certain and unknown bytes (which the search itself rarely
// builds): a concrete difference that fits the input pattern always fits
// the predicted output, through Turing's real layers in both directions,
// and `consistent` never rules out a transition that really happens.
#[test]
fn truncated_rules_hold_for_real_differences() {
    use bombe::rng::Rng;
    let mut rng = Rng::new("truncated soundness");
    let fits = |t: Trunc, d: &[u8; 16]| (0..16).all(|i| (t.nz >> i & 1 == 0 || d[i] != 0) && (t.z >> i & 1 == 0 || d[i] == 0));
    for _ in 0..20_000 {
        let (mut nz, mut z) = (0u32, 0u32);
        for i in 0..16 {
            match rng.below(3) {
                0 => nz |= 1 << i,
                1 => z |= 1 << i,
                _ => {}
            }
        }
        let t = Trunc { nz, z };
        for layer in [A, M] {
            let (ahead, behind) = (impossible::forward(layer, t), impossible::backward(layer, t));
            for _ in 0..4 {
                let d: [u8; 16] = std::array::from_fn(|i| match (nz >> i & 1, z >> i & 1) {
                    (1, _) => 1 + rng.below(255) as u8,
                    (_, 1) => 0,
                    _ if rng.below(2) == 0 => 0,
                    _ => rng.below(256) as u8,
                });
                let y = turing::linear::apply_layer(layer, &d);
                assert!(fits(ahead, &y), "forward {layer:?}: {t:?} -> {ahead:?}, but {d:02x?} -> {y:02x?}");
                let x = turing::linear::invert_layer(layer, &d);
                assert!(fits(behind, &x), "backward {layer:?}: {t:?} -> {behind:?}, but {d:02x?} <- {x:02x?}");
                let definite = |v: &[u8; 16]| Trunc::definite((0..16).filter(|&i| v[i] != 0).fold(0, |p, i| p | 1 << i));
                assert!(impossible::consistent(layer, t, definite(&y)), "consistent rejects a real transition");
            }
        }
    }
}
