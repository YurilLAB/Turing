//! Round tracer: runs Turing one operation at a time and records the state
//! after each, optionally for a second input alongside so the difference can
//! be watched spreading through the rounds.

use turing::linear;
use turing::sbox;
use turing::structure::{self, Layer};
use turing::{Block, Turing};

pub struct Step {
    pub label: String,
    pub a: Block,
    pub b: Option<Block>,
}

fn xor_into(state: &mut Block, key: &Block) {
    for (s, k) in state.iter_mut().zip(key) {
        *s ^= k;
    }
}

fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::MixState => "MixState",
        Layer::ShiftMixColumns => "ShiftRows+MixColumns",
    }
}

/// Every intermediate state of an encryption with `rounds` rounds. The final
/// state is checked against `Turing::encrypt_rounds`, so the trace can never
/// show something the cipher does not do.
fn states(t: &Turing, plaintext: &Block, rounds: usize) -> Vec<(String, Block)> {
    let mut out = vec![("input".to_string(), *plaintext)];
    let mut s = *plaintext;
    xor_into(&mut s, t.round_key(0));
    out.push(("+ round key 0".to_string(), s));
    for round in 1..=rounds {
        sbox::sub_bytes(&mut s);
        out.push((format!("R{round:<2} S-box"), s));
        if round < rounds {
            let layer = structure::layer(round).expect("layer");
            s = linear::apply_layer(layer, &s);
            out.push((format!("R{round:<2} {}", layer_name(layer)), s));
        }
        xor_into(&mut s, t.round_key(round));
        out.push((format!("R{round:<2} + round key {round}"), s));
    }
    let mut check = *plaintext;
    t.encrypt_rounds(&mut check, rounds);
    assert_eq!(check, s, "tracer disagrees with the cipher");
    out
}

pub fn trace(
    key_a: &[u8; 32],
    plaintext_a: &Block,
    other: Option<(&[u8; 32], &Block)>,
    rounds: usize,
) -> Vec<Step> {
    let a = states(&Turing::new(key_a), plaintext_a, rounds);
    let b = other.map(|(k, p)| states(&Turing::new(k), p, rounds));
    a.into_iter()
        .enumerate()
        .map(|(i, (label, sa))| Step { label, a: sa, b: b.as_ref().map(|v| v[i].1) })
        .collect()
}

pub fn hex(b: &Block) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The XOR of two states, with ".." for bytes that are equal.
pub fn diff(a: &Block, b: &Block) -> String {
    a.iter()
        .zip(b)
        .map(|(x, y)| if x == y { "..".to_string() } else { format!("{:02x}", x ^ y) })
        .collect()
}

pub fn bits_differing(a: &Block, b: &Block) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

pub fn render(steps: &[Step]) -> String {
    let mut out = String::new();
    let compare = steps.first().is_some_and(|s| s.b.is_some());
    if compare {
        out += &format!("{:<28}{:<34}{:<34}{:>5}{:>7}\n", "step", "state A", "A xor B (.. = same byte)", "bits", "bytes");
    } else {
        out += &format!("{:<28}{}\n", "step", "state");
    }
    for s in steps {
        match s.b {
            Some(b) => {
                let bytes = s.a.iter().zip(&b).filter(|(x, y)| x != y).count();
                out += &format!(
                    "{:<28}{:<34}{:<34}{:>5}{:>7}\n",
                    s.label,
                    hex(&s.a),
                    diff(&s.a, &b),
                    bits_differing(&s.a, &b),
                    bytes
                );
            }
            None => out += &format!("{:<28}{}\n", s.label, hex(&s.a)),
        }
    }
    out
}
