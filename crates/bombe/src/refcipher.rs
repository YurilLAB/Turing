//! A second, independent implementation of Turing, written differently on
//! purpose: table-lookup S-box, generic matrix multiplication with Bombe's
//! table-based field arithmetic, its own ShiftRows, its own key schedule
//! (cSHAKE256 straight from the sha3 crate) and its own round loop and layer
//! rule. It shares only the published constants with the `turing` crate.
//! Agreement between the two on many random inputs is evidence that both
//! implement the specification; the known-answer vectors come from here.
//! Not constant-time: for testing only.

use crate::matrix::{self, Matrix};
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub type Block = [u8; 16];

/// Rounds in the full cipher, written out independently of turing::structure.
pub const ROUNDS: usize = 24;
const WARMUP: usize = 13;
const PER_PAIR: usize = 8;

fn cshake(label: &[u8], input: &[u8]) -> impl XofReader {
    let mut h = CoreWrapper::from_core(sha3::CShake256Core::new(label));
    h.update(input);
    h.finalize_xof()
}

struct Tables {
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    mix_state: Matrix,
    mix_state_inv: Matrix,
    mix_columns: Matrix,
    mix_columns_inv: Matrix,
}

fn tables() -> &'static Tables {
    static TABLES: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let sbox = turing::sbox::TABLE;
        let mut inv_sbox = [0u8; 256];
        for (x, &y) in sbox.iter().enumerate() {
            inv_sbox[y as usize] = x as u8;
        }
        Tables {
            sbox,
            inv_sbox,
            mix_state: matrix::from_array(&turing::linear::MIX_STATE),
            mix_state_inv: matrix::from_array(&turing::linear::MIX_STATE_INV),
            mix_columns: matrix::from_array(&turing::linear::MIX_COLUMNS),
            mix_columns_inv: matrix::from_array(&turing::linear::MIX_COLUMNS_INV),
        }
    })
}

/// The state as a grid: byte 4c + r is row r, column c. Row r rotates left
/// by r positions.
fn shift_rows(s: &Block, inverse: bool) -> Block {
    let mut out = [0u8; 16];
    for r in 0..4 {
        let row: Vec<u8> = (0..4).map(|c| s[4 * c + r]).collect();
        for c in 0..4 {
            let from = if inverse { (c + 4 - r) % 4 } else { (c + r) % 4 };
            out[4 * c + r] = row[from];
        }
    }
    out
}

fn mix_columns(s: &Block, m: &Matrix) -> Block {
    let mut out = [0u8; 16];
    for c in 0..4 {
        let col = matrix::mat_vec(m, &s[4 * c..4 * c + 4]);
        out[4 * c..4 * c + 4].copy_from_slice(&col);
    }
    out
}

fn mix_state(s: &Block, m: &Matrix) -> Block {
    matrix::mat_vec(m, s).try_into().expect("16 bytes")
}

/// Odd rounds use MixState, even rounds ShiftRows + MixColumns.
fn uses_mix_state(round: usize) -> bool {
    round % 2 == 1
}

pub struct Reference {
    round_keys: Vec<Block>,
}

impl Reference {
    pub fn new(key: &[u8; 32]) -> Reference {
        Reference { round_keys: key_schedule(key, ROUNDS + 1, true) }
    }

    pub fn round_keys(&self) -> &[Block] {
        &self.round_keys
    }

    pub fn encrypt(&self, block: &Block, rounds: usize) -> Block {
        let t = tables();
        let mut s = xor(block, &self.round_keys[0]);
        for round in 1..=rounds {
            s = s.map(|b| t.sbox[b as usize]);
            if round != rounds {
                s = if uses_mix_state(round) {
                    mix_state(&s, &t.mix_state)
                } else {
                    mix_columns(&shift_rows(&s, false), &t.mix_columns)
                };
            }
            s = xor(&s, &self.round_keys[round]);
        }
        s
    }

    pub fn decrypt(&self, block: &Block, rounds: usize) -> Block {
        let t = tables();
        let mut s = *block;
        for round in (1..=rounds).rev() {
            s = xor(&s, &self.round_keys[round]);
            if round != rounds {
                s = if uses_mix_state(round) {
                    mix_state(&s, &t.mix_state_inv)
                } else {
                    shift_rows(&mix_columns(&s, &t.mix_columns_inv), true)
                };
            }
            s = s.map(|b| t.inv_sbox[b as usize]);
        }
        xor(&s, &self.round_keys[0])
    }
}

fn xor(a: &Block, b: &Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// The key schedule written out: cSHAKE256 whitening, a Feistel network
/// with F(x) = MixState(S(x ^ C)), 13 warm-up rounds, then a pair of round
/// keys every 8 rounds, each fed forward with K'. `feed_forward = false`
/// exists only to show in tests that the real schedule applies it.
pub fn key_schedule(key: &[u8; 32], count: usize, feed_forward: bool) -> Vec<Block> {
    let t = tables();
    let mut kp = [0u8; 32];
    cshake(b"Turing v2 key", key).read(&mut kp);
    let k_l: Block = kp[..16].try_into().expect("16 bytes");
    let k_r: Block = kp[16..].try_into().expect("16 bytes");
    let (mut l, mut r) = (k_l, k_r);
    let mut constants = cshake(b"Turing v2 key schedule constants", &[]);
    let mut round = |l: &mut Block, r: &mut Block| {
        let mut c = [0u8; 16];
        constants.read(&mut c);
        let f = mix_state(&xor(l, &c).map(|b| t.sbox[b as usize]), &t.mix_state);
        let new_l = xor(r, &f);
        *r = std::mem::replace(l, new_l);
    };
    for _ in 0..WARMUP {
        round(&mut l, &mut r);
    }
    let mut out = Vec::with_capacity(count + 1);
    while out.len() < count {
        if !out.is_empty() {
            for _ in 0..PER_PAIR {
                round(&mut l, &mut r);
            }
        }
        let (ff_l, ff_r) = if feed_forward { (k_l, k_r) } else { ([0u8; 16], [0u8; 16]) };
        out.push(xor(&l, &ff_l));
        out.push(xor(&r, &ff_r));
    }
    out.truncate(count);
    out
}

/// Known-answer vectors: (key, plaintext, ciphertext) for the full cipher.
pub fn known_answer_vectors() -> Vec<([u8; 32], Block, Block)> {
    let mut inputs: Vec<([u8; 32], Block)> = vec![
        ([0; 32], [0; 16]),
        ([0xff; 32], [0xff; 16]),
        (std::array::from_fn(|i| i as u8), std::array::from_fn(|i| (i as u8) * 0x11)),
        ([0; 32], std::array::from_fn(|i| (i == 15) as u8)),
        (std::array::from_fn(|i| (i == 0) as u8), [0; 16]),
    ];
    let mut stream = cshake(b"Turing v2 known-answer vectors", &[]);
    for _ in 0..3 {
        let mut k = [0u8; 32];
        let mut p = [0u8; 16];
        stream.read(&mut k);
        stream.read(&mut p);
        inputs.push((k, p));
    }
    inputs.into_iter().map(|(k, p)| (k, p, Reference::new(&k).encrypt(&p, ROUNDS))).collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The committed `vectors/turing-v2.txt`: known-answer vectors, plus every
/// round key and the state after every round for one of them, to help
/// anyone writing their own implementation find where it diverges.
pub fn render_vectors() -> String {
    let mut out = String::new();
    out += "# Turing v2 known-answer vectors (128-bit block, 256-bit key, 24 rounds).\n";
    out += "# @generated by `bombe vectors --out vectors/turing-v2.txt` from the independent\n";
    out += "# reference implementation; the turing crate must reproduce every line.\n";
    out += "# Byte strings in hex. The state is 16 bytes, byte 4c + r at row r, column c.\n\n";
    let vectors = known_answer_vectors();
    for (i, (k, p, c)) in vectors.iter().enumerate() {
        out += &format!("COUNT = {i}\nKEY = {}\nPLAINTEXT = {}\nCIPHERTEXT = {}\n\n", hex(k), hex(p), hex(c));
    }
    let (k, p, _) = &vectors[2];
    let r = Reference::new(k);
    out += "# Intermediate values for COUNT = 2.\n";
    for (i, rk) in r.round_keys().iter().enumerate() {
        out += &format!("ROUND_KEY[{i}] = {}\n", hex(rk));
    }
    for rounds in 1..=ROUNDS {
        out += &format!("AFTER_ROUND[{rounds}] = {}\n", hex(&r.encrypt(p, rounds)));
    }
    out
}

/// One parsed known-answer vector.
pub struct Vector {
    pub key: [u8; 32],
    pub plaintext: Block,
    pub ciphertext: Block,
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Parses the KEY / PLAINTEXT / CIPHERTEXT triples of a vector file.
pub fn parse_vectors(text: &str) -> Result<Vec<Vector>, String> {
    let mut out = Vec::new();
    let (mut key, mut plaintext) = (None, None);
    for line in text.lines() {
        let Some((name, value)) = line.split_once(" = ") else { continue };
        let value = value.trim();
        match name.trim() {
            "KEY" => key = Some(unhex::<32>(value).ok_or(format!("bad KEY {value}"))?),
            "PLAINTEXT" => plaintext = Some(unhex::<16>(value).ok_or(format!("bad PLAINTEXT {value}"))?),
            "CIPHERTEXT" => {
                let ciphertext = unhex::<16>(value).ok_or(format!("bad CIPHERTEXT {value}"))?;
                out.push(Vector {
                    key: key.take().ok_or("CIPHERTEXT without KEY")?,
                    plaintext: plaintext.take().ok_or("CIPHERTEXT without PLAINTEXT")?,
                    ciphertext,
                });
            }
            _ => {}
        }
    }
    Ok(out)
}
