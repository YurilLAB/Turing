//! A second, independent implementation of Turing-256 v2 (docs/15), written
//! differently on purpose, as `refcipher` is for Turing: table S-box,
//! generic matrix products with Bombe's table arithmetic, its own ShiftRows
//! written as row rotations, its own key schedule and round constants
//! (cSHAKE256 straight from the sha3 crate) and its own round loop. It
//! shares only the published S-box and matrices with the `turing` crate
//! (research/scripts/turing256_py.py derives those too). The known-answer
//! vectors come from here. Not constant-time: for testing only.

use crate::matrix::{self, Matrix};
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub type Block256 = [u8; 32];

pub const ROUNDS: usize = 24;
const WARMUP: usize = 9;
const PER_PAIR: usize = 8;
/// Left rotation of rows 0-3 of the 4 x 8 state.
const SHIFTS: [usize; 4] = [0, 1, 3, 4];

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
            mix_state: matrix::from_array(&turing::linear256::MIX_STATE_256),
            mix_state_inv: matrix::from_array(&turing::linear256::MIX_STATE_256_INV),
            mix_columns: matrix::from_array(&turing::linear::MIX_COLUMNS),
            mix_columns_inv: matrix::from_array(&turing::linear::MIX_COLUMNS_INV),
        }
    })
}

/// Rotates each row of the 4 x 8 grid (byte 4c + r is row r, column c).
fn shift_rows(s: &Block256, inverse: bool) -> Block256 {
    let mut out = [0u8; 32];
    for (r, &shift) in SHIFTS.iter().enumerate() {
        let mut row: Vec<u8> = (0..8).map(|c| s[4 * c + r]).collect();
        if inverse {
            row.rotate_right(shift);
        } else {
            row.rotate_left(shift);
        }
        for (c, b) in row.into_iter().enumerate() {
            out[4 * c + r] = b;
        }
    }
    out
}

fn mix_columns(s: &Block256, m: &Matrix) -> Block256 {
    let mut out = [0u8; 32];
    for c in 0..8 {
        out[4 * c..4 * c + 4].copy_from_slice(&matrix::mat_vec(m, &s[4 * c..4 * c + 4]));
    }
    out
}

fn mix_state(s: &Block256, m: &Matrix) -> Block256 {
    matrix::mat_vec(m, s).try_into().expect("32 bytes")
}

fn xor(a: &Block256, b: &Block256) -> Block256 {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Round constants 1..=ROUNDS, read in order from their own cSHAKE256 stream.
fn round_constants() -> &'static [Block256] {
    static RC: std::sync::OnceLock<Vec<Block256>> = std::sync::OnceLock::new();
    RC.get_or_init(|| {
        let mut stream = cshake(b"Turing-256 v2 round constants", &[]);
        (0..ROUNDS)
            .map(|_| {
                let mut c = [0u8; 32];
                stream.read(&mut c);
                c
            })
            .collect()
    })
}

pub struct Reference256 {
    round_keys: Vec<Block256>,
}

impl Reference256 {
    pub fn new(key: &[u8; 32]) -> Reference256 {
        Reference256 { round_keys: key_schedule(key, ROUNDS + 1) }
    }

    pub fn round_keys(&self) -> &[Block256] {
        &self.round_keys
    }

    pub fn encrypt(&self, block: &Block256, rounds: usize) -> Block256 {
        let (t, rc) = (tables(), round_constants());
        let mut s = xor(block, &self.round_keys[0]);
        for round in 1..=rounds {
            s = s.map(|b| t.sbox[b as usize]);
            if round != rounds {
                s = if round % 2 == 1 { mix_state(&s, &t.mix_state) } else { mix_columns(&shift_rows(&s, false), &t.mix_columns) };
            }
            s = xor(&s, &xor(&rc[round - 1], &self.round_keys[round]));
        }
        s
    }

    pub fn decrypt(&self, block: &Block256, rounds: usize) -> Block256 {
        let (t, rc) = (tables(), round_constants());
        let mut s = *block;
        for round in (1..=rounds).rev() {
            s = xor(&s, &xor(&rc[round - 1], &self.round_keys[round]));
            if round != rounds {
                s = if round % 2 == 1 { mix_state(&s, &t.mix_state_inv) } else { shift_rows(&mix_columns(&s, &t.mix_columns_inv), true) };
            }
            s = s.map(|b| t.inv_sbox[b as usize]);
        }
        xor(&s, &self.round_keys[0])
    }
}

/// cSHAKE256 whitening to 64 bytes, a Feistel on 32-byte halves with
/// F(x) = MixState256(S(x ^ C)), 9 warm-up rounds, a pair of round keys
/// every 8 rounds, each fed forward with its half of K'.
pub fn key_schedule(key: &[u8; 32], count: usize) -> Vec<Block256> {
    let t = tables();
    let mut kp = [0u8; 64];
    cshake(b"Turing-256 v2 key", key).read(&mut kp);
    let k_l: Block256 = kp[..32].try_into().expect("32 bytes");
    let k_r: Block256 = kp[32..].try_into().expect("32 bytes");
    let (mut l, mut r) = (k_l, k_r);
    let mut constants = cshake(b"Turing-256 v2 key schedule constants", &[]);
    let mut round = |l: &mut Block256, r: &mut Block256| {
        let mut c = [0u8; 32];
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
        out.push(xor(&l, &k_l));
        out.push(xor(&r, &k_r));
    }
    out.truncate(count);
    out
}

/// Known-answer vectors: (key, plaintext, ciphertext) for the full cipher.
pub fn known_answer_vectors() -> Vec<([u8; 32], Block256, Block256)> {
    let mut inputs: Vec<([u8; 32], Block256)> = vec![
        ([0; 32], [0; 32]),
        ([0xff; 32], [0xff; 32]),
        (std::array::from_fn(|i| i as u8), std::array::from_fn(|i| (i as u8).wrapping_mul(0x11))),
        ([0; 32], std::array::from_fn(|i| (i == 31) as u8)),
        (std::array::from_fn(|i| (i == 0) as u8), [0; 32]),
    ];
    let mut stream = cshake(b"Turing-256 v2 known-answer vectors", &[]);
    for _ in 0..3 {
        let mut k = [0u8; 32];
        let mut p = [0u8; 32];
        stream.read(&mut k);
        stream.read(&mut p);
        inputs.push((k, p));
    }
    inputs.into_iter().map(|(k, p)| (k, p, Reference256::new(&k).encrypt(&p, ROUNDS))).collect()
}

/// The committed `vectors/turing-256-v2.txt`, in the format of Turing's.
pub fn render_vectors() -> String {
    let hex = crate::refcipher::hex;
    let mut out = String::new();
    out += "# Turing-256 v2 known-answer vectors (256-bit block, 256-bit key, 24 rounds, round constants).\n";
    out += "# @generated by `bombe vectors --turing-256 --out vectors/turing-256-v2.txt` from the\n";
    out += "# independent reference implementation; the turing crate must reproduce every line.\n";
    out += "# Byte strings in hex. The state is 32 bytes, byte 4c + r at row r, column c.\n\n";
    let vectors = known_answer_vectors();
    for (i, (k, p, c)) in vectors.iter().enumerate() {
        out += &format!("COUNT = {i}\nKEY = {}\nPLAINTEXT = {}\nCIPHERTEXT = {}\n\n", hex(k), hex(p), hex(c));
    }
    out += "# The round constants, the same for every key (round r adds ROUND_CONSTANT[r] with ROUND_KEY[r]).\n";
    for (i, rc) in round_constants().iter().enumerate() {
        out += &format!("ROUND_CONSTANT[{}] = {}\n", i + 1, hex(rc));
    }
    let (k, p, _) = &vectors[2];
    let r = Reference256::new(k);
    out += "\n# Intermediate values for COUNT = 2.\n";
    for (i, rk) in r.round_keys().iter().enumerate() {
        out += &format!("ROUND_KEY[{i}] = {}\n", hex(rk));
    }
    for rounds in 1..=ROUNDS {
        out += &format!("AFTER_ROUND[{rounds}] = {}\n", hex(&r.encrypt(p, rounds)));
    }
    out
}

/// One parsed vector.
pub struct Vector256 {
    pub key: [u8; 32],
    pub plaintext: Block256,
    pub ciphertext: Block256,
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

/// Parses the KEY / PLAINTEXT / CIPHERTEXT triples of a Turing-256 vector file.
pub fn parse_vectors(text: &str) -> Result<Vec<Vector256>, String> {
    let mut out = Vec::new();
    let (mut key, mut plaintext) = (None, None);
    for line in text.lines() {
        let Some((name, value)) = line.split_once(" = ") else { continue };
        let value = value.trim();
        match name.trim() {
            "KEY" => key = Some(unhex::<32>(value).ok_or(format!("bad KEY {value}"))?),
            "PLAINTEXT" => plaintext = Some(unhex::<32>(value).ok_or(format!("bad PLAINTEXT {value}"))?),
            "CIPHERTEXT" => {
                let ciphertext = unhex::<32>(value).ok_or(format!("bad CIPHERTEXT {value}"))?;
                out.push(Vector256 {
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
