//! An independent reference implementation of Turing-1026 (docs/16), written
//! from the specification, not from the turing crate's code: cSHAKE256 from
//! the sha3 library (the crate uses its own Keccak code for secrets), A as a
//! full matrix, arithmetic in i64 reduced with rem_euclid, noise and packing
//! bit by bit, and decoding phrased as "bit 1 iff x mod q lies in
//! [q/4, 3q/4)". It is slow and keeps secrets anywhere; it exists to check
//! the real implementation and to generate the known-answer vectors.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{CShake256Core, Sha3_256};
use turing::lwe::Params;

pub const TURING_1026: Params = Params { n: 1026, nbar: 32, mbar: 8, log_q: 15, eta: 18 };
const SALT: usize = 64;

fn cshake(label: &str, parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut h = CoreWrapper::from_core(CShake256Core::new(label.as_bytes()));
    for p in parts {
        h.update(p);
    }
    let mut out = vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

/// The byte stream of one noise seed, read `count` samples at a time; each
/// call starts at a fresh byte.
struct Noise {
    bytes: Vec<u8>,
    pos: usize,
}

impl Noise {
    fn new(label: &str, seed: &[u8], total_bytes: usize) -> Noise {
        Noise { bytes: cshake(label, &[seed], total_bytes), pos: 0 }
    }

    fn samples(&mut self, eta: u32, count: usize) -> Vec<i64> {
        let bits_needed = count * 2 * eta as usize;
        let bits: Vec<i64> = (0..bits_needed).map(|k| i64::from((self.bytes[self.pos + k / 8] >> (k % 8)) & 1)).collect();
        self.pos += bits_needed.div_ceil(8);
        bits.chunks(2 * eta as usize).map(|c| c[..eta as usize].iter().sum::<i64>() - c[eta as usize..].iter().sum::<i64>()).collect()
    }
}

fn noise_bytes(p: &Params, counts: &[usize]) -> usize {
    counts.iter().map(|c| (c * 2 * p.eta as usize).div_ceil(8)).sum()
}

fn matrix(p: &Params, seed_a: &[u8]) -> Vec<Vec<i64>> {
    (0..p.n)
        .map(|i| {
            let bytes = cshake(turing::lwe::MATRIX_LABEL, &[seed_a, &(i as u16).to_le_bytes()], 2 * p.n);
            bytes.chunks(2).map(|b| (i64::from(b[0]) + 256 * i64::from(b[1])) % (1 << p.log_q)).collect()
        })
        .collect()
}

fn pack(p: &Params, values: &[i64]) -> Vec<u8> {
    let bits: Vec<u8> = values.iter().flat_map(|&v| (0..p.log_q).map(move |k| ((v >> k) & 1) as u8)).collect();
    bits.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |acc, (k, &b)| acc | (b << k))).collect()
}

fn unpack(p: &Params, bytes: &[u8], count: usize) -> Vec<i64> {
    (0..count).map(|i| (0..p.log_q as usize).map(|k| i64::from((bytes[(i * p.log_q as usize + k) / 8] >> ((i * p.log_q as usize + k) % 8)) & 1) << k).sum()).collect()
}

/// A key pair of the plain-LWE encryption: S (n x nbar) and B = A S + E.
pub struct PkeKeys {
    pub s: Vec<i64>,
    pub b: Vec<i64>,
}

pub fn pke_keygen(p: &Params, seed_a: &[u8], noise_label: &str, noise_seed: &[u8]) -> PkeKeys {
    let q = 1i64 << p.log_q;
    let count = p.n * p.nbar;
    let mut noise = Noise::new(noise_label, noise_seed, noise_bytes(p, &[count, count]));
    let s = noise.samples(p.eta, count);
    let e = noise.samples(p.eta, count);
    let a = matrix(p, seed_a);
    let mut b = vec![0i64; count];
    for i in 0..p.n {
        for j in 0..p.nbar {
            let dot: i64 = (0..p.n).map(|k| a[i][k] * s[k * p.nbar + j]).sum();
            b[i * p.nbar + j] = (dot + e[i * p.nbar + j]).rem_euclid(q);
        }
    }
    PkeKeys { s, b }
}

/// (B', C) for message bits `msg` (bit i = coefficient i of C).
pub fn pke_encrypt(p: &Params, seed_a: &[u8], b: &[i64], msg: &[u8], noise_label: &str, noise_seed: &[u8]) -> (Vec<i64>, Vec<i64>) {
    let q = 1i64 << p.log_q;
    let (big, small) = (p.mbar * p.n, p.mbar * p.nbar);
    let mut noise = Noise::new(noise_label, noise_seed, noise_bytes(p, &[big, big, small]));
    let sp = noise.samples(p.eta, big);
    let ep = noise.samples(p.eta, big);
    let epp = noise.samples(p.eta, small);
    let a = matrix(p, seed_a);
    let mut bp = vec![0i64; big];
    for r in 0..p.mbar {
        for c in 0..p.n {
            let dot: i64 = (0..p.n).map(|k| sp[r * p.n + k] * a[k][c]).sum();
            bp[r * p.n + c] = (dot + ep[r * p.n + c]).rem_euclid(q);
        }
    }
    let mut cc = vec![0i64; small];
    for r in 0..p.mbar {
        for j in 0..p.nbar {
            let i = r * p.nbar + j;
            let dot: i64 = (0..p.n).map(|k| sp[r * p.n + k] * b[k * p.nbar + j]).sum();
            let bit = i64::from((msg[i / 8] >> (i % 8)) & 1);
            cc[i] = (dot + epp[i] + bit * (q / 2)).rem_euclid(q);
        }
    }
    (bp, cc)
}

pub fn pke_decrypt(p: &Params, s: &[i64], bp: &[i64], c: &[i64]) -> Vec<u8> {
    let q = 1i64 << p.log_q;
    let mut msg = vec![0u8; p.message_bytes()];
    for r in 0..p.mbar {
        for j in 0..p.nbar {
            let i = r * p.nbar + j;
            let x = (c[i] - (0..p.n).map(|k| bp[r * p.n + k] * s[k * p.nbar + j]).sum::<i64>()).rem_euclid(q);
            if (q / 4..3 * q / 4).contains(&x) {
                msg[i / 8] |= 1 << (i % 8);
            }
        }
    }
    msg
}

/// Turing-1026 from its seed.
pub struct ReferenceKem {
    pub public_key: Vec<u8>,
    seed_a: Vec<u8>,
    b: Vec<i64>,
    s: Vec<i64>,
    z: Vec<u8>,
    pk_hash: Vec<u8>,
}

impl ReferenceKem {
    pub fn from_seed(seed: &[u8; 32]) -> ReferenceKem {
        let p = TURING_1026;
        let derived = cshake("Turing-1026 v1 key generation", &[seed], 96);
        let (seed_a, noise_seed, z) = (&derived[..32], &derived[32..64], &derived[64..]);
        let keys = pke_keygen(&p, seed_a, "Turing-1026 v1 key noise", noise_seed);
        let mut public_key = seed_a.to_vec();
        public_key.extend(pack(&p, &keys.b));
        let pk_hash = cshake("Turing-1026 v1 public key", &[&public_key], 32);
        ReferenceKem { public_key, seed_a: seed_a.to_vec(), b: keys.b, s: keys.s, z: z.to_vec(), pk_hash }
    }

    fn encrypt(&self, mu: &[u8], salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let p = TURING_1026;
        let coins = cshake("Turing-1026 v1 coins", &[&self.pk_hash, mu, salt], 96);
        let (bp, c) = pke_encrypt(&p, &self.seed_a, &self.b, mu, "Turing-1026 v1 encryption noise", &coins[..64]);
        let mut ct = pack(&p, &bp);
        ct.extend(pack(&p, &c));
        ct.extend_from_slice(salt);
        (ct, coins[64..].to_vec())
    }

    /// (ciphertext, shared key) for a chosen message and salt.
    pub fn encapsulate(&self, mu: &[u8; 32], salt: &[u8; SALT]) -> (Vec<u8>, [u8; 32]) {
        let (ct, k) = self.encrypt(mu, salt);
        let key = cshake("Turing-1026 v1 shared key", &[&ct, &k], 32);
        (ct, key.try_into().expect("32"))
    }

    /// The shared key this ciphertext would give if the re-encryption check
    /// accepted it: cSHAKE256("shared key", c || k'), k' from G(h, Dec(s, c),
    /// salt). This is what a decapsulation fault that defeats the check leaks;
    /// the fault map (`fault1026`) compares the faulted output against it.
    pub fn accepted_key(&self, ct: &[u8]) -> [u8; 32] {
        let p = TURING_1026;
        let body = p.ciphertext_bytes();
        let bp = unpack(&p, &ct[..p.packed_bytes(p.mbar * p.n)], p.mbar * p.n);
        let c = unpack(&p, &ct[p.packed_bytes(p.mbar * p.n)..body], p.mbar * p.nbar);
        let mu = pke_decrypt(&p, &self.s, &bp, &c);
        let (_again, k) = self.encrypt(&mu, &ct[body..]);
        cshake("Turing-1026 v1 shared key", &[ct, &k], 32).try_into().expect("32")
    }

    /// The rejection key cSHAKE256("rejection key", z || h || c).
    pub fn rejection_key(&self, ct: &[u8]) -> [u8; 32] {
        cshake("Turing-1026 v1 rejection key", &[&self.z, &self.pk_hash, ct], 32).try_into().expect("32")
    }

    /// The rejection key with z left out, cSHAKE256("rejection key", h || c):
    /// what a fault that skips absorbing z would produce, computable by
    /// anyone who knows the public key, hence a validity oracle.
    pub fn rejection_key_without_z(&self, ct: &[u8]) -> [u8; 32] {
        cshake("Turing-1026 v1 rejection key", &[&self.pk_hash, ct], 32).try_into().expect("32")
    }

    /// The shared key, or the rejection key; None for a wrong length.
    pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; 32]> {
        let p = TURING_1026;
        let body = p.ciphertext_bytes();
        if ct.len() != body + SALT {
            return None;
        }
        let bp = unpack(&p, &ct[..p.packed_bytes(p.mbar * p.n)], p.mbar * p.n);
        let c = unpack(&p, &ct[p.packed_bytes(p.mbar * p.n)..body], p.mbar * p.nbar);
        let mu = pke_decrypt(&p, &self.s, &bp, &c);
        let (again, k) = self.encrypt(&mu, &ct[body..]);
        let key = if again == ct { cshake("Turing-1026 v1 shared key", &[ct, &k], 32) } else { cshake("Turing-1026 v1 rejection key", &[&self.z, &self.pk_hash, ct], 32) };
        Some(key.try_into().expect("32"))
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// One known-answer vector.
pub struct KemVector {
    pub seed: [u8; 32],
    pub public_key_sha3: [u8; 32],
    pub message: [u8; 32],
    pub salt: [u8; SALT],
    pub ciphertext_sha3: [u8; 32],
    pub shared_key: [u8; 32],
    /// Decapsulation of the ciphertext with its first byte XORed with 1.
    pub rejected_key: [u8; 32],
}

pub fn known_answer_vectors() -> Vec<KemVector> {
    let mut stream = CoreWrapper::from_core(CShake256Core::new(b"Turing-1026 v1 known-answer vectors")).finalize_xof();
    let mut inputs: Vec<([u8; 32], [u8; 32], [u8; SALT])> = vec![([0; 32], [0; 32], [0; SALT]), ([0xff; 32], [0xff; 32], [0xff; SALT])];
    for _ in 0..2 {
        let (mut seed, mut mu, mut salt) = ([0u8; 32], [0u8; 32], [0u8; SALT]);
        stream.read(&mut seed);
        stream.read(&mut mu);
        stream.read(&mut salt);
        inputs.push((seed, mu, salt));
    }
    inputs
        .into_iter()
        .map(|(seed, message, salt)| {
            let kem = ReferenceKem::from_seed(&seed);
            let (ct, shared_key) = kem.encapsulate(&message, &salt);
            let mut bad = ct.clone();
            bad[0] ^= 1;
            KemVector {
                seed,
                public_key_sha3: sha3_256(&kem.public_key),
                message,
                salt,
                ciphertext_sha3: sha3_256(&ct),
                shared_key,
                rejected_key: kem.decapsulate(&bad).expect("length"),
            }
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn render_vectors() -> String {
    let mut out = String::from(
        "# Turing-1026 v1 known-answer vectors (plain LWE, n = 1026, q = 2^15, CBD(18), nbar = 32, mbar = 8).\n\
         # @generated by `bombe vectors --turing-1026 --out vectors/turing-1026-v1.txt` from the\n\
         # independent reference implementation; the turing crate must reproduce every line.\n\
         # Byte strings in hex. The public key (61,592 bytes) and ciphertext (15,934 bytes) are\n\
         # given by their SHA3-256 digests. REJECTED_KEY is what decapsulation returns for the\n\
         # ciphertext with its first byte XORed with 1.\n",
    );
    for (i, v) in known_answer_vectors().iter().enumerate() {
        out += &format!(
            "\nCOUNT = {i}\nSEED = {}\nPUBLIC_KEY_SHA3_256 = {}\nMESSAGE = {}\nSALT = {}\nCIPHERTEXT_SHA3_256 = {}\nSHARED_KEY = {}\nREJECTED_KEY = {}\n",
            hex(&v.seed),
            hex(&v.public_key_sha3),
            hex(&v.message),
            hex(&v.salt),
            hex(&v.ciphertext_sha3),
            hex(&v.shared_key),
            hex(&v.rejected_key)
        );
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len().is_multiple_of(2)).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Parses the file `render_vectors` writes.
pub fn parse_vectors(text: &str) -> Result<Vec<KemVector>, String> {
    let mut out = Vec::new();
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    let finish = |fields: &mut Vec<(String, Vec<u8>)>, out: &mut Vec<KemVector>| -> Result<(), String> {
        if fields.is_empty() {
            return Ok(());
        }
        let get = |name: &str| -> Result<Vec<u8>, String> { fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()).ok_or(format!("missing {name}")) };
        let arr = |name: &str| -> Result<[u8; 32], String> { get(name)?.try_into().map_err(|_| format!("{name}: wrong length")) };
        out.push(KemVector {
            seed: arr("SEED")?,
            public_key_sha3: arr("PUBLIC_KEY_SHA3_256")?,
            message: arr("MESSAGE")?,
            salt: get("SALT")?.try_into().map_err(|_| "SALT: wrong length".to_string())?,
            ciphertext_sha3: arr("CIPHERTEXT_SHA3_256")?,
            shared_key: arr("SHARED_KEY")?,
            rejected_key: arr("REJECTED_KEY")?,
        });
        fields.clear();
        Ok(())
    };
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once(" = ").ok_or(format!("bad line: {line}"))?;
        if k == "COUNT" {
            finish(&mut fields, &mut out)?;
            continue;
        }
        fields.push((k.to_string(), unhex(v).ok_or(format!("bad hex in {k}"))?));
    }
    finish(&mut fields, &mut out)?;
    Ok(out)
}
