//! ML-KEM (turing::mlkem, FIPS 203) against the official vectors
//! (vectors/ml-kem-fips203.txt, made by tools/ml_kem_vectors.py from NIST's
//! ACVP-Server samples and C2SP CCTV) and against CCTV's accumulated tests,
//! whose 10,000 cases per parameter set are hashed into one value.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake128};
use turing::mlkem::{self, Params, ML_KEM_1024, ML_KEM_512, ML_KEM_768};

const VECTORS: &str = include_str!("../../../vectors/ml-kem-fips203.txt");

fn params(name: &str) -> Params {
    match name {
        "ML-KEM-512" => ML_KEM_512,
        "ML-KEM-768" => ML_KEM_768,
        "ML-KEM-1024" => ML_KEM_1024,
        _ => panic!("unknown parameter set {name}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha3(b: &[u8]) -> String {
    hex(&Sha3_256::digest(b))
}

fn arr(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// (kind, parameter set, fields) for every case in the file.
fn cases() -> Vec<(String, String, std::collections::HashMap<String, String>)> {
    let mut out = Vec::new();
    let (mut kind, mut set) = (String::new(), String::new());
    let mut fields = std::collections::HashMap::new();
    for line in VECTORS.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                out.push((kind.clone(), set.clone(), std::mem::take(&mut fields)));
            }
        } else if let Some(h) = line.strip_prefix('[') {
            let mut parts = h.trim_end_matches(']').split_whitespace();
            kind = parts.next().expect("kind").to_string();
            set = parts.next().expect("parameter set").to_string();
        } else {
            let (k, v) = line.split_once(" = ").expect("key = value");
            fields.insert(k.to_string(), v.to_string());
        }
    }
    out
}

#[test]
fn every_official_vector_passes() {
    let mut counts = std::collections::BTreeMap::new();
    for (kind, set, f) in cases() {
        let p = params(&set);
        let id = format!("{kind} {set} tcId {}", f.get("tcId").map_or("-", String::as_str));
        let (mut ek, mut dk) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
        let (mut c, mut key) = (vec![0u8; p.ct_bytes()], [0u8; 32]);
        match kind.as_str() {
            "keyGen" | "cctvUnluckyIpd" => {
                let (d, z) = (arr(&unhex(&f["d"])), arr(&unhex(&f["z"])));
                if kind == "keyGen" {
                    mlkem::keygen_internal(&p, &d, &z, &mut ek, &mut dk);
                } else {
                    mlkem::keygen_internal_ipd(&p, &d, &z, &mut ek, &mut dk);
                }
                assert_eq!(sha3(&ek), f["ek_sha3"], "{id}: ek");
                assert_eq!(sha3(&dk), f["dk_sha3"], "{id}: dk");
                assert!(mlkem::check_encapsulation_key(&p, &ek) && mlkem::check_decapsulation_key(&p, &dk), "{id}: own keys pass the checks");
                if kind == "cctvUnluckyIpd" {
                    mlkem::encaps_internal(&p, &ek, &arr(&unhex(&f["m"])), &mut c, &mut key);
                    assert_eq!(sha3(&c), f["c_sha3"], "{id}: c");
                    assert_eq!(hex(&key), f["k"], "{id}: K");
                    let mut back = [0u8; 32];
                    mlkem::decaps_internal(&p, &dk, &c, &mut back);
                    assert_eq!(back, key, "{id}: decapsulation");
                }
            }
            "encaps" => {
                let ek = unhex(&f["ek"]);
                assert!(mlkem::check_encapsulation_key(&p, &ek), "{id}: ACVP keys are valid");
                mlkem::encaps_internal(&p, &ek, &arr(&unhex(&f["m"])), &mut c, &mut key);
                assert_eq!(sha3(&c), f["c_sha3"], "{id}: c");
                assert_eq!(hex(&key), f["k"], "{id}: K");
            }
            "decaps" | "cctvStrcmp" => {
                let dk = unhex(&f["dk"]);
                mlkem::decaps_internal(&p, &dk, &unhex(&f["c"]), &mut key);
                assert_eq!(hex(&key), f["k"], "{id}: K");
            }
            "decapsSeed" => {
                mlkem::keygen_internal(&p, &arr(&unhex(&f["d"])), &arr(&unhex(&f["z"])), &mut ek, &mut dk);
                mlkem::decaps_internal(&p, &dk, &unhex(&f["c"]), &mut key);
                assert_eq!(hex(&key), f["k"], "{id}: K");
            }
            "ekCheck" => {
                assert_eq!(mlkem::check_encapsulation_key(&p, &unhex(&f["ek"])), f["valid"] == "1", "{id}");
            }
            "dkCheck" => {
                assert_eq!(mlkem::check_decapsulation_key(&p, &unhex(&f["dk"])), f["valid"] == "1", "{id}");
            }
            other => panic!("unknown kind {other}"),
        }
        *counts.entry(kind).or_insert(0) += 1;
    }
    println!("{counts:?}");
    // Every group of the file was reached (tools/ml_kem_vectors.py's counts).
    let expected = [("cctvStrcmp", 3), ("cctvUnluckyIpd", 3), ("decaps", 30), ("decapsSeed", 30), ("dkCheck", 30), ("ekCheck", 30), ("encaps", 75), ("keyGen", 75)];
    for (kind, n) in expected {
        assert_eq!(counts.get(kind), Some(&n), "{kind}");
    }
}

/// CCTV's accumulated test: a SHAKE-128 of the empty string supplies d, z,
/// m and a random ciphertext for each case; ek, dk, c, K and the key from
/// decapsulating the random ciphertext go into a running SHAKE-128, whose
/// first 32 bytes are compared. Every honest ciphertext must decapsulate.
fn accumulated(p: &Params, cases: usize, ipd: bool) -> String {
    let mut rng = Shake128::default().finalize_xof();
    let mut acc = Shake128::default();
    let (mut ek, mut dk) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
    let (mut c, mut random_c) = (vec![0u8; p.ct_bytes()], vec![0u8; p.ct_bytes()]);
    for i in 0..cases {
        let (mut d, mut z, mut m) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        rng.read(&mut d);
        rng.read(&mut z);
        rng.read(&mut m);
        rng.read(&mut random_c);
        if ipd {
            mlkem::keygen_internal_ipd(p, &d, &z, &mut ek, &mut dk);
        } else {
            mlkem::keygen_internal(p, &d, &z, &mut ek, &mut dk);
        }
        let (mut key, mut back, mut rejected) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        mlkem::encaps_internal(p, &ek, &m, &mut c, &mut key);
        mlkem::decaps_internal(p, &dk, &c, &mut back);
        assert_eq!(back, key, "{p:?}: case {i} does not decapsulate");
        mlkem::decaps_internal(p, &dk, &random_c, &mut rejected);
        for part in [&ek[..], &dk[..], &c[..], &key[..], &rejected[..]] {
            acc.update(part);
        }
    }
    let mut out = [0u8; 32];
    acc.finalize_xof().read(&mut out);
    hex(&out)
}

/// `accumulated` with the cases spread over every thread: the inputs are
/// drawn from the RNG in order, blocks of cases run in parallel, and each
/// case's outputs are absorbed in order, so the hash is the sequential one.
fn accumulated_parallel(p: &Params, cases: usize, ipd: bool) -> String {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut rng = Shake128::default().finalize_xof();
    let mut acc = Shake128::default();
    let mut done = 0;
    while done < cases {
        let block = (cases - done).min(8192);
        // Per case: d, z and m (32 bytes each), then the random ciphertext.
        let inputs: Vec<([u8; 96], Vec<u8>)> = (0..block)
            .map(|_| {
                let (mut dzm, mut random_c) = ([0u8; 96], vec![0u8; p.ct_bytes()]);
                rng.read(&mut dzm);
                rng.read(&mut random_c);
                (dzm, random_c)
            })
            .collect();
        let mut outputs = vec![Vec::new(); block];
        let per = block.div_ceil(threads);
        std::thread::scope(|scope| {
            for (ins, outs) in inputs.chunks(per).zip(outputs.chunks_mut(per)) {
                scope.spawn(move || {
                    for ((dzm, random_c), out) in ins.iter().zip(outs) {
                        let (d, z, m) = (arr(&dzm[..32]), arr(&dzm[32..64]), arr(&dzm[64..]));
                        let (mut ek, mut dk) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
                        if ipd {
                            mlkem::keygen_internal_ipd(p, &d, &z, &mut ek, &mut dk);
                        } else {
                            mlkem::keygen_internal(p, &d, &z, &mut ek, &mut dk);
                        }
                        let (mut c, mut key, mut back, mut rejected) = (vec![0u8; p.ct_bytes()], [0u8; 32], [0u8; 32], [0u8; 32]);
                        mlkem::encaps_internal(p, &ek, &m, &mut c, &mut key);
                        mlkem::decaps_internal(p, &dk, &c, &mut back);
                        assert_eq!(back, key, "{p:?}: a case does not decapsulate");
                        mlkem::decaps_internal(p, &dk, random_c, &mut rejected);
                        *out = [&ek[..], &dk[..], &c[..], &key[..], &rejected[..]].concat();
                    }
                });
            }
        });
        for out in &outputs {
            acc.update(out);
        }
        done += block;
    }
    let mut out = [0u8; 32];
    acc.finalize_xof().read(&mut out);
    hex(&out)
}

// CCTV's 1,000,000-case accumulated hashes (draft mode, like the 10,000-case
// ones): three million key generations, encapsulations and pairs of
// decapsulations, on every thread. The parallel runner first reproduces the
// sequential 10,000-case hashes, so a scheduling mistake cannot pass. Run it
// with `cargo test --release -p bombe --test mlkem -- --ignored` (tools/ci.py
// stage mlkem-million).
#[test]
#[ignore = "two and a half minutes of every CPU thread; tools/ci.py runs it in the full profile"]
fn cctv_accumulated_one_million() {
    let sets = [
        (ML_KEM_512, "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4", "578eeaa1156848cbf7a15bafef963b4ccabe3308ddfb7dbdd20ad965f634e81d"),
        (ML_KEM_768, "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3", "70090cc5842aad0ec43d5042c783fae9bc320c047b5dafcb6e134821db02384d"),
        (ML_KEM_1024, "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543", "7ccc6d803739d3db3c5ce39c7130f459db32a199c6605e3be210e5a89d4c4b95"),
    ];
    for (p, ten_thousand, million) in sets {
        assert_eq!(accumulated_parallel(&p, 10_000, true), ten_thousand, "{p:?}: the parallel runner at 10,000 cases");
        assert_eq!(accumulated_parallel(&p, 1_000_000, true), million, "{p:?}: CCTV's published 1,000,000-case hash");
    }
}

// CCTV publishes the hash of the draft-mode (G(d)) run, which this must
// reproduce exactly. The final-mode (G(d || k)) hashes come from the
// research's independent Python implementation
// (research/scripts/pq/cca_mlkem_accumulated.py, cca_mlkem_ref.py), whose
// draft-mode run also reproduces CCTV's values: agreement is a differential
// test over the same 10,000 cases.
#[test]
fn cctv_accumulated_vectors_draft_and_final() {
    let sets = [
        (ML_KEM_512, "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4", "705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13"),
        (ML_KEM_768, "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3", "f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1"),
        (ML_KEM_1024, "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543", "e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5"),
    ];
    for (p, draft, fin) in sets {
        assert_eq!(accumulated(&p, 10_000, true), draft, "{p:?}: CCTV's published draft-mode hash");
        assert_eq!(accumulated(&p, 10_000, false), fin, "{p:?}: the independent Python implementation's final-mode hash");
    }
}

// The modulus check (FIPS 203 section 7.2) at every coefficient position
// with the smallest and largest out-of-range values, and at one position with
// every out-of-range value: CCTV's "modulus" vectors, generated here.
#[test]
fn every_unreduced_coefficient_fails_the_modulus_check() {
    for p in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        let (mut ek, mut dk) = (vec![0u8; p.ek_bytes()], vec![0u8; p.dk_bytes()]);
        mlkem::keygen_internal(&p, &[5; 32], &[6; 32], &mut ek, &mut dk);
        assert!(mlkem::check_encapsulation_key(&p, &ek));
        let set = |ek: &mut [u8], i: usize, v: u16| {
            let (byte, odd) = (i / 2 * 3, i % 2 == 1);
            if odd {
                ek[byte + 1] = (ek[byte + 1] & 0x0f) | ((v << 4) as u8);
                ek[byte + 2] = (v >> 4) as u8;
            } else {
                ek[byte] = v as u8;
                ek[byte + 1] = (ek[byte + 1] & 0xf0) | ((v >> 8) as u8 & 0x0f);
            }
        };
        for i in 0..256 * p.k {
            for v in [3329, 4095] {
                let mut bad = ek.clone();
                set(&mut bad, i, v);
                assert!(!mlkem::check_encapsulation_key(&p, &bad), "{p:?}: coefficient {i} = {v} accepted");
            }
        }
        for v in 3329..4096 {
            let mut bad = ek.clone();
            set(&mut bad, 77, v);
            assert!(!mlkem::check_encapsulation_key(&p, &bad), "{p:?}: coefficient 77 = {v} accepted");
            set(&mut bad, 77, v - 3329);
            assert!(mlkem::check_encapsulation_key(&p, &bad), "{p:?}: coefficient 77 = {} refused", v - 3329);
        }
        assert!(!mlkem::check_encapsulation_key(&p, &ek[..ek.len() - 1]), "type check");
        let mut bad_dk = dk.clone();
        let hash_at = 768 * p.k + 32;
        bad_dk[hash_at] ^= 1;
        assert!(!mlkem::check_decapsulation_key(&p, &bad_dk), "{p:?}: hash check");
    }
}
