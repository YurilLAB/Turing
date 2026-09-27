"""Mutation checks: plant one bug, run the named tests, restore the file.

Each mutation must make at least one test fail; the script reports which
tests caught it and always restores the original file (and verifies it). A
test run that exceeds the time limit has not passed either: it counts as
caught, and the whole process tree is killed.

    python tools/mutate.py [--step8 | --step9 | --round3 | --round4 | --round5 | --round6] [--check] [NAME ...]

--check only verifies that every pattern still matches the current code
exactly once, without running any tests. NAME filters mutations by name.
Test arguments that start with "--wsl" run the tests on Linux in WSL
(tools/wsl_linux.py), for the Linux-only code paths.
"""
import os
import pathlib
import signal
import subprocess
import sys

TIMEOUT = 580

ROOT = pathlib.Path(__file__).resolve().parent.parent

MUTATIONS_STEP8 = [
    ("gf: 8-lane multiply lets carries leak between lanes", "crates/turing/src/gf.rs",
     "a = ((a << 1) & LANES_CLEAR_LOW_BIT) ^ carry;", "a = (a << 1) ^ carry;",
     ["-p", "turing", "--lib"]),
    ("gf: inverse chain ends on x^253", "crates/turing/src/gf.rs",
     "mul8(x252, x2)\n}", "mul8(x252, x)\n}",
     ["-p", "turing", "--lib"]),
    ("linear: fast MixState swaps its two output halves", "crates/turing/src/linear.rs",
     "out[..8].copy_from_slice(&y[0].to_le_bytes());", "out[..8].copy_from_slice(&y[1].to_le_bytes());",
     ["-p", "turing", "--lib"]),
    ("cipher: round keys off by one", "crates/turing/src/cipher.rs",
     "            add_round_key(block, self.keys.key(round));\n        }\n    }",
     "            add_round_key(block, self.keys.key(round - 1));\n        }\n    }",
     ["-p", "bombe", "--test", "cipher"]),
    ("cipher: decryption applies the forward layer", "crates/turing/src/cipher.rs",
     "*block = linear::invert_layer(layer, block);", "*block = linear::apply_layer(layer, block);",
     ["-p", "turing", "--lib"]),
    ("reference: MixState in even rounds", "crates/bombe/src/refcipher.rs",
     "    round % 2 == 1\n}", "    round % 2 == 0\n}",
     ["-p", "bombe", "--test", "cipher"]),
    ("square attack: forward S-box instead of inverse", "crates/bombe/src/integral.rs",
     "acc ^ inv[(c[j] ^ k) as usize]", "acc ^ turing::sbox::TABLE[(c[j] ^ k) as usize]",
     ["-p", "bombe", "--test", "attacks"]),
    ("nist: spectral threshold at 1% instead of 5%", "crates/bombe/src/nist.rs",
     "((1.0f64 / 0.05).ln() * n as f64).sqrt()", "((1.0f64 / 0.01).ln() * n as f64).sqrt()",
     ["-p", "bombe", "--test", "nist"]),
    ("nist: longest-run class probability typo", "crates/bombe/src/nist.rs",
     "0.0882, 0.2092, 0.2483", "0.0882, 0.2092, 0.2438",
     ["-p", "bombe", "--test", "nist"]),
    ("nist: serial test without wrap-around", "crates/bombe/src/nist.rs",
     "e.0[(i + m - 1) % n] as usize", "e.0[(i + m - 1).min(n - 1)] as usize",
     ["-p", "bombe", "--test", "nist"]),
    ("timing control made constant-time", "crates/bombe/src/timing.rs",
     "result = crate::gf256::mul(result, base);\n            }\n            base = crate::gf256::mul(base, base);",
     "result = turing::gf::mul(result, base);\n            }\n            base = turing::gf::mul(base, base);",
     ["-p", "bombe", "--test", "attacks", "timing"]),
    ("battery: false-alarm budget 100x looser", "crates/bombe/src/battery.rs",
     "pub const FAMILY_ALPHA: f64 = 0.001;", "pub const FAMILY_ALPHA: f64 = 0.1;",
     ["-p", "bombe", "--test", "attacks"]),
    ("truncated differential counts changed bytes", "crates/bombe/src/differential.rs",
     ".filter(|(a, b)| a == b).count() as u64;", ".filter(|(a, b)| a != b).count() as u64;",
     ["-p", "bombe", "--test", "attacks"]),
]

MUTATIONS_STEP9 = [
    ("xof: secret cSHAKE drops its label", "crates/turing/src/xof.rs",
     "let mut core = CShake256Core::new(label.as_bytes());", 'let mut core = CShake256Core::new(b"");',
     ["-p", "turing", "--lib"]),
    ("keyschedule: right half of K' copied from the left half", "crates/turing/src/keyschedule.rs",
     "whitened[16 + i]", "whitened[i]",
     ["-p", "bombe", "--test", "cipher"]),
    ("cipher: Turing gains a Debug impl that prints a round key", "crates/turing/src/cipher.rs",
     "pub struct Turing {\n    keys: RoundKeys<ROUND_KEYS>,\n}\n",
     "pub struct Turing {\n    keys: RoundKeys<ROUND_KEYS>,\n}\n\nimpl core::fmt::Debug for Turing {\n    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {\n        write!(f, \"{:?}\", self.keys.key(0))\n    }\n}\n",
     ["-p", "turing", "--lib"]),
    ("division: S-box keeps degree 2 of structure (unsound)", "crates/bombe/src/division.rs",
     "        _ => 1,\n", "        _ => 2,\n",
     ["-p", "bombe", "--test", "division"]),
    ("structured square: forward S-box in the key test", "crates/bombe/src/integral.rs",
     ".fold(0u8, |acc, c| acc ^ inv[(c ^ k) as usize])", ".fold(0u8, |acc, c| acc ^ turing::sbox::TABLE[(c ^ k) as usize])",
     ["-p", "bombe", "--test", "classic_attacks", "structured"]),
    ("boomerang: only one ciphertext shifted", "crates/bombe/src/boomerang.rs",
     "        c2[0] ^= d;\n", "",
     ["-p", "bombe", "--test", "classic_attacks", "boomerang"]),
    ("cube: each worker skips one plaintext", "crates/bombe/src/cube.rs",
     "for index in total * w / threads..total * (w + 1) / threads {", "for index in total * w / threads + 1..total * (w + 1) / threads {",
     ["-p", "bombe", "--test", "classic_attacks", "cube"]),
    ("relatedkey: difference weight counts one byte", "crates/bombe/src/relatedkey.rs",
     "a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()", "a.iter().zip(b).take(1).map(|(x, y)| (x ^ y).count_ones()).sum()",
     ["-p", "bombe", "--test", "classic_attacks", "related"]),
    ("fault: DFA uses a row of MixState instead of a column", "crates/bombe/src/fault.rs",
     "let target = gf::mul(linear::MIX_STATE[j][p], beta);", "let target = gf::mul(linear::MIX_STATE[p][j], beta);",
     ["-p", "bombe", "--test", "classic_attacks", "fault"]),
    ("fault: fault injected one round late", "crates/bombe/src/fault.rs",
     "        if r == round {", "        if r == round + 1 {",
     ["-p", "bombe", "--test", "classic_attacks", "fault"]),
    ("interpolation: coefficients stored reversed", "crates/bombe/src/interpolation.rs",
     "c[255 - e] ^= gf256::mul(y, p);", "c[e] ^= gf256::mul(y, p);",
     ["-p", "bombe", "--lib", "interpolation"]),
    ("invariant: closure forgets the images of new vectors", "crates/bombe/src/invariant.rs",
     "            if span.insert(w) {\n                queue.push(w);\n            }", "            span.insert(w);",
     ["-p", "bombe", "--lib", "invariant"]),
    ("invariant: Turing layer map always MixState", "crates/bombe/src/invariant.rs",
     "linear::apply_layer(layer, &v.to_le_bytes())", "linear::apply_layer(Layer::MixState, &v.to_le_bytes())",
     ["-p", "bombe", "--lib", "invariant"]),
    ("invariant: differences mixed across layers", "crates/bombe/src/invariant.rs",
     "structure::layer(r) == Some(layer)", "structure::layer(r).is_some()",
     ["-p", "bombe", "--lib", "invariant"]),
    ("boomerang: return shift uses MixState instead of its inverse", "crates/bombe/src/boomerang.rs",
     "let c = turing::gf::mul(m_inv, t);", "let c = turing::gf::mul(m, t);",
     ["-p", "bombe", "--test", "classic_attacks", "boomerang"]),
    ("power: attacker's model adds the key instead of XOR", "crates/bombe/src/power.rs",
     "sbox::TABLE[(p[j] ^ k) as usize]", "sbox::TABLE[p[j].wrapping_add(k) as usize]",
     ["-p", "bombe", "--test", "classic_attacks", "cpa"]),
]

MUTATIONS_ROUND3 = [
    ("provable: Park bound uses one power too few", "crates/bombe/src/provable.rs",
     "u128::from(v).checked_pow(power)", "u128::from(v).checked_pow(power - 1)",
     ["-p", "bombe", "--lib", "provable"]),
    ("provable: pruning ignores future doublings", "crates/bombe/src/provable.rs",
     "let bound = next.sum() + ((1u64 << remaining) - 1) * next.largest();", "let bound = next.sum();",
     ["-p", "bombe", "--release", "--test", "kerckhoffs", "keliher_sui"]),
    ("provable: round-2 inner differences taken from round 1", "crates/bombe/src/provable.rs",
     "col[ins.len() + q] = ys[j];", "col[ins.len() + q] = xs[j];",
     ["-p", "bombe", "--release", "--test", "kerckhoffs", "keliher_sui"]),
    ("symmetry: permutation check accepts any match", "crates/bombe/src/symmetry.rs",
     "if (0..depth).all(|i| m[perm[i]][c] == m[i][depth]", "if (0..depth).any(|i| m[perm[i]][c] == m[i][depth]",
     ["-p", "bombe", "--test", "kerckhoffs", "symmetries"]),
    ("symmetry: pair search reads the wrong column", "crates/bombe/src/symmetry.rs",
     "(0..16).find(|&r| m[r][pi_in[0]] == m[i][0])", "(0..16).find(|&r| m[r][pi_in[1]] == m[i][0])",
     ["-p", "bombe", "--lib", "symmetry"]),
    ("symmetry: scalings skip b = 0", "crates/bombe/src/symmetry.rs",
     "        for b in 0..=255u8 {", "        for b in 1..=255u8 {",
     ["-p", "bombe", "--lib", "symmetry"]),
    ("symmetry: cross-ratio test inverted", "crates/bombe/src/symmetry.rs",
     "!in_gf16(ratio)", "in_gf16(ratio)",
     ["-p", "bombe", "--test", "kerckhoffs", "symmetries"]),
    ("symmetry: reflection map composed in the wrong order", "crates/bombe/src/symmetry.rs",
     "a_in_inv[a_out_inv[x] as usize]", "a_out_inv[a_in_inv[x] as usize]",
     ["-p", "bombe", "--lib", "symmetry"]),
    ("keyrelations: AES round constant typo", "crates/bombe/src/keyrelations.rs",
     "0x80, 0x1b, 0x36]", "0x80, 0x1c, 0x36]",
     ["-p", "bombe", "--lib", "keyrelations"]),
    ("keyrelations: constant column dropped", "crates/bombe/src/keyrelations.rs",
     "            bits[(columns - 1) / 64] |= 1 << ((columns - 1) % 64);\n", "",
     ["-p", "bombe", "--test", "kerckhoffs", "key_schedule"]),
    ("difflinear: prediction reads a row of MixState", "crates/bombe/src/difflinear.rs",
     "let m = turing::linear::MIX_STATE[j][0];", "let m = turing::linear::MIX_STATE[0][j];",
     ["-p", "bombe", "--test", "kerckhoffs", "differential_linear"]),
    ("selftest: encryption uses the previous round key", "crates/turing/src/cipher.rs",
     "            add_round_key(block, self.keys.key(round));\n        }\n    }",
     "            add_round_key(block, self.keys.key(round - 1));\n        }\n    }",
     ["-p", "turing", "--lib", "self_test"]),
    ("checked: comparison ANDs instead of ORs", "crates/turing/src/cipher.rs",
     "fold(0u8, |acc, (a, b)| acc | (a ^ b))", "fold(0u8, |acc, (a, b)| acc & (a ^ b))",
     ["-p", "turing", "--lib", "checked"]),
    ("checked: faulty output released", "crates/turing/src/cipher.rs",
     "    } else {\n        block.zeroize();\n        Err(FaultDetected)", "    } else {\n        Err(FaultDetected)",
     ["-p", "turing", "--lib", "checked"]),
]

MUTATIONS = [
    ("trail: MixColumns branch 5 -> 4", "crates/bombe/src/trail.rs",
     "x.count_ones() + y.count_ones() >= 5)\n}", "x.count_ones() + y.count_ones() >= 4)\n}",
     ["-p", "bombe", "--test", "rounds"]),
    ("trail: MixState branch 17 -> 16", "crates/bombe/src/trail.rs",
     "*slot = at_least[(17 - wy).max(1)];", "*slot = at_least[(16 - wy).max(1)];",
     ["-p", "bombe", "--test", "rounds"]),
    ("impossible: claim 'all non-zero' even with unknown bytes", "crates/bombe/src/impossible.rs",
     "} else if nz.count_ones() == 1 && unknown == 0 {", "} else if nz.count_ones() == 1 {",
     ["-p", "bombe", "--test", "rounds"]),
    ("impossible: forget the branch-number check across layers", "crates/bombe/src/impossible.rs",
     "let non_zero = in_max >= 1 && out_max >= 1 && in_max + out_max >= branch;",
     "let non_zero = in_max >= 1 && out_max >= 1;",
     ["-p", "bombe", "--test", "rounds"]),
    ("key schedule: 12 warm-up rounds", "crates/turing/src/keyschedule.rs",
     "pub const WARMUP_ROUNDS: usize = 13;", "pub const WARMUP_ROUNDS: usize = 12;",
     ["-p", "bombe", "--test", "keyschedule"]),
    ("xof: plain SHAKE (empty customization)", "crates/turing/src/xof.rs",
     "CoreWrapper::from_core(CShake256Core::new(label.as_bytes()))", "CoreWrapper::from_core(CShake256Core::new(&[]))",
     ["-p", "turing", "--lib"]),
    ("structure: MixState in even rounds", "crates/turing/src/structure.rs",
     "} else if round % 2 == 1 {", "} else if round % 2 == 0 {",
     ["-p", "bombe", "--test", "rounds"]),
    ("structure: 22 rounds", "crates/turing/src/structure.rs",
     "pub const ROUNDS: usize = 24;", "pub const ROUNDS: usize = 22;",
     ["-p", "bombe", "--test", "rounds"]),
]

TURING = ["-p", "turing", "--lib"]
MUTATIONS_ROUND4 = [
    # Keys in memory
    ("memory: key pages not locked", "crates/turing/src/memory.rs",
     "let locked = unsafe { VirtualLock(ptr.as_ptr().cast(), size) } != 0;", "let locked = false;",
     TURING),
    ("memory: drop skips the wipe", "crates/turing/src/memory.rs",
     "        (**self).zeroize();\n        // SAFETY: the value's bytes", "        // SAFETY: the value's bytes",
     TURING),
    ("memory: burn_stack writes nothing", "crates/turing/src/memory.rs",
     "        unsafe { words.add(i).write_volatile(0) };", "        let _ = unsafe { words.add(i) };",
     TURING),
    ("memory: burn covers 1 KB", "crates/turing/src/memory.rs",
     "pub const BURN_BYTES: usize = 32 * 1024;", "pub const BURN_BYTES: usize = 1024;",
     ["-p", "bombe", "--release", "--test", "memory", "--", "--test-threads=1"]),
    ("memory (Linux): pages left in core dumps", "crates/turing/src/memory.rs",
     "advise(raw, size, libc::MADV_DONTDUMP)", "true",
     ["--wsl", "-p", "turing", "--lib"]),
    ("memory (Linux): pages not wiped on fork", "crates/turing/src/memory.rs",
     "wipe_on_fork && advise(raw, size, libc::MADV_WIPEONFORK)", "wipe_on_fork",
     ["--wsl", "-p", "turing", "--lib"]),
    ("memory (Linux): refused advice reported as taken", "crates/turing/src/memory.rs",
     "libc::madvise(raw, size, advice) == 0", "{ libc::madvise(raw, size, advice); true }",
     ["--wsl", "-p", "turing", "--lib"]),
    # Randomness
    ("random: seed left in the stream state", "crates/turing/src/random.rs",
     "        keccak::f1600(&mut st.lanes);\n        st.block.zeroize();", "        keccak::f1600(&mut st.lanes);",
     TURING),
    ("random: stream padded like SHA-3 instead of cSHAKE", "crates/turing/src/random.rs",
     "st.lanes[SEED_BYTES / 8] ^= 0x04 << (8 * (SEED_BYTES % 8));", "st.lanes[SEED_BYTES / 8] ^= 0x06 << (8 * (SEED_BYTES % 8));",
     TURING),
    ("random: check_fork never reseeds", "crates/turing/src/random.rs",
     "if self.state.seeded == 0 || self.state.pid != u64::from(std::process::id()) {", "if false {",
     TURING),
    ("random (Linux): a wiped state is not reseeded", "crates/turing/src/random.rs",
     "        if self.state.seeded == 0 {\n            self.check_fork();\n        }", "",
     ["--wsl", "-p", "turing", "--lib"]),
    ("random (Linux): public fill skips the process check", "crates/turing/src/random.rs",
     "    pub fn fill(&mut self, out: &mut [u8]) {\n        self.check_fork();\n", "    pub fn fill(&mut self, out: &mut [u8]) {\n",
     ["--wsl", "-p", "turing", "--lib"]),
    ("random (Linux): public u64 skips the process check", "crates/turing/src/random.rs",
     "    pub fn u64(&mut self) -> u64 {\n        self.check_fork();\n", "    pub fn u64(&mut self) -> u64 {\n",
     ["--wsl", "-p", "turing", "--lib"]),
    ("random (Linux): public block skips the process check", "crates/turing/src/random.rs",
     "    pub fn block(&mut self) -> [u8; 16] {\n        self.check_fork();\n", "    pub fn block(&mut self) -> [u8; 16] {\n",
     ["--wsl", "-p", "turing", "--lib"]),
    ("random: new_key is the raw OS seed", "crates/turing/src/random.rs",
     "    crate::xof::cshake256_secret(KEY_LABEL, seed, &mut key[..]);", "    key.copy_from_slice(&seed[..32]);",
     TURING),
    # Masking
    ("masked: key shares not re-randomised per call", "crates/turing/src/masked.rs",
     "        self.stream.check_fork();\n        self.refresh();\n        let mask = halves(&self.stream.draw_block());\n        let data = halves(block);\n        let mut st = State { s: [[data[0] ^ mask[0], data[1] ^ mask[1]], mask] };\n        st.add_key(&self.shares, 0);",
     "        self.stream.check_fork();\n        let mask = halves(&self.stream.draw_block());\n        let data = halves(block);\n        let mut st = State { s: [[data[0] ^ mask[0], data[1] ^ mask[1]], mask] };\n        st.add_key(&self.shares, 0);",
     TURING),
    ("masked: no fork check before encrypting", "crates/turing/src/masked.rs",
     "    fn encrypt_inner(&mut self, block: &mut Block, mut probe: Probe) {\n        self.stream.check_fork();", "    fn encrypt_inner(&mut self, block: &mut Block, mut probe: Probe) {",
     TURING),
    ("masked: SecMult forms the unmasked product (same output)", "crates/turing/src/masked.rs",
     "    let r10 = cross ^ mul(a.1, b.0);", "    let r10 = r ^ mul(a.0 ^ a.1, b.0 ^ b.1) ^ mul(a.0, b.0) ^ mul(a.1, b.1);",
     ["-p", "bombe", "--release", "--test", "leakage", "intermediate"]),
    ("masked: SecExp254 skips the first refresh (same output)", "crates/turing/src/masked.rs",
     "    let z = refresh(square(x), stream); // x^2", "    let z = square(x); // x^2",
     ["-p", "bombe", "--release", "--test", "leakage", "intermediate"]),
    ("masked: S-box output recombined, then re-shared as (y, 0) (same output)", "crates/turing/src/masked.rs",
     "    noted((map_out.apply(y.0), map_out.apply(y.1) ^ map_out.apply(0)))", "    noted((map_out.apply(y.0 ^ y.1), 0))",
     ["-p", "bombe", "--release", "--test", "leakage"]),
    # Shielding
    ("shield: refresh does not re-mask", "crates/turing/src/shield.rs",
     "        for (s, d) in self.shielded.iter_mut().zip(&delta) {\n            *s ^= d;\n        }\n", "",
     TURING),
    ("shield: key stored in the clear", "crates/turing/src/shield.rs",
     "            *s = k ^ mk;", "            *s = *k;",
     TURING),
    # Integrity and time of check to time of use
    ("cipher: no key check after the computation", "crates/turing/src/cipher.rs",
     "        if result.is_err() || !self.keys.intact() {", "        if result.is_err() {",
     TURING),
    ("masked: no share check after the computation", "crates/turing/src/masked.rs",
     "        if diff != 0 || !self.intact() {", "        if diff != 0 {",
     TURING),
    ("checksum: last round key left out", "crates/turing/src/keyschedule.rs",
     "keys.iter().rev().fold(0u128,", "keys[..keys.len() - 1].iter().rev().fold(0u128,",
     TURING),
    ("checksum: public point x (version 2's first checksum)", "crates/turing/src/keyschedule.rs",
     "    let h = u128::from_le_bytes(*point);", "    let h = 2u128;",
     TURING),
    ("checksum: weights start at H^0, so RK_0 and the checksum cancel", "crates/turing/src/keyschedule.rs",
     "gf::mul128(acc ^ u128::from_le_bytes(*k), h)", "gf::mul128(acc, h) ^ u128::from_le_bytes(*k)",
     TURING),
    ("checksum: point not derived from the key", "crates/turing/src/keyschedule.rs",
     "    xof::cshake256_secret(CHECK_LABEL, &whitened, point);", "    point.copy_from_slice(&[2; 16]);",
     TURING),
    ("masked: checksum point never drawn", "crates/turing/src/masked.rs",
     "        shares.point = stream.draw_block();\n", "",
     TURING),
    ("gf128: product left unreduced", "crates/turing/src/gf.rs",
     "    reduce128(low ^ (middle << 64), high ^ (middle >> 64))", "    low ^ (middle << 64)",
     TURING),
    ("gf128: overflow of the reduction not folded back", "crates/turing/src/gf.rs",
     " ^ over ^ (over << 1) ^ (over << 2) ^ (over << 7)", "",
     TURING),
    ("gf128: high half of a 64-bit product not realigned", "crates/turing/src/gf.rs",
     ".reverse_bits() >> 1;", ".reverse_bits();",
     TURING),
    # The attackers themselves
    ("memscan: fragments never match", "crates/bombe/src/memscan.rs",
     "        let masked = window ^ self.pad;", "        let masked = window;",
     ["-p", "bombe", "--release", "--test", "memory", "--", "--test-threads=1"]),
    ("memscan: the setup thread is scanned after it moves on", "crates/bombe/src/memscan.rs",
     "            out.push(at_step(step, stack));\n            parker.release.store(step, Ordering::Release);",
     "            parker.release.store(step, Ordering::Release);\n            out.push(at_step(step, stack));",
     ["-p", "bombe", "--release", "--test", "memory", "--", "--test-threads=1"]),
    ("leakage: CPA predicts with the inverse S-box", "crates/bombe/src/leakage.rs",
     "let s = sbox::TABLE[v ^ k as usize];", "let s = turing::sbox::inv_sub((v ^ k as usize) as u8);",
     ["-p", "bombe", "--release", "--test", "leakage"]),
]

BOMBE_LIB = ["-p", "bombe", "--release", "--lib"]
MUTATIONS_ROUND5 = [
    # Table-driven rounds
    ("fast: tables built from the inverse S-box", "crates/bombe/src/fast.rs",
     "for (v, &y) in sbox.iter().enumerate() {", "for (v, &y) in inv_sbox.iter().enumerate() {",
     BOMBE_LIB + ["fast"]),
    ("fast: the last round keeps a linear layer", "crates/bombe/src/fast.rs",
     "        sub(x) ^ self.keys[rounds]", "        sub_then(Layer::MixState, x) ^ self.keys[rounds]",
     BOMBE_LIB + ["fast"]),
    # The square attack with round key 0 guessed
    ("keyed square: plaintexts skip the inverse S-box", "crates/bombe/src/keyedsquare.rs",
     "fast::inv_sub(fast::invert(Layer::MixState, z)) ^ rk0", "fast::invert(Layer::MixState, z) ^ rk0",
     BOMBE_LIB + ["keyedsquare"]),
    ("keyed square: ShiftRows undone the wrong way", "crates/bombe/src/keyedsquare.rs",
     "let p = 4 * ((c + 4 - r) % 4) + r;", "let p = 4 * ((c + r) % 4) + r;",
     BOMBE_LIB + ["keyedsquare"]),
    ("keyed square: partial sums drop k3", "crates/bombe/src/keyedsquare.rs",
     "let x3 = x2 ^ s[3][c3 as usize ^ k3];", "let x3 = x2 ^ s[3][c3 as usize];",
     BOMBE_LIB + ["keyedsquare"]),
    ("keyed square: a column survives with one target", "crates/bombe/src/keyedsquare.rs",
     "        if es.iter().all(|e| !e.is_empty()) {", "        if es.iter().any(|e| !e.is_empty()) {",
     BOMBE_LIB + ["keyedsquare"]),
    ("keyed square: round key 6 guesses face one structure", "crates/bombe/src/keyedsquare.rs",
     "                structures.iter().all(|s| {", "                structures.iter().take(1).all(|s| {",
     BOMBE_LIB + ["keyedsquare"]),
    ("keyed square: the diagonal misses a byte", "crates/bombe/src/keyedsquare.rs",
     "pub const DIAGONAL: [usize; 4] = [0, 5, 10, 15];", "pub const DIAGONAL: [usize; 4] = [0, 5, 10, 14];",
     BOMBE_LIB + ["keyedsquare"]),
    # Yoyo
    ("yoyo: swap a word where the texts agree", "crates/bombe/src/yoyo.rs",
     "let first = zeros.iter().position(|&z| !z)?;", "let first = zeros.iter().position(|&z| z).unwrap_or(0);",
     BOMBE_LIB + ["yoyo"]),
    ("yoyo: zero pattern reads one byte per word", "crates/bombe/src/yoyo.rs",
     "words.iter().map(|w| w.iter().all(|&i| a[i] == b[i])).collect()", "words.iter().map(|w| a[w[0]] == b[w[0]]).collect()",
     BOMBE_LIB + ["yoyo"]),
    ("aes: yoyo shape keeps round 1's ShiftRows", "crates/bombe/src/aes.rs",
     "Shape::Yoyo => (round > 1 && round < rounds, round < rounds),", "Shape::Yoyo => (round < rounds, round < rounds),",
     ["-p", "bombe", "--release", "--test", "yoyo"]),
    # Meet-in-the-middle
    ("mitm: MixColumns reads the wrong diagonal", "crates/bombe/src/mitm.rs",
     "(0..4).fold(0, |acc, r| acc | 1 << (4 * ((c + r) % 4) + r))", "(0..4).fold(0, |acc, r| acc | 1 << (4 * ((c + 4 - r) % 4) + r))",
     BOMBE_LIB + ["mitm"]),
    ("mitm: active bytes counted whether needed or not", "crates/bombe/src/mitm.rs",
     ".map(|(a, n)| (a & n).count_ones())", ".map(|(a, _)| a.count_ones())",
     BOMBE_LIB + ["mitm"]),
    ("mitm: enumeration forgets the output byte", "crates/bombe/src/mitm.rs",
     "Enumerated { free: 2 + before + after, cost }", "Enumerated { free: 1 + before + after, cost }",
     BOMBE_LIB + ["mitm"]),
]

MUTATIONS_ROUND6 = [
    # Turing-256, the cipher (docs/15)
    ("turing-256: ShiftRows offsets 0, 1, 2, 3", "crates/turing/src/linear256.rs",
     "pub const SHIFTS: [usize; 4] = [0, 1, 3, 4];", "pub const SHIFTS: [usize; 4] = [0, 1, 2, 3];",
     ["-p", "bombe", "--release", "--test", "turing256"]),
    ("turing-256: MixState applies the inverse matrix", "crates/turing/src/linear256.rs",
     "const MIX_STATE_PREPARED: [[[u64; 4]; 8]; 32] = prepare32(&MIX_STATE_256);", "const MIX_STATE_PREPARED: [[[u64; 4]; 8]; 32] = prepare32(&MIX_STATE_256_INV);",
     TURING),
    ("turing-256: one warm-up round fewer", "crates/turing/src/keyschedule256.rs",
     "pub const WARMUP_ROUNDS: usize = 9;", "pub const WARMUP_ROUNDS: usize = 8;",
     TURING),
    ("turing-256: no feed-forward", "crates/turing/src/keyschedule256.rs",
     "                        let mut rk = xor(value, base);", "                        let mut rk = *value; let _ = base;",
     ["-p", "bombe", "--release", "--test", "turing256"]),
    ("turing-256: key-schedule F without S-boxes", "crates/turing/src/keyschedule256.rs",
     "    let mut t = xor(x, c);\n    sub32(&mut t);", "    let mut t = xor(x, c);",
     ["-p", "bombe", "--release", "--test", "turing256"]),
    ("turing-256: last round keeps its linear layer", "crates/turing/src/turing256.rs",
     "            sub32(block);\n            if round < rounds {", "            sub32(block);\n            if round <= rounds && round < ROUNDS {",
     ["-p", "bombe", "--release", "--test", "turing256"]),
    ("turing-256: decryption applies the forward layer", "crates/turing/src/turing256.rs",
     "*block = linear256::invert_layer(layer, block);", "*block = linear256::apply_layer(layer, block);",
     TURING),
    # Turing-128's layers, hardened in the same round
    ("linear: bit masks read the wrong bit", "crates/turing/src/linear.rs",
     "core::array::from_fn(|k| opaque(((x as u64 >> k) & 1).wrapping_neg()))",
     "core::array::from_fn(|k| opaque(((x as u64 >> (k + 1)) & 1).wrapping_neg()))",
     TURING),
    # The analysis behind it
    ("wide: ShiftMix output allowed one byte short", "crates/bombe/src/wide.rs",
     "5 * m >= p && 5 * m - p <= q && q <= 4 * m", "5 * m >= p + 1 && 5 * m - p - 1 <= q && q <= 4 * m",
     BOMBE_LIB + ["wide"]),
    ("wide: a unit allowed from five bytes in one column", "crates/bombe/src/wide.rs",
     "unit |= eights == 0 && (1..=4).contains(&ones);", "unit |= eights == 0 && (1..=5).contains(&ones);",
     BOMBE_LIB + ["wide"]),
    ("matrix: Gosper's step skips subsets", "crates/bombe/src/matrix.rs",
     "m = ripple | (((m ^ ripple) >> 2) / low);", "m = ripple | (((m ^ ripple) >> 3) / low);",
     BOMBE_LIB + ["matrix"]),
    ("reference 256: ShiftRows rotates right", "crates/bombe/src/refcipher256.rs",
     "            row.rotate_left(shift);", "            row.rotate_right(shift);",
     ["-p", "bombe", "--release", "--test", "turing256"]),
    ("attack 256: key guesses judged on the last structure only", "crates/bombe/src/attack256.rs",
     "        for (j, keep) in candidates.iter_mut().enumerate() {\n            keep.retain(",
     "        for (j, keep) in candidates.iter_mut().enumerate() {\n            *keep = (0..=255u8).collect();\n            keep.retain(",
     ["-p", "bombe", "--release", "--test", "turing256", "square"]),
]


def kill_tree(p):
    """Kills cargo and the test binary it started."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    else:
        os.killpg(p.pid, signal.SIGKILL)


def run(args):
    # No -q: the default output prints one "test <name> ... FAILED" line per
    # failing test, which is what tells us which test caught the bug.
    if args and args[0] == "--wsl":
        cmd = [sys.executable, str(ROOT / "tools" / "wsl_linux.py"), "test", *args[1:]]
    else:
        cmd = ["cargo", "test", *args]
    group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **group)
    try:
        out, _ = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        kill_tree(p)
        p.communicate()
        return None, [], False
    failed = [line.split()[1] for line in out.splitlines()
              if line.startswith("test ") and line.rstrip().endswith("FAILED")]
    compile_error = "could not compile" in out or "error[E" in out
    return p.returncode, failed, compile_error


def main():
    sets = {"--step8": MUTATIONS_STEP8, "--step9": MUTATIONS_STEP9, "--round3": MUTATIONS_ROUND3, "--round4": MUTATIONS_ROUND4, "--round5": MUTATIONS_ROUND5, "--round6": MUTATIONS_ROUND6}
    check_only = "--check" in sys.argv
    only = [a for a in sys.argv[1:] if a not in sets and a != "--check"]
    mutations = next((m for flag, m in sets.items() if flag in sys.argv), MUTATIONS)
    all_caught = True
    for name, rel, old, new, args in mutations:
        if only and not any(o in name for o in only):
            continue
        path = ROOT / rel
        original = path.read_bytes()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            print(f"SKIP {name}: pattern found {text.count(old)} times")
            all_caught = False
            continue
        if check_only:
            print(f"OK      {name}")
            continue
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            code, failed, compile_error = run(args)
        finally:
            path.write_bytes(original)
        assert path.read_bytes() == original, f"{rel} not restored"
        caught = code != 0
        all_caught &= caught
        if code is None:
            how = f"timed out after {TIMEOUT} s (the test did not pass)"
        else:
            how = ", ".join(failed) if failed else ("compile error" if compile_error else "exit %d" % code)
        print(f"{'CAUGHT' if caught else 'MISSED'}  {name}: {how}", flush=True)
    if check_only:
        print("all patterns match" if all_caught else "SOME PATTERNS ARE STALE")
    else:
        print("all mutations caught" if all_caught else "SOME MUTATIONS NOT CAUGHT")
    return 0 if all_caught else 1


if __name__ == "__main__":
    sys.exit(main())
