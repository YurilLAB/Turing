"""Mutation checks: plant one bug, run the named tests, restore the file.

Each mutation must make at least one test fail; the script reports which
tests caught it and always restores the original file (and verifies it). A
test run that exceeds the time limit has not passed either: it counts as
caught, and the whole process tree is killed.

    python tools/mutate.py [--step8 | --step9 | --round3 | --round4 | --round5 | --round6 | --round7 | --review1 | --mlkem | --review2] [--check] [NAME ...]

--check only verifies that every pattern still matches the current code
exactly once, without running any tests. NAME filters mutations by name.
Test arguments that start with "--wsl" run the tests on Linux in WSL
(tools/wsl_linux.py), for the Linux-only code paths; arguments that start
with "--python" run a Python check instead of cargo (tools/ct_check.py, for
what only the machine code shows), and a failing exit status counts as
caught there too.
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
     "    let mut x = SecretXof::new(label);\n    x.absorb(input);", "    let mut x = SecretXof::shake256();\n    x.absorb(input);",
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
     "        let locked = lock(ptr, size);\n        Some(Mapping { ptr, size, locked, dump_excluded: false, wiped_on_fork: false })",
     "        let locked = { let _ = lock; false };\n        Some(Mapping { ptr, size, locked, dump_excluded: false, wiped_on_fork: false })",
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
     "if st.seeded == 0 || st.generation != fork_generation() || st.pid != u64::from(std::process::id()) {", "if { let _ = st; false } {",
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
     "        for (s, d) in self.shielded.iter_mut().zip(delta.iter()) {\n            *s ^= d;\n        }\n", "",
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


MUTATIONS_ROUND7 = [
    # Turing-1026, the KEM (docs/16)
    ("turing-1026: rejection returns the decrypted key", "crates/turing/src/turing1026.rs",
     "            select_into(tmp, accepted, accept_bytes);\n            select_into(&mut key, tmp, accept_coeffs);",
     "            let _ = (accept_bytes, accept_coeffs);\n            key.copy_from_slice(&accepted[..]);",
     TURING),
    ("turing-1026: re-encryption byte check always accepts", "crates/turing/src/turing1026.rs",
     "        let accept_bytes = fault.accept_packed(eq_mask(&w.packed, body));",
     "        let accept_bytes = fault.accept_packed(0xffu8);",
     ["-p", "bombe", "--release", "--lib", "fault1026"]),
    ("turing-1026: re-encryption coefficient check always accepts", "crates/turing/src/turing1026.rs",
     "        let accept_coeffs = fault.accept_coeffs(eq_mask_u16(&w.bp, &received_bp) & eq_mask_u16(&w.c, &received_c));",
     "        let accept_coeffs = fault.accept_coeffs(0xffu8);",
     ["-p", "bombe", "--release", "--lib", "fault1026"]),
    ("turing-1026: selection collapses to one check", "crates/turing/src/turing1026.rs",
     "            select_into(&mut key, tmp, accept_coeffs);",
     "            select_into(&mut key, tmp, { let _ = accept_coeffs; 0xffu8 });",
     ["-p", "bombe", "--release", "--lib", "fault1026"]),
    ("turing-1026: only one re-encryption (shared intermediate)", "crates/turing/src/turing1026.rs",
     "        // as coefficients: reads a separate computation from the first.\n        self.public.reencrypt(&mut w);\n        {\n            let Workspace { bp, c, .. } = &mut *w;\n            fault.intermediate(2, bp, c);\n        }",
     "        // as coefficients: reads a separate computation from the first.\n        {\n            let Workspace { bp, c, .. } = &mut *w;\n            fault.intermediate(2, bp, c);\n        }",
     ["-p", "bombe", "--release", "--lib", "fault1026"]),
    ("turing-1026: rejection key without z", "crates/turing/src/turing1026.rs",
     "        if !fault.skip_rejection_z() {\n            h.absorb(&self.secret.z);\n        }\n        h.absorb(&self.public.hash);",
     "        h.absorb(&self.public.hash);",
     TURING),
    ("turing-1026: rejection key without H(pk)", "crates/turing/src/turing1026.rs",
     "        h.absorb(&self.public.hash);\n        h.absorb(ciphertext);\n        h.squeeze(&mut key[..]);",
     "        h.absorb(ciphertext);\n        h.squeeze(&mut key[..]);",
     TURING),
    ("turing-1026: salt left out of the coins", "crates/turing/src/turing1026.rs",
     "        g.absorb(&w.mu);\n        g.absorb(salt);", "        g.absorb(&w.mu);",
     TURING),
    ("turing-1026: H(pk) left out of the coins", "crates/turing/src/turing1026.rs",
     "        g.absorb(&self.hash);\n        g.absorb(&w.mu);", "        g.absorb(&w.mu);",
     TURING),
    ("turing-1026: shared key ignores the ciphertext", "crates/turing/src/turing1026.rs",
     "    h.absorb(ciphertext);\n    h.absorb(k);", "    h.absorb(k);",
     TURING),
    ("turing-1026: pair-wise check always passes", "crates/turing/src/turing1026.rs",
     "        eq_mask(&key[..], &back[..]) == 0xff", "        eq_mask(&key[..], &back[..]) | 0xff == 0xff",
     ["-p", "bombe", "--release", "--test", "turing1026", "faults"]),
    ("turing-1026: workspace message not wiped", "crates/turing/src/turing1026.rs",
     "        self.mu.zeroize();\n        self.coins.zeroize();", "        self.coins.zeroize();",
     TURING),
    ("lwe: noise skips a bit per sample", "crates/turing/src/lwe.rs",
     "    let need = 2 * eta;", "    let need = 2 * eta + 1;",
     TURING),
    ("lwe: decoding rounds down", "crates/turing/src/lwe.rs",
     "            let bit = ((x.wrapping_add(quarter) & mask) >> shift) as u8;", "            let bit = ((x & mask) >> shift) as u8;",
     TURING),
    ("lwe: packing drops each coefficient's top bit", "crates/turing/src/lwe.rs",
     "        acc |= (u32::from(c) & mask) << bits;", "        acc |= (u32::from(c) & (mask >> 1)) << bits;",
     TURING),
    ("lwe: matrix rows ignore their index", "crates/turing/src/lwe.rs",
     "    input[SEED_A_BYTES..].copy_from_slice(&(i as u16).to_le_bytes());", "    let _ = i;",
     TURING),
    ("xof: SecretXof pads like SHAKE", "crates/turing/src/xof.rs",
     "        let mut x = SecretXof::sponge(RATE, 0x04);", "        let mut x = SecretXof::sponge(RATE, 0x1f);",
     TURING),
    # The analysis behind it
    ("dfr: n products instead of 2n", "crates/bombe/src/dfr.rs",
     "    chi.product(chi).power(2 * n).conv(chi)", "    chi.product(chi).power(n).conv(chi)",
     BOMBE_LIB + ["dfr"]),
    ("coresvp: Chen's delta with the wrong exponent", "crates/bombe/src/coresvp.rs",
     ".powf(1.0 / (2.0 * b - 2.0))", ".powf(1.0 / (2.0 * b - 1.0))",
     BOMBE_LIB + ["coresvp"]),
    ("lattice: LLL skips size reduction", "crates/bombe/src/lattice.rs",
     "            let r = mu[k][j].round();", "            let r = 0.0 * mu[k][j].round();",
     BOMBE_LIB + ["lattice"]),
    ("lattice: enumeration tries one sign everywhere", "crates/bombe/src/lattice.rs",
     "                if top && xi < 0 {", "                if xi < 0 {",
     BOMBE_LIB + ["lattice"]),
    ("reference 1026: decoding window shifted", "crates/bombe/src/refkem1026.rs",
     "            if (q / 4..3 * q / 4).contains(&x) {", "            if (q / 4 + 64..3 * q / 4 + 64).contains(&x) {",
     ["-p", "bombe", "--release", "--test", "turing1026"]),
]

# The fixes of the 2026-09-27 review (research/reviews/2026-09-27/): each
# planted bug undoes one defence, and a test added with the fix must catch it.
MEMORY_RELEASE = ["-p", "bombe", "--release", "--test", "memory", "shield_mask"]
MUTATIONS_REVIEW1 = [
    ("checksum: intact ignores whether the point is odd", "crates/turing/src/keyschedule.rs",
     "        (diff | even) == 0", "        diff == 0",
     TURING + ["reset_faults"]),
    ("checksum: stored check without its constant term", "crates/turing/src/keyschedule.rs",
     "    core::array::from_fn(|i| c[i] ^ CHECK_CONSTANT[i])", "    c",
     TURING + ["reset_faults"]),
    ("masked: intact ignores whether the point is odd", "crates/turing/src/masked.rs",
     "        (diff | even) == 0", "        diff == 0",
     TURING + ["reset_faults"]),
    ("shield: new moves the mask through its own frame", "crates/turing/src/shield.rs",
     "        let m = mask(&prekey);", "        let m = { let mut v = [0u8; 32]; mask_into(&prekey, &mut v); v };",
     MEMORY_RELEASE),
    ("shield: refresh computes the new mask in its own frame", "crates/turing/src/shield.rs",
     "        let (old, new) = (mask(&self.prekey), mask(&fresh));",
     "        let (old, new) = (mask(&self.prekey), { let mut v = [0u8; 32]; mask_into(&fresh, &mut v); v });",
     MEMORY_RELEASE),
    ("checksum: intact compares only 8 of 16 bytes", "crates/turing/src/keyschedule.rs",
     "        let diff = now.iter().zip(&self.material.check).fold(0u8, |acc, (a, b)| acc | (a ^ b));",
     "        let diff = now.iter().take(8).zip(&self.material.check).fold(0u8, |acc, (a, b)| acc | (a ^ b));",
     TURING + ["every_bit_of_the_check"]),
    ("masked: intact compares only 8 of 16 bytes", "crates/turing/src/masked.rs",
     "        let diff = a.iter().zip(&b).fold(0u8, |acc, (x, y)| acc | (x ^ y));",
     "        let diff = a.iter().take(8).zip(&b).fold(0u8, |acc, (x, y)| acc | (x ^ y));",
     TURING + ["every_bit_of_the_check_shares"]),
    ("checked: decrypt-and-compare ignores the last byte", "crates/turing/src/cipher.rs",
     "    let diff = core::hint::black_box(input.iter().zip(&check).fold(0u8, |acc, (a, b)| acc | (a ^ b)));",
     "    let diff = core::hint::black_box(input.iter().zip(&check).take(15).fold(0u8, |acc, (a, b)| acc | (a ^ b)));",
     TURING + ["decrypt_and_compare_covers_every_byte"]),
    ("turing-256: decrypt-and-compare ignores the last byte", "crates/turing/src/turing256.rs",
     "    let diff = core::hint::black_box(input.iter().zip(&check).fold(0u8, |acc, (a, b)| acc | (a ^ b)));",
     "    let diff = core::hint::black_box(input.iter().zip(&check).take(31).fold(0u8, |acc, (a, b)| acc | (a ^ b)));",
     TURING + ["decrypt_and_compare_covers_every_byte"]),
    ("turing-256: second key check removed", "crates/turing/src/turing256.rs",
     "        if result.is_err() || !self.keys.intact() {", "        if result.is_err() {",
     TURING + ["a_key_flip_between_check_and_use_is_caught"]),
]

# ML-KEM (turing::mlkem, FIPS 203): the classic ways an implementation goes
# wrong. Each must fail the official vectors (bombe tests/mlkem.rs) or the
# module's own exhaustive tests.
MLKEM_VECTORS = ["-p", "bombe", "--release", "--test", "mlkem"]
MUTATIONS_MLKEM = [
    ("ml-kem: key generation hashes G(d) without k (the FIPS 203 draft)", "crates/turing/src/mlkem.rs",
     "        g(&[d, &k_byte], &mut rho, &mut sigma);",
     "        g(&[d], &mut rho, &mut sigma);",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: SampleNTT reads rho || i || j", "crates/turing/src/mlkem.rs",
     "            sample_ntt(rho, j as u8, i as u8, entry);", "            sample_ntt(rho, i as u8, j as u8, entry);",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: e1 drawn with eta1", "crates/turing/src/mlkem.rs",
     "    for ei in e1.iter_mut().take(p.k) {\n        prf_cbd(p.eta2, r, nonce, ei);",
     "    for ei in e1.iter_mut().take(p.k) {\n        prf_cbd(p.eta1, r, nonce, ei);",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: Compress rounds down", "crates/turing/src/mlkem.rs",
     "    let v = (u32::from(x) << d) + 1664;", "    let v = u32::from(x) << d;",
     TURING + ["mlkem"]),
    ("ml-kem: inverse NTT scaled by 3302", "crates/turing/src/mlkem.rs",
     "        *x = mul(*x, 3303);", "        *x = mul(*x, 3302);",
     TURING + ["mlkem"]),
    ("ml-kem: base-case multiply uses zeta instead of gamma", "crates/turing/src/mlkem.rs",
     "        let c0 = add(mul(a0, b0), mul(mul(a1, b1), GAMMAS[i]));",
     "        let c0 = add(mul(a0, b0), mul(mul(a1, b1), ZETAS[i]));",
     TURING + ["mlkem"]),
    ("ml-kem: ByteDecode12 does not reduce mod q", "crates/turing/src/mlkem.rs",
     "        *c = if d == 12 { csub(v) } else { v as u16 };", "        *c = v as u16;",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: modulus check skipped", "crates/turing/src/mlkem.rs",
     "        again[..] == ek[384 * i..384 * (i + 1)]", "        true",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: decapsulation-key hash check skipped", "crates/turing/src/mlkem.rs",
     "    h(&dk[pke..pke + p.ek_bytes()])[..] == dk[pke + p.ek_bytes()..pke + p.ek_bytes() + 32]", "    true",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: rejection returns the decrypted key", "crates/turing/src/mlkem.rs",
     "        *out ^= (*out ^ a) & accept;", "        *out = a;",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: re-encryption compared on its first half only", "crates/turing/src/mlkem.rs",
     "    let accept = eq_mask(c, again);", "    let accept = eq_mask(&c[..c.len() / 2], &again[..c.len() / 2]);",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
    ("ml-kem: noise sign flipped", "crates/turing/src/mlkem.rs",
     "        *c = csub(x + Q - y);", "        *c = csub(y + Q - x);",
     MLKEM_VECTORS + ["every_official_vector_passes"]),
]

# The fixes of the 2026-09-28 review (research/reviews/2026-09-28/crypto-audit.md):
# each planted bug undoes one defence, and a test or check added with the fix
# must catch it. Defences layered on the same bug (R1, R3) are each enough on
# their own, so removing one leaves the others holding; those are shown by
# the tests' own controls and by running the tests on the unfixed code.
CT_CHECK = ["--python", "tools/ct_check.py"]
MUTATIONS_REVIEW2 = [
    # R1: the seed in a leftover sponge state
    ("xof: wipe leaves the state", "crates/turing/src/xof.rs",
     "        self.state.zeroize();\n        self.state.wiped = 1;", "        self.state.wiped = 1;",
     TURING + ["wipe_clears_the_state_in_place"]),
    # R2: the verdicts fused, or the accepted key no longer bound
    ("turing-1026: accepted key not bound to the comparison", "crates/turing/src/turing1026.rs",
     "        bind_to_verdict(&mut coins[COIN_SEED_BYTES..], &key, accept_binding);",
     "        let _ = accept_binding;",
     BOMBE_LIB + ["fault1026"]),
    ("turing-1026: binding verdict always accepts", "crates/turing/src/turing1026.rs",
     "        let accept_binding = fault.accept_binding(eq_mask(&w.packed, body));",
     "        let accept_binding = fault.accept_binding(0xffu8);",
     BOMBE_LIB + ["fault1026"]),
    ("turing-1026: binding verdict reads the first run", "crates/turing/src/turing1026.rs",
     "        self.public.pack_reencryption(&mut w);\n        let accept_binding",
     "        let accept_binding",
     BOMBE_LIB + ["fault1026"]),
    ("turing-1026: the two selections fused into one mask", "crates/turing/src/turing1026.rs",
     "            select_into(tmp, accepted, accept_bytes);\n            select_into(&mut key, tmp, accept_coeffs);",
     "            let _ = tmp;\n            select_into(&mut key, accepted, accept_bytes & accept_coeffs);",
     CT_CHECK),
    ("turing-1026: selection inlined", "crates/turing/src/turing1026.rs",
     "#[inline(never)]\nfn select_into(", "#[inline(always)]\nfn select_into(",
     CT_CHECK),
    # R3 and R7: ML-KEM's division check
    ("ml-kem: Compress divides by q (KyberSlash)", "crates/turing/src/mlkem.rs",
     "    let quotient = ((u64::from(v) * COMPRESS_M) >> 40) as u32;", "    let quotient = v / core::hint::black_box(Q);",
     CT_CHECK),
    # R4: the checksum point left in dead stack
    ("checked: no stack burn after encrypt_block_checked", "crates/turing/src/cipher.rs",
     "        let result = self.guarded(block, true, || {});\n        crate::memory::burn_stack();",
     "        let result = self.guarded(block, true, || {});",
     TURING + ["checked_calls_leave_no_checksum_point_behind"]),
    ("masked: no stack burn after decrypt_block_checked", "crates/turing/src/masked.rs",
     "        let result = self.guarded(block, false, |_| {});\n        memory::burn_stack();",
     "        let result = self.guarded(block, false, |_| {});",
     TURING + ["checked_calls_leave_no_checksum_point_behind"]),
    # R5: the deterministic key check
    ("turing-1026: key check skipped", "crates/turing/src/turing1026.rs",
     "        let key_matches = lwe::check_key(&PARAMS, &self.public.seed_a, &self.secret.s, &self.public.b);",
     "        let key_matches = true;",
     ["-p", "bombe", "--release", "--test", "turing1026", "key_generation_faults"]),
    ("lwe: key check accepts any noise", "crates/turing/src/lwe.rs",
     "            bad |= (2 * u32::from(eta)).wrapping_sub(shifted) >> 31;", "            bad |= 0 & shifted;",
     TURING + ["check_key"]),
    # R8: fork detection by generation, not only by process ID
    ("random (Linux): check_fork ignores the fork generation", "crates/turing/src/random.rs",
     "        if st.seeded == 0 || st.generation != fork_generation() || st.pid", "        if st.seeded == 0 || st.pid",
     ["--wsl", "-p", "turing", "--lib", "random"]),
    ("random (Linux): no fork handler installed", "crates/turing/src/random.rs",
     "        unsafe { libc::pthread_atfork(None, None, Some(in_child)) };", "        let _ = in_child;",
     ["--wsl", "-p", "turing", "--lib", "random"]),
    # R9: the self-test runs the masked cipher and the mask stream
    ("selftest: masked S-box output constant missing", "crates/turing/src/masked.rs",
     "    noted((map_out.apply(y.0), map_out.apply(y.1) ^ map_out.apply(0)))", "    noted((map_out.apply(y.0), map_out.apply(y.1)))",
     TURING + ["self_test"]),
    ("selftest: mask stream never permutes", "crates/turing/src/random.rs",
     "                keccak::f1600(&mut st.lanes);\n                st.used = 0;", "                st.used = 0;",
     TURING + ["self_test"]),
    # R11: locking beyond the default quota
    ("memory: working set never grown", "crates/turing/src/memory.rs",
     "        if *grown + step > MAX_LOCK_GROWTH {\n            return false;\n        }\n        let (mut min, mut max) = (0usize, 0usize);",
     "        if *grown + step > 0 {\n            return false;\n        }\n        let (mut min, mut max) = (0usize, 0usize);",
     TURING + ["secrets_beyond_the_default_quota"]),
    ("memory (Linux): soft memlock limit never raised", "crates/turing/src/memory.rs",
     "        if limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur >= limit.rlim_max {",
     "        if true || limit.rlim_cur >= limit.rlim_max {",
     ["--wsl", "-p", "turing", "--lib", "memlock"]),
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
    elif args and args[0] == "--python":
        cmd = [sys.executable, *(str(ROOT / a) if a.endswith(".py") else a for a in args[1:])]
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
    sets = {"--step8": MUTATIONS_STEP8, "--step9": MUTATIONS_STEP9, "--round3": MUTATIONS_ROUND3, "--round4": MUTATIONS_ROUND4, "--round5": MUTATIONS_ROUND5, "--round6": MUTATIONS_ROUND6, "--round7": MUTATIONS_ROUND7, "--review1": MUTATIONS_REVIEW1, "--mlkem": MUTATIONS_MLKEM, "--review2": MUTATIONS_REVIEW2}
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
        # Patterns are written with "\n", but a checkout with
        # core.autocrlf=true (this repository's setting on Windows) gives
        # "\r\n" files, where every multi-line pattern silently failed to
        # match: 21 planted bugs in six sets on 2026-09-27. Match and write
        # in the file's own line ending instead.
        if "\r\n" in text:
            old, new = old.replace("\n", "\r\n"), new.replace("\n", "\r\n")
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
