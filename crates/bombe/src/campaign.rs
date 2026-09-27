//! The attack campaign: every experiment Bombe can run against the real
//! cipher, with a verdict for each. Reduced-round versions are attacked to
//! find how many rounds each technique breaks; the full cipher must resist
//! all of them; negative controls must fail, or the test that missed them
//! is useless.

use crate::aes::{Aes, Shape as AesShape};
use crate::invariant::LinearMap;
use crate::refcipher::Reference;
use crate::refcipher256::Reference256;
use crate::rng::Rng;
use crate::leakage::{self, View};
use crate::residue::{self, Snapshot};
use crate::{
    avalanche, battery, boomerang, cube, difflinear, differential, fast, fault, integral, interpolation, invariant, keycheck, keyedsquare, keyrelations, mitm,
    power, provable, relatedkey, symmetry, timing, toctou, yoyo,
};
use std::fmt::Write;
use std::time::Instant;
use turing::structure::{Layer, ROUNDS};
use turing::turing1026::{DecapsulationKey, EncapsulationKey};
use turing::{MaskedTuring, ShieldedKey, Turing, Turing256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The full cipher resists, or a check holds.
    Pass,
    /// A problem in the full cipher, or a check that does not hold.
    Fail,
    /// A reduced-round version is broken, as expected from the analysis.
    Broken,
    /// A negative control was caught, proving the test has teeth.
    Caught,
    /// An implementation attack that works on the full cipher given physical
    /// access (fault injection); needs a countermeasure, not a design fix.
    Exposed,
    /// Measurement only.
    Info,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Broken => "BROKEN",
            Verdict::Caught => "CAUGHT",
            Verdict::Exposed => "EXPOSED",
            Verdict::Info => "INFO",
        }
    }
}

pub struct Finding {
    pub section: &'static str,
    pub test: String,
    pub result: String,
    pub verdict: Verdict,
}

pub struct Campaign {
    pub findings: Vec<Finding>,
    pub quick: bool,
    pub seconds: f64,
}

impl Campaign {
    pub fn failures(&self) -> usize {
        self.findings.iter().filter(|f| f.verdict == Verdict::Fail).count()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let mut section = "";
        for f in &self.findings {
            if f.section != section {
                section = f.section;
                let _ = writeln!(out, "\n{section}");
            }
            let _ = writeln!(out, "  {:<7} {:<46} {}", f.verdict.label(), f.test, f.result);
        }
        let _ = writeln!(
            out,
            "\n{} findings, {} failures, {:.0} s ({} run).",
            self.findings.len(),
            self.failures(),
            self.seconds,
            if self.quick { "quick" } else { "full" }
        );
        out
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# Bombe attack campaign\n\n");
        let _ = writeln!(
            out,
            "{} run, {:.0} s, {} findings, {} failures.\n",
            if self.quick { "Quick" } else { "Full" },
            self.seconds,
            self.findings.len(),
            self.failures()
        );
        let mut section = "";
        for f in &self.findings {
            if f.section != section {
                section = f.section;
                let _ = writeln!(out, "\n## {section}\n\n| Verdict | Test | Result |\n|---|---|---|");
            }
            let _ = writeln!(out, "| {} | {} | {} |", f.verdict.label(), f.test, f.result.replace('|', "\\|"));
        }
        out
    }
}

struct Log<'a> {
    findings: Vec<Finding>,
    progress: &'a mut dyn FnMut(&Finding),
}

impl Log<'_> {
    fn add(&mut self, section: &'static str, test: impl Into<String>, result: impl Into<String>, verdict: Verdict) {
        let f = Finding { section, test: test.into(), result: result.into(), verdict };
        (self.progress)(&f);
        self.findings.push(f);
    }
}

fn pass_if(ok: bool) -> Verdict {
    if ok {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

fn caught_if(ok: bool) -> Verdict {
    if ok {
        Verdict::Caught
    } else {
        Verdict::Fail
    }
}

/// One memory scan, in words.
fn describe(snap: &Snapshot) -> String {
    let mut out = format!("{} key fragments where they belong, {} anywhere else", snap.expected, snap.stray.len());
    if !snap.stray.is_empty() {
        let _ = write!(out, " ({} in the stack of the thread that ran it: {})", snap.on_stack, snap.stray_secrets.join(", "));
    }
    out
}

/// Runs everything. `progress` sees each finding as it is made.
pub fn run(quick: bool, deep: bool, progress: &mut dyn FnMut(&Finding)) -> Campaign {
    let start = Instant::now();
    let mut log = Log { findings: Vec::new(), progress };
    let scale = |full: usize, fast: usize| if quick { fast } else { full };

    // --- Does it work? ---------------------------------------------------
    let s = "1. Correctness";
    let mut rng = Rng::new("campaign correctness");
    let trials = scale(2000, 300);
    let mut mismatches = 0;
    for _ in 0..trials {
        let key: [u8; 32] = rng.bytes();
        let (t, r) = (Turing::new(&key), Reference::new(&key));
        let p: [u8; 16] = rng.bytes();
        let rounds = 1 + rng.below(ROUNDS as u64) as usize;
        let mut c = p;
        t.encrypt_rounds(&mut c, rounds);
        let mut d = c;
        t.decrypt_rounds(&mut d, rounds);
        mismatches += usize::from(c != r.encrypt(&p, rounds) || d != p);
    }
    log.add(
        s,
        "matches the independent reference",
        format!("{trials} random keys/blocks/round counts, {mismatches} mismatches"),
        pass_if(mismatches == 0),
    );
    let vectors = crate::refcipher::known_answer_vectors();
    let kat_ok = vectors.iter().all(|(k, p, c)| {
        let mut b = *p;
        Turing::new(k).encrypt_block(&mut b);
        b == *c
    });
    log.add(s, "known-answer vectors", format!("{} of {} reproduced", if kat_ok { vectors.len() } else { 0 }, vectors.len()), pass_if(kat_ok));
    let self_test = turing::self_test();
    log.add(s, "library self-test (turing::self_test, run at start-up)", format!("{self_test:?}"), pass_if(self_test.is_ok()));
    if deep {
        let trials = 100_000;
        let mut rng = Rng::new("campaign correctness at scale");
        let mut mismatches = 0;
        for _ in 0..trials {
            let key: [u8; 32] = rng.bytes();
            let (t, r) = (Turing::new(&key), Reference::new(&key));
            let p: [u8; 16] = rng.bytes();
            let mut c = p;
            t.encrypt_block(&mut c);
            let mut d = c;
            t.decrypt_block(&mut d);
            mismatches += usize::from(c != r.encrypt(&p, ROUNDS) || d != p);
        }
        log.add(s, "matches the reference at scale (--deep)", format!("{trials} random keys and blocks, {mismatches} mismatches"), pass_if(mismatches == 0));
    }

    // --- Speed -------------------------------------------------------------
    let s = "2. Speed (constant-time implementation)";
    let t = Turing::new(&[7; 32]);
    let blocks = scale(400_000, 100_000);
    let mut b = [0u8; 16];
    let timer = Instant::now();
    for _ in 0..blocks {
        t.encrypt_block(&mut b);
    }
    let secs = timer.elapsed().as_secs_f64();
    std::hint::black_box(b);
    log.add(s, "encryption", format!("{:.2} us per block, {:.1} MB/s", secs * 1e6 / blocks as f64, blocks as f64 * 16.0 / secs / 1e6), Verdict::Info);
    let timer = Instant::now();
    for i in 0..2000u32 {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_le_bytes());
        std::hint::black_box(Turing::new(&k));
    }
    log.add(s, "key setup", format!("{:.1} us per key", timer.elapsed().as_secs_f64() * 1e6 / 2000.0), Verdict::Info);

    // --- Real attack: integral / square ---------------------------------------
    let s = "3. Square attack (integral cryptanalysis)";
    let mut broken_through = 0;
    for rounds in 1..=5 {
        let d = integral::distinguisher(rounds, scale(64, 24), &format!("integral {rounds}"));
        let rate = d.balanced as f64 / (16 * d.sets) as f64;
        let verdict = if d.works() {
            broken_through = rounds;
            Verdict::Broken
        } else {
            Verdict::Pass
        };
        log.add(s, format!("balanced-sum distinguisher, {rounds} round(s)"), format!("{:.1}% of output bytes balanced (random: 0.4%), z = {:.1}", rate * 100.0, d.z), verdict);
    }
    for rounds in 1..=4 {
        let a = integral::square_attack(rounds, 6, &format!("square attack {rounds}"));
        let emptied = a.candidates.iter().filter(|&&c| c == 0).count();
        let (result, verdict) = match (a.recovered, a.correct) {
            (Some(_), true) => (format!("RECOVERED round key {rounds} from {} chosen plaintexts", a.chosen_plaintexts), Verdict::Broken),
            (Some(_), false) => ("recovered a key, but the wrong one".to_string(), Verdict::Fail),
            // Every guess passes: the output is so structured that the sum
            // is zero whatever the key, so this method cannot single one out.
            // The distinguisher above already breaks these round counts.
            (None, _) if a.candidates.iter().all(|&c| c == 256) => {
                ("not applicable: the sum is zero for every key guess (already broken by the distinguisher)".to_string(), Verdict::Info)
            }
            (None, _) if emptied == 16 => {
                (format!("fails: no guess survives for any key byte after {} texts", a.chosen_plaintexts), Verdict::Pass)
            }
            (None, _) => (format!("inconclusive: candidates per byte {:?}", a.candidates), Verdict::Info),
        };
        log.add(s, format!("key recovery, {rounds} round(s)"), result, verdict);
    }
    // Bigger structures: what the division property says, then the attack.
    let schedule = turing::structure::schedule();
    let reach = |n: usize| crate::division::balanced_until(&crate::division::active(&(0..n).collect::<Vec<_>>()), &schedule);
    log.add(
        s,
        "division property: reach by structure size",
        format!(
            "2^8-2^24 plaintexts: {:?}, 2^32-2^112: {:?}, 2^120: {:?} (S-box layer the set stays balanced to)",
            reach(1).unwrap_or(0),
            reach(4).unwrap_or(0),
            reach(15).unwrap_or(0)
        ),
        Verdict::Info,
    );
    let sets_used = |a: &integral::KeyRecovery, bytes: usize| a.chosen_plaintexts >> (8 * bytes);
    for (rounds, bytes) in [(3usize, 2usize), (4, 2), (4, 3)] {
        let a = integral::structured_square_attack(rounds, &(0..bytes).collect::<Vec<_>>(), 4, &format!("structured {rounds} {bytes}"));
        let (result, verdict) = if a.correct {
            (format!("RECOVERED round key {rounds} with {} sets of 2^{} plaintexts", sets_used(&a, bytes), 8 * bytes), Verdict::Broken)
        } else {
            (format!("fails with 2^{} plaintexts per set, as the division property predicts", 8 * bytes), Verdict::Pass)
        };
        log.add(s, format!("key recovery, {rounds} rounds, {bytes} active bytes"), result, verdict);
    }
    if deep {
        let a = integral::structured_square_attack(4, &[0, 1, 2, 3], 4, "structured 4 4");
        let verdict = if a.correct { Verdict::Broken } else { Verdict::Fail };
        log.add(
            s,
            "key recovery, 4 rounds, 4 active bytes",
            format!(
                "{} with {} sets of 2^32 plaintexts (the division property predicts success)",
                if a.correct { "RECOVERED round key 4" } else { "no key" },
                sets_used(&a, 4)
            ),
            verdict,
        );
    } else {
        log.add(s, "key recovery, 4 rounds, 4 active bytes", "not run (2^33 encryptions, about 15 min): use --deep", Verdict::Info);
    }
    // Guess all of round key 0 and a structure can start at round 2, whose
    // ShiftRows + MixColumns turns a diagonal into a column (docs/14).
    let from_round_2 = |bytes: &[usize]| crate::division::balanced_until(&crate::division::active(bytes), &schedule[1..]).map_or(0, |l| l + 1);
    log.add(
        s,
        "division property: structures at round 2's S-box input (round key 0 guessed)",
        format!(
            "1 byte: balanced to S-box layer {}; the diagonal (2^32): to layer {}, where 2^32 plaintexts chosen at round 1 reach layer {}",
            from_round_2(&[0]),
            from_round_2(&keyedsquare::DIAGONAL),
            reach(4).unwrap_or(0)
        ),
        Verdict::Info,
    );
    let mut rng = Rng::new("campaign keyed square");
    let t = Turing::new(&rng.bytes());
    let z: [u8; 16] = rng.bytes();
    let rk0 = *t.round_key(0);
    let small = keyedsquare::structure(&t, &rk0, &z, 0, [0, 0], 8);
    let reached = keyedsquare::balanced_to(&small);
    log.add(
        s,
        "keyed structure: 1 byte at round 2, round key 0 right (2^8 texts)",
        format!("balanced to S-box layer {reached} (predicted {}); {} blocks rechecked on the real cipher, {} mismatches", from_round_2(&[0]), small.checked, small.mismatches),
        pass_if(reached == from_round_2(&[0]) && small.mismatches == 0),
    );
    let mut wrong = rk0;
    wrong[3] ^= 0x5a;
    let off = keyedsquare::balanced_to(&keyedsquare::structure(&t, &wrong, &z, 0, [0, 0], 8));
    log.add(s, "control: the same with round key 0 one byte wrong", format!("balanced to S-box layer {off} only"), caught_if(off < reached));
    let seven_rounds = if deep {
        let a = keyedsquare::attack(&t, &rk0, 4, "campaign keyed attack");
        let layers: Vec<usize> = a.structures.iter().map(keyedsquare::balanced_to).collect();
        let (checked, mismatches) = a.structures.iter().fold((0, 0), |(c, m), st| (c + st.checked, m + st.mismatches));
        let predicted = from_round_2(&keyedsquare::DIAGONAL);
        log.add(
            s,
            "keyed structure: the diagonal at round 2, round key 0 right (2^32 texts, --deep)",
            format!("{} structures balanced to S-box layer {layers:?} (predicted {predicted}); {checked} blocks rechecked on the real cipher, {mismatches} mismatches", a.structures.len()),
            pass_if(layers.iter().all(|&l| l == predicted) && mismatches == 0),
        );
        log.add(
            s,
            "6 rounds, given round key 0: round key 6 byte by byte (--deep)",
            format!(
                "{} with {} structures (guesses left per byte: {:?})",
                if a.rk6_right { "RECOVERED round key 6" } else { "not recovered" },
                a.structures.len(),
                a.rk6.iter().map(Vec::len).collect::<Vec<_>>()
            ),
            if a.rk6_right { Verdict::Broken } else { Verdict::Fail },
        );
        log.add(
            s,
            "7 rounds, given round key 0 and 2 bytes of round key 7: partial sums (--deep)",
            format!(
                "{} of the 2^16 guesses of the column's other 2 bytes left, {}, with the 4 equivalent round key 6 bytes",
                a.column.len(),
                if a.column_right { "the right one" } else { "not the right one alone" }
            ),
            if a.column_right { Verdict::Broken } else { Verdict::Fail },
        );
        let guess: [u8; 16] = rng.bytes();
        let control = keyedsquare::structure(&t, &guess, &z, 0, [0, 0], 32);
        let depth = keyedsquare::balanced_to(&control);
        let kept = keyedsquare::rk6_candidates(&[&control]).iter().enumerate().filter(|(j, c)| c.contains(&t.round_key(6)[*j])).count();
        log.add(
            s,
            "control: a random guess of round key 0 (2^32 texts, --deep)",
            format!("balanced to S-box layer {depth} only; the right round key 6 byte survives in {kept} of 16 positions"),
            caught_if(depth < predicted && kept < 16),
        );
        a.rk6_right && a.column_right
    } else {
        log.add(s, "keyed structure: the diagonal at round 2 (2^32 texts)", "not run (3 structures of 2^32 texts through 7 rounds, about 20 min on 4 threads): use --deep", Verdict::Info);
        false
    };
    let costs = keyedsquare::costs();
    log.add(
        s,
        "cost of those attacks over every guess of round key 0",
        format!(
            "6 rounds: 2^{:.0} codebook lookups; 7 rounds: 2^{:.1} S-box lookups (2^{:.1} 7-round encryptions); both need all 2^128 texts; trying every key is 2^256",
            costs.six_lookups, costs.seven_sbox_lookups, costs.seven_encryptions
        ),
        Verdict::Info,
    );
    log.add(
        s,
        "security margin against this attack",
        format!(
            "1-byte distinguisher reaches {broken_through} rounds; key recovery 3 rounds (2^8 texts), 4 rounds (2^32 texts, predicted{}); 7 rounds with round key 0 guessed (the full codebook{}); {ROUNDS} rounds in the cipher",
            if deep { " and run above" } else { "; --deep runs it" },
            if seven_rounds { ", last steps run above" } else { "" }
        ),
        Verdict::Info,
    );

    // --- Differential and linear --------------------------------------------
    let s = "4. Differential and linear cryptanalysis";
    for check in differential::branch_numbers(scale(200_000, 40_000), "branch numbers") {
        log.add(
            s,
            format!("{} branch number, measured", check.layer),
            format!("smallest in+out active bytes over {} differences: {} (theory {})", check.samples, check.min_observed, check.theory),
            pass_if(check.min_observed == check.theory),
        );
    }
    let m = differential::one_round_differential(scale(1 << 18, 1 << 16), "one-round differential");
    log.add(
        s,
        "best S-box differential through 1 round",
        format!("measured {:.5}, predicted {:.5} (+/- {:.5})", m.measured, m.predicted, m.standard_error),
        pass_if((m.measured - m.predicted).abs() < 5.0 * m.standard_error),
    );
    for rounds in [1, 2, 3, 4, ROUNDS] {
        let tr = differential::truncated(rounds, scale(1 << 16, 1 << 14), &format!("truncated {rounds}"));
        let verdict = match (tr.distinguishes(), rounds == ROUNDS) {
            (true, true) => Verdict::Fail,
            (true, false) => Verdict::Broken,
            (false, _) => Verdict::Pass,
        };
        log.add(
            s,
            format!("truncated differential, {rounds} round(s)"),
            format!("{} unchanged output bytes, random expects {:.0} (z = {:.1})", tr.zero_bytes, tr.expected, tr.z),
            verdict,
        );
    }
    for rounds in [1, 2, ROUNDS] {
        let c = differential::linear_correlation(rounds, scale(1 << 20, 1 << 18), &format!("linear {rounds}"));
        let detected = c.measured > 5.0 * c.standard_error;
        let verdict = match (detected, rounds == ROUNDS) {
            (true, true) => Verdict::Fail,
            (true, false) => Verdict::Broken,
            (false, _) => Verdict::Pass,
        };
        log.add(
            s,
            format!("best linear approximation, {rounds} round(s)"),
            format!("|correlation| {:.4} (noise level {:.4}, predicted {:.4})", c.measured, c.standard_error, c.predicted),
            verdict,
        );
    }

    // --- Avalanche -------------------------------------------------------------
    let s = "5. Avalanche (strict avalanche criterion, 128 x 128 cells)";
    let samples = scale(2000, 400);
    let mut full_avalanche_at = None;
    for rounds in [1, 2, 3, 4, ROUNDS] {
        let a = avalanche::plaintext(rounds, samples, &format!("avalanche {rounds}"));
        let verdict = match (a.passed(), rounds == ROUNDS) {
            (false, true) => Verdict::Fail,
            (false, false) => Verdict::Broken,
            (true, _) => {
                full_avalanche_at.get_or_insert(rounds);
                Verdict::Pass
            }
        };
        log.add(
            s,
            format!("plaintext bits, {rounds} round(s)"),
            format!("mean {:.4} of bits flip, worst cell |z| {:.1} (limit {:.1})", a.mean, a.worst_z, a.threshold),
            verdict,
        );
    }
    let k = avalanche::key(ROUNDS, scale(400, 100), "key avalanche");
    log.add(
        s,
        "key bits, full cipher",
        format!("mean {:.4} of bits flip, worst cell |z| {:.1} (limit {:.1})", k.mean, k.worst_z, k.threshold),
        pass_if(k.passed()),
    );

    // --- Randomness batteries ----------------------------------------------------
    let s = "6. NIST SP 800-22 battery on keystreams (2^20 bits each)";
    let sequences = scale(64, 16);
    let sources = [
        battery::Source::Counter,
        battery::Source::Cshake,
        battery::Source::Turing { rounds: 1 },
        battery::Source::Turing { rounds: 2 },
        battery::Source::Turing { rounds: 3 },
        battery::Source::Turing { rounds: ROUNDS },
        battery::Source::TuringZeroKey,
    ];
    for source in sources {
        let r = battery::run(source, sequences, "campaign battery");
        let failing = r.failing_tests();
        let expected_bad = matches!(source, battery::Source::Counter);
        let reduced = matches!(source, battery::Source::Turing { rounds } if rounds < ROUNDS);
        let verdict = match (r.passed(), expected_bad, reduced) {
            (false, true, _) => Verdict::Caught,
            (true, true, _) => Verdict::Fail,
            (false, false, true) => Verdict::Broken,
            (ok, false, _) => pass_if(ok),
        };
        let detail = if failing.is_empty() {
            format!("all 11 statistics pass ({} sequences, >= {} must pass each)", r.sequences, r.min_pass)
        } else {
            format!("fails: {}", failing.join(", "))
        };
        log.add(s, r.source, detail, verdict);
    }
    if deep {
        for source in [battery::Source::Turing { rounds: ROUNDS }, battery::Source::TuringZeroKey] {
            let r = battery::run(source, 1000, "campaign battery at scale");
            let failing = r.failing_tests();
            let detail = if failing.is_empty() {
                format!("all 11 statistics pass and P-values are uniform (1000 sequences, >= {} must pass each)", r.min_pass)
            } else {
                format!("fails: {}", failing.join(", "))
            };
            log.add(s, format!("{} at NIST's scale (--deep)", r.source), detail, pass_if(r.passed()));
        }
    }

    // --- Keys --------------------------------------------------------------------
    let s = "7. Keys";
    let scan = keycheck::scan(&keycheck::suspicious_keys());
    log.add(
        s,
        "suspicious keys (zero, ones, patterns, 256 one-bit keys)",
        format!("{} keys, {} round keys: {} zero, {} repeated, {} ciphertext collisions", scan.keys, scan.round_keys, scan.zero_round_keys, scan.repeated_round_keys, scan.ciphertext_collisions),
        pass_if(scan.clean()),
    );
    let neighbours = keycheck::neighbouring_keys();
    log.add(
        s,
        "equivalent keys among 65,536 neighbours",
        format!("{} ciphertext collisions, {} repeated round keys", neighbours.ciphertext_collisions, neighbours.repeated_round_keys),
        pass_if(neighbours.clean()),
    );

    // --- Timing side channel -------------------------------------------------------
    let s = "8. Timing side channel (dudect-style Welch t-test, |t| > 4.5 = leak)";
    let n = scale(400_000, 100_000);
    let t = Turing::new(&[0x42; 32]);
    let r = timing::dudect("Turing encryption", n, 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        t.encrypt_block(&mut b);
        std::hint::black_box(b);
    });
    log.add(s, "encryption, fixed vs random plaintext", format!("max |t| {:.2} over {} runs", r.max_t, n), pass_if(!r.leaks()));
    let r = timing::dudect("Turing key setup", scale(60_000, 20_000), 32, |input| {
        std::hint::black_box(Turing::new(input.try_into().expect("32")));
    });
    log.add(s, "key setup, fixed vs random key", format!("max |t| {:.2}", r.max_t), pass_if(!r.leaks()));
    let r = timing::dudect("Turing decryption", n, 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        t.decrypt_block(&mut b);
        std::hint::black_box(b);
    });
    log.add(s, "decryption, fixed vs random ciphertext", format!("max |t| {:.2} over {} runs", r.max_t, n), pass_if(!r.leaks()));
    let checked_runs = scale(200_000, 50_000);
    let r = timing::dudect("checked encryption", checked_runs, 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        let _ = std::hint::black_box(t.encrypt_block_checked(&mut b));
        std::hint::black_box(b);
    });
    log.add(s, "checked encryption (two key checks, decrypt-and-compare)", format!("max |t| {:.2} over {} runs", r.max_t, checked_runs), pass_if(!r.leaks()));
    let r = timing::dudect("checked decryption", checked_runs, 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        let _ = std::hint::black_box(t.decrypt_block_checked(&mut b));
        std::hint::black_box(b);
    });
    log.add(s, "checked decryption", format!("max |t| {:.2} over {} runs", r.max_t, checked_runs), pass_if(!r.leaks()));
    let mut m = MaskedTuring::new(&[0x42; 32]).expect("OS randomness");
    let masked_runs = scale(60_000, 15_000);
    let r = timing::dudect("masked encryption", masked_runs, 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        m.encrypt_block(&mut b);
        std::hint::black_box(b);
    });
    log.add(s, "masked encryption, fixed vs random plaintext", format!("max |t| {:.2} over {} runs", r.max_t, masked_runs), pass_if(!r.leaks()));
    let setup_runs = scale(20_000, 6_000);
    let r = timing::dudect("masked key setup", setup_runs, 32, |input| {
        std::hint::black_box(MaskedTuring::new(input.try_into().expect("32")).expect("OS randomness"));
    });
    log.add(s, "masked key setup, fixed vs random key", format!("max |t| {:.2} over {} runs", r.max_t, setup_runs), pass_if(!r.leaks()));
    let r = timing::dudect("shielded key", setup_runs, 32, |input| {
        let k = ShieldedKey::new(input.try_into().expect("32")).expect("OS randomness");
        std::hint::black_box(k.cipher());
    });
    log.add(s, "shielding a key, then unshielding it into a cipher", format!("max |t| {:.2} over {} runs", r.max_t, setup_runs), pass_if(!r.leaks()));
    let r = timing::dudect("leaky S-box (control)", scale(200_000, 60_000), 16, |input| {
        let mut b: [u8; 16] = input.try_into().expect("16");
        timing::leaky_sub_bytes(&mut b);
        std::hint::black_box(b);
    });
    log.add(
        s,
        "control: textbook early-exit S-box",
        format!("max |t| {:.1}", r.max_t),
        if r.leaks() { Verdict::Caught } else { Verdict::Fail },
    );

    // --- Boomerang ---------------------------------------------------------------------
    let s = "9. Boomerang attack (Wagner 1999; broke COCONUT98)";
    let quartets = scale(1 << 18, 1 << 16);
    let (alpha, delta, bct) = boomerang::best_bct_pair();
    for rounds in [1, 2, 3, 4] {
        let b = boomerang::run(rounds, quartets, &format!("boomerang {rounds}"));
        // A random permutation returns with probability 2^-128: any handful
        // of returns is a distinguisher.
        let verdict = if b.returned >= 5 { Verdict::Broken } else { Verdict::Pass };
        let rate = if b.returned > 0 { format!("2^{:.1}", (b.returned as f64 / b.quartets as f64).log2()) } else { "0".into() };
        let predicted = match rounds {
            1 => format!(", predicted 2^{:.1} by the BCT", (f64::from(bct) / 256.0).log2()),
            2 => format!(", predicted 2^{:.1} exactly", boomerang::two_round_rate(alpha, delta).log2()),
            _ => String::new(),
        };
        log.add(s, format!("{rounds} round(s)"), format!("{} of {} quartets returned (rate {rate}{predicted}; random 2^-128)", b.returned, b.quartets), verdict);
    }

    // --- Cube testers --------------------------------------------------------------------
    let s = "10. Cube testers (Dinur-Shamir 2009 family; bit-level, 16-dimensional)";
    for rounds in [1, 2, 3, 4] {
        let c = cube::run(rounds, 16, scale(16, 8), &format!("cube {rounds}"));
        let verdict = if c.distinguishes() { Verdict::Broken } else { Verdict::Pass };
        log.add(
            s,
            format!("{rounds} round(s)"),
            format!("{} of {} cube-sum bits zero (random: half), z = {:.1}", c.zero_bits, 128 * c.cubes, c.z),
            verdict,
        );
    }

    // --- Related keys -------------------------------------------------------------------
    let s = "11. Related keys (the 2009 AES-256 attack model)";
    let keys = scale(16, 4);
    for r in [relatedkey::master_key_bits(keys, "related master"), relatedkey::feistel_bits(keys, "related feistel")] {
        log.add(
            s,
            r.label,
            format!("{} round-key differences: mean {:.2} of 128 bits, lowest {}, z = {:.2}", r.samples, r.mean, r.min, r.z),
            pass_if(r.random_looking()),
        );
    }
    for rounds in [1, ROUNDS] {
        let r = relatedkey::cipher_output(rounds, keys, &format!("related output {rounds}"));
        log.add(
            s,
            format!("same plaintext, one key bit flipped, {rounds} round(s)"),
            format!("mean output difference {:.2} of 128 bits, lowest {}, z = {:.2}", r.mean, r.min, r.z),
            pass_if(r.random_looking()),
        );
    }

    // --- Fault attacks --------------------------------------------------------------------
    let s = "12. Fault attacks (implementation; Piret-Quisquater DFA, CHES 2003)";
    let f = fault::last_round_key(6, "campaign dfa");
    log.add(
        s,
        format!("byte fault in round {}, unprotected implementation", ROUNDS - 1),
        format!(
            "{} last round key from {} faulty ciphertexts (candidates after each: {:?})",
            if f.correct { "RECOVERED the" } else { "did not recover the" },
            f.faults,
            f.remaining
        ),
        if f.correct { Verdict::Exposed } else { Verdict::Info },
    );
    let (caught, trials) = fault::countermeasure(scale(20_000, 2_000), "campaign countermeasure");
    log.add(
        s,
        "countermeasure: decrypt the output and compare",
        format!("{caught} of {trials} single faults detected (random round, byte and value)"),
        pass_if(caught == trials),
    );
    let (caught, blind, tried) = fault::two_bit_key_faults("campaign two-bit key faults");
    log.add(
        s,
        "persistent two-bit faults in the stored round keys",
        format!("{caught} of {tried} caught by the keyed checksum, block wiped (every pair that cancels in Σ x^i · RK_i)"),
        pass_if(caught == tried && tried > 0),
    );
    log.add(
        s,
        "control: version 2's first checksum, Σ x^i · RK_i, same faults",
        format!("{blind} of {tried} leave it unchanged: each would release a ciphertext under the wrong keys"),
        caught_if(blind == tried && tried > 0),
    );
    let (caught, tried) = fault::point_faults("campaign point faults");
    log.add(
        s,
        "persistent faults that move the checksum's secret point",
        format!("{caught} of {tried} caught: each of its 128 bits alone, and paired with every other stored bit"),
        pass_if(caught == tried && tried > 0),
    );
    let (caught, trials) = fault::multi_bit_key_faults(scale(20_000, 2_000), "campaign multi-bit key faults");
    log.add(s, "persistent faults of 2 to 16 random bits in the keys, checksum and point", format!("{caught} of {trials} caught"), pass_if(caught == trials));

    // --- Interpolation and invariants -----------------------------------------------------
    let s = "13. Interpolation and invariant attacks (Jakobsen-Knudsen 1997; PRINTcipher 2011; Midori-64 2016)";
    let table = &turing::sbox::TABLE;
    let (terms, inverse_terms) = (interpolation::terms(table), interpolation::terms(&interpolation::inverse_table(table)));
    let aes = crate::gf256::aes_sbox();
    log.add(
        s,
        "S-box as a polynomial over GF(2^8)",
        format!(
            "{terms} terms, inverse {inverse_terms} (AES: {} and {}; a random permutation about 254)",
            interpolation::terms(&aes),
            interpolation::terms(&interpolation::inverse_table(&aes))
        ),
        pass_if(terms >= 240 && inverse_terms >= 240),
    );
    let midori = invariant::profile(&LinearMap::midori64(), 64, "campaign midori");
    log.add(
        s,
        "tool check: Midori-64 linear layer (BCLR 2017, section 4.2)",
        format!("reaches {:?} with 1, 2, ... differences, as published", midori),
        pass_if(midori == invariant::midori64_published_profile()),
    );
    let profiles: Vec<Vec<usize>> = [LinearMap::turing(Layer::MixState), LinearMap::turing(Layer::ShiftMixColumns), LinearMap::aes()]
        .iter()
        .enumerate()
        .map(|(i, m)| invariant::profile(m, 64, &format!("campaign layer {i}")))
        .collect();
    log.add(
        s,
        "linear layers: invariant factors (BCLR Theorem 1)",
        format!(
            "MixState {}, ShiftRows+MixColumns {} (minimal polynomials of degree {} and {}: one round-key difference can reach all 128 bits); AES {} of degree {}",
            profiles[0].len(),
            profiles[1].len(),
            profiles[0][0],
            profiles[1][0],
            profiles[2].len(),
            profiles[2][0]
        ),
        pass_if(profiles[0] == [128] && profiles[1] == [128]),
    );
    let r = invariant::round_key_spaces(scale(64, 16), "campaign invariants");
    log.add(
        s,
        "real round keys: smallest W_L(D) over random keys",
        format!(
            "{} keys: {} (MixState rounds, {} differences), {} (ShiftRows+MixColumns rounds, {}), {} (all rounds) of 128: only affine invariants remain, and the S-box has no linear component",
            r.keys, r.mix_state, r.differences.0, r.shift_mix, r.differences.1, r.both
        ),
        pass_if(r.full()),
    );
    let control = invariant::identical_round_keys();
    log.add(
        s,
        "control: the same round key in every round",
        format!("W_L(D) = {control} of 128"),
        if control == 0 { Verdict::Caught } else { Verdict::Fail },
    );

    // --- Power analysis -------------------------------------------------------------------
    let s = "14. Power analysis (implementation; CPA, Brier-Clavier-Olivier CHES 2004)";
    for (sigma, snr) in [(0.0, "no noise"), (2f64.sqrt(), "SNR 1"), (20f64.sqrt(), "SNR 0.1")] {
        let n = power::traces_needed(sigma, 1 << 16, &format!("campaign cpa {snr}"));
        log.add(
            s,
            format!("unmasked implementation, Hamming-weight leakage, {snr}"),
            match n {
                Some(n) => format!("RECOVERED round key 0 from {n} traces"),
                None => "round key 0 not recovered from 65,536 traces".into(),
            },
            if n.is_some() { Verdict::Exposed } else { Verdict::Info },
        );
    }
    log.add(
        s,
        "countermeasure",
        "first-order masking: MaskedTuring computes x^254 on shares with Rivain-Prouff's chain; attacked in section 19",
        Verdict::Info,
    );

    // --- Provable bounds --------------------------------------------------------------------
    let s = "15. Provable bounds, every trail counted (Park et al. 2003; Keliher-Sui 2005)";
    let aes_sbox = crate::gf256::aes_sbox();
    let (aes_dp, aes_lp) = (provable::dp_bound(&aes_sbox, 5), provable::lp_bound(&aes_sbox, 5));
    log.add(
        s,
        "tool check: Park et al.'s AES bounds",
        format!("MEDP <= {:?}, MELP <= {:?} (published: 79/2^34 = 5056/2^40, 192,773,764/2^54)", aes_dp.exact, aes_lp.exact),
        pass_if(aes_dp.exact == Some((79 << 6, 40)) && aes_lp.exact == Some((192_773_764u128 << 26, 80))),
    );
    let aes_lower = provable::ks_lower_bound(&aes_sbox, &provable::AES_MIX_COLUMNS, 255);
    log.add(
        s,
        "tool check: Keliher-Sui's exact 2-round AES MEDP",
        format!("{} x 2^-35 = 2^{:.2} (published: 53/2^34)", aes_lower.units, aes_lower.log2),
        pass_if(aes_lower.units == 106),
    );
    let table = &turing::sbox::TABLE;
    let (dp5, lp5, dp17, lp17) = (provable::dp_bound(table, 5), provable::lp_bound(table, 5), provable::dp_bound(table, 17), provable::lp_bound(table, 17));
    let lower = if deep {
        let l = provable::ks_lower_bound(table, &turing::linear::MIX_COLUMNS, 255);
        format!("the best differential over minimal patterns reaches {} x 2^-35 = 2^{:.2}", l.units, l.log2)
    } else {
        "the best differential over minimal patterns is 57 x 2^-35 = 2^-29.17 (run with --deep)".into()
    };
    log.add(s, "2 rounds through ShiftRows+MixColumns (B = 5)", format!("MEDP <= 2^{:.2}, MELP <= 2^{:.2}; {lower}", dp5.log2, lp5.log2), Verdict::Info);
    log.add(
        s,
        "any 3 consecutive rounds (they contain S, MixState with B = 17, S)",
        format!("MEDP <= 2^{:.2}, MELP <= 2^{:.2} (the same argument gives AES 2^-28.27)", dp17.log2, lp17.log2),
        Verdict::Info,
    );
    let (full_dp, full_lp) = (4.0 * dp5.log2, 4.0 * lp5.log2);
    log.add(
        s,
        "any 5 consecutive rounds, so the full cipher (two super-box layers around MixState)",
        format!("MEDP <= 2^{full_dp:.1}, MELP <= 2^{full_lp:.1}: every differential and linear hull needs over 2^100 texts"),
        pass_if(full_dp < -100.0 && full_lp < -100.0 && dp17.log2 < -100.0 && lp17.log2 < -96.0),
    );

    // --- Symmetries --------------------------------------------------------------------------
    let s = "16. Symmetries and reflection (custom: the attacker knows every constant)";
    const AES_MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    let aes_round = symmetry::byte_matrix(|x| turing::linear::mix_columns_with(&AES_MIX, &turing::linear::shift_rows(x)));
    let (ms, sm) = (
        symmetry::byte_matrix(|x| turing::linear::apply_layer(Layer::MixState, x)),
        symmetry::byte_matrix(|x| turing::linear::apply_layer(Layer::ShiftMixColumns, x)),
    );
    let aes_perms = symmetry::permutation_symmetries(&aes_round).len();
    log.add(s, "control: AES round, byte permutations it commutes with", format!("{aes_perms} (the column rotations)"), if aes_perms > 1 { Verdict::Caught } else { Verdict::Fail });
    let (ms_perms, sm_perms) = (symmetry::permutation_symmetries(&ms), symmetry::permutation_symmetries(&sm).len());
    let joint = ms_perms.iter().filter(|p| symmetry::is_symmetry(&sm, p)).count();
    log.add(
        s,
        "Turing's rounds, byte permutations they commute with",
        format!("ShiftRows+MixColumns {sm_perms} (like AES), MixState {}, both layers {joint}", ms_perms.len()),
        pass_if(joint == 1),
    );
    let control_pairs = symmetry::permutation_pairs(&symmetry::structured_cauchy()).len();
    log.add(s, "control: Cauchy matrix on points GF(16) and 2 + GF(16), shuffle pairs", format!("{control_pairs} (one per shift)"), if control_pairs > 1 { Verdict::Caught } else { Verdict::Fail });
    let ms_pairs = symmetry::permutation_pairs(&ms).len();
    log.add(s, "MixState, pairs (pi_out, pi_in) with pi_out MixState = MixState pi_in", format!("{ms_pairs}: only the identity, so no round-dependent shuffle crosses it"), pass_if(ms_pairs == 1));
    let generate = symmetry::cross_ratios_generate(&ms) && symmetry::cross_ratios_generate(&sm);
    log.add(s, "precondition: cross-ratios of both matrices generate GF(2^8)", format!("{generate}: any bytewise symmetry must be a field multiplication"), pass_if(generate));
    let bare: [u8; 256] = std::array::from_fn(|x| crate::gf256::inv(x as u8));
    let bare_count = symmetry::scalar_symmetries(&bare).len();
    log.add(s, "control: bare inverse x^-1, scaling symmetries", format!("{bare_count} of 255"), if bare_count == 255 { Verdict::Caught } else { Verdict::Fail });
    let own = symmetry::scalar_symmetries(table);
    log.add(s, "Turing's S-box, scalings x -> S^-1(beta S(x) ^ b) that are affine", format!("{own:?} (only the identity)"), pass_if(own == [(1, 0)]));
    let identity: [u8; 256] = std::array::from_fn(|x| x as u8);
    let hadamard = LinearMap::from_fn(128, |v| u128::from_le_bytes(symmetry::hadamard_columns(&v.to_le_bytes())));
    let control = symmetry::reflection_distance(&identity, &hadamard, &hadamard);
    log.add(s, "control: involutional SPN (x^-1, Hadamard layer)", format!("reflection distance {control}"), if control == 0 { Verdict::Caught } else { Verdict::Fail });
    let t = symmetry::turing_reflection_map();
    let layers = [Layer::MixState, Layer::ShiftMixColumns];
    let nearest = layers
        .iter()
        .flat_map(|&l| {
            let inv = LinearMap::from_fn(128, |v| u128::from_le_bytes(turing::linear::invert_layer(l, &v.to_le_bytes())));
            layers.iter().map(move |&target| symmetry::reflection_distance(&t, &inv, &LinearMap::turing(target))).collect::<Vec<_>>()
        })
        .min()
        .unwrap_or(0);
    log.add(s, "Turing: decryption rewritten with S^-1 = T S T", format!("closest to an encryption layer at rank {nearest} of 128 (0 would be a reflection)"), pass_if(nearest > 64));

    // --- Key-schedule relations ---------------------------------------------------------------
    let s = "17. Linear relations in the key schedule";
    let aes_rel = keyrelations::aes128(128, "campaign aes relations");
    log.add(s, "control: AES-128 key and round keys", format!("{} relations among {} bits", aes_rel.count(), aes_rel.columns - 1), if aes_rel.count() > 0 { Verdict::Caught } else { Verdict::Fail });
    for (name, r) in [("Turing key and all round keys", keyrelations::turing(128, "campaign relations")), ("Feistel stage alone (K' and round keys)", keyrelations::turing_feistel(128, "campaign feistel relations"))] {
        log.add(s, name, format!("{} relations among {} bits ({} random keys)", r.count(), r.columns - 1, r.samples), pass_if(r.count() == 0));
    }

    // --- Differential-linear ------------------------------------------------------------------
    let s = "18. Differential-linear (Langford-Hellman 1994)";
    let predicted = difflinear::predict_two_rounds(0x01);
    for rounds in [1, 2, 3, 4] {
        let d = difflinear::measure(rounds, 0x01, scale(1 << 22, 1 << 20), &format!("difflinear {rounds}"));
        let note = if rounds == 2 { format!(", predicted {:+.4} there", predicted[d.byte][d.mask as usize]) } else { String::new() };
        log.add(
            s,
            format!("{rounds} round(s)"),
            format!("best |correlation| {:.4} (byte {}, mask {:#04x}{note}); noise limit {:.4}", d.max_correlation, d.byte, d.mask, d.threshold()),
            if d.distinguishes() { Verdict::Broken } else { Verdict::Pass },
        );
    }

    // --- Masked implementation ------------------------------------------------------------------
    let s = "19. Masked implementation (first-order Boolean masking: ISW 2003, Rivain-Prouff 2010)";
    let mut rng = Rng::new("campaign masked");
    let trials = scale(200, 50);
    let mut mismatches = 0;
    for _ in 0..trials {
        let key: [u8; 32] = rng.bytes();
        let (t, mut m) = (Turing::new(&key), MaskedTuring::new(&key).expect("OS randomness"));
        let p: [u8; 16] = rng.bytes();
        let (mut a, mut b) = (p, p);
        t.encrypt_block(&mut a);
        m.encrypt_block(&mut b);
        let mut d = b;
        m.decrypt_block(&mut d);
        mismatches += usize::from(a != b || d != p);
    }
    log.add(s, "equals the plain cipher", format!("{trials} random keys and blocks, {mismatches} mismatches"), pass_if(mismatches == 0));
    let mut m = MaskedTuring::new(&[7; 32]).expect("OS randomness");
    let blocks = scale(40_000, 10_000);
    let mut b = [0u8; 16];
    let timer = Instant::now();
    for _ in 0..blocks {
        m.encrypt_block(&mut b);
    }
    log.add(s, "speed", format!("{:.2} us per block", timer.elapsed().as_secs_f64() * 1e6 / blocks as f64), Verdict::Info);
    let sigma = 2f64.sqrt();
    let key: [u8; 32] = rng.bytes();
    let n = scale(8000, 4000);
    let traces = leakage::collect(&key, n, &mut rng);
    let (s0, s1) = (leakage::cpa(&traces, View::Share(0), sigma, "campaign share 0"), leakage::cpa(&traces, View::Share(1), sigma, "campaign share 1"));
    log.add(
        s,
        "first-order CPA on one share (SNR 1; weight and 8 bit predictions)",
        format!("{s0} and {s1} of 16 key bytes ranked first from {n} traces (chance: 0.06)"),
        pass_if(s0 <= 2 && s1 <= 2),
    );
    let unmasked = leakage::cpa(&traces, View::Unmasked, sigma, "campaign unmasked");
    log.add(s, "control: the same attack on the unmasked value", format!("{unmasked} of 16 key bytes"), caught_if(unmasked == 16));
    let second = leakage::cpa(&traces, View::Product, sigma, "campaign product");
    log.add(
        s,
        "second-order CPA (centred product of both shares)",
        format!("{second} of 16 key bytes from {n} traces: order-1 masking does not claim order 2"),
        if second >= 12 { Verdict::Exposed } else { Verdict::Info },
    );
    let r = leakage::tvla(&key, scale(40_000, 20_000), sigma, false, "campaign tvla");
    log.add(
        s,
        "TVLA, every share byte after every S-box layer",
        format!("{} of {} points leak in both groups (max |t| {:.2}, {} traces)", r.shares.confirmed, r.shares.points, r.shares.max_t, r.traces),
        pass_if(!r.shares.leaks()),
    );
    log.add(s, "control: TVLA on the unmasked values", format!("{} of {} points leak (max |t| {:.0})", r.unmasked.confirmed, r.unmasked.points, r.unmasked.max_t), caught_if(r.unmasked.leaks()));
    let rep = leakage::tvla(&key, scale(8000, 4000), sigma, true, "campaign tvla repeat");
    log.add(
        s,
        "control: masks repeated in every trace (fixed seed)",
        format!("{} of {} share points leak (max |t| {:.0}): why masks are fresh and fork-safe", rep.shares.confirmed, rep.shares.points, rep.shares.max_t),
        caught_if(rep.shares.leaks()),
    );
    log.add(
        s,
        "TVLA second order (centred products of both shares)",
        format!("{} of {} points leak (max |t| {:.1}), as expected at order 1", r.product.confirmed, r.product.points, r.product.max_t),
        if r.product.leaks() { Verdict::Exposed } else { Verdict::Info },
    );

    // --- Keys in memory -------------------------------------------------------------------------
    let s = "20. Keys in memory (a memory-dump attacker: cold boot, crash dumps, RAMBleed)";
    let (hits, there) = residue::planted();
    log.add(s, "control: a key planted in the heap", format!("found at its address ({hits} fragment hits in all)"), caught_if(there && hits == 4));
    let plant = residue::stack_plant(false);
    log.add(s, "control: a key copy left in a dead stack frame", format!("{} of 4 fragments found in that thread's stack", plant.on_stack), caught_if(plant.on_stack == 4));
    let burned = residue::stack_plant(true);
    log.add(s, "the same copy, then burn_stack", describe(&burned), pass_if(burned.clean()));
    let (found, all) = residue::round_keys_found_in_their_page();
    log.add(s, "the scanner reads locked pages", format!("{found} of {all} round-key fragments found in the cipher's locked page"), pass_if(found == all));
    let (dirty, fragments) = residue::generator_copies(false, 8);
    log.add(
        s,
        "a key taken straight from the OS generator",
        format!(
            "{dirty} of 8 keys left {fragments} fragments elsewhere ({})",
            if cfg!(windows) { "Windows' ProcessPrng often leaves up to the last 16 bytes of its output in memory" } else { "getrandom(2) writes straight into the buffer" }
        ),
        Verdict::Info,
    );
    let (dirty, _) = residue::generator_copies(true, 8);
    log.add(s, "turing::random::new_key (cSHAKE256 of a 64-byte OS seed)", format!("{dirty} of 8 keys left a copy"), pass_if(dirty == 0));
    for snap in [residue::plain(true), residue::masked(), residue::shielded()].into_iter().flatten() {
        let verdict = pass_if(snap.clean());
        log.add(s, snap.scenario, describe(&snap), verdict);
    }
    let unburned = residue::plain(false);
    let (at_once, after_drop) = (&unburned[0], &unburned[2]);
    log.add(
        s,
        "control: the same key schedule without the stack burn",
        format!("{}; after the cipher is dropped: {} stray", describe(at_once), after_drop.stray.len()),
        if at_once.clean() { Verdict::Info } else { Verdict::Caught },
    );
    let depths = residue::stack_depths();
    let deepest = depths.iter().map(|d| d.1).max().unwrap_or(0);
    log.add(
        s,
        "stack the burn must cover",
        format!("{} bytes at most ({}); the burn writes {}", deepest, depths.iter().map(|(n, d)| format!("{n} {d}")).collect::<Vec<_>>().join(", "), turing::memory::BURN_BYTES),
        pass_if(deepest > 0 && deepest < turing::memory::BURN_BYTES),
    );
    let locked = Turing::new(&[1; 32]).keys_locked()
        && MaskedTuring::new(&[1; 32]).expect("OS randomness").keys_locked()
        && ShieldedKey::new(&[1; 32]).expect("OS randomness").locked();
    log.add(
        s,
        "key pages locked out of the page file",
        if locked { "Turing, MaskedTuring and ShieldedKey: all locked" } else { "the OS refused to lock (fallback: ordinary memory, still wiped)" },
        if locked { Verdict::Pass } else { Verdict::Info },
    );
    let excluded = Turing::new(&[1; 32]).keys_dump_excluded()
        && MaskedTuring::new(&[1; 32]).expect("OS randomness").keys_dump_excluded()
        && ShieldedKey::new(&[1; 32]).expect("OS randomness").dump_excluded();
    log.add(
        s,
        "key pages left out of core dumps",
        if excluded {
            "Turing, MaskedTuring and ShieldedKey: all excluded (MADV_DONTDUMP accepted)"
        } else if cfg!(any(target_os = "linux", target_os = "android")) {
            "the kernel refused MADV_DONTDUMP"
        } else {
            "no such call on this platform (Linux and Android only); crash dumps include the keys"
        },
        if excluded { Verdict::Pass } else { Verdict::Info },
    );

    // --- Time of check to time of use, concurrency ----------------------------------------------
    let s = "21. Time of check to time of use, and concurrency";
    let (caught, released, trials) = toctou::plain_flip_in_window(scale(400, 100), "campaign toctou");
    log.add(s, "round-key bit flipped between the key check and its use", format!("{caught} of {trials} caught by the second check, block wiped"), pass_if(caught == trials));
    log.add(
        s,
        "control: decrypt-and-compare alone, same flips",
        format!("{released} of {trials} would have released a ciphertext under the wrong key"),
        caught_if(released == trials),
    );
    let (caught, trials) = toctou::masked_flip_in_window(scale(100, 30), "campaign toctou masked");
    log.add(s, "masked cipher, a share bit flipped in the same window", format!("{caught} of {trials} caught"), pass_if(caught == trials));
    let (bad, total) = toctou::shared_across_threads(8, scale(5000, 1000), "campaign threads");
    log.add(s, "one Turing shared by 8 threads (plain and checked calls)", format!("{bad} of {total} results differ from a single-threaded run"), pass_if(bad == 0));
    match toctou::fork_draws_fresh_masks() {
        Some(fresh) => log.add(
            s,
            "fork(2): masks in the child and the parent",
            if fresh { "different: the child reseeded" } else { "IDENTICAL: the child reused the parent's masks" },
            pass_if(fresh),
        ),
        None => log.add(s, "fork(2): masks in the child and the parent", "no fork(2) here; run the campaign on Linux (tools/wsl_linux.py)", Verdict::Info),
    }
    log.add(
        s,
        "compile-time guarantees",
        "all key types are Send + Sync; MaskedTuring is not Clone and needs &mut for every call (doc tests E0277, E0596); checked calls take &mut Block, so nothing can rewrite it mid-call",
        Verdict::Info,
    );

    // --- Yoyo game ------------------------------------------------------------
    let s = "22. Yoyo game (Rønjom-Bardeh-Helleseth, ASIACRYPT 2017)";
    let trials = scale(1000, 200);
    let aes = Aes::new(&Rng::new("campaign yoyo aes").bytes());
    let aes_game = |rounds: usize, single: bool| {
        let (enc, dec) = (|p: &[u8; 16]| aes.encrypt(p, rounds, AesShape::Yoyo), |c: &[u8; 16]| aes.decrypt(c, rounds, AesShape::Yoyo));
        let label = format!("campaign yoyo aes {rounds}");
        if single {
            yoyo::single_game(enc, dec, &yoyo::columns(), &yoyo::columns(), trials, &label)
        } else {
            yoyo::pair_game(enc, dec, &yoyo::columns(), &yoyo::columns(), trials, &label)
        }
    };
    for (rounds, single, published) in [(3, true, "their Algorithm 2: always"), (4, false, "Algorithm 3: always"), (5, false, "not of the form S-L-S: never")] {
        let g = aes_game(rounds, single);
        let expected = if rounds < 5 { g.always() } else { g.kept == 0 };
        log.add(s, format!("AES, {rounds} rounds (validation; {published})"), format!("pattern returned in {} of {} games", g.kept, g.trials), pass_if(expected));
    }
    let t = Turing::new(&Rng::new("campaign yoyo turing").bytes());
    let turing_game = |rounds: usize, cipher: &yoyo::Words| {
        yoyo::pair_game(
            |p| {
                let mut c = *p;
                t.encrypt_rounds(&mut c, rounds);
                c
            },
            |c| {
                let mut p = *c;
                t.decrypt_rounds(&mut p, rounds);
                p
            },
            &yoyo::bytes(),
            cipher,
            trials,
            &format!("campaign yoyo turing {rounds}"),
        )
    };
    for (rounds, cipher, words) in [(2, yoyo::bytes(), "bytes"), (3, yoyo::columns(), "columns")] {
        let g = turing_game(rounds, &cipher);
        log.add(
            s,
            format!("{rounds} rounds, swapping ciphertext {words}"),
            format!("pattern returned in {} of {} games (a random permutation: never)", g.kept, g.trials),
            if g.always() { Verdict::Broken } else { Verdict::Fail },
        );
    }
    let kept4: usize = [yoyo::bytes(), yoyo::columns(), yoyo::diagonals()].iter().map(|w| turing_game(4, w).kept).sum();
    log.add(s, "4 rounds (MixState on both sides of a super-box layer)", format!("pattern returned in {kept4} of {} games (bytes, columns, diagonals)", 3 * trials), pass_if(kept4 == 0));
    let rk0 = *t.round_key(0);
    let keyed = |guess: &[u8; 16], rounds: usize| {
        let g = fast::to_u128(guess);
        yoyo::pair_game(
            |u| {
                let mut c = fast::to_block(keyedsquare::plaintext_for(fast::to_u128(u), g));
                t.encrypt_rounds(&mut c, rounds);
                c
            },
            |c| {
                let mut p = *c;
                t.decrypt_rounds(&mut p, rounds);
                fast::to_block(fast::sub_then(Layer::MixState, fast::to_u128(&p) ^ g))
            },
            &yoyo::diagonals(),
            &yoyo::columns(),
            trials,
            &format!("campaign keyed yoyo {rounds}"),
        )
    };
    let right = keyed(&rk0, 5);
    let mut wrong = rk0;
    wrong[7] ^= 1;
    let (off, six) = (keyed(&wrong, 5), keyed(&rk0, 6));
    log.add(
        s,
        "5 rounds with round key 0 guessed (rounds 2-5: super-box, linear, super-box)",
        format!(
            "right guess: {} of {}; one bit wrong: {}; 6 rounds even with the right guess: {}. Over 2^128 guesses: about 2^130 work and the full codebook, more than the square attack needs for 5 rounds (two 2^120 structures)",
            right.kept, right.trials, off.kept, six.kept
        ),
        if right.always() && off.kept == 0 && six.kept == 0 { Verdict::Broken } else { Verdict::Fail },
    );

    // --- Demirci-Selçuk meet-in-the-middle -----------------------------------
    let s = "23. Demirci-Selçuk meet-in-the-middle (FSE 2008; the best single-key attacks on AES-256)";
    let aes4 = mitm::parameters(&[Layer::ShiftMixColumns; 4], 0, 0);
    log.add(
        s,
        "AES, 4 rounds (validation: 25 parameters, 24 for differences; Derbez-Fouque FSE 2013, Property 5)",
        format!("{} and {} ({:?} per S-box layer)", aes4.values, aes4.differences, aes4.per_layer),
        pass_if((aes4.values, aes4.differences) == (25, 24)),
    );
    let windows: Vec<String> = (3..=5)
        .map(|rounds| {
            let first = mitm::best(&schedule[..rounds]).differences;
            let second = mitm::best(&schedule[1..=rounds]).differences;
            format!("{rounds} rounds: {first} after round 1's S-boxes, {second} after round 2's (AES {})", mitm::best(&[Layer::ShiftMixColumns; 5][..rounds]).differences)
        })
        .collect();
    log.add(s, "fewest parameters of a δ-set sequence (differences)", windows.join("; "), Verdict::Info);
    let four = mitm::best(&schedule[1..5]).differences.min(mitm::best(&schedule[..4]).differences);
    log.add(
        s,
        "4-round property",
        format!("{four} parameters: 2^{} sequences, more than the 2^256 keys; AES needs 24 (2^192)", 8 * four),
        pass_if(8 * four > 256),
    );
    let aes_table = mitm::enumerated(&[Layer::ShiftMixColumns; 4], 0, 0);
    let turing_table = mitm::enumerated(&schedule[1..5], 0, 0);
    log.add(
        s,
        "differential enumeration (validation: AES's 4-round table has 10 bytes, Derbez-Fouque-Jean 2013)",
        format!(
            "AES {} bytes (pair costs 2^-{}); Turing {} bytes, 2^{} sequences (pair costs 2^-{}: MixState turns 16 active bytes into 1)",
            aes_table.free,
            aes_table.cost,
            turing_table.free,
            8 * turing_table.free,
            turing_table.cost
        ),
        pass_if(aes_table.free == 10 && 8 * turing_table.free > 128),
    );
    log.add(
        s,
        "best attack from it",
        "the 3-round property (8 parameters) starts after round 2's S-boxes, so building a δ-set needs round key 0 (2^128 guesses) and reading its output a byte of round key 5: 5 rounds at about 2^144 S-box lookups with the full codebook, weaker than the square attack's 5 rounds with a 2^120 structure",
        Verdict::Info,
    );

    // --- Turing-256 ---------------------------------------------------------------------
    let s = "24. Turing-256: the same design on a 256-bit block (docs/15)";
    let mut rng = Rng::new("campaign turing-256");
    let trials = scale(300, 60);
    let mut mismatches = 0;
    for _ in 0..trials {
        let key: [u8; 32] = rng.bytes();
        let (t, r) = (Turing256::new(&key), Reference256::new(&key));
        let p: [u8; 32] = rng.bytes();
        let rounds = 1 + rng.below(turing::turing256::ROUNDS as u64) as usize;
        let mut c = p;
        t.encrypt_rounds(&mut c, rounds);
        let mut d = c;
        t.decrypt_rounds(&mut d, rounds);
        mismatches += usize::from(c != r.encrypt(&p, rounds) || d != p);
    }
    log.add(s, "matches its independent reference", format!("{trials} random keys/blocks/round counts, {mismatches} mismatches"), pass_if(mismatches == 0));
    let vectors = crate::refcipher256::known_answer_vectors();
    let kat_ok = vectors.iter().all(|(k, p, c)| {
        let mut b = *p;
        Turing256::new(k).encrypt_block(&mut b);
        b == *c
    });
    log.add(s, "known-answer vectors (vectors/turing-256-v1.txt)", format!("{} of {} reproduced", if kat_ok { vectors.len() } else { 0 }, vectors.len()), pass_if(kat_ok));
    let t = Turing256::new(&[7; 32]);
    let blocks = scale(100_000, 20_000);
    let mut b = [0u8; 32];
    let timer = Instant::now();
    for _ in 0..blocks {
        t.encrypt_block(&mut b);
    }
    let secs = timer.elapsed().as_secs_f64();
    std::hint::black_box(b);
    log.add(s, "speed", format!("{:.2} us per 32-byte block, {:.1} MB/s", secs * 1e6 / blocks as f64, blocks as f64 * 32.0 / secs / 1e6), Verdict::Info);
    let mix = crate::gen::linear256();
    let cauchy = crate::matrix::is_cauchy(&mix.m, &mix.xs, &mix.ys);
    let measured = mix.report.branch.iter().map(|&(_, b, _, _)| b).min().unwrap_or(0);
    log.add(
        s,
        "MixState256 (32 x 32) is MDS",
        format!("Cauchy over 64 distinct points from cSHAKE256: {}; submatrices of every size checked (sampled for 2-30); smallest measured branch {measured} (need 33)", if cauchy { "yes" } else { "NO" }),
        pass_if(cauchy && mix.report.passed()),
    );
    let bounds = crate::wide::min_active_alternating(32, 8);
    log.add(
        s,
        "trail bound (active S-boxes by window, exact for alternating layers)",
        format!(
            "1-8 rounds: {bounds:?}; any 4 rounds >= {} active (<= 2^-{}), beyond the 2^256 codebook, so usable trails cover at most 3 rounds",
            bounds[3],
            6 * bounds[3]
        ),
        pass_if(6 * bounds[3] > 256),
    );
    let windows_5: [Vec<Layer>; 2] = [crate::wide::alternating(Layer::MixState, 4), crate::wide::alternating(Layer::ShiftMixColumns, 4)];
    let four = crate::wide::one_byte_impossible(&[Layer::ShiftMixColumns, Layer::MixState, Layer::ShiftMixColumns], 32);
    let five = windows_5.iter().any(|w| crate::wide::one_byte_impossible(w, 32));
    log.add(
        s,
        "impossible differentials (one byte in, one out; active-byte counts)",
        format!("4 rounds (ShiftMix, MixState, ShiftMix): {}; 5 rounds: {}", if four { "yes" } else { "no" }, if five { "yes" } else { "none" }),
        pass_if(four && !five),
    );
    let from_round_1 = crate::wide::alternating(Layer::MixState, 30);
    let reach256 = |k: usize| crate::wide::balanced_until(&crate::wide::active(32, &(0..k).collect::<Vec<_>>()), &from_round_1, &turing::linear256::SHIFTS).unwrap_or(0);
    log.add(
        s,
        "division property: plaintext sets, S-box layer they stay balanced to",
        format!(
            "2^8-2^24: {}; 2^32-2^192: {}; 2^200-2^240: {}; 2^248: {} (a 5-round distinguisher, one round more than Turing's 2^120 set)",
            reach256(1),
            reach256(4),
            reach256(25),
            reach256(31)
        ),
        Verdict::Info,
    );
    let ks = crate::keyschedule::feistel_min_active_general(32, 33, turing::keyschedule256::round_key_depth(turing::turing256::ROUND_KEYS - 1));
    let weakest = (0..turing::turing256::ROUND_KEYS).map(|i| ks[turing::keyschedule256::round_key_depth(i) - 1]).min().unwrap_or(0);
    log.add(
        s,
        "key schedule: active S-boxes in front of every round key",
        format!("at least {weakest} (2^-{}), target 43; 9 warm-up rounds of 32-byte halves", 6 * weakest),
        pass_if(weakest >= crate::keyschedule::ROUND_KEY_TARGET),
    );
    let three = crate::attack256::balanced_bytes(3, &[0], "campaign 256 balance 3");
    let four_bal = crate::attack256::balanced_bytes(4, &[0], "campaign 256 balance 4");
    log.add(
        s,
        "square distinguisher, 2^8 texts, known key",
        format!("S-box layer 3 input: {three} of 32 bytes balanced; layer 4: {four_bal} (division property: 3)"),
        pass_if(three == 32 && four_bal < 32),
    );
    let a = crate::attack256::square_attack(3, &[0], 6, "campaign 256 square 3");
    log.add(
        s,
        "square attack, 3 rounds, 2^8 texts per structure",
        if a.correct { format!("RECOVERED round key 3 with {} structures", a.structures) } else { format!("not recovered: {:?}", a.candidates) },
        if a.correct { Verdict::Broken } else { Verdict::Fail },
    );
    let a = crate::attack256::square_attack(4, &[0, 1], 2, "campaign 256 square 4");
    log.add(
        s,
        "square attack, 4 rounds, 2^16 texts per structure",
        if a.correct { "RECOVERED round key 4 (the division property says it should fail)".to_string() } else { "fails, as the division property predicts".to_string() },
        pass_if(!a.correct),
    );
    let av = crate::avalanche::plaintext256(ROUNDS, scale(40, 12), "campaign 256 avalanche");
    log.add(
        s,
        "plaintext avalanche, full cipher (256 x 256 cells)",
        format!("mean {:.4} of output bits flip, worst |z| {:.2} (limit {:.2})", av.mean, av.worst_z, av.threshold),
        pass_if(av.passed()),
    );
    let av = crate::avalanche::key256(ROUNDS, scale(12, 4), "campaign 256 key avalanche");
    log.add(
        s,
        "key avalanche, full cipher",
        format!("mean {:.4}, worst |z| {:.2} (limit {:.2})", av.mean, av.worst_z, av.threshold),
        pass_if(av.passed()),
    );
    for rounds in [1, 2, ROUNDS] {
        let r = battery::run(battery::Source::Turing256 { rounds }, scale(64, 16), "campaign battery 256");
        let failing = r.failing_tests();
        let detail = if failing.is_empty() { format!("all 11 statistics pass ({} sequences)", r.sequences) } else { format!("fails: {}", failing.join(", ")) };
        let verdict = match (r.passed(), rounds < ROUNDS) {
            (false, true) => Verdict::Broken,
            (ok, _) => pass_if(ok),
        };
        log.add(s, r.source, detail, verdict);
    }
    let n = scale(300_000, 80_000);
    let t = Turing256::new(&[0x42; 32]);
    let r = timing::dudect("Turing-256 encryption", n, 32, |input| {
        let mut b: [u8; 32] = input.try_into().expect("32");
        t.encrypt_block(&mut b);
        std::hint::black_box(b);
    });
    log.add(s, "timing: encryption, fixed vs random plaintext", format!("max |t| {:.2} over {} runs", r.max_t, n), pass_if(!r.leaks()));
    let r = timing::dudect("Turing-256 decryption", n, 32, |input| {
        let mut b: [u8; 32] = input.try_into().expect("32");
        t.decrypt_block(&mut b);
        std::hint::black_box(b);
    });
    log.add(s, "timing: decryption, fixed vs random ciphertext", format!("max |t| {:.2} over {} runs", r.max_t, n), pass_if(!r.leaks()));
    let r = timing::dudect("Turing-256 key setup", scale(20_000, 6_000), 32, |input| {
        std::hint::black_box(Turing256::new(input.try_into().expect("32")));
    });
    log.add(s, "timing: key setup, fixed vs random key", format!("max |t| {:.2}", r.max_t), pass_if(!r.leaks()));
    let mut caught = 0;
    let faults = scale(400, 100);
    let bits = (2 * turing::turing256::ROUND_KEYS + 2) * 128;
    for _ in 0..faults {
        let mut t = Turing256::new(&[0x42; 32]);
        t.flip_stored_bit(rng.below(bits as u64) as usize);
        let mut b = [1u8; 32];
        caught += usize::from(t.encrypt_block_checked(&mut b).is_err() && b == [0; 32]);
    }
    log.add(s, "persistent key faults through the checked call", format!("{caught} of {faults} random stored-bit flips caught, block wiped"), pass_if(caught == faults));
    let t = Turing256::new(&[0x42; 32]);
    log.add(
        s,
        "round keys in locked, dump-excluded pages",
        format!("locked: {}, excluded from core dumps: {}", t.keys_locked(), t.keys_dump_excluded()),
        if t.keys_locked() { Verdict::Pass } else { Verdict::Info },
    );
    for snap in residue::plain256(true) {
        log.add(s, format!("memory scan: {}", snap.scenario), describe(&snap), pass_if(snap.clean()));
    }
    log.add(
        s,
        "security margin",
        format!(
            "usable trails 3 rounds, impossible differentials 4, integral 5 (2^248 texts); the docs/09 rule gives 5 + 4 = 9. On paper the integral with partial sums reaches 7 rounds for about 2^251; a whole round key is 256 bits, so guessing one costs as much as the key. {} rounds in the cipher",
            turing::turing256::ROUNDS
        ),
        Verdict::Info,
    );

    // --- Turing-1026 --------------------------------------------------------------------
    let s = "25. Turing-1026: post-quantum key encapsulation on plain LWE (docs/16)";
    let mut rng = Rng::new("campaign turing-1026");
    let seeds = scale(3, 1);
    let mut mismatches = 0;
    for _ in 0..seeds {
        let seed: [u8; 32] = rng.bytes();
        let dk = DecapsulationKey::from_seed(&seed).expect("consistent");
        let r = crate::refkem1026::ReferenceKem::from_seed(&seed);
        let (mu, salt): ([u8; 32], [u8; 64]) = (rng.bytes(), rng.bytes());
        let (ct, key) = dk.encapsulation_key().encapsulate_with(&mu, &salt);
        let (rct, rkey) = r.encapsulate(&mu, &salt);
        let mut bad = ct.clone();
        bad[rng.below(ct.len() as u64) as usize] ^= 1 << rng.below(8);
        let same = dk.encapsulation_key().as_bytes() == &r.public_key[..]
            && ct == rct
            && key[..] == rkey
            && dk.decapsulate(&ct).expect("length")[..] == rkey
            && Some(<[u8; 32]>::try_from(&dk.decapsulate(&bad).expect("length")[..]).expect("32")) == r.decapsulate(&bad);
        mismatches += usize::from(!same);
    }
    log.add(
        s,
        "matches its independent reference",
        format!("{seeds} random seeds: public key, ciphertext, shared key, decapsulation and a tampered ciphertext's rejection key; {mismatches} mismatches"),
        pass_if(mismatches == 0),
    );
    let vectors = crate::refkem1026::known_answer_vectors();
    let kat_ok = vectors.iter().all(|v| {
        let dk = DecapsulationKey::from_seed(&v.seed).expect("consistent");
        let (ct, key) = dk.encapsulation_key().encapsulate_with(&v.message, &v.salt);
        crate::refkem1026::sha3_256(dk.encapsulation_key().as_bytes()) == v.public_key_sha3 && crate::refkem1026::sha3_256(&ct) == v.ciphertext_sha3 && key[..] == v.shared_key
    });
    log.add(s, "known-answer vectors (vectors/turing-1026-v1.txt)", format!("{} of {} reproduced; turing::self_test checks vector 2: {:?}", if kat_ok { vectors.len() } else { 0 }, vectors.len(), turing::self_test()), pass_if(kat_ok && turing::self_test().is_ok()));
    let timer = Instant::now();
    let dk = DecapsulationKey::from_seed(&[0x5a; 32]).expect("consistent");
    let keygen = timer.elapsed().as_secs_f64();
    let reps = scale(20, 5);
    let timer = Instant::now();
    let cts: Vec<_> = (0..reps).map(|_| dk.encapsulation_key().encapsulate().expect("OS randomness")).collect();
    let encaps = timer.elapsed().as_secs_f64() / reps as f64;
    let timer = Instant::now();
    let all_back = cts.iter().all(|(ct, k)| dk.decapsulate(ct).expect("length")[..] == k[..]);
    let decaps = timer.elapsed().as_secs_f64() / reps as f64;
    log.add(
        s,
        "sizes and speed",
        format!(
            "public key {} bytes, ciphertext {} bytes, secret key a 32-byte seed; key generation {:.0} ms (with its pair-wise check), encapsulation {:.1} ms, decapsulation {:.1} ms",
            turing::turing1026::PUBLIC_KEY_BYTES,
            turing::turing1026::CIPHERTEXT_BYTES,
            keygen * 1e3,
            encaps * 1e3,
            decaps * 1e3
        ),
        pass_if(all_back),
    );
    let rows = crate::coresvp::published();
    let reproduced = rows.iter().filter(|r| crate::coresvp::estimate(&r.lwe, r.conv).is_some_and(|e| crate::coresvp::reproduces(r, &e))).count();
    log.add(
        s,
        "core-SVP model against published tables",
        format!("{reproduced} of {} rows reproduced (FrodoKEM round 3 Table 10, NewHope round 2 Table 12, ADPS16 Table 1), block sizes included", rows.len()),
        pass_if(reproduced == rows.len()),
    );
    let mut weakest = f64::INFINITY;
    for (name, lwe) in crate::coresvp::turing_1026() {
        let e = crate::coresvp::estimate(&lwe, crate::coresvp::Convention::NewHope).expect("an attack");
        let f = crate::coresvp::estimate(&lwe, crate::coresvp::Convention::Frodo).expect("an attack");
        weakest = weakest.min(e.classical());
        log.add(
            s,
            format!("lattice attacks, {name}"),
            format!(
                "primal BKZ-{}: 2^{:.1} classical, 2^{:.1} quantum; dual 2^{:.1} / 2^{:.1} (core-SVP; FrodoKEM's convention adds log2 b: 2^{:.1})",
                e.primal.b,
                e.primal_cost[0],
                e.primal_cost[1],
                e.dual_cost[0],
                e.dual_cost[1],
                f.classical()
            ),
            pass_if(e.classical() >= 250.0 && e.quantum() >= 225.0),
        );
    }
    let frodo_ok = crate::dfr::FRODO.iter().all(|&(_, n, lq, b, table, published)| (crate::dfr::frodo_rate(n, lq, b, table).message_symmetric - published).abs() < 0.05);
    log.add(s, "exact failure computation against FrodoKEM", format!("round-3 Table 2 rates (2^-138.7, 2^-199.6, 2^-252.5) {}", if frodo_ok { "reproduced to 0.05 bit" } else { "NOT reproduced" }), pass_if(frodo_ok));
    let rate = crate::dfr::turing_1026_rate();
    log.add(
        s,
        "decryption-failure probability",
        format!(
            "2^{:.2} per ciphertext (union bound over 256 coefficients of 2^{:.2}; error standard deviation {:.1}, window q/4 = 8192), below 2^-{:.1}, the weakest attack",
            rate.message, rate.per_coefficient, rate.sd, weakest
        ),
        pass_if(rate.message <= -weakest),
    );
    // The rate above is an average over keys; `bombe weak-keys` runs the
    // same with 100,000 keys.
    let tails = crate::weakkeys::proven_tails(&[-weakest, -240.0, -220.0]);
    let mut sample = crate::weakkeys::sample_keys(scale(2000, 200), "campaign weak keys");
    sample.sort_by(|a, b| b.saddlepoint_log2.total_cmp(&a.saddlepoint_log2));
    let (saddle, chernoff, exact) = crate::weakkeys::recheck_heaviest(&sample, 1)[0];
    log.add(
        s,
        "failure rates of individual keys",
        format!(
            "proven for all keys: at most 2^{:.1} of them above 2^-{weakest:.1}, 2^{:.1} above 2^-240, 2^{:.1} above 2^-220; {} sampled keys: median 2^{:.1}, the heaviest 2^{exact:.2} with every column's law exact (the saddlepoint approximation {:+.3} bits from it, the Chernoff bound 2^{chernoff:.1})",
            tails[0].fraction_log2(),
            tails[1].fraction_log2(),
            tails[2].fraction_log2(),
            sample.len(),
            sample[sample.len() / 2].saddlepoint_log2,
            saddle - exact
        ),
        pass_if((saddle - exact).abs() < 0.05 && chernoff >= exact && exact <= -weakest),
    );
    for (i, p) in crate::dfr::TRIAL_SETS.iter().enumerate() {
        // At least about 170 failures expected even in a quick run.
        let mc = crate::dfr::monte_carlo(*p, scale(400, 250), 50, &format!("campaign dfr {i}"));
        log.add(
            s,
            format!("failures of the real code at n = {}, q = 2^{}, CBD({})", p.n, p.log_q, p.eta),
            format!("{} wrong bits in {} decrypted, {:.3e} each against the exact law's {:.3e} (z = {:.2})", mc.failures, mc.trials, mc.failures as f64 / mc.trials as f64, mc.expected, mc.z),
            pass_if(mc.agrees()),
        );
    }
    let mut attacks = vec![(40, vec![10]), (70, vec![10])];
    if !quick {
        attacks.extend([(80, vec![10]), (90, vec![10, 16])]);
    }
    let mut observed = Vec::new();
    for (n, betas) in attacks {
        let a = crate::lattice::attack_turing_key(n, 15, 18, &betas, &format!("campaign lattice {n}"));
        observed.push((n, a.broken_by, betas.clone()));
        let by = match a.broken_by {
            0 => format!("not broken by BKZ-{}", betas.last().copied().unwrap_or(2)),
            2 => "LLL".to_string(),
            b => format!("BKZ-{b}"),
        };
        log.add(s, format!("primal attack on a real key cut to n = {n}"), format!("q = 2^15, CBD(18) as in Turing-1026: secret column recovered by {by} ({:.1} s)", a.seconds), if a.broken_by != 0 { Verdict::Broken } else { Verdict::Fail });
    }
    if !quick {
        // The model's largest n for each block size, from the root Hermite
        // factor this BKZ reaches on random lattices of the attack's shape.
        // Keys differ, so observations near a limit go either way: each is
        // checked against the model within 5 dimensions.
        let delta = [(10, crate::lattice::measured_delta(80, 15, 10, 1, "campaign delta 10")), (16, crate::lattice::measured_delta(80, 15, 16, 1, "campaign delta 16"))];
        let limit = |beta: usize| {
            let d = delta.iter().find(|&&(b, _)| b == beta).map(|&(_, d)| d);
            d.map(|d| (10..200).filter(|&n| crate::lattice::predicts_success(n, 15, 3.0, beta, d)).max().unwrap_or(0))
        };
        let consistent = observed.iter().all(|(n, by, betas)| {
            let broke_ok = *by < 10 || limit(*by).is_none_or(|l| l + 5 >= *n);
            let failed_ok = betas.iter().filter(|&&b| b < *by || *by == 0).all(|&b| limit(b).is_none_or(|l| l <= *n + 5));
            broke_ok && failed_ok
        });
        let seen: Vec<String> = observed.iter().filter(|o| o.1 >= 10).map(|(n, by, _)| format!("n = {n} by BKZ-{by}")).collect();
        log.add(
            s,
            "the estimate's success condition at small n",
            format!(
                "with the root Hermite factors this BKZ reaches (BKZ-10 {:.4}, BKZ-16 {:.4}) it puts their limits at n = {} and {}; observed {}, consistent within 5; at n = 1026 it asks for BKZ-868",
                delta[0].1,
                delta[1].1,
                limit(10).unwrap_or(0),
                limit(16).unwrap_or(0),
                seen.join(", ")
            ),
            pass_if(consistent),
        );
    }
    let tampered = scale(24, 6);
    let mut rejected = 0;
    let (ct, key) = dk.encapsulation_key().encapsulate().expect("OS randomness");
    for _ in 0..tampered {
        let mut bad = ct.clone();
        bad[rng.below(ct.len() as u64) as usize] ^= 1 << rng.below(8);
        rejected += usize::from(dk.decapsulate(&bad).expect("length")[..] != key[..]);
    }
    let other = DecapsulationKey::from_seed(&[0xa5; 32]).expect("consistent");
    let wrong_key = other.decapsulate(&ct).expect("length")[..] != key[..];
    let lengths = dk.decapsulate(&ct[1..]).is_err() && EncapsulationKey::from_bytes(&dk.encapsulation_key().as_bytes()[1..]).is_err();
    log.add(
        s,
        "chosen-ciphertext checks",
        format!("{rejected} of {tampered} single-bit changes anywhere in the ciphertext (salt included) give the rejection key; the right ciphertext under another key: {}; wrong lengths refused: {lengths}", if wrong_key { "rejection key" } else { "THE SHARED KEY" }),
        pass_if(rejected == tampered && wrong_key && lengths),
    );
    let faults = scale(24, 6);
    let mut caught = 0;
    for _ in 0..faults {
        let entry = rng.below((1026 * 32) as u64) as usize;
        let bit = rng.below(14) as u32;
        caught += usize::from(DecapsulationKey::from_seed_with_fault(&[0x5a; 32], entry, bit).is_err());
    }
    let harmless = DecapsulationKey::from_seed_with_fault(&[0x5a; 32], 77, 15).is_ok();
    log.add(
        s,
        "faults in S during key generation",
        format!("{caught} of {faults} single-bit flips in bits 0-13 of S caught by the pair-wise check; bit 15 changes S by 2^15 = 0 mod q, so it changes nothing and is not caught ({})", if harmless { "as expected" } else { "unexpectedly caught" }),
        pass_if(caught == faults && harmless),
    );
    let fault_map = crate::fault1026::single_fault_summary(3);
    log.add(
        s,
        "faults in decapsulation (the fault map)",
        format!(
            "over the accept mask, re-encryption, decoded message, coins, rejection and accepted keys and the selection: {} single faults bypass the re-encryption check, {} give a validity oracle (skipping z, which the double check cannot stop); two independent comparisons and chained selections mean forcing both verdicts (a correlated pair) is the cheapest bypass: {}",
            fault_map.bypasses,
            fault_map.validity_oracles,
            if fault_map.pair_bypasses { "two faults" } else { "not found" }
        ),
        pass_if(fault_map.bypasses == 0 && fault_map.pair_bypasses),
    );
    let n = scale(200_000, 50_000);
    let packed = vec![0x3cu8; 15_870];
    // Both classes do the same work: copy the packed ciphertext, change one
    // byte at a position from a generator of their own (independent of the
    // class) by 0 (fixed class: equal) or not (random class: differing),
    // compare. Harness mistakes show up here as leaks: comparing the fixed
    // class's buffer with itself gave |t| 113, and a position that was 0 for
    // the fixed class (the byte the comparison reads first, just written)
    // gave |t| 91.
    let equal_or_not = |compare: fn(&[u8], &[u8]) -> bool, name: &str| {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        timing::dudect(name, n, 2, |input| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut other = packed.clone();
            let at = (state % other.len() as u64) as usize;
            other[at] ^= (input[0] | 1) * u8::from(input != [0, 0]);
            std::hint::black_box(compare(&packed, &other));
        })
    };
    let r = equal_or_not(|a, b| turing::turing1026::eq_mask_for_timing(a, b) == 0xff, "Turing-1026 re-encryption check");
    log.add(s, "timing: re-encryption check, equal vs differing", format!("max |t| {:.2} over {} runs", r.max_t, n), pass_if(!r.leaks()));
    let r = equal_or_not(|a, b| a == b, "early-exit comparison");
    log.add(s, "control: the same test on an early-exit comparison (slice ==)", format!("max |t| {:.2}", r.max_t), caught_if(r.leaks()));
    let (ct, _) = dk.encapsulation_key().encapsulate().expect("OS randomness");
    let r = timing::dudect("Turing-1026 decapsulation", scale(3000, 400), 1, |input| {
        let mut c = ct.clone();
        if input[0] != 0 {
            c[usize::from(input[0]) * 61] ^= 1;
        }
        std::hint::black_box(dk.decapsulate(&c).expect("length"));
    });
    log.add(s, "timing: decapsulation, valid vs tampered ciphertext", format!("max |t| {:.2} over {} runs", r.max_t, r.measurements), pass_if(!r.leaks()));
    if !quick {
        let r = timing::dudect("Turing-1026 key generation", 600, 32, |input| {
            std::hint::black_box(DecapsulationKey::from_seed(input.try_into().expect("32")).expect("consistent"));
        });
        log.add(s, "timing: key generation, fixed vs random seed", format!("max |t| {:.2} over {} runs", r.max_t, r.measurements), pass_if(!r.leaks()));
    }
    log.add(
        s,
        "secret key in locked memory",
        format!("locked: {}", dk.keys_locked()),
        if dk.keys_locked() { Verdict::Pass } else { Verdict::Info },
    );
    for snap in residue::kem1026(true) {
        log.add(s, format!("memory scan: {}", snap.scenario), describe(&snap), pass_if(snap.clean()));
    }
    let unburned = residue::kem1026(false);
    log.add(
        s,
        "control: key generation without the stack burn",
        format!("{}; after drop: {} stray", describe(&unburned[0]), unburned[2].stray.len()),
        if unburned[0].clean() { Verdict::Info } else { Verdict::Caught },
    );
    log.add(
        s,
        "security summary",
        format!(
            "weakest lattice attack 2^{weakest:.1} classical core-SVP (the ciphertext's dual attack); the lattice-estimator's default model gives 2^269.7 against ML-KEM-1024's 2^262.3 and FrodoKEM-1344's 2^281.7 (docs/16); failure probability 2^{:.1}; attacks break the real code up to the dimensions above, the scheme needs BKZ-868",
            rate.message
        ),
        Verdict::Info,
    );

    Campaign { findings: log.findings, quick, seconds: start.elapsed().as_secs_f64() }
}
