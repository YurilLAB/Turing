//! The attack campaign: every experiment Bombe can run against the real
//! cipher, with a verdict for each. Reduced-round versions are attacked to
//! find how many rounds each technique breaks; the full cipher must resist
//! all of them; negative controls must fail, or the test that missed them
//! is useless.

use crate::invariant::LinearMap;
use crate::refcipher::Reference;
use crate::rng::Rng;
use crate::leakage::{self, View};
use crate::residue::{self, Snapshot};
use crate::{
    avalanche, battery, boomerang, cube, difflinear, differential, fault, integral, interpolation, invariant, keycheck, keyrelations, power, provable,
    relatedkey, symmetry, timing, toctou,
};
use std::fmt::Write;
use std::time::Instant;
use turing::structure::{Layer, ROUNDS};
use turing::{MaskedTuring, ShieldedKey, Turing};

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
    log.add(
        s,
        "security margin against this attack",
        format!(
            "1-byte distinguisher reaches {broken_through} rounds; key recovery 3 rounds (2^8 texts), 4 rounds (2^32 texts, predicted{}); {ROUNDS} rounds in the cipher",
            if deep { " and run above" } else { "; --deep runs it" }
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

    Campaign { findings: log.findings, quick, seconds: start.elapsed().as_secs_f64() }
}
