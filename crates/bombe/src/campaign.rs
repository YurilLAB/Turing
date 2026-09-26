//! The attack campaign: every experiment Bombe can run against the real
//! cipher, with a verdict for each. Reduced-round versions are attacked to
//! find how many rounds each technique breaks; the full cipher must resist
//! all of them; negative controls must fail, or the test that missed them
//! is useless.

use crate::invariant::LinearMap;
use crate::refcipher::Reference;
use crate::rng::Rng;
use crate::{avalanche, battery, boomerang, cube, differential, fault, integral, interpolation, invariant, keycheck, power, relatedkey, timing};
use std::fmt::Write;
use std::time::Instant;
use turing::structure::{Layer, ROUNDS};
use turing::Turing;

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
        "byte fault in round 15, unprotected implementation",
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
        "masking, not implemented (not in the desktop threat model): the S-box's x^254 is Rivain-Prouff's 4-multiplication chain, maskable at any order",
        Verdict::Info,
    );

    Campaign { findings: log.findings, quick, seconds: start.elapsed().as_secs_f64() }
}
