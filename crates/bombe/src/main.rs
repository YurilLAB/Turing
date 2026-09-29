use bombe::matrix::{self, MdsReport};
use bombe::{gen, html, report::Report, sbox::Sbox};
use std::process::ExitCode;

const USAGE: &str = "\
Bombe: cryptanalysis workbench for the Turing cipher

Usage:
  bombe sbox <SOURCE> [--html <OUT.html>]
  bombe gen-sbox [--rust <OUT.rs>] [--html <OUT.html>]
  bombe gen-linear [--turing-256] [--rust <OUT.rs>]
  bombe gen-constants --turing-256 [--rust <OUT.rs>]
  bombe key-schedule
  bombe rounds [ROUNDS]
  bombe vectors [--turing-256 | --turing-1026] [--out PATH]
  bombe attack [--quick] [--deep] [--report PATH | --no-report]
  bombe weak-keys [KEYS]      Turing-1026's per-key failure rates (default 100,000 keys)
  bombe fault-map             Turing-1026 decapsulation under transient faults
  bombe noise [--keys K] [--encryptions E] [--minutes M] [--state PATH] [--label L]
              [--negative-control]
                              the real Turing-1026 code's decryption error against
                              docs/16's exact law, on every thread (tools/CI.md)
  bombe dfr-tail N ETA T...   P(X < -T or X >= T) for docs/16's law of 2N products
                              of CBD(ETA) plus one sample (for tools/simulate.py)
  bombe trace [--key HEX] [--plaintext HEX] [--rounds N]
              [--flip-plaintext-bit N | --flip-key-bit N | --key2 HEX | --plaintext2 HEX]

SOURCE:
  turing       the Turing S-box
  aes          the AES S-box (reference for validating the tools)
  aes-inv      its inverse
  identity     S(x) = x (negative control)
  random:SEED  a seeded random permutation (baseline)
  <path>       a file with 256 hex bytes

Exit status: 0 if the S-box meets the Turing v1 criteria, 1 if not, 2 on error.";

fn load(source: &str) -> Result<(String, Sbox), String> {
    match source {
        "turing" => Ok(("Turing S-box".into(), Sbox::new(turing::sbox::TABLE))),
        "aes" => Ok(("AES S-box".into(), Sbox::aes())),
        "aes-inv" => Ok(("AES inverse S-box".into(), Sbox::aes().inverse().expect("AES S-box is a permutation"))),
        "identity" => Ok(("Identity S-box".into(), Sbox::identity())),
        s if s.starts_with("random:") => {
            let seed = s["random:".len()..].parse::<u64>().map_err(|_| format!("bad seed in {s:?}"))?;
            Ok((format!("Random permutation (seed {seed})"), Sbox::random(seed)))
        }
        path => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
            let sbox = Sbox::parse(&text).map_err(|e| format!("{path}: {e}"))?;
            Ok((path.to_string(), sbox))
        }
    }
}

fn run_sbox(args: &[String]) -> Result<bool, String> {
    let mut source = None;
    let mut html_out = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--html" => html_out = Some(it.next().ok_or("--html needs a file path")?.clone()),
            s if source.is_none() => source = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s:?}")),
        }
    }
    let (name, sbox) = load(&source.ok_or("missing SOURCE")?)?;
    let report = Report::new(&name, &sbox);
    print!("{}", report.to_text());
    if let Some(path) = html_out {
        std::fs::write(&path, html::render(&report)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("Worksheet written to {path}");
    }
    Ok(report.passed())
}

fn parse_outputs(args: &[String]) -> Result<(Option<String>, Option<String>), String> {
    let (mut rust, mut html_out) = (None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let slot = match arg.as_str() {
            "--rust" => &mut rust,
            "--html" => &mut html_out,
            s => return Err(format!("unexpected argument {s:?}")),
        };
        *slot = Some(it.next().ok_or(format!("{arg} needs a file path"))?.clone());
    }
    Ok((rust, html_out))
}

fn run_gen(args: &[String]) -> Result<bool, String> {
    let (rust, html_out) = parse_outputs(args)?;
    let search = gen::search();
    let c = &search.chosen;
    println!("Deriving from cSHAKE256(X = counter, S = \"{}\")\n", gen::LABEL);
    for (counter, failed) in &search.rejected {
        println!("  candidate {counter:>3}  rejected: {}", failed.join(", "));
    }
    println!("  candidate {:>3}  ACCEPTED\n", c.counter);
    for (name, a) in [("A_in ", &c.a_in), ("A_out", &c.a_out)] {
        let rows: Vec<String> = a.rows.iter().map(|r| format!("{r:08b}")).collect();
        println!("{name} rows {}  constant {:#04x}", rows.join(" "), a.constant);
    }
    println!();
    print!("{}", search.report.to_text());
    if let Some(path) = rust {
        std::fs::write(&path, gen::render_rust(&search)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("Rust constants written to {path}");
    }
    if let Some(path) = html_out {
        std::fs::write(&path, html::render(&search.report)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("Worksheet written to {path}");
    }
    Ok(search.report.passed())
}

const AES_MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

fn print_matrix(m: &matrix::Matrix) {
    for row in m {
        let cells: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
        println!("    {}", cells.join(" "));
    }
}

fn run_gen_linear(args: &[String]) -> Result<bool, String> {
    if args.first().map(String::as_str) == Some("--turing-256") {
        return run_gen_linear256(&args[1..]);
    }
    let (rust, html_out) = parse_outputs(args)?;
    if html_out.is_some() {
        return Err("gen-linear has no HTML output".into());
    }
    let aes = matrix::from_array(&AES_MIX);
    let aes_report = MdsReport::new(&aes, &matrix::invert(&aes).ok_or("AES matrix is singular")?);
    println!("Reference: AES MixColumns");
    print!("{}", aes_report.to_text());
    println!("  verdict: {}\n", if aes_report.passed() { "MDS" } else { "NOT MDS" });

    let l = gen::linear();
    for c in [&l.columns, &l.state] {
        let n = c.m.len();
        println!("{} ({n}x{n}): cSHAKE256(X = {}, S = \"{}\")", if n == 4 { "MixColumns" } else { "MixState" }, c.counter, c.label);
        let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        println!("  x = {}", hex(&c.xs));
        println!("  y = {}", hex(&c.ys));
        println!("  Cauchy structure (proves MDS)       {}", if matrix::is_cauchy(&c.m, &c.xs, &c.ys) { "yes" } else { "NO" });
        if n == 4 {
            print_matrix(&c.m);
        }
        print!("{}", c.report.to_text());
        println!("  verdict: {}\n", if c.report.passed() { "MDS" } else { "NOT MDS" });
    }
    let aes_round = |p| matrix::mix_columns_pattern(matrix::shift_rows_pattern(p));
    println!("Rounds until every output byte depends on every input byte");
    println!("  ShiftRows + MixColumns   {}", matrix::rounds_to_full_diffusion(aes_round));
    println!("  MixState                 {}", matrix::rounds_to_full_diffusion(matrix::mix_state_pattern));
    if let Some(path) = rust {
        std::fs::write(&path, gen::render_linear_rust(&l)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("\nRust constants written to {path}");
    }
    Ok(aes_report.passed() && l.columns.report.passed() && l.state.report.passed())
}

/// Turing-256's round constants (docs/15, version 2).
fn run_gen_constants(args: &[String]) -> Result<bool, String> {
    if args.first().map(String::as_str) != Some("--turing-256") {
        return Err("usage: bombe gen-constants --turing-256 [--rust <OUT.rs>]".into());
    }
    let (rust, html_out) = parse_outputs(&args[1..])?;
    if html_out.is_some() {
        return Err("gen-constants has no HTML output".into());
    }
    let constants = gen::round_constants256();
    println!("Turing-256 round constants: cSHAKE256(X = \"\", S = \"{}\")", gen::ROUND_CONSTANTS256_LABEL);
    for (i, c) in constants.iter().enumerate() {
        println!("  round {:2}: {}", i + 1, c.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    if let Some(path) = rust {
        std::fs::write(&path, gen::render_round_constants256_rust(&constants)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("\nRust constants written to {path}");
    }
    Ok(true)
}

/// Turing-256's 32x32 MixState (docs/15).
fn run_gen_linear256(args: &[String]) -> Result<bool, String> {
    let (rust, html_out) = parse_outputs(args)?;
    if html_out.is_some() {
        return Err("gen-linear has no HTML output".into());
    }
    let c = gen::linear256();
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    println!("Turing-256 MixState (32x32): cSHAKE256(X = {}, S = \"{}\")", c.counter, c.label);
    println!("  x = {}", hex(&c.xs));
    println!("  y = {}", hex(&c.ys));
    println!("  Cauchy structure (proves MDS)       {}", if matrix::is_cauchy(&c.m, &c.xs, &c.ys) { "yes" } else { "NO" });
    print!("{}", c.report.to_text());
    println!("  verdict: {}", if c.report.passed() { "MDS" } else { "NOT MDS" });
    if let Some(path) = rust {
        std::fs::write(&path, gen::render_linear256_rust(&c)).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("\nRust constants written to {path}");
    }
    Ok(c.report.passed())
}

fn run_key_schedule() -> Result<bool, String> {
    use bombe::keyschedule::{feistel_min_active, round_key_bound, ROUND_KEY_TARGET};
    use turing::keyschedule::{round_key_depth, ROUNDS_PER_PAIR, WARMUP_ROUNDS};
    use turing::structure::ROUND_KEYS;
    println!("Key-schedule Feistel, F = MixState(S(x ^ C)): minimum active S-boxes");
    println!("for any non-zero key difference (each costs at least 2^-6)\n");
    for (i, b) in feistel_min_active(16).iter().enumerate() {
        println!("  {:>2} rounds  >= {b:>2} active  (trail probability <= 2^-{})", i + 1, 6 * b);
    }
    println!("\nWarm-up {WARMUP_ROUNDS} rounds, then one pair of round keys every {ROUNDS_PER_PAIR} rounds.");
    println!("Round key  Feistel rounds behind it  Min active S-boxes");
    let mut worst = u32::MAX;
    for i in 0..ROUND_KEYS {
        let b = round_key_bound(i);
        worst = worst.min(b);
        println!("  RK{i:<3}    {:>4}                      {b:>4}", round_key_depth(i));
    }
    let pass = worst >= ROUND_KEY_TARGET;
    println!("\nEvery round key >= {ROUND_KEY_TARGET} active S-boxes: weakest {worst}  {}", if pass { "PASS" } else { "FAIL" });
    Ok(pass)
}

fn run_rounds(args: &[String]) -> Result<bool, String> {
    use bombe::structure::{candidates, evaluate};
    let rounds = match args.first() {
        Some(r) => r.parse::<usize>().map_err(|_| format!("bad round count {r:?}"))?,
        None => turing::structure::ROUNDS,
    };
    if !(2..=40).contains(&rounds) {
        return Err("round count must be 2..=40".into());
    }
    const WINDOWS: usize = 8;
    println!("Candidate round structures for a {rounds}-round cipher (weakest window of r rounds)\n");
    print!("{:<34}", "structure");
    for r in 1..=WINDOWS {
        print!("{:>5}", format!("r{r}"));
    }
    println!("  to22  to43  ID  diff  run  MS  cost");
    let fmt = |v: Option<usize>| v.map_or("-".to_string(), |x| x.to_string());
    let show = |name: &str, schedule: &[bombe::trail::Layer]| {
        let e = evaluate(schedule, WINDOWS);
        print!("{name:<34}");
        for b in &e.weakest {
            print!("{b:>5}");
        }
        println!(
            "  {:>4}  {:>4}  {:>2}  {:>4}  {:>3}  {:>2}  {:>4}",
            fmt(e.rounds_to_22),
            fmt(e.rounds_to_43),
            e.impossible,
            fmt(e.diffusion),
            e.aes_like_run,
            e.mix_states,
            e.cost
        );
    };
    for (name, schedule) in candidates(rounds) {
        show(&name, &schedule);
    }
    if rounds == turing::structure::ROUNDS {
        println!();
        show("TURING (turing::structure)", &turing::structure::schedule());
    }
    println!("\nto22/to43: rounds until every window has >= 22 / 43 active S-boxes (2^-132 / 2^-258).");
    println!("ID: longest impossible differential. diff: rounds to full diffusion.");
    println!("run: longest stretch of ShiftRows+MixColumns. MS: MixState layers. cost: relative work.");
    Ok(true)
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let s = s.trim();
    if s.len() != 2 * N {
        return Err(format!("{what} must be {} hex digits", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| format!("{what} is not hex"))?;
    }
    Ok(out)
}

fn run_trace(args: &[String]) -> Result<bool, String> {
    let mut key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let mut plaintext: [u8; 16] = std::array::from_fn(|i| (i as u8) * 0x11);
    let (mut key2, mut plaintext2) = (None, None);
    let mut rounds = turing::structure::ROUNDS;
    let mut it = args.iter();
    let value = |it: &mut std::slice::Iter<String>, flag: &str| {
        it.next().cloned().ok_or(format!("{flag} needs a value"))
    };
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--key" => key = parse_hex(&value(&mut it, flag)?, "key")?,
            "--plaintext" => plaintext = parse_hex(&value(&mut it, flag)?, "plaintext")?,
            "--key2" => key2 = Some(parse_hex(&value(&mut it, flag)?, "key2")?),
            "--plaintext2" => plaintext2 = Some(parse_hex(&value(&mut it, flag)?, "plaintext2")?),
            "--flip-plaintext-bit" | "--flip-key-bit" => {
                let bit: usize = value(&mut it, flag)?.parse().map_err(|_| "bit must be a number")?;
                if flag == "--flip-key-bit" {
                    if bit >= 256 {
                        return Err("key bit must be 0..=255".into());
                    }
                    let mut k = key2.unwrap_or(key);
                    k[bit / 8] ^= 1 << (bit % 8);
                    key2 = Some(k);
                } else {
                    if bit >= 128 {
                        return Err("plaintext bit must be 0..=127".into());
                    }
                    let mut p = plaintext2.unwrap_or(plaintext);
                    p[bit / 8] ^= 1 << (bit % 8);
                    plaintext2 = Some(p);
                }
            }
            "--rounds" => {
                rounds = value(&mut it, flag)?.parse().map_err(|_| "rounds must be a number")?;
                if !(1..=turing::structure::ROUNDS).contains(&rounds) {
                    return Err(format!("rounds must be 1..={}", turing::structure::ROUNDS));
                }
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    let compare = key2.is_some() || plaintext2.is_some();
    let (k2, p2) = (key2.unwrap_or(key), plaintext2.unwrap_or(plaintext));
    println!("Turing round tracer, {rounds} round(s)");
    println!("key A        {}", bombe::refcipher::hex(&key));
    println!("plaintext A  {}", bombe::refcipher::hex(&plaintext));
    if compare {
        println!("key B        {}", bombe::refcipher::hex(&k2));
        println!("plaintext B  {}", bombe::refcipher::hex(&p2));
    }
    println!();
    let steps = bombe::trace::trace(&key, &plaintext, compare.then_some((&k2, &p2)), rounds);
    print!("{}", bombe::trace::render(&steps));
    Ok(true)
}

fn run_attack(args: &[String]) -> Result<bool, String> {
    let mut quick = false;
    let mut deep = false;
    let mut report = Some("target/reports/attack-report.md".to_string());
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--quick" => quick = true,
            "--deep" => deep = true,
            "--report" => report = Some(it.next().ok_or("--report needs a path")?.clone()),
            "--no-report" => report = None,
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    println!("Bombe attack campaign against Turing ({} run)", if quick { "quick" } else { "full" });
    println!("PASS = resists / holds, BROKEN = reduced rounds broken (expected), CAUGHT = control detected,");
    println!("EXPOSED = implementation attack needing a countermeasure, FAIL = a problem, INFO = measurement.");
    let mut section = String::new();
    let campaign = bombe::campaign::run(quick, deep, &mut |f| {
        if f.section != section {
            section = f.section.to_string();
            println!("\n{section}");
        }
        println!("  {:<7} {:<46} {}", format!("{:?}", f.verdict).to_uppercase(), f.test, f.result);
    });
    println!("\n{} findings, {} failures, {:.0} s.", campaign.findings.len(), campaign.failures(), campaign.seconds);
    if let Some(path) = report {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        std::fs::write(&path, campaign.to_markdown()).map_err(|e| format!("cannot write {path}: {e}"))?;
        println!("Report written to {path}");
    }
    Ok(campaign.failures() == 0)
}

fn run_vectors(args: &[String]) -> Result<bool, String> {
    let (text, args) = match args.first().map(String::as_str) {
        Some("--turing-256") => (bombe::refcipher256::render_vectors(), &args[1..]),
        Some("--turing-1026") => (bombe::refkem1026::render_vectors(), &args[1..]),
        _ => (bombe::refcipher::render_vectors(), args),
    };
    match args {
        [flag, path] if flag == "--out" => {
            std::fs::write(path, &text).map_err(|e| format!("cannot write {path}: {e}"))?;
            println!("Known-answer vectors written to {path}");
        }
        [] => print!("{text}"),
        _ => return Err("usage: bombe vectors [--turing-256 | --turing-1026] [--out PATH]".into()),
    }
    Ok(true)
}

fn run_fault_map(args: &[String]) -> Result<bool, String> {
    if !args.is_empty() {
        return Err("usage: bombe fault-map".into());
    }
    let (text, ok) = bombe::fault1026::report(1);
    print!("{text}");
    Ok(ok)
}

fn run_weak_keys(args: &[String]) -> Result<bool, String> {
    let keys = match args {
        [] => 100_000,
        [k] => k.parse::<usize>().map_err(|_| format!("bad key count {k:?}"))?,
        _ => return Err("usage: bombe weak-keys [KEYS]".into()),
    };
    let (text, ok) = bombe::weakkeys::report(keys, 5, "weak key distribution");
    print!("{text}");
    Ok(ok)
}

fn run_dfr_tail(args: &[String]) -> Result<bool, String> {
    let usage = "usage: bombe dfr-tail N ETA T [T ...]";
    let [n, eta, thresholds @ ..] = args else {
        return Err(usage.into());
    };
    let n: u64 = n.parse().ok().filter(|n| (1..=4096).contains(n)).ok_or(format!("bad N {n:?} (1..=4096)"))?;
    let eta: u32 = eta.parse().ok().filter(|e| (1..=32).contains(e)).ok_or(format!("bad ETA {eta:?} (1..=32)"))?;
    if thresholds.is_empty() {
        return Err(usage.into());
    }
    let thresholds = thresholds.iter().map(|t| t.parse::<i64>().ok().filter(|&t| t > 0).ok_or(format!("bad threshold {t:?}"))).collect::<Result<Vec<_>, _>>()?;
    let law = bombe::dfr::error_law(&bombe::dfr::Law::cbd(eta), n);
    for t in thresholds {
        println!("{t} {:e}", law.sum_where(|x| x < -t || x >= t));
    }
    Ok(true)
}

fn run_noise(args: &[String]) -> Result<bool, String> {
    use bombe::noise1026::{self as noise, Tally};
    let (mut keys, mut encryptions, mut minutes) = (400usize, 4usize, 0.0f64);
    let (mut state, mut label, mut negative) = (None::<String>, None::<String>, false);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--keys" => keys = value()?.parse().map_err(|_| "bad --keys")?,
            "--encryptions" => encryptions = value()?.parse().map_err(|_| "bad --encryptions")?,
            "--minutes" => minutes = value()?.parse().map_err(|_| "bad --minutes")?,
            "--state" => state = Some(value()?.clone()),
            "--label" => label = Some(value()?.clone()),
            "--negative-control" => negative = true,
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    if keys < noise::MIN_KEYS as usize || !(1..=64).contains(&encryptions) || !minutes.is_finite() || minutes < 0.0 {
        return Err(format!("need --keys >= {}, --encryptions 1..=64, --minutes >= 0", noise::MIN_KEYS));
    }
    if label.is_some() && state.is_some() {
        // A label names its keys, so a repeated label would add the same
        // samples to the evidence twice.
        return Err("--label reproduces a run's keys; it cannot be combined with --state".into());
    }
    // The law under test is docs/16's; the negative control encrypts with
    // CBD(eta - 1) noise instead and must be caught.
    let claimed = turing::turing1026::PARAMS;
    let data = if negative { turing::lwe::Params { eta: claimed.eta - 1, ..claimed } } else { claimed };
    let label = match label {
        Some(l) => l,
        None => {
            let mut nonce = [0u8; 8];
            turing::random::os_random(&mut nonce).map_err(|_| "no OS randomness")?;
            format!("noise {:016x}", u64::from_le_bytes(nonce))
        }
    };
    let n = claimed.n as u64;
    let grid = noise::grid(noise::sd(claimed.eta, n));
    let laws = [
        (format!("docs/16's law (CBD({}), {} products)", claimed.eta, 2 * n), noise::exact(claimed.eta, n, &grid)),
        (format!("control: CBD({}) noise", claimed.eta - 1), noise::exact(claimed.eta - 1, n, &grid)),
        (format!("control: {n} products instead of {}", 2 * n), noise::exact(claimed.eta, n / 2, &grid)),
    ];
    println!("Real Turing-1026 encryptions{}, label {label:?}", if negative { " with CBD(17) noise (negative control)" } else { "" });
    let per_key = (encryptions * claimed.mbar * claimed.nbar) as u64;
    // The accumulated evidence, saved after every batch so that a long run
    // cut short keeps what it measured. The negative control's samples are
    // wrong on purpose and never join it.
    let fingerprint = noise::fingerprint(&data, encryptions, &grid);
    let mut total = match (&state, negative) {
        (Some(path), false) => Some(std::fs::read_to_string(path).ok().and_then(|t| Tally::from_text(&t, &fingerprint, per_key)).unwrap_or_else(|| {
            println!("(starting a new state file {path}: none yet, or it is from other code or parameters)");
            Tally::new(per_key)
        })),
        _ => None,
    };
    let save = |total: &Tally, path: &str| -> Result<(), String> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, total.to_text(&fingerprint)).map_err(|e| format!("cannot write {tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {path}: {e}"))
    };
    let start = std::time::Instant::now();
    let mut run = Tally::new(per_key);
    let mut batch = 0u64;
    loop {
        let t = std::time::Instant::now();
        let measured = noise::measure(&data, &grid, batch * keys as u64, keys, encryptions, &label);
        run.merge(&measured);
        if let (Some(total), Some(path)) = (total.as_mut(), &state) {
            total.merge(&measured);
            save(total, path)?;
        }
        batch += 1;
        println!("  {} keys, {} ciphertexts, {} coefficients, {:.1} s", run.keys, run.keys * encryptions as u64, run.keys * run.per_key, t.elapsed().as_secs_f64());
        if start.elapsed().as_secs_f64() >= minutes * 60.0 {
            break;
        }
    }
    let judge_all = |tally: &Tally, heading: &str| -> bool {
        println!("\n{heading}: {} keys, {} coefficients; {} decryption failures, {} decryptions disagreeing with their measured error", tally.keys, tally.keys * tally.per_key, tally.failures, tally.inconsistent);
        let verdicts: Vec<noise::Verdict> = laws.iter().map(|(_, e)| noise::judge(tally, e)).collect();
        println!("  {:<16} {:>13} {:>13} {:>9} {:>9} {:>9}", "statistic", "exact", "measured", "z", "z ctl 1", "z ctl 2");
        let k = tally.keys as f64;
        for i in 0..noise::STATS {
            let se = (tally.m2[i] / (k - 1.0) / k).sqrt();
            let zs: Vec<String> = verdicts.iter().map(|v| v.z[i].map_or("-".into(), |z| format!("{z:.2}"))).collect();
            println!("  {:<16} {:>13.6e} {:>13.6e} {:>9} {:>9} {:>9}  (+- {se:.1e})", noise::stat_name(&grid, i), laws[0].1[i], tally.mean[i], zs[0], zs[1], zs[2]);
        }
        let mut ok = tally.failures == 0 && tally.inconsistent == 0;
        for (i, ((name, _), v)) in laws.iter().zip(&verdicts).enumerate() {
            let worst = v.worst().map_or("nothing judged yet".into(), |(s, z)| format!("largest |z| {:.2} at {}", z.abs(), noise::stat_name(&grid, s)));
            let (word, good) = match (i, negative, v.rejected()) {
                (0, false, false) => ("agrees", v.judged > 0),
                (0, false, true) => ("DISAGREES", false),
                (0, true, true) => ("rejected, as the negative control must be", true),
                (0, true, false) => ("NOT REJECTED: the check cannot see CBD(17) noise", false),
                (_, false, true) => ("rejected", true),
                (_, false, false) => ("NOT REJECTED", false),
                (_, true, _) => ("(not judged in the negative control)", true),
            };
            println!("  {name}: {word}; {} statistics judged, critical |z| {:.2}, {worst}", v.judged, v.critical);
            ok &= good;
        }
        ok
    };
    let mut ok = judge_all(&run, "This run");
    if let (Some(total), Some(path)) = (&total, &state) {
        ok &= judge_all(total, &format!("All runs so far ({path})"));
    }
    println!("\nRESULT: {}", if ok { "PASS" } else { "FAIL" });
    Ok(ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("sbox") => run_sbox(&args[1..]),
        Some("gen-sbox") => run_gen(&args[1..]),
        Some("gen-linear") => run_gen_linear(&args[1..]),
        Some("gen-constants") => run_gen_constants(&args[1..]),
        Some("key-schedule") => run_key_schedule(),
        Some("rounds") => run_rounds(&args[1..]),
        Some("vectors") => run_vectors(&args[1..]),
        Some("trace") => run_trace(&args[1..]),
        Some("attack") => run_attack(&args[1..]),
        Some("weak-keys") => run_weak_keys(&args[1..]),
        Some("fault-map") => run_fault_map(&args[1..]),
        Some("noise") => run_noise(&args[1..]),
        Some("dfr-tail") => run_dfr_tail(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
