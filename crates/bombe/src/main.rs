use bombe::matrix::{self, MdsReport};
use bombe::{gen, html, report::Report, sbox::Sbox};
use std::process::ExitCode;

const USAGE: &str = "\
Bombe: cryptanalysis workbench for the Turing cipher

Usage:
  bombe sbox <SOURCE> [--html <OUT.html>]
  bombe gen-sbox [--rust <OUT.rs>] [--html <OUT.html>]
  bombe gen-linear [--rust <OUT.rs>]
  bombe key-schedule
  bombe rounds [ROUNDS]
  bombe vectors [--out PATH]
  bombe attack [--quick] [--report PATH | --no-report]
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
    let mut report = Some("target/reports/attack-report.md".to_string());
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--quick" => quick = true,
            "--report" => report = Some(it.next().ok_or("--report needs a path")?.clone()),
            "--no-report" => report = None,
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    println!("Bombe attack campaign against Turing ({} run)", if quick { "quick" } else { "full" });
    println!("PASS = resists / holds, BROKEN = reduced rounds broken (expected), CAUGHT = control detected,");
    println!("FAIL = a problem, INFO = measurement.");
    let mut section = String::new();
    let campaign = bombe::campaign::run(quick, &mut |f| {
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
    let text = bombe::refcipher::render_vectors();
    match args {
        [flag, path] if flag == "--out" => {
            std::fs::write(path, &text).map_err(|e| format!("cannot write {path}: {e}"))?;
            println!("Known-answer vectors written to {path}");
        }
        [] => print!("{text}"),
        _ => return Err("usage: bombe vectors [--out PATH]".into()),
    }
    Ok(true)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("sbox") => run_sbox(&args[1..]),
        Some("gen-sbox") => run_gen(&args[1..]),
        Some("gen-linear") => run_gen_linear(&args[1..]),
        Some("key-schedule") => run_key_schedule(),
        Some("rounds") => run_rounds(&args[1..]),
        Some("vectors") => run_vectors(&args[1..]),
        Some("trace") => run_trace(&args[1..]),
        Some("attack") => run_attack(&args[1..]),
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
