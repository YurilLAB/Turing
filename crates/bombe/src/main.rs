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
    println!("Deriving from SHAKE256(\"{}\" || counter)\n", gen::LABEL);
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
        println!("{} ({n}x{n}): SHAKE256(\"{}\" || {})", if n == 4 { "MixColumns" } else { "MixState" }, c.label, c.counter);
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
    use bombe::keyschedule::{feistel_min_active, PAIR_TARGET, WARMUP_TARGET};
    use turing::keyschedule::{ROUNDS_PER_PAIR, WARMUP_ROUNDS};
    println!("Key-schedule Feistel, F = MixState(S(x ^ C)): minimum active S-boxes");
    println!("for any non-zero key difference (each costs at least 2^-6)\n");
    let bounds = feistel_min_active(16);
    for (i, b) in bounds.iter().enumerate() {
        let r = i + 1;
        let mut note = String::new();
        if r == ROUNDS_PER_PAIR {
            note += "  <- rounds between round-key pairs";
        }
        if r == WARMUP_ROUNDS {
            note += "  <- warm-up before the first round keys";
        }
        println!("  {r:>2} rounds  >= {b:>2} active  (trail probability <= 2^-{}){note}", 6 * b);
    }
    let warm = bounds[WARMUP_ROUNDS - 1];
    let pair = bounds[ROUNDS_PER_PAIR - 1];
    println!("\nWarm-up target  >= {WARMUP_TARGET}: {warm}  {}", if warm >= WARMUP_TARGET { "PASS" } else { "FAIL" });
    println!("Per-pair target >= {PAIR_TARGET}: {pair}  {}", if pair >= PAIR_TARGET { "PASS" } else { "FAIL" });
    Ok(warm >= WARMUP_TARGET && pair >= PAIR_TARGET)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("sbox") => run_sbox(&args[1..]),
        Some("gen-sbox") => run_gen(&args[1..]),
        Some("gen-linear") => run_gen_linear(&args[1..]),
        Some("key-schedule") => run_key_schedule(),
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
