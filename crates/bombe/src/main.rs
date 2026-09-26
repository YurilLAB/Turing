use bombe::{html, report::Report, sbox::Sbox};
use std::process::ExitCode;

const USAGE: &str = "\
Bombe: cryptanalysis workbench for the Turing cipher

Usage:
  bombe sbox <SOURCE> [--html <OUT.html>]

SOURCE:
  aes          the AES S-box (reference for validating the tools)
  aes-inv      its inverse
  identity     S(x) = x (negative control)
  random:SEED  a seeded random permutation (baseline)
  <path>       a file with 256 hex bytes

Exit status: 0 if the S-box meets the Turing v1 criteria, 1 if not, 2 on error.";

fn load(source: &str) -> Result<(String, Sbox), String> {
    match source {
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("sbox") => run_sbox(&args[1..]),
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
