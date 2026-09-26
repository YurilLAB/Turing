//! Runs every S-box measurement and grades it against Turing's acceptance
//! criteria (docs/03-design-spec.md).

use crate::analysis::{self, Ddt, Degrees, Equations, Lat};
use crate::sbox::Sbox;
use std::collections::BTreeMap;
use std::fmt::Write;

pub struct Check {
    pub name: &'static str,
    pub requirement: &'static str,
    pub measured: String,
    pub pass: bool,
}

pub struct Report {
    pub name: String,
    pub sbox: Sbox,
    pub bijective: bool,
    pub ddt: Ddt,
    pub lat: Lat,
    pub boomerang_uniformity: Option<u16>,
    pub degrees: Degrees,
    pub fixed_points: usize,
    pub opposite_fixed_points: usize,
    pub cycles: Option<Vec<usize>>,
    pub differential_branch: u32,
    pub linear_branch: u32,
    pub equations: Equations,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new(name: &str, sbox: &Sbox) -> Report {
        let ddt = analysis::ddt(sbox);
        let lat = analysis::lat(sbox);
        let mut report = Report {
            name: name.to_string(),
            sbox: sbox.clone(),
            bijective: sbox.is_bijective(),
            boomerang_uniformity: analysis::boomerang_uniformity(sbox),
            degrees: analysis::degrees(sbox),
            fixed_points: analysis::fixed_points(sbox),
            opposite_fixed_points: analysis::opposite_fixed_points(sbox),
            cycles: analysis::cycles(sbox),
            differential_branch: analysis::differential_branch_number(sbox),
            linear_branch: analysis::linear_branch_number(&lat),
            equations: analysis::implicit_equations(sbox),
            ddt,
            lat,
            checks: Vec::new(),
        };
        report.checks = report.grade();
        report
    }

    fn grade(&self) -> Vec<Check> {
        let du = self.ddt.uniformity();
        let lin = self.lat.linearity();
        let bu = self.boomerang_uniformity;
        vec![
            Check {
                name: "bijective",
                requirement: "every output exactly once",
                measured: yes_no(self.bijective).into(),
                pass: self.bijective,
            },
            Check {
                name: "differential uniformity",
                requirement: "<= 4",
                measured: du.to_string(),
                pass: du <= 4,
            },
            Check {
                name: "linearity (max |Walsh|)",
                requirement: "<= 32  (correlation <= 2^-3)",
                measured: lin.to_string(),
                pass: lin <= 32,
            },
            Check {
                name: "boomerang uniformity",
                requirement: "<= 6",
                measured: bu.map_or("n/a (not bijective)".into(), |v| v.to_string()),
                pass: bu.is_some_and(|v| v <= 6),
            },
            Check {
                name: "min component degree",
                requirement: "= 7",
                measured: self.degrees.component_min.to_string(),
                pass: self.degrees.component_min == 7,
            },
            Check {
                name: "fixed points S(x)=x",
                requirement: "0",
                measured: self.fixed_points.to_string(),
                pass: self.fixed_points == 0,
            },
            Check {
                name: "opposite fixed points S(x)=~x",
                requirement: "0",
                measured: self.opposite_fixed_points.to_string(),
                pass: self.opposite_fixed_points == 0,
            },
        ]
    }

    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let w = &mut out;
        let _ = writeln!(w, "Bombe S-box report: {}", self.name);
        let _ = writeln!(w);
        let _ = writeln!(w, "Differential");
        let _ = writeln!(w, "  uniformity              {}", self.ddt.uniformity());
        let _ = writeln!(w, "  DDT spectrum            {}", spectrum(&self.ddt.spectrum()));
        let _ = writeln!(w, "  branch number           {}", self.differential_branch);
        let _ = writeln!(w, "Linear");
        let _ = writeln!(w, "  linearity (max |W|)     {}", self.lat.linearity());
        let _ = writeln!(w, "  nonlinearity            {}", self.lat.nonlinearity());
        let _ = writeln!(w, "  |W| spectrum            {}", spectrum(&self.lat.spectrum()));
        let _ = writeln!(w, "  branch number           {}", self.linear_branch);
        let _ = writeln!(w, "Boomerang");
        let bu = self.boomerang_uniformity.map_or("n/a".into(), |v| v.to_string());
        let _ = writeln!(w, "  uniformity              {bu}");
        let _ = writeln!(w, "Algebraic");
        let coords: Vec<String> = self.degrees.coordinates.iter().map(u32::to_string).collect();
        let _ = writeln!(w, "  coordinate degrees      {}", coords.join(" "));
        let _ = writeln!(
            w,
            "  component degree        min {}  max {}",
            self.degrees.component_min, self.degrees.component_max
        );
        let _ = writeln!(w, "  quadratic equations     {}", self.equations.quadratic);
        let _ = writeln!(w, "  bi-affine equations     {}", self.equations.bi_affine);
        let _ = writeln!(w, "Structure");
        let _ = writeln!(w, "  bijective               {}", yes_no(self.bijective));
        let _ = writeln!(w, "  fixed points            {}", self.fixed_points);
        let _ = writeln!(w, "  opposite fixed points   {}", self.opposite_fixed_points);
        let cyc = self.cycles.as_ref().map_or("n/a".into(), |c| run_lengths(c));
        let _ = writeln!(w, "  cycle lengths           {cyc}");
        let _ = writeln!(w);
        let _ = writeln!(w, "Acceptance (Turing v1)");
        for c in &self.checks {
            let mark = if c.pass { "PASS" } else { "FAIL" };
            let _ = writeln!(w, "  {mark}  {:<32} {:<22} need {}", c.name, c.measured, c.requirement);
        }
        let verdict = if self.passed() { "ACCEPTED" } else { "REJECTED" };
        let _ = writeln!(w, "\nVerdict: {verdict}");
        out
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// "87 81 59 27 2" stays as is; 256 cycles of length 1 become "1x256".
fn run_lengths(sorted: &[usize]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let run = sorted[i..].iter().take_while(|&&v| v == sorted[i]).count();
        parts.push(if run > 1 { format!("{}x{run}", sorted[i]) } else { sorted[i].to_string() });
        i += run;
    }
    parts.join(" ")
}

fn spectrum(h: &BTreeMap<u16, usize>) -> String {
    h.iter().map(|(v, n)| format!("{v}:{n}")).collect::<Vec<_>>().join("  ")
}
