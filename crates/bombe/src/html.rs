//! Renders a Report as a self-contained HTML worksheet with DDT and LAT
//! heatmaps you can hover to read individual entries.

use crate::report::Report;
use std::fmt::Write;

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn join<T: ToString>(values: impl Iterator<Item = T>) -> String {
    values.map(|v| v.to_string()).collect::<Vec<_>>().join(",")
}

pub fn render(r: &Report) -> String {
    let mut checks = String::new();
    for c in &r.checks {
        let class = if c.pass { "pass" } else { "fail" };
        let mark = if c.pass { "Pass" } else { "Fail" };
        let _ = write!(
            checks,
            "<tr class=\"{class}\"><td>{mark}</td><td>{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
            escape(c.name),
            escape(&c.measured),
            escape(c.requirement)
        );
    }

    let mut grid = String::from("<tr><th></th>");
    for col in 0..16 {
        let _ = write!(grid, "<th>.{col:x}</th>");
    }
    grid.push_str("</tr>");
    for row in 0..16 {
        let _ = write!(grid, "<tr><th>{row:x}.</th>");
        for col in 0..16 {
            let x = (row * 16 + col) as u8;
            let _ = write!(grid, "<td>{:02x}</td>", r.sbox.get(x));
        }
        grid.push_str("</tr>");
    }

    let spectrum = |h: &std::collections::BTreeMap<u16, usize>| {
        h.iter().map(|(v, n)| format!("{v}&times;{n}")).collect::<Vec<_>>().join(", ")
    };
    let metrics = [
        ("Differential uniformity", r.ddt.uniformity().to_string()),
        ("DDT spectrum (value&times;count)", spectrum(&r.ddt.spectrum())),
        ("Differential branch number", r.differential_branch.to_string()),
        ("Linearity (max |W|)", r.lat.linearity().to_string()),
        ("Nonlinearity", r.lat.nonlinearity().to_string()),
        ("|W| spectrum", spectrum(&r.lat.spectrum())),
        ("Linear branch number", r.linear_branch.to_string()),
        (
            "Boomerang uniformity",
            r.boomerang_uniformity.map_or("n/a".into(), |v| v.to_string()),
        ),
        (
            "Coordinate degrees",
            r.degrees.coordinates.iter().map(u32::to_string).collect::<Vec<_>>().join(" "),
        ),
        (
            "Component degree",
            format!("min {}, max {}", r.degrees.component_min, r.degrees.component_max),
        ),
        ("Quadratic implicit equations", r.equations.quadratic.to_string()),
        ("Bi-affine implicit equations", r.equations.bi_affine.to_string()),
        ("Fixed points", r.fixed_points.to_string()),
        ("Opposite fixed points", r.opposite_fixed_points.to_string()),
    ];
    let mut metric_rows = String::new();
    for (k, v) in metrics {
        let _ = write!(metric_rows, "<tr><th>{k}</th><td>{v}</td></tr>");
    }

    let cycles = r.cycles.clone().unwrap_or_default();
    let verdict = if r.passed() { "Accepted" } else { "Rejected" };
    let verdict_class = if r.passed() { "pass" } else { "fail" };

    TEMPLATE
        .replace("{{NAME}}", &escape(&r.name))
        .replace("{{VERDICT}}", verdict)
        .replace("{{VERDICT_CLASS}}", verdict_class)
        .replace("{{CHECKS}}", &checks)
        .replace("{{METRICS}}", &metric_rows)
        .replace("{{GRID}}", &grid)
        .replace("{{CYCLES}}", &join(cycles.iter()))
        .replace("{{DDT}}", &join(r.ddt.raw().iter()))
        .replace("{{LAT}}", &join(r.lat.raw().iter().map(|w| w.unsigned_abs())))
}

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bombe: {{NAME}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;700&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap" rel="stylesheet">
<style>
:root {
  --sheet: #e8ece3;
  --rule: #b9c2b4;
  --ink: #1f2a44;
  --ink-soft: #55607a;
  --pass: #2f6b3a;
  --fail: #a8322d;
  --heat: 31, 42, 68;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --sheet: #161b24; --rule: #334055; --ink: #dfe5d8; --ink-soft: #9aa6b8;
    --pass: #7fc28a; --fail: #ef7d74; --heat: 223, 229, 216;
  }
}
:root[data-theme="dark"] {
  --sheet: #161b24; --rule: #334055; --ink: #dfe5d8; --ink-soft: #9aa6b8;
  --pass: #7fc28a; --fail: #ef7d74; --heat: 223, 229, 216;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--sheet); color: var(--ink);
  font: 17px/1.55 "Source Serif 4", Georgia, serif;
}
main { max-width: 1120px; margin: 0 auto; padding: 40px 16px 64px; }
h1, h2 { font-family: "Barlow Condensed", "Arial Narrow", sans-serif; font-weight: 700; margin: 0; }
h1 { font-size: 44px; line-height: 1.05; }
h2 { font-size: 26px; margin: 48px 0 12px; }
p { max-width: 68ch; }
.lede { color: var(--ink-soft); margin: 8px 0 0; }
header { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; flex-wrap: wrap; }
.stamp {
  font-family: "Barlow Condensed", sans-serif; font-weight: 700; font-size: 34px;
  padding: 4px 18px; border: 4px double currentColor; transform: rotate(-4deg);
  letter-spacing: 0.04em; margin-top: 6px;
}
.stamp.pass { color: var(--pass); }
.stamp.fail { color: var(--fail); }
table { border-collapse: collapse; width: 100%; }
td, th { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
.num { font-variant-numeric: tabular-nums; }
.checks tr.pass td:first-child { color: var(--pass); font-weight: 600; }
.checks tr.fail td:first-child { color: var(--fail); font-weight: 600; }
.metrics th { font-weight: 400; color: var(--ink-soft); width: 38%; }
.metrics td { font-variant-numeric: tabular-nums; word-break: break-word; }
.maps { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 32px; }
figure { margin: 0; }
canvas { width: 100%; aspect-ratio: 1; image-rendering: pixelated; border: 1px solid var(--rule); display: block; }
figcaption { color: var(--ink-soft); font-size: 15px; margin-top: 8px; min-height: 3em; }
.readout { color: var(--ink); font-variant-numeric: tabular-nums; }
.grid-wrap { overflow-x: auto; }
.grid td, .grid th { padding: 2px 5px; text-align: center; border: 0; font-variant-numeric: tabular-nums; }
.grid th { color: var(--ink-soft); font-weight: 400; }
.cycles { display: flex; height: 28px; border: 1px solid var(--rule); }
.cycles span { border-right: 2px solid var(--sheet); background: rgba(var(--heat), 0.75); color: var(--sheet); font-size: 13px; padding-left: 4px; overflow: hidden; white-space: nowrap; }
</style>
</head>
<body>
<main>
<header>
  <div>
    <h1>{{NAME}}</h1>
    <p class="lede">S-box worksheet from Bombe, graded against the Turing v1 acceptance criteria.</p>
  </div>
  <div class="stamp {{VERDICT_CLASS}}">{{VERDICT}}</div>
</header>

<h2>Acceptance</h2>
<table class="checks"><tbody>{{CHECKS}}</tbody></table>

<h2>Where an attacker would look</h2>
<p>Heavier ink means a bigger weakness. On a good S-box both sheets look like even static. Any line, block or bright spot is structure an attack can use. Hover a sheet to read one entry.</p>
<div class="maps">
  <figure>
    <canvas id="ddt" width="256" height="256"></canvas>
    <figcaption><strong>Differential table.</strong> Row: input difference. Column: output difference. <span class="readout" id="ddt-out"></span></figcaption>
  </figure>
  <figure>
    <canvas id="lat" width="256" height="256"></canvas>
    <figcaption><strong>Linear table (|Walsh|).</strong> Row: input mask. Column: output mask. <span class="readout" id="lat-out"></span></figcaption>
  </figure>
</div>

<h2>Measurements</h2>
<table class="metrics"><tbody>{{METRICS}}</tbody></table>

<h2>Permutation cycles</h2>
<p>Following x &rarr; S(x) &rarr; S(S(x)) until it repeats. Short cycles are a warning sign.</p>
<div class="cycles" id="cycles"></div>

<h2>The table</h2>
<div class="grid-wrap"><table class="grid"><tbody>{{GRID}}</tbody></table></div>
</main>
<script>
const DDT = [{{DDT}}];
const LAT = [{{LAT}}];
const CYCLES = [{{CYCLES}}];
const heat = getComputedStyle(document.documentElement).getPropertyValue("--heat").trim();
function draw(id, data, skipRow0, skipCol0, label) {
  const canvas = document.getElementById(id);
  const ctx = canvas.getContext("2d");
  let max = 1;
  for (let r = 0; r < 256; r++) for (let c = 0; c < 256; c++) {
    if ((skipRow0 && r === 0) || (skipCol0 && c === 0)) continue;
    max = Math.max(max, data[r * 256 + c]);
  }
  const img = ctx.createImageData(256, 256);
  const [hr, hg, hb] = heat.split(",").map(Number);
  for (let i = 0; i < 65536; i++) {
    const a = Math.sqrt(Math.min(data[i] / max, 1));
    img.data[i * 4] = hr; img.data[i * 4 + 1] = hg; img.data[i * 4 + 2] = hb;
    img.data[i * 4 + 3] = Math.round(a * 255);
  }
  ctx.putImageData(img, 0, 0);
  const out = document.getElementById(id + "-out");
  canvas.addEventListener("mousemove", e => {
    const box = canvas.getBoundingClientRect();
    const c = Math.min(255, Math.floor((e.clientX - box.left) / box.width * 256));
    const r = Math.min(255, Math.floor((e.clientY - box.top) / box.height * 256));
    const hex = v => v.toString(16).padStart(2, "0");
    out.textContent = label(hex(r), hex(c), data[r * 256 + c]);
  });
  canvas.addEventListener("mouseleave", () => { out.textContent = ""; });
}
draw("ddt", DDT, true, false, (r, c, v) => `Δx=${r} → Δy=${c}: ${v} of 256 inputs.`);
draw("lat", LAT, false, true, (r, c, v) => `a=${r}, b=${c}: |W| = ${v}, correlation ${(v / 256).toFixed(4)}.`);
const strip = document.getElementById("cycles");
for (const len of CYCLES) {
  const s = document.createElement("span");
  s.style.flex = String(len);
  s.textContent = len;
  s.title = `cycle of length ${len}`;
  strip.appendChild(s);
}
if (!CYCLES.length) strip.textContent = "Not a permutation.";
</script>
</body>
</html>
"##;
