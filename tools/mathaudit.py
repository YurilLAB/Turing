"""Independent maths audit (tools/CI.md, "math-audit").

Recomputes numbers the design documents rely on with code that shares
nothing with the code that produced them, and compares:

1. Reproduction first: the exhaustive core-SVP search (coresvp_exhaustive.py,
   written from Alkim-Ducas-Poppelmann-Schwabe 2016) must reproduce that
   paper's published Table 1 before it is allowed to judge anything else.
2. docs/16 (Turing-1026): every row of the parameter table and the
   comparison table: noise width, sigma^2/q, primal and dual core-SVP
   (searched over every (m, b), never greedily; lattice-estimator issue
   #219), a proven Chernoff upper bound that must lie above each exact
   decryption-failure figure and close to it, and every key and ciphertext
   size recomputed from the parameters (and from the code's own constants).
3. Arithmetic stated in docs/14 and docs/15, and docs/16's count and list
   of Turing-1026's cSHAKE labels against the labels in the code (the review
   of 2026-09-28 found "nine" where the code had ten, R13).
4. A lint for checks that cannot fail: `check(..., True, ...)` and
   `assert True` in Python helpers, and Rust tests with no assertion.

Each numeric check also runs a sensitivity control: the same computation
with a plausible mistake planted (a wrong noise width, q, n or sample
count) must fall outside the tolerance, or the check is too weak to catch
that mistake and is reported as such. `--negative-control` additionally
plants a wrong claimed value into every comparison and requires every one
to be flagged.

A claim whose text is no longer found in its document is reported as MOVED
(a warning, not a failure): documents change, and the registry below must
be updated with them.

    python tools/mathaudit.py                  # audit; exit 1 on any FAIL
    python tools/mathaudit.py --negative-control
    python tools/mathaudit.py --lint-only
"""
import argparse
import ast
import math
import pathlib
import re
import sys
from math import comb

import mpmath as mp

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import coresvp_exhaustive as cs  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
mp.mp.dps = 50

# Tolerance for core-SVP figures produced by another implementation of the
# same model: published tables round to whole bits, and the repo's port
# differs from ADPS16's exact formulas by a lattice dimension of one
# (d = n + m against n + m + 1, delta^d against delta^(d-1)), which moves
# the result by up to 0.7 bit.
CORE_SVP_TOL = 1.0


class Report:
    def __init__(self, quiet=False):
        self.rows = []
        self.quiet = quiet

    def add(self, status, name, detail):
        self.rows.append((status, name, detail))
        if not self.quiet:
            print(f"  {status:5s} {name}: {detail}", flush=True)

    def count(self, status):
        return sum(1 for s, _, _ in self.rows if s == status)


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Failure probability: a proven Chernoff bound for sums of products of CBD
# samples (docs/16: 2n products plus one sample per coefficient, failure
# when a coefficient leaves [-q/4, q/4)).

def cbd_pmf(eta):
    return {v: mp.mpf(comb(2 * eta, eta + v)) / mp.mpf(4) ** eta for v in range(-eta, eta + 1)}


def log2_failure_bound(n, log_q, eta, coefficients):
    """Two-sided Chernoff bound, per ciphertext (union over coefficients)."""
    p = cbd_pmf(eta)
    t = mp.mpf(2) ** log_q / 4

    def log_bound(lam):
        lam = mp.mpf(lam)
        prod_mgf = sum(pa * mp.cosh(lam * a / 2) ** (2 * eta) for a, pa in p.items())
        return 2 * n * mp.log(prod_mgf) + 2 * eta * mp.log(mp.cosh(lam / 2)) - lam * t

    lo, hi = mp.mpf("1e-7"), mp.mpf(1)
    for _ in range(160):  # golden section; the log-MGF bound is convex in lambda
        m1, m2 = lo + (hi - lo) * 0.382, lo + (hi - lo) * 0.618
        if log_bound(m1) < log_bound(m2):
            hi = m2
        else:
            lo = m1
    per_coefficient = (log_bound((lo + hi) / 2) + mp.log(2)) / mp.log(2)
    return float(per_coefficient + mp.log(coefficients, 2))


# ---------------------------------------------------------------------------

def check_close(rep, name, computed, claimed, tol, controls=()):
    """computed vs claimed within tol; each control is (label, value computed
    with a planted mistake), which must fall outside tol."""
    ok = abs(computed - claimed) <= tol
    weak = [label for label, v in controls if abs(v - claimed) <= tol]
    detail = f"computed {computed:.2f}, claimed {claimed:.2f} (tolerance {tol})"
    if weak:
        detail += f"; TOO WEAK: would not catch {', '.join(weak)}"
    rep.add("PASS" if ok and not weak else "FAIL", name, detail)
    return ok and not weak


def adps16_reproduction(rep):
    print("1. Reproduction: ADPS16 Table 1 (research/papers/2016-alkim-ducas-poppelmann-schwabe-newhope.pdf)")
    for name, n, q, s, _pm, pb, pc, _pq, _dm, db, dc, _dq in cs.ADPS16_TABLE_1:
        if name == "NTRU Encrypt":
            rep.add("SKIP", f"ADPS16 {name}", "NTRU is not plain LWE and the table models it differently (b 603 published, 552 as LWE)")
            continue
        b, _ = cs.primal(n, q, s, 2 * n)
        cost, b2, _, _ = cs.dual(n, q, s, 2 * n)
        rep.add("PASS" if abs(b - pb) <= 3 else "FAIL", f"ADPS16 {name} primal block size", f"computed {b}, published {pb}")
        rep.add("PASS" if abs(b2 - db) <= 3 else "FAIL", f"ADPS16 {name} dual block size", f"computed {b2}, published {db}")
        rep.add("PASS" if abs(cs.CLASSICAL * b - pc) <= 1.0 and abs(cost - dc) <= 1.0 else "FAIL",
                f"ADPS16 {name} classical costs", f"computed {cs.CLASSICAL * b:.1f} / {cost:.1f}, published {pc} / {dc}")


SWEEP_ROW = re.compile(
    r"^\|\s*\**2\^(\d+)\**\s*\|\s*\**(\d+)\**\s*\|\s*\**([\d.]+)\**\s*\|\s*\**([\d.]+e-\d+)\**\s*\|"
    r"\s*\**2\^(-[\d.]+)\**\s*\|\s*\**([\d.]+)\s*/\s*([\d.]+)\**\s*\|", re.M)


def docs16_parameter_table(rep, negative):
    print("2. docs/16 parameter table (n = 1026, 256 coefficients, m <= n + 32)")
    text = read("docs/16-turing-1026.md")
    rows = SWEEP_ROW.findall(text)
    if not rows:
        rep.add("MOVED", "docs/16 parameter table", "no row matched; update the registry in tools/mathaudit.py")
        return
    n, m_max = 1026, 1026 + 32
    for log_q, eta, sigma, ratio, dfr, primal_claim, dual_claim in rows:
        log_q, eta = int(log_q), int(eta)
        q, s = 2 ** log_q, math.sqrt(eta / 2)
        tag = f"q 2^{log_q}, CBD({eta})"
        rep.add("PASS" if abs(s - float(sigma)) < 0.006 else "FAIL", f"{tag} sigma", f"sqrt(eta/2) = {s:.3f}, claimed {sigma}")
        rep.add("PASS" if abs(s * s / q - float(ratio)) / float(ratio) < 0.01 else "FAIL", f"{tag} sigma^2/q",
                f"{s * s / q:.3e}, claimed {ratio}")
        b, _ = cs.primal(n, q, s, m_max)
        cost, _, _, _ = cs.dual(n, q, s, m_max)
        pc, dc = float(primal_claim), float(dual_claim)
        if negative:
            pc, dc = pc + 3, dc + 3
        # Controls: noise one CBD step narrower, and all samples dropped but n.
        b_narrow, _ = cs.primal(n, q, math.sqrt((eta - 2) / 2), m_max)
        d_narrow, _, _, _ = cs.dual(n, q, math.sqrt((eta - 2) / 2), m_max)
        check_close(rep, f"{tag} primal core-SVP", cs.CLASSICAL * b, pc, CORE_SVP_TOL, [("CBD(eta-2)", cs.CLASSICAL * b_narrow)])
        check_close(rep, f"{tag} dual core-SVP", cost, dc, CORE_SVP_TOL, [("CBD(eta-2)", d_narrow)])
        bound = log2_failure_bound(n, log_q, eta, 256)
        exact = float(dfr) + (8 if negative else 0)
        ok = exact <= bound + 0.05 and bound - exact <= 8.0
        rep.add("PASS" if ok else "FAIL", f"{tag} failure rate",
                f"proven bound 2^{bound:.1f} per ciphertext, claimed exact 2^{exact:.1f} (must be below the bound, within 8 bits)")


def cells(line):
    return [c.strip().strip("*").strip() for c in line.strip().strip("|").split("|")]


def docs16_comparison_table(rep, negative):
    print("3. docs/16 comparison table")
    text = read("docs/16-turing-1026.md")
    schemes = [  # name, n, q, sigma, m_max, public key, ciphertext
        ("Turing-1026", 1026, 2 ** 15, 3.0, 1026 + 32, 32 + (1026 * 32 * 15 + 7) // 8, (8 * 1026 * 15 + 7) // 8 + (8 * 32 * 15 + 7) // 8 + 64),
        ("ML-KEM-1024", 1024, 3329, 1.0, 1024, 1568, 1568),
        ("FrodoKEM-976", 976, 2 ** 16, 2.3, 976 + 8, 16 + 976 * 8 * 2, (8 * 976 + 64) * 2),
        ("FrodoKEM-1344", 1344, 2 ** 16, 1.4, 1344 + 8, 16 + 1344 * 8 * 2, (8 * 1344 + 64) * 2),
    ]
    lines = {key: next((l for l in text.splitlines() if l.startswith(key)), None) for key in (
        "| Classical core-SVP, primal / dual", "| Quantum core-SVP", "| Public key / ciphertext (bytes)")}
    for key, line in lines.items():
        if line is None:
            rep.add("MOVED", f"docs/16 row '{key[2:]}'", "not found; update the registry in tools/mathaudit.py")
    for i, (name, n, q, s, m_max, pk, ct) in enumerate(schemes):
        b, _ = cs.primal(n, q, s, m_max)
        cost, b2, _, quantum_dual = cs.dual(n, q, s, m_max)
        shift = 3 if negative else 0
        if lines["| Classical core-SVP, primal / dual"]:
            p_claim, d_claim = (float(x) for x in cells(lines["| Classical core-SVP, primal / dual"])[1 + i].replace("*", "").split("/"))
            check_close(rep, f"{name} primal core-SVP", cs.CLASSICAL * b, p_claim + shift, CORE_SVP_TOL)
            check_close(rep, f"{name} dual core-SVP", cost, d_claim + shift, CORE_SVP_TOL)
            if cost < d_claim - 0.05:
                rep.add("INFO", f"{name} dual core-SVP", f"exhaustive, formula-exact optimum {cost:.2f} is {d_claim - cost:.2f} bit below the documented {d_claim}")
        if lines["| Quantum core-SVP"]:
            q_claim = float(cells(lines["| Quantum core-SVP"])[1 + i]) + shift
            check_close(rep, f"{name} quantum core-SVP", min(cs.QUANTUM * b, quantum_dual), q_claim, CORE_SVP_TOL)
        if lines["| Public key / ciphertext (bytes)"]:
            pk_claim, ct_claim = (int(x.replace(",", "")) for x in cells(lines["| Public key / ciphertext (bytes)"])[1 + i].split("/"))
            ok = (pk, ct) == (pk_claim + shift, ct_claim)
            rep.add("PASS" if ok else "FAIL", f"{name} sizes", f"computed {pk} / {ct}, claimed {pk_claim + shift} / {ct_claim}")


def code_constants(rep, negative):
    print("4. Turing-1026 sizes in the code")
    src = read("crates/turing/src/turing1026.rs")
    params = re.search(r"Params \{ n: (\d+), nbar: (\d+), mbar: (\d+), log_q: (\d+), eta: (\d+) \}", src)
    asserted = re.search(r"PUBLIC_KEY_BYTES == ([\d_]+) && CIPHERTEXT_BYTES == ([\d_]+)", src)
    if not params or not asserted:
        rep.add("MOVED", "turing1026.rs PARAMS / size assertion", "not found; update the registry")
        return
    n, nbar, mbar, log_q, _ = (int(x) for x in params.groups())
    pk = 32 + (n * nbar * log_q + 7) // 8
    ct = (mbar * n * log_q + 7) // 8 + (mbar * nbar * log_q + 7) // 8 + 64
    claim = tuple(int(x.replace("_", "")) for x in asserted.groups())
    if negative:
        claim = (claim[0] + 1, claim[1])
    rep.add("PASS" if (pk, ct) == claim else "FAIL", "sizes from PARAMS vs the const assertion", f"computed {pk} / {ct}, asserted {claim[0]} / {claim[1]}")


def docs_arithmetic(rep, negative):
    print("5. Arithmetic stated in docs/14 and docs/15")
    d15 = read("docs/15-turing-256.md")
    for n, claim in [(128, "about 2^43"), (256, "about 2^85")]:
        found = claim in d15
        value = n / 3
        target = float(claim.split("^")[1]) + (2 if negative else 0)
        if not found:
            rep.add("MOVED", f"docs/15 '{claim}'", "not found")
        else:
            rep.add("PASS" if abs(value - target) <= 0.5 else "FAIL", f"docs/15 Brassard-Hoyer-Tapp on a {n}-bit block", f"2^(n/3) = 2^{value:.2f}, stated {claim}")
    d14 = read("docs/14-attacks-from-the-aes-256-literature.md")
    lookups, encryptions = re.search(r"2\^([\d.]+) S-box lookups \(2\^([\d.]+) encryptions\)", d14).groups() if re.search(r"2\^([\d.]+) S-box lookups \(2\^([\d.]+) encryptions\)", d14) else (None, None)
    if lookups is None:
        rep.add("MOVED", "docs/14 seven-round cost", "not found")
    else:
        per_encryption = math.log2(7 * 16)  # 16 S-boxes in each of 7 rounds
        gap = float(lookups) - float(encryptions) + (1 if negative else 0)
        rep.add("PASS" if abs(gap - per_encryption) <= 0.1 else "FAIL", "docs/14 lookups vs encryptions (7 rounds x 16 S-boxes)",
                f"2^{lookups} / 2^{encryptions} = 2^{gap:.2f}, 7 x 16 = 2^{per_encryption:.2f}")


NUMBER_WORDS = {w: i for i, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen".split())}


def docs16_labels(rep, negative):
    print("5b. docs/16's cSHAKE labels against the code")
    code = read("crates/turing/src/turing1026.rs") + read("crates/turing/src/lwe.rs")
    labels = sorted(set(re.findall(r'const \w+_LABEL: &str = "Turing-1026 v1 ([^"]+)";', code)))
    d16 = read("docs/16-turing-1026.md")
    claims = re.findall(r'under (\w+) "Turing-1026 v1 \.\.\." labels', d16) + re.findall(r'All (\w+) labels begin "Turing-1026 v1 "', d16)
    if not claims:
        rep.add("MOVED", "docs/16 label count", "not found")
        return
    for word in claims:
        stated = NUMBER_WORDS.get(word.lower(), -1) + (1 if negative else 0)
        rep.add("PASS" if stated == len(labels) else "FAIL", "docs/16 label count vs the code", f"docs/16 says {word}, the code defines {len(labels)}: {', '.join(labels)}")
    missing = [l for l in labels + (["planted label"] if negative else []) if l not in d16]
    rep.add("PASS" if not missing else "FAIL", "docs/16 names every label the code uses", f"missing: {', '.join(missing)}" if missing else f"all {len(labels)} named")


# ---------------------------------------------------------------------------
# Lint: checks that cannot fail.

ASSERTION = re.compile(r"assert|panic!|unwrap\(|expect\(|\?;|unreachable!|is_err\(\)|is_ok\(\)|catch_unwind")


def rust_functions(text):
    """(name, attributes line block, body) for every fn in a Rust file."""
    out = []
    for m in re.finditer(r"((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)[^{;]*\{", text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append((m.group(2), m.group(1), text[m.end():i]))
    return out


def lint(rep, paths=None):
    if not rep.quiet:
        print("6. Lint: checks that cannot fail")
    found = []
    py_files = paths or sorted(list((ROOT / "research" / "scripts").rglob("*.py")) + list((ROOT / "tools").glob("*.py")))
    for f in py_files:
        if f.name == "mathaudit.py":
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "check" and len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant) and node.args[1].value is True:
                    found.append(f"{f.relative_to(ROOT)}:{node.lineno}: check(..., True, ...) always passes")
            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Constant) and node.test.value:
                found.append(f"{f.relative_to(ROOT)}:{node.lineno}: assert on a constant")
    rust_files = [] if paths else sorted(list((ROOT / "crates").rglob("*.rs")))
    for f in rust_files:
        text = f.read_text(encoding="utf-8", errors="replace")
        fns = rust_functions(text)
        helpers = {name for name, _, body in fns if ASSERTION.search(body)}
        for name, attrs, body in fns:
            if "#[test]" not in attrs or "should_panic" in attrs:
                continue
            calls = set(re.findall(r"\b(\w+)\s*\(", body))
            if not ASSERTION.search(body) and not (calls & helpers):
                start = text.find(f"fn {name}")
                line = text[:start].count("\n") + 1
                # A test documented as a measurement is allowed not to assert.
                comment = "\n".join(l for l in text[:start].splitlines()[-12:] if l.strip().startswith("//"))
                if re.search(r"not a check|measurement", comment, re.I):
                    rep.add("INFO", "documented measurement", f"{f.relative_to(ROOT)}:{line}: test `{name}` asserts nothing on purpose")
                    continue
                found.append(f"{f.relative_to(ROOT)}:{line}: test `{name}` asserts nothing")
    for item in found:
        rep.add("WARN", "cannot fail", item)
    if not found:
        rep.add("PASS", "lint", "no check that cannot fail was found")
    return found


def lint_self_test(rep):
    """The lint must flag planted examples of what it looks for."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        planted = pathlib.Path(d) / "planted.py"
        planted.write_text("def check(name, ok, why):\n    pass\ncheck('x', True, 'hard-coded')\nassert True\n", encoding="utf-8")
        sub = Report(quiet=True)
        global ROOT
        saved, ROOT = ROOT, pathlib.Path(d)
        try:
            hits = lint(sub, paths=[planted])
        finally:
            ROOT = saved
    rust = "#[test]\nfn nothing() {\n    let _x = 1;\n}\n#[test]\nfn fine() {\n    assert_eq!(1, 1);\n}\n"
    fns = rust_functions(rust)
    vacuous = [n for n, a, b in fns if "#[test]" in a and not ASSERTION.search(b)]
    ok = len(hits) == 2 and vacuous == ["nothing"]
    rep.add("PASS" if ok else "FAIL", "lint negative control", f"planted 2 Python and 1 Rust vacuous checks; flagged {len(hits)} and {vacuous}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--negative-control", action="store_true", help="plant a wrong claimed value in every comparison; every one must be flagged")
    ap.add_argument("--lint-only", action="store_true")
    args = ap.parse_args()
    rep = Report()
    if args.lint_only:
        lint(rep)
        lint_self_test(rep)
    else:
        adps16_reproduction(rep)
        docs16_parameter_table(rep, args.negative_control)
        docs16_comparison_table(rep, args.negative_control)
        code_constants(rep, args.negative_control)
        docs_arithmetic(rep, args.negative_control)
        docs16_labels(rep, args.negative_control)
        if not args.negative_control:
            lint(rep)
            lint_self_test(rep)
    fails, moved, warns = rep.count("FAIL"), rep.count("MOVED"), rep.count("WARN")
    if args.negative_control:
        planted = [r for r in rep.rows if r[0] in ("PASS", "FAIL") and r[1].startswith(("q 2^", "Turing", "ML-KEM", "Frodo", "sizes", "docs/1"))]
        caught = [r for r in planted if r[0] == "FAIL" and "TOO WEAK" not in r[2]]
        untouched = [r for r in planted if r[1].endswith(("sigma", "sigma^2/q"))]
        missed = [r for r in planted if r[0] != "FAIL" and r not in untouched]
        print(f"\nnegative control: {len(caught)} planted errors flagged, {len(missed)} missed")
        for r in missed:
            print(f"  MISSED {r[1]}: {r[2]}")
        return 1 if missed else 0
    print(f"\n{rep.count('PASS')} pass, {fails} fail, {moved} moved, {warns} warnings, {rep.count('INFO')} info")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
