"""Machine-checked expectations on the release build's assembly.

`asm_branches.py` lists jumps, divisions and indexed loads for a person to
judge; this script turns the judgements that can be made mechanically into a
pass/fail check, so CI can run it. It builds the production `turing` library
(no `analysis` feature) and, for code only the analysis build compiles
(ML-KEM, which the hybrid will call), the `analysis` build too, emits their
assembly, and asserts:

  divisions   The lattice code (`lwe`, `turing1026`, `mlkem`) must contain no
              division of a secret: x86 `div`/`idiv` take operand-dependent
              time, which is how KyberSlash (Bernstein et al., 2024) read
              Kyber's key out of `(x*2^d + q/2)/q`. The only divisions allowed
              are the three in `DecapsulationKey::expanded`, where a constant
              allocation size is divided by the page size (public, docs/16).
              Every listed module must contribute functions to the build it is
              checked in: until the review of 2026-09-28 (R7) ML-KEM was
              listed but compiled only in analysis builds, so the check had
              never read it and passed a planted division.

  selections  Turing-1026 decapsulation keeps its verdicts apart (docs/16):
              three masks derived separately (three `sar $63` or `shr $63`),
              two calls of `select_into` and one of `bind_to_verdict`, both
              real functions. The release build once fused the two selections
              into one mask (one `sar`, one select): a single fault then
              accepted an invalid ciphertext (review of 2026-09-28, R2).

It is x86-64 only (rustc's default on the CI runner); on another target the
mnemonics differ and the check skips with a clear message rather than passing
vacuously.

    python tools/ct_check.py                       # build both, emit asm, check
    python tools/ct_check.py PROD.s [ANALYSIS.s]   # check assembly already emitted

Exit status 0 if every expectation holds, 1 if any fails, 2 on a setup error.
"""
import os
import platform
import re
import subprocess
import sys

# Modules whose machine code must not divide secrets, by mangled-name
# substring, and the build each is read in.
PRODUCTION_MODULES = ("3lwe", "10turing1026")
ANALYSIS_MODULES = ("5mlkem",)
DIVISION_ALLOWANCE = {"expanded": 3}
DECAPSULATION = "20decapsulated_faulted"
SELECT = "11select_into"
BIND = "15bind_to_verdict"


def emit_asm(features):
    """Build the turing lib (with `features`) and return the path to its
    assembly. codegen-units=1 puts the whole crate in one .s file; with the
    default many units the lattice functions scatter across several files (and
    CI then read one without them). Each build gets its own target directory,
    so the two builds do not overwrite each other's .s file."""
    base = os.environ.get("CARGO_TARGET_DIR", "target")
    target = os.path.join(base, "ct-" + (features or "production"))
    cmd = ["cargo", "rustc", "-p", "turing", "--release", "--lib", "--target-dir", target]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "--emit", "asm", "-C", "codegen-units=1"]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        sys.exit(2)
    deps = os.path.join(target, "release", "deps")
    files = [f for f in os.listdir(deps) if re.fullmatch(r"turing-[0-9a-f]+\.s", f)]
    if not files:
        print("no turing-<hash>.s emitted", file=sys.stderr)
        sys.exit(2)
    return max((os.path.join(deps, f) for f in files), key=os.path.getmtime)


def functions(path):
    """(mangled name, instruction lines) for each function in the asm file."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    starts = [i for i, l in enumerate(lines) if re.match(r"^_ZN\S+:$", l)]
    starts.append(len(lines))
    for a, b in zip(starts, starts[1:]):
        code = [l.strip() for l in lines[a + 1 : b] if l.strip() and not l.strip().startswith((".", "#"))]
        yield lines[a][:-1], code


def allowance(name):
    for key, n in DIVISION_ALLOWANCE.items():
        if key in name:
            return n
    return 0


def check_divisions(path, modules):
    """Returns the number of failures; prints each."""
    div = re.compile(r"^i?div[bwlq]?\s")
    failures = 0
    counts = {m: 0 for m in modules}
    for name, code in functions(path):
        hit = [m for m in modules if m in name]
        if not hit:
            continue
        for m in hit:
            counts[m] += 1
        divs = sum(1 for l in code if div.match(l))
        limit = allowance(name)
        if divs > limit:
            failures += 1
            print(f"  FAIL {name.split('17h')[0]}: {divs} divisions (at most {limit} allowed)")
            for l in code:
                if div.match(l):
                    print(f"         {l}")
    for m, n in counts.items():
        if n == 0:
            failures += 1
            print(f"  FAIL module {m!r}: no function of it is in {os.path.basename(path)}; the check would pass without reading it")
        else:
            print(f"  {m}: {n} functions, divisions checked")
    return failures


def check_selections(path):
    """Returns the number of failures; prints each."""
    funcs = dict(functions(path))
    decap = [code for name, code in funcs.items() if DECAPSULATION in name and "turing1026" in name]
    select = [name for name in funcs if SELECT in name and "turing1026" in name]
    bind = [name for name in funcs if BIND in name and "turing1026" in name]
    if not decap:
        print(f"  FAIL no {DECAPSULATION} in {os.path.basename(path)}")
        return 1
    code = decap[0]
    masks = sum(1 for l in code if re.match(r"^s[ah]rq\s+\$63,", l))
    calls_select = sum(1 for l in code if l.startswith("call") and SELECT in l)
    calls_bind = sum(1 for l in code if l.startswith("call") and BIND in l)
    failures = 0
    for ok, what in [
        (masks >= 3, f"three verdict masks derived separately (found {masks} `sar/shr $63`)"),
        (len(select) == 1 and calls_select == 2, f"select_into a function of its own, called twice (function: {len(select)}, calls: {calls_select})"),
        (len(bind) == 1 and calls_bind == 1, f"bind_to_verdict a function of its own, called once (function: {len(bind)}, calls: {calls_bind})"),
    ]:
        print(f"  {'ok  ' if ok else 'FAIL'} decapsulation: {what}")
        failures += 0 if ok else 1
    return failures


def main():
    if platform.machine() not in ("x86_64", "AMD64"):
        print(f"ct_check: skipping, assembly check is x86-64 only (this is {platform.machine()})")
        return 0
    production = sys.argv[1] if len(sys.argv) > 1 else emit_asm("")
    analysis = sys.argv[2] if len(sys.argv) > 2 else (emit_asm("analysis") if len(sys.argv) == 1 else None)
    print(f"ct_check: production build {production}")
    failures = check_divisions(production, PRODUCTION_MODULES)
    failures += check_selections(production)
    if analysis:
        print(f"ct_check: analysis build {analysis}")
        failures += check_divisions(analysis, ANALYSIS_MODULES)
    else:
        print("ct_check: no analysis build given, ML-KEM NOT checked")
        failures += 1
    if failures:
        print(f"ct_check: {failures} failure(s)")
        return 1
    print("ct_check: no secret division in the lattice code (KyberSlash class clean), decapsulation's verdicts kept apart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
