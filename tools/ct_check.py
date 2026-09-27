"""Machine-checked constant-time expectations on the release build's assembly.

`asm_branches.py` lists jumps, divisions and indexed loads for a person to
judge; this script turns the judgements that can be made mechanically into a
pass/fail check, so CI can run it. It builds the production `turing` library
(no `analysis` feature), emits its assembly, and asserts:

  divisions   The lattice code (`lwe`, `turing1026`) must contain no division
              of a secret: x86 `div`/`idiv` take operand-dependent time, which
              is how KyberSlash (Bernstein et al., 2024) read Kyber's key out
              of `(x*2^d + q/2)/q`. The only divisions allowed are the three
              in `DecapsulationKey::expanded`, where a constant allocation size
              is divided by the page size (public, docs/16).

It is x86-64 only (rustc's default on the CI runner); on another target the
mnemonics differ and the check skips with a clear message rather than passing
vacuously.

    python tools/ct_check.py            # build, emit asm, check
    python tools/ct_check.py PATH.s     # check an assembly file already emitted

Exit status 0 if every expectation holds, 1 if any fails, 2 on a setup error.
"""
import os
import platform
import re
import subprocess
import sys

# Functions whose machine code must not divide secrets, by mangled-name
# substring, and the per-function allowance (page-size divides of public
# constant sizes).
LATTICE = ("lwe", "turing1026", "mlkem")
DIVISION_ALLOWANCE = {"expanded": 3}


def emit_asm():
    """Build the production turing lib and return the path to its assembly.

    codegen-units=1 puts the whole crate in one .s file; with the default many
    units the lattice functions scatter across several files (and CI then read
    one without them)."""
    out = subprocess.run(
        ["cargo", "rustc", "-p", "turing", "--release", "--lib", "--", "--emit", "asm", "-C", "codegen-units=1"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        sys.exit(2)
    target = os.environ.get("CARGO_TARGET_DIR", "target")
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


def main():
    if platform.machine() not in ("x86_64", "AMD64"):
        print(f"ct_check: skipping, assembly check is x86-64 only (this is {platform.machine()})")
        return 0
    path = sys.argv[1] if len(sys.argv) > 1 else emit_asm()
    print(f"ct_check: reading {path}")
    div = re.compile(r"^i?div[bwlq]?\s")
    failures = 0
    checked = 0
    for name, code in functions(path):
        if not any(w in name for w in LATTICE):
            continue
        checked += 1
        divs = sum(1 for l in code if div.match(l))
        limit = allowance(name)
        if divs > limit:
            failures += 1
            short = name.split("17h")[0]
            print(f"  FAIL {short}: {divs} divisions (at most {limit} allowed)")
            for l in code:
                if div.match(l):
                    print(f"         {l}")
    if checked == 0:
        print("ct_check: no lattice functions found in the assembly", file=sys.stderr)
        return 2
    if failures:
        print(f"ct_check: {failures} function(s) divide secret data")
        return 1
    print(f"ct_check: {checked} lattice functions, no secret division (KyberSlash class clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
