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

  redundancy  Every countermeasure that computes something twice or three
              times must still do so in the machine code: an optimiser that
              proves two computations equal may keep one (review of 2026-09-28,
              R2: the release build had fused decapsulation's two selections
              into one mask, one `sar`, a single-fault bypass). Checked as calls
              (or tail-call jumps) that must survive: decapsulation's two
              selections, its binding, its two rejection-key computations and
              their comparison, its two re-encryptions; the three decryption
              passes, each with its own order and its own C - B'S; and in the
              checked calls of Turing, Turing-256 and the masked cipher, a key
              check before and after each direction. Plus three verdict masks
              derived separately in decapsulation.

`--self-test` runs the checker on synthetic assembly, a correct one and one
broken per rule, without building anything: each broken one must fail, so a
check that can no longer fail is caught (review of 2026-09-28, R7).

It is x86-64 only (rustc's default on the CI runner); on another target the
mnemonics differ and the check skips with a clear message rather than passing
vacuously.

    python tools/ct_check.py                       # build both, emit asm, check
    python tools/ct_check.py PROD.s [ANALYSIS.s]   # check assembly already emitted
    python tools/ct_check.py --self-test           # the checker against synthetic asm

Exit status 0 if every expectation holds, 1 if any fails, 2 on a setup error.
"""
import os
import platform
import re
import subprocess
import sys

# Modules whose machine code must not divide secrets, by mangled-name
# substring, and the build each is read in.
PRODUCTION_MODULES = ("3lwe", "10turing1026", "5mlkem")
ANALYSIS_MODULES = ("5mlkem",)
DIVISION_ALLOWANCE = {"expanded": 3}
DECAPSULATION = "20decapsulated_faulted"

# (function, callee, calls at least, why): calls or tail-call jumps that must
# survive the optimiser, each the second or third copy of a computation.
REDUNDANCY = [
    (DECAPSULATION, "11select_into", 2, "two chained selections (R2)"),
    (DECAPSULATION, "15bind_to_verdict", 1, "the accepted key bound to the third verdict (R2)"),
    (DECAPSULATION, "9reencrypt", 2, "two independent re-encryptions"),
    (DECAPSULATION, "13rejection_key", 2, "the rejection key computed twice (the z-skip fault)"),
    (DECAPSULATION, "6infect", 1, "a disagreement of the two infected (the z-skip fault)"),
    ("13decrypt_voted", "11decode_pass", 3, "three decryption passes (the decoder fault)"),
    ("13decrypt_voted", "8majority", 1, "the passes voted (the decoder fault)"),
    ("11decode_pass", "14decrypt_values", 1, "each pass computes C - B'S itself"),
    ("11decode_pass", "13shuffle_order", 1, "each pass decodes in its own random order"),
]
# The checked calls: a key check before and after each direction.
GUARDED = ("6cipher6Turing7guarded", "9turing2569Turing2567guarded", "6masked12MaskedTuring7guarded")


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


def calls(code, callee):
    """Calls of, or tail-call jumps to, a function whose name holds `callee`,
    direct or through the GOT: position-independent code on Linux calls a
    `pub` function as `callq *sym@GOTPCREL(%rip)`, which a direct-call
    pattern misses (it failed seven rules on Linux assembly)."""
    return sum(1 for l in code if re.match(r"^(call|jmp)[qw]?\s+\*?_ZN", l) and callee in l)


def check_redundancy(path):
    """Returns the number of failures; prints each."""
    funcs = list(functions(path))
    failures = 0

    def report(ok, what):
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'} {what}")
        failures += 0 if ok else 1

    decap = [code for name, code in funcs if DECAPSULATION in name and "turing1026" in name]
    if not decap:
        report(False, f"no {DECAPSULATION} in {os.path.basename(path)}")
        return failures
    masks = sum(1 for l in decap[0] if re.match(r"^s[ah]rq\s+\$63,", l))
    report(masks >= 3, f"decapsulation: three verdict masks derived separately (found {masks} `sar/shr $63`)")
    for owner, callee, least, why in REDUNDANCY:
        bodies = [code for name, code in funcs if owner in name and "turing1026" in name]
        exists = any(callee in name for name, _ in funcs)
        found = max((calls(code, callee) for code in bodies), default=0)
        report(bool(bodies) and exists and found >= least, f"{owner.lstrip('0123456789')} calls {callee.lstrip('0123456789')} {found} time(s), at least {least}: {why}")
    for owner in GUARDED:
        bodies = [(name, code) for name, code in funcs if owner in name]
        if not bodies:
            report(False, f"no {owner} in {os.path.basename(path)}")
            continue
        for name, code in bodies:
            directions = calls(code, "13encrypt_block") + calls(code, "13decrypt_block")
            checks = calls(code, "6intact")
            report(directions >= 2 and checks >= directions, f"{owner}: {checks} key checks for {directions} encrypt/decrypt calls (two per direction: before and after)")
    return failures


def self_test():
    """The checker on synthetic assembly: the good one passes, each broken one
    fails. Returns the number of rules the checker got wrong."""
    import tempfile

    def fn(name, *lines):
        return [f"_ZN{name}17h0123456789abcdefE:"] + [f"\t{l}" for l in lines]

    def good():
        return {
            "decap": fn("6turing10turing102616DecapsulationKey20decapsulated_faulted",
                        "sarq\t$63, %rax", "sarq\t$63, %rbx", "sarq\t$63, %rcx",
                        *["callq\t_ZN6turing10turing102611select_into17h1E"] * 2,
                        "callq\t_ZN6turing10turing102615bind_to_verdict17h1E",
                        *["callq\t_ZN6turing10turing102616EncapsulationKey9reencrypt17h1E"] * 2,
                        *["callq\t_ZN6turing10turing102616DecapsulationKey13rejection_key17h1E"] * 2,
                        "callq\t_ZN6turing10turing10266infect17h1E", "retq"),
            "voted": fn("6turing10turing102616DecapsulationKey13decrypt_voted",
                        *["callq\t_ZN6turing10turing102616DecapsulationKey11decode_pass17h1E"] * 3,
                        "jmp\t_ZN6turing10turing10268majority17h1E"),
            # decrypt_values called through the GOT, as Linux's PIC build does.
            "pass": fn("6turing10turing102616DecapsulationKey11decode_pass",
                       "callq\t*_ZN6turing3lwe14decrypt_values17h1E@GOTPCREL(%rip)", "callq\t_ZN6turing10turing102613shuffle_order17h1E", "retq"),
            "callees": fn("6turing10turing102611select_into", "retq") + fn("6turing10turing102615bind_to_verdict", "retq")
            + fn("6turing10turing102616EncapsulationKey9reencrypt", "retq") + fn("6turing10turing102616DecapsulationKey13rejection_key", "retq")
            + fn("6turing10turing10266infect", "retq") + fn("6turing10turing10268majority", "retq")
            + fn("6turing3lwe14decrypt_values", "imull\t%eax, %ebx", "retq") + fn("6turing10turing102613shuffle_order", "retq"),
            "guarded": sum((fn(g, "callq\t_ZN6turing11keyschedule6intact17h1E", "callq\t_ZN6turing6cipher6Turing13encrypt_block17h1E",
                               "callq\t_ZN6turing6cipher6Turing13decrypt_block17h1E", "callq\t_ZN6turing11keyschedule6intact17h1E", "retq")
                            for g in GUARDED), []),
        }

    def write(parts):
        f = tempfile.NamedTemporaryFile("w", suffix=".s", delete=False, encoding="utf-8")
        f.write("\n".join(sum(parts.values(), [])) + "\n")
        f.close()
        return f.name

    def quiet(check, *args):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            return check(*args)

    wrong = 0
    good_path = write(good())
    if quiet(check_redundancy, good_path) or quiet(check_divisions, good_path, ("3lwe", "10turing1026")):
        print("  FAIL self-test: the correct synthetic assembly does not pass")
        wrong += 1
    broken = [
        ("the two selections fused (R2)", "decap", "callq\t_ZN6turing10turing102611select_into17h1E", None),
        ("one verdict mask", "decap", "sarq\t$63, %rbx", None),
        ("the rejection key computed once", "decap", "callq\t_ZN6turing10turing102616DecapsulationKey13rejection_key17h1E", None),
        ("no infection", "decap", "callq\t_ZN6turing10turing10266infect17h1E", None),
        ("two decryption passes", "voted", "callq\t_ZN6turing10turing102616DecapsulationKey11decode_pass17h1E", None),
        ("no vote", "voted", "jmp\t_ZN6turing10turing10268majority17h1E", None),
        ("one order for all passes", "pass", "callq\t_ZN6turing10turing102613shuffle_order17h1E", None),
        ("one C - B'S for all passes (a call through the GOT)", "pass", "callq\t*_ZN6turing3lwe14decrypt_values17h1E@GOTPCREL(%rip)", None),
        ("a checked call's second key check merged away", "guarded", "callq\t_ZN6turing11keyschedule6intact17h1E", None),
        ("a division in the lattice code (KyberSlash)", "callees", "imull\t%eax, %ebx", "divl\t%ebx"),
        ("a decryption pass inlined into the vote", "pass", "*", None),
        ("the lattice module missing from the build (R7)", "callees",
         "_ZN6turing3lwe14decrypt_values17h0123456789abcdefE:", "_ZN6turing4misc14decrypt_values17h0123456789abcdefE:"),
    ]
    for what, part, line, replacement in broken:
        parts = good()
        lines = parts[part]
        if line == "*":
            lines.clear()
        else:
            # A function label is matched as it is, an instruction with its tab.
            label = line.startswith("_ZN")
            i = lines.index(line if label else "\t" + line)
            if replacement is None:
                del lines[i]
            else:
                lines[i] = replacement if label else "\t" + replacement
        path = write(parts)
        caught = quiet(check_redundancy, path) + quiet(check_divisions, path, ("3lwe", "10turing1026"))
        print(f"  {'ok  ' if caught else 'FAIL'} self-test: {what} {'is caught' if caught else 'PASSES the check'}")
        wrong += 0 if caught else 1
        os.unlink(path)
    os.unlink(good_path)
    return wrong


def main():
    if "--self-test" in sys.argv:
        wrong = self_test()
        print("ct_check self-test: every rule fails on its broken assembly" if not wrong else f"ct_check self-test: {wrong} rule(s) wrong")
        return 1 if wrong else 0
    if platform.machine() not in ("x86_64", "AMD64"):
        print(f"ct_check: skipping, assembly check is x86-64 only (this is {platform.machine()})")
        return 0
    production = sys.argv[1] if len(sys.argv) > 1 else emit_asm("")
    analysis = sys.argv[2] if len(sys.argv) > 2 else (emit_asm("analysis") if len(sys.argv) == 1 else None)
    print(f"ct_check: production build {production}")
    failures = check_divisions(production, PRODUCTION_MODULES)
    failures += check_redundancy(production)
    if analysis:
        print(f"ct_check: analysis build {analysis}")
        failures += check_divisions(analysis, ANALYSIS_MODULES)
    else:
        print("ct_check: no analysis build given, ML-KEM NOT checked")
        failures += 1
    if failures:
        print(f"ct_check: {failures} failure(s)")
        return 1
    print("ct_check: no secret division in the lattice code (KyberSlash class clean), every redundant computation kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
