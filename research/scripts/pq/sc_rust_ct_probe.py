"""Build sc_rust_ct_probe.rs at several rustc opt-levels and check it three ways.

Reproduces the Rust rows of the constant-time tool matrix in
research/notes/pq/side-channels-faults-and-ct-verification.md (Section 5):
for each build it counts div/idiv and conditional jumps in every rs_*
function (objdump), then runs every case under
  * stock Valgrind memcheck with the secret marked undefined from Rust
    (the ctgrind / TIMECOP method), and
  * the KyberSlash-patched memcheck with --variable-latency-errors=yes
    (valgrind-varlat-patch-20250805.txt, built by build_valgrind_varlat.sh).
Builds: opt-level 0, 1, 2, 3, s, z, and "0dbg" = opt-level 0 with
debug-assertions and overflow-checks on, which is what `cargo test` uses by
default (the dev profile).

The Rust code is compiled on Windows by rustc for x86_64-unknown-linux-gnu as
a no_std staticlib (no linker needed on Windows) and linked statically by gcc
inside WSL (static, because a stock Ubuntu Valgrind needs libc6-dbg, i.e.
root, to run dynamic binaries).

Usage: python sc_rust_ct_probe.py STOCK_VG_ROOT PATCHED_VG_PREFIX OUTDIR
  STOCK_VG_ROOT      Windows path of the unpacked valgrind .deb ('root')
  PATCHED_VG_PREFIX  WSL path given as PREFIX to build_valgrind_varlat.sh
  OUTDIR             Windows scratch directory for the build products
Every subprocess has a timeout.
"""
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sc_rust_ct_probe.rs")
CASES = ["tomsg_div", "tomsg_mul", "frommsg_mask", "frommsg_blackbox", "frommsg_asm",
         "frommsg_volatile", "eq_slice", "eq_fold", "rej_secret", "rej_public"]
FUNCS = ["rs_tomsg_div", "rs_tomsg_mul", "rs_frommsg_mask", "rs_frommsg_blackbox",
         "rs_frommsg_asm", "rs_frommsg_volatile", "rs_eq_slice", "rs_eq_fold", "rs_rej_uniform"]
LEVELS = [("0", []), ("0dbg", ["-C", "debug-assertions=on", "-C", "overflow-checks=on"]),
          ("1", []), ("2", []), ("3", []), ("s", []), ("z", [])]


def to_wsl(p):
    p = os.path.abspath(p).replace("\\", "/")
    return "/mnt/" + p[0].lower() + p[2:]


def wsl(cmd, timeout=300):
    r = subprocess.run(["wsl.exe", "-e", "bash", "-c", cmd], capture_output=True, text=True,
                       timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


def disasm_stats(binary):
    _, out, _ = wsl(f"objdump -d --no-show-raw-insn -M intel '{binary}'")
    stats, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1) if m.group(1) in FUNCS else None
            if cur:
                stats[cur] = [0, 0]
            continue
        if cur:
            m = re.match(r"^\s+[0-9a-f]+:\s+(\S+)", line)
            if m:
                op = m.group(1)
                if op in ("div", "idiv"):
                    stats[cur][0] += 1
                elif op.startswith("j") and op != "jmp":
                    stats[cur][1] += 1
    return stats


def hits(err):
    """One entry per memcheck error that has a frame in the .rs file:
    kind@innermost-function<-first .rs frame (function:line)."""
    out, kind, frames = [], None, []

    def flush():
        if kind and frames:
            rs = next((f for f in frames if f[1]), None)
            if rs:
                inner = frames[0][0]
                tag = f"{kind}@{rs[0]}:{rs[1]}" if inner == rs[0] else f"{kind}@{inner}<-{rs[0]}:{rs[1]}"
                out.append(tag)

    for line in err.splitlines():
        body = re.sub(r"^==\d+==\s?", "", line)
        new = None
        if body.startswith("Conditional jump or move depends on uninitialised"):
            new = "branch"
        elif body.startswith("Use of uninitialised value of size"):
            new = "address"
        elif body.startswith("Variable-latency instruction operand"):
            new = "varlat"
        elif body.startswith("Syscall param"):
            new = "syscall"
        if new:
            flush()
            kind, frames = new, []
            continue
        m = re.match(r"\s+(?:at|by) 0x[0-9A-F]+: (.+?)(?: \((?:in )?([^():]+?)(?::(\d+))?\))?$", body)
        if kind and m:
            fn, file, ln = m.group(1), m.group(2) or "", m.group(3)
            short = fn.split("::")[-1].split("(")[0]
            frames.append((short, ln if file.endswith("sc_rust_ct_probe.rs") else None))
        elif kind and body.strip() == "":
            flush()
            kind, frames = None, []
    flush()
    return sorted(set(out))


def main():
    stock_root = to_wsl(sys.argv[1])
    patched = sys.argv[2]
    outdir = sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    vg_stock = f"VALGRIND_LIB={stock_root}/usr/libexec/valgrind {stock_root}/usr/bin/valgrind"
    vg_var = f"{patched}/bin/valgrind"
    rv = subprocess.run(["rustc", "--version"], capture_output=True, text=True, timeout=60)
    print(rv.stdout.strip())
    _, out, _ = wsl(f"gcc --version | head -1; {vg_stock} --version; {vg_var} --version")
    print(out.strip())
    summary = {c: {"stock": [], "varlat": []} for c in CASES}
    for level, extra in LEVELS:
        opt = "0" if level == "0dbg" else level
        lib = os.path.join(outdir, f"libprobe_{level}.a")
        cmd = ["rustc", "--edition", "2021", "--crate-type", "staticlib", "--crate-name",
               "sc_rust_ct_probe", "--target", "x86_64-unknown-linux-gnu", "-C", f"opt-level={opt}",
               "-C", "debuginfo=2", "-C", "panic=abort", *extra, "-o", lib, SRC]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            print(f"opt-level {level}: rustc FAILED\n{r.stderr[-3000:]}")
            continue
        binary = to_wsl(os.path.join(outdir, f"probe_{level}"))
        rc, o, e = wsl(f"gcc -static -o '{binary}' '{to_wsl(lib)}' 2>&1 && '{binary}' selftest")
        print(f"-- rustc opt-level={level}{' (+debug-assertions, overflow-checks)' if extra else ''}")
        print(f"   link+selftest: rc={rc} {o.strip()} {e.strip()[-300:]}")
        if not os.path.exists(os.path.join(outdir, f"probe_{level}")):
            continue
        st = disasm_stats(binary)
        print("   disasm [div, jcc]: " + " ".join(
            f"{f[3:]}[{st[f][0]},{st[f][1]}]" if f in st else f"{f[3:]}[inlined]" for f in FUNCS))
        for label, vg, flag in [("stock", vg_stock, ""), ("varlat", vg_var, "--variable-latency-errors=yes")]:
            verdicts = []
            for case in CASES:
                rc, o, e = wsl(f"{vg} --tool=memcheck -q {flag} '{binary}' {case}", timeout=180)
                if not o.startswith(case):
                    verdicts.append(f"{case}=RUNFAIL(rc={rc})")
                    sys.stderr.write(f"[{level} {label} {case}]\n{e[-1500:]}\n")
                    continue
                hs = hits(e)
                if hs:
                    summary[case][label].append(level)
                verdicts.append(f"{case}=" + (f"FLAG({','.join(hs)})" if hs else "ok"))
            print(f"   {label}: " + " ".join(verdicts))
    print()
    print("== summary: rustc opt-levels at which each case was flagged")
    for case in CASES:
        s = summary[case]
        print(f"   {case:18s} stock: {','.join(s['stock']) or '-'} | varlat: {','.join(s['varlat']) or '-'}")


if __name__ == "__main__":
    main()
