"""Which constant-time checks catch which lattice-KEM timing bug class?

Reproduces, on this machine, the tool-coverage facts used in
research/notes/pq/side-channels-faults-and-ct-verification.md:

  * gcc at -Os compiles the pre-fix Kyber `/KYBER_Q` code (KyberSlash1 and 2)
    to a hardware divide on x86-64, while -O1/-O2/-O3 use a multiply
    (Bernstein et al., "KyberSlash", TCHES 2025(2), Sec. 1.1 and 7.1).
  * Stock Valgrind memcheck with the secret marked undefined (ctgrind,
    Langley 2010; TIMECOP) flags secret branches and secret-indexed loads but
    does NOT flag a secret division (KyberSlash paper Sec. 7.1.1: "Memcheck
    does not test for uninitialized divisions; this is why a patch is
    needed").
  * Memcheck with the KyberSlash "varlat" patch (valgrind-varlat-patch-
    20250805.txt from kyberslash.cr.yp.to, built by build_valgrind_varlat.sh)
    and --variable-latency-errors=yes DOES flag the secret division, in
    exactly the builds whose disassembly contains div.
  * An early-exit comparison (the FrodoKEM bug class, Guo-Johansson-Nilsson
    CRYPTO 2020, which used memcmp) and a secret-indexed table are flagged.
  * Rejection sampling is flagged when its input is marked secret and is
    clean when the (public) seed is declassified, the TIMECOP false positive
    the KyberSlash paper describes (Sec. 7.1.3).
  * Whether current clang still turns the pre-Clangover poly_frommsg mask
    into a branch (Purnal 2024 reports clang 15-18 on x86 at -Os, -O1,
    -O2 -fno-vectorize, -O3 -fno-vectorize), and whether the 0264efa fix
    without the 7dff53d asm barrier still branches when caller and cmov are
    in one translation unit.

It also runs the C program's exhaustive self-test: the multiply-shift code
that replaced each division equals the division on every input the caller can
pass, with a negative control.

Needs WSL with gcc, clang and objdump, a stock Valgrind unpacked (no root)
from the Ubuntu archive (apt-get download valgrind; dpkg -x valgrind_*.deb
root), and optionally the patched Valgrind installed by
build_valgrind_varlat.sh.
Usage (from Windows):  python ct_bugclasses.py STOCK_ROOT [PATCHED_PREFIX]
STOCK_ROOT is that 'root' directory (Windows path, or WSL path starting
with /); PATCHED_PREFIX is the --prefix given to build_valgrind_varlat.sh
(a WSL path).
Every subprocess has a timeout. Output is deterministic apart from the
compiler version lines.
"""
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "ct_bugclasses.c")


def wslpath(p):
    out = subprocess.run(["wsl.exe", "-e", "wslpath", "-a", p.replace("\\", "/")],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


def wsl(cmd, timeout=300):
    r = subprocess.run(["wsl.exe", "-e", "bash", "-c", cmd], capture_output=True,
                       text=True, timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


FUNCS = ["tomsg_div", "tomsg_mul", "compress4_div", "compress4_mul", "frommsg_mask",
         "frommsg_cmov", "frommsg_cmov_nobar", "verify_ct", "cmp_early", "table_lookup",
         "rej_uniform"]
CASES = ["tomsg_div", "tomsg_mul", "compress4_div", "compress4_mul", "frommsg_mask",
         "frommsg_cmov", "frommsg_cmov_nobar", "verify_ct", "cmp_early", "table_lookup",
         "rej_secret", "rej_public"]
BUILDS = [("gcc", "-O0"), ("gcc", "-O1"), ("gcc", "-O2"), ("gcc", "-O3"), ("gcc", "-Os"),
          ("clang", "-O0"), ("clang", "-O1"), ("clang", "-O2"), ("clang", "-O3"),
          ("clang", "-Os"), ("clang", "-O2 -fno-vectorize"), ("clang", "-O3 -fno-vectorize")]


def disasm_stats(binary):
    """Per function: number of div/idiv, conditional jumps, cmov/setcc."""
    _, out, _ = wsl(f"objdump -d --no-show-raw-insn -M intel '{binary}'")
    stats, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1) if m.group(1) in FUNCS else None
            if cur:
                stats[cur] = {"div": 0, "jcc": 0, "cmov": 0, "insns": 0}
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+[0-9a-f]+:\s+(\S+)", line)
        if not m:
            continue
        op = m.group(1)
        s = stats[cur]
        s["insns"] += 1
        if op in ("div", "idiv"):
            s["div"] += 1
        elif op.startswith("j") and op != "jmp":
            s["jcc"] += 1
        elif op.startswith("cmov") or op.startswith("set"):
            s["cmov"] += 1
    return stats


def memcheck_hits(err):
    """Error reports whose innermost frame is in ct_bugclasses.c.

    The binaries are linked statically (the stock Ubuntu Valgrind refuses to
    start on a dynamic binary without libc6-dbg, which needs root), and a
    static glibc start-up triggers known memcheck reports in __strcspn_sse42.
    Those are outside the code under test and are skipped, as TIMECOP's
    reports are attributed to source lines."""
    hits, kind = [], None
    for line in err.splitlines():
        body = re.sub(r"^==\d+==\s?", "", line)
        if body.startswith("Conditional jump or move depends on uninitialised"):
            kind = "branch"
        elif body.startswith("Use of uninitialised value of size"):
            kind = "address"
        elif body.startswith("Variable-latency instruction operand"):
            kind = "varlat"
        elif body.startswith("Syscall param"):
            kind = "syscall"
        elif kind and body.strip().startswith("at 0x"):
            m = re.search(r"at 0x[0-9A-F]+: (\S+) \(ct_bugclasses\.c:(\d+)\)", body)
            if m:
                hits.append(f"{kind}@{m.group(1)}:{m.group(2)}")
            kind = None
    return sorted(set(hits))


def run_case(vg, binary, case, extra=""):
    rc, out, err = wsl(f"{vg} --tool=memcheck -q {extra} {binary} {case}", timeout=120)
    if not out.startswith(case):
        sys.stderr.write(err[-2000:])
        return "RUNFAIL", []
    hits = memcheck_hits(err)
    return ("FLAG" if hits else "ok"), hits


def main():
    # Accept a Windows path (Git Bash rewrites /mnt/... arguments) or a WSL path.
    vgroot = sys.argv[1] if sys.argv[1].startswith("/") else wslpath(sys.argv[1])
    patched = sys.argv[2] if len(sys.argv) > 2 else None
    src = wslpath(SRC)
    work = "/tmp/turing-ctbug"
    vg = f"VALGRIND_LIB={vgroot}/usr/libexec/valgrind {vgroot}/usr/bin/valgrind"
    vgp = f"{patched}/bin/valgrind" if patched else None
    rc, out, err = wsl(f"mkdir -p {work}; gcc --version | head -1; clang --version | head -1; "
                       f"objdump --version | head -1; {vg} --version"
                       + (f"; echo patched: $({vgp} --version); {vgp} --tool=memcheck --help"
                          f" | grep -c variable-latency-errors" if vgp else ""))
    print(out.strip())
    print()
    # 1. Exhaustive self-test (no Valgrind).
    rc, out, err = wsl(f"gcc -O2 -I{vgroot}/usr/include -o {work}/st '{src}' && {work}/st selftest")
    print("== self-test (gcc -O2): multiply-shift vs division")
    print(out.strip() or err.strip())
    print(f"   exit code {rc} (0 = no mismatch on the ranges the callers use)")
    print()
    # 2. Builds, disassembly, memcheck (stock, then patched with varlat on).
    print("== per build: [div, conditional jumps] per function; memcheck verdict per case")
    print("   stock   = Valgrind memcheck as shipped (ctgrind/TIMECOP method)")
    print("   varlat  = KyberSlash-patched memcheck, --variable-latency-errors=yes")
    print("   FLAG(kind@function:line) = secret-dependent branch/address/variable-latency op")
    summary = {c: {"stock": [], "varlat": []} for c in CASES}
    for cc, opt in BUILDS:
        tag = f"{cc}{opt.replace(' ', '')}"
        binary = f"{work}/{tag}"
        rc, out, err = wsl(f"{cc} {opt} -g -static -I{vgroot}/usr/include -o {binary} '{src}'")
        if rc != 0:
            print(f"{cc} {opt}: BUILD FAILED\n{err}")
            continue
        st = disasm_stats(binary)
        parts = []
        for f in FUNCS:
            s = st.get(f)
            parts.append(f"{f}[{s['div']},{s['jcc']}]" if s else f"{f}[inlined]")
        print(f"-- {cc} {opt}")
        print("   disasm: " + " ".join(parts))
        for label, v, extra in [("stock", vg, ""), ("varlat", vgp, "--variable-latency-errors=yes")]:
            if v is None:
                continue
            verdicts = []
            for case in CASES:
                verdict, hits = run_case(v, binary, case, extra)
                if hits:
                    summary[case][label].append(f"{cc}{opt.replace(' ', '')}")
                verdicts.append(f"{case}={verdict}" + (f"({','.join(hits)})" if hits else ""))
            print(f"   {label}: " + " ".join(verdicts))
    print()
    print("== summary: builds in which each case was flagged")
    for case in CASES:
        s = summary[case]
        line = f"   {case:20s} stock: {','.join(s['stock']) or '-'}"
        if vgp:
            line += f" | varlat: {','.join(s['varlat']) or '-'}"
        print(line)


if __name__ == "__main__":
    main()
