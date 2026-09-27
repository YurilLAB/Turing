"""sc_rust_cmov_probe.py - test the RustCrypto `cmov` crate's constant-time
claim on rustc output, and see how Valgrind secret-poisoning reports CMOV.

Settles ledger item "cmov crate's constant-time guarantee" in
research/notes/pq/side-channels-faults-and-ct-verification.md as far as a
test can: for each rustc opt-level it
  1. compiles cmov 0.5.4 (from the local cargo cache) as an rlib and
     sc_rust_cmov_probe.rs as a no_std staticlib for x86_64-unknown-linux-gnu
     (on Windows), links statically with gcc in WSL;
  2. counts conditional jumps (jcc) and cmov instructions in each rs_*
     function with objdump;
  3. runs each case with the select condition marked secret under stock
     Valgrind memcheck (the ctgrind / TIMECOP method), for condition 0 and 1,
     and reports whether memcheck complains.
Cases: cmov_u32, cmov_arr (the crate), mask_u32 (hand-written mask select),
maskbar_u32 (the same with the mask behind an empty asm block), branch_u32
(explicit branch: positive control, must be flagged at every level).
Only complaints whose innermost frame is an rs_* function are counted.
Found on 2026-09-27: at opt-levels 1-3, s, z rustc 1.95.0 compiles mask_u32
to `test; cmove rsi,rdi; mov eax,[rsi]` (a pointer select followed by a load:
a secret-dependent address), which memcheck reports as a use of an
uninitialised value of size 8.

Usage: python sc_rust_cmov_probe.py STOCK_VG_ROOT OUTDIR [CMOV_SRC_DIR]
  STOCK_VG_ROOT  Windows path of the unpacked valgrind .deb ('root')
  OUTDIR         Windows scratch directory for build products
  CMOV_SRC_DIR   default: ~/.cargo/registry/src/*/cmov-0.5.4
Every subprocess has a timeout.
"""
import glob
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sc_rust_cmov_probe.rs")
CASES = ["cmov_u32", "cmov_arr", "mask_u32", "maskbar_u32", "branch_u32"]
LEVELS = ["0", "1", "2", "3", "s", "z"]


def wsl(cmd, timeout=300):
    r = subprocess.run(["wsl.exe", "-e", "bash", "-c", cmd], capture_output=True,
                       text=True, timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


def to_wsl(p):
    r = subprocess.run(["wsl.exe", "-e", "wslpath", "-a", p.replace("\\", "/")],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip()


def disasm_stats(binary):
    _, out, _ = wsl(f"objdump -d --no-show-raw-insn -M intel '{binary}'", timeout=120)
    stats, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <(\w+)>:", line)
        if m:
            cur = m.group(1)
            continue
        if cur and cur.startswith("rs_"):
            s = stats.setdefault(cur, [0, 0])
            if re.search(r"\sj(?!mp)[a-z]+\s", line):
                s[0] += 1
            if re.search(r"\scmov[a-z]+\s", line):
                s[1] += 1
    return stats


def main():
    stock_root = to_wsl(sys.argv[1])
    outdir = sys.argv[2]
    cmov_dir = sys.argv[3] if len(sys.argv) > 3 else glob.glob(os.path.expanduser(
        "~/.cargo/registry/src/*/cmov-0.5.4"))[0]
    os.makedirs(outdir, exist_ok=True)
    vg = f"VALGRIND_LIB={stock_root}/usr/libexec/valgrind {stock_root}/usr/bin/valgrind"
    rv = subprocess.run(["rustc", "--version"], capture_output=True, text=True, timeout=60)
    print(rv.stdout.strip(), "| cmov source:", cmov_dir)
    _, out, _ = wsl(f"{vg} --version")
    print(out.strip())
    summary = {c: [] for c in CASES}
    for lvl in LEVELS:
        rlib = os.path.join(outdir, f"libcmov_{lvl}.rlib")
        lib = os.path.join(outdir, f"libcmovprobe_{lvl}.a")
        common = ["--target", "x86_64-unknown-linux-gnu", "-C", f"opt-level={lvl}", "-C", "panic=abort"]
        r1 = subprocess.run(["rustc", "--edition", "2024", "--crate-type", "rlib", "--crate-name", "cmov",
                             *common, "-o", rlib, os.path.join(cmov_dir, "src", "lib.rs")],
                            capture_output=True, text=True, timeout=600)
        if r1.returncode:
            print(f"opt-level {lvl}: cmov rlib failed\n{r1.stderr[-2000:]}")
            return 1
        r2 = subprocess.run(["rustc", "--edition", "2021", "--crate-type", "staticlib", "--crate-name",
                             "sc_rust_cmov_probe", *common, "--extern", f"cmov={rlib}", "-o", lib, SRC],
                            capture_output=True, text=True, timeout=600)
        if r2.returncode:
            print(f"opt-level {lvl}: probe failed\n{r2.stderr[-2000:]}")
            return 1
        binary = to_wsl(os.path.join(outdir, f"cmovprobe_{lvl}"))
        rc, o, e = wsl(f"gcc -static -o '{binary}' '{to_wsl(lib)}'", timeout=120)
        if rc:
            print(f"opt-level {lvl}: link failed {e[-800:]}")
            return 1
        st = disasm_stats(binary)
        print(f"-- rustc opt-level={lvl}: [jcc, cmov] per function: " + " ".join(
            f"{f}[{v[0]},{v[1]}]" for f, v in sorted(st.items())))
        verdicts = []
        for case in CASES:
            flagged = []
            outs = []
            for c in "01":
                rc, o, e = wsl(f"{vg} --tool=memcheck -q '{binary}' {case} {c}", timeout=180)
                outs.append(o.strip().split()[-1] if o.strip() else "RUNFAIL")
                # Keep only complaints whose innermost frame is one of our rs_* functions
                # (a static glibc start-up routine, __strcspn_sse42 under _dl_init_paths,
                # is reported in every run and is unrelated to the probe).
                kinds = set()
                for block in re.split(r"==\d+== \n", e):
                    m = re.search(r"==\d+== (Conditional jump or move depends on uninitialised value\(s\)"
                                  r"|Use of uninitialised value of size \d+)\n==\d+==    at 0x[0-9A-F]+: (\w+)",
                                  block)
                    if m and m.group(2).startswith("rs_"):
                        kinds.add(("jump/move" if m.group(1).startswith("Conditional") else "use")
                                  + "@" + m.group(2))
                if kinds:
                    flagged.append(f"c={c}:" + "/".join(sorted(kinds)))
            ok = outs == ["11111111", "22222222"] or (case == "cmov_arr" and outs == ["00001111", "00002222"])
            verdicts.append(f"{case}=" + (f"FLAG({','.join(flagged)})" if flagged else "clean")
                            + ("" if ok else f"[WRONG OUTPUT {outs}]"))
            if flagged:
                summary[case].append(lvl)
        print("   memcheck: " + " ".join(verdicts))
    print("\n== summary: opt-levels at which memcheck reported the secret-condition select")
    for c in CASES:
        print(f"   {c:11} {','.join(summary[c]) if summary[c] else '-'}")
    # Controls: the explicit branch must be flagged at every level (positive
    # control); at opt-level 0, where rustc keeps the arithmetic as written,
    # the hand-written mask select must be clean (negative control).
    ctrl = len(summary["branch_u32"]) == len(LEVELS) and "0" not in summary["mask_u32"]
    print("CHECK controls (branch flagged at every level; mask select clean at opt-level 0):",
          "PASS" if ctrl else "FAIL")
    print("RESULT mask select flagged (compiler-introduced secret-dependent access) at:",
          ",".join(summary["mask_u32"]) or "none",
          "| with asm barrier:", ",".join(summary["maskbar_u32"]) or "none",
          "| cmov crate:", ",".join(sorted(set(summary["cmov_u32"] + summary["cmov_arr"]))) or "none")
    return 0 if ctrl else 1


if __name__ == "__main__":
    sys.exit(main())
