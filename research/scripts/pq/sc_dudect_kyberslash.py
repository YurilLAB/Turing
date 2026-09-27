"""sc_dudect_kyberslash.py - would a dudect-style timing test have caught
KyberSlash on this machine?

Drives sc_dudect_kyberslash.c (the dudect method of Reparaz, Balasch,
Verbauwhede, DATE 2017; see the C file's header) in WSL:
  1. compiles it with gcc at -Os (the setting where the pre-fix Kyber code
     becomes a hardware divide on x86-64: KyberSlash, TCHES 2025(2), Sec. 1.1)
     and at -O2 (no divide: a control);
  2. confirms with objdump which functions contain div/idiv;
  3. runs each timing test for several PRNG seeds, pinned to one core, and
     prints the largest |t| (dudect threshold 4.5).
Tests: KyberSlash1 (tomsg) and KyberSlash2 (compress d=4) with a fixed class
of all-zero coefficients or all-3300 coefficients against uniformly random
coefficients; the multiply-shift fixes as negative controls; an early-exit
compare as a positive control.

A calibration test (div64_calib: 256 64-bit divisions with a small versus a
full-width dividend) shows whether the harness can see division timing on
this CPU at all.

Usage (from Windows): python sc_dudect_kyberslash.py [NMEAS] [SEEDS] [TEST,...]
Defaults: NMEAS = 1000000 measurements per run, SEEDS = 3, all tests.
Every subprocess has a timeout. The inputs are deterministic; the cycle
counts are not, so the printed |t| values vary between runs; the verdict
column is what is compared.
"""
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sc_dudect_kyberslash.c")
TESTS = ["tomsg_div_zero", "tomsg_div_high", "compress_div_zero",
         "compress_div_high", "tomsg_mul_zero", "compress_mul_zero", "cmp_early",
         "div64_calib"]
FUNCS = ["tomsg_div", "tomsg_mul", "compress4_div", "compress4_mul", "cmp_early",
         "div64_calib"]


def wsl(cmd, timeout=300):
    r = subprocess.run(["wsl.exe", "-e", "bash", "-c", cmd], capture_output=True,
                       text=True, timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


def wslpath(p):
    r = subprocess.run(["wsl.exe", "-e", "wslpath", "-a", p.replace("\\", "/")],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip()


def divs_per_function(binary):
    _, out, _ = wsl(f"objdump -d --no-show-raw-insn -M intel '{binary}'", timeout=120)
    counts, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <(\w+)>:", line)
        if m:
            cur = m.group(1)
            continue
        if cur in FUNCS and re.search(r"\s(i?div)\s", line):
            counts[cur] = counts.get(cur, 0) + 1
    return {f: counts.get(f, 0) for f in FUNCS}


def main():
    nmeas = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000
    seeds = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    tests = sys.argv[3].split(",") if len(sys.argv) > 3 else TESTS
    src = wslpath(SRC)
    work = "/tmp/turing-sc-dudect"
    rc, out, err = wsl(f"mkdir -p {work}; gcc --version | head -1; "
                       "grep -m1 'model name' /proc/cpuinfo")
    print(out.strip())
    print(f"measurements per run: {nmeas}; seeds: {seeds}; threshold |t| > 4.5")
    summary = {}
    for opt in ["-Os", "-O2"]:
        binary = f"{work}/dd{opt.replace('-', '_')}"
        rc, out, err = wsl(f"gcc {opt} -march=x86-64 -o {binary} '{src}' -lm", timeout=120)
        if rc != 0:
            print("compile failed", opt, err)
            return 1
        print(f"\n-- gcc {opt}: div/idiv instructions per function: {divs_per_function(binary)}")
        for test in tests:
            verdicts = []
            for seed in range(1, seeds + 1):
                rc, out, err = wsl(f"taskset -c 3 timeout 240 {binary} {test} {nmeas} {seed}",
                                   timeout=300)
                line = out.strip()
                print("   ", f"seed={seed}", line if line else f"RUNFAIL rc={rc} {err.strip()[:200]}")
                m = re.search(r"verdict=(\S+)", line)
                verdicts.append(m.group(1) if m else "RUNFAIL")
            summary[(opt, test)] = verdicts
    print("\n== summary: verdict per seed")
    for (opt, test), v in summary.items():
        print(f"   gcc {opt:4} {test:18} {' '.join(v)}")
    # Checks that make the experiment meaningful:
    pos = all(v.startswith("LEAK") for o in ["-Os", "-O2"]
              for v in summary.get((o, "cmp_early"), []))
    neg = all(v == "no-evidence" for o in ["-Os", "-O2"]
              for t in ["tomsg_mul_zero", "compress_mul_zero"] for v in summary.get((o, t), []))
    print("CHECK positive control (early-exit compare) flagged in every run:", "PASS" if pos else "FAIL")
    print("CHECK negative controls (multiply-shift fixes) never flagged:", "PASS" if neg else "FAIL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
