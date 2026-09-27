"""sc_fault_sim.py - exhaustive fault simulation of the final key selection in
lattice-KEM decapsulation, three orders, on real x86-64 machine code.

Question it answers: does the "default fail" order recommended by Xagawa
et al. (ASIACRYPT 2021, Sec. 7) and used by the pq-crystals reference code
stop single-instruction-skip faults, and what does it take to also stop a
single stored-bit flip of the decision (the Rowhammer fault of Mondal et al.,
ACNS 2024, on the FO "fail" variable)?

Victim: sc_fault_victim.c (variants literal = FIPS 203 Alg. 18 order,
ref = pq-crystals ref/kem.c order, hardened = a proposal written here).
Simulator: sc_fault_sim.c (ptrace; skips each dynamic instruction in the
victim code once).

Steps (all in WSL, every command under a timeout):
  1. gcc -static -no-pie at each optimisation level; objdump gives the
     address and length of every instruction in section victim_text.
  2. Fault-free runs: the invalid ciphertext must give K-bar, the valid one K'.
  3. Skip model: for every dynamic instruction k of the variant's tail
     function on an INVALID ciphertext, skip k and classify the output:
     REAL (= K', the attacker's win: a plaintext-checking oracle / the FO check
     bypassed), MIXK (neither, but some byte equals K' where K' and K-bar
     differ: a partial leak the attacker can still compare with the key they
     expect), REJ (= K-bar), OTHER (neither, no K' byte), CRASH (no output).
  4. Flip model (build with -DFLIPHOOK): flip each bit 0..31 of each decision
     variable once, right after it is computed; same classification.
Negative control: the literal order must show at least one REAL skip (the
skipped cmov call of Xagawa et al.); otherwise the simulator is not working.

Rust: the entries "rust:LEVEL" build sc_fault_victim.rs with rustc
(x86_64-unknown-linux-gnu, no_std staticlib, on Windows) linked with
sc_fault_victim_rs_main.c in WSL; skip model only.

Usage (from Windows): python sc_fault_sim.py [BUILDS]
  default BUILDS "-O2,-Os,-O0"; e.g. "-O2,-Os,-O0,rust:3,rust:s,rust:z,rust:0"
  Rust libraries go to %SC_FAULT_OUTDIR% (default: the system temp dir).
Deterministic: fixed victim data, exhaustive fault enumeration.
"""
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
VARIANTS = ["literal", "ref", "hardened"]
FLIP_TARGETS = {"literal": ["fail"], "ref": ["fail"], "hardened": ["d1", "m1", "d2", "m2"]}
WORK = "/tmp/turing-sc-fault"
# Windows-side directory for the Rust static libraries (rustc runs on Windows).
OUTDIR = os.environ.get("SC_FAULT_OUTDIR",
                        os.path.join(__import__("tempfile").gettempdir(), "turing-sc-fault"))


def wsl(cmd, timeout=300):
    r = subprocess.run(["wsl.exe", "-e", "bash", "-c", cmd], capture_output=True,
                       text=True, timeout=timeout, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


def wslpath(p):
    r = subprocess.run(["wsl.exe", "-e", "wslpath", "-a", p.replace("\\", "/")],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip()


def symbols(binary):
    _, out, _ = wsl(f"nm {binary}", timeout=60)
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
    return syms


def lengths(binary, lenfile):
    _, out, _ = wsl(f"objdump -d --insn-width=16 -j victim_text {binary}", timeout=60)
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)", line)
        if m:
            rows.append((int(m.group(1), 16), len(m.group(2).split())))
    text = "\n".join(f"{a:x} {n}" for a, n in rows) + "\n"
    wsl(f"cat > {lenfile} <<'EOF'\n{text}EOF", timeout=60)
    return len(rows)


def classify(out, kr, rk):
    """REAL = output is K'; REJ = K-bar; MIXK = neither, but at least one byte
    equals K' where K' and K-bar differ (a partial leak of K', still usable as
    an oracle); OTHER = neither and no such byte; CRASH = no output."""
    m = re.search(r"^SS ([0-9a-f]+)$", out, re.M)
    if not m:
        return "CRASH"
    ss = m.group(1)
    if ss == kr:
        return "REAL"
    if ss == rk:
        return "REJ"
    b = lambda h, i: h[2 * i:2 * i + 2]
    if any(b(ss, i) == b(kr, i) != b(rk, i) for i in range(len(kr) // 2)):
        return "MIXK"
    return "OTHER"


def build_rust(level, outdir):
    """rustc (Windows) -> no_std staticlib for x86_64-unknown-linux-gnu, then
    gcc links it with sc_fault_victim_rs_main.c inside WSL."""
    os.makedirs(outdir, exist_ok=True)
    lib = os.path.join(outdir, f"libfaultvictim_{level}.a")
    cmd = ["rustc", "--edition", "2021", "--crate-type", "staticlib", "--crate-name",
           "sc_fault_victim", "--target", "x86_64-unknown-linux-gnu", "-C", f"opt-level={level}",
           "-C", "panic=abort", "-o", lib, os.path.join(HERE, "sc_fault_victim.rs")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode:
        print("rustc failed", r.stderr[-2000:])
        return None
    vbin = f"{WORK}/victim_rs{level}"
    rc, _, err = wsl(f"gcc -O2 -static -no-pie -fno-stack-protector -o {vbin} "
                     f"'{wslpath(os.path.join(HERE, 'sc_fault_victim_rs_main.c'))}' '{wslpath(lib)}'",
                     timeout=120)
    if rc:
        print("link failed", err)
        return None
    return vbin


def run_opt(opt, victim_src, sim_bin):
    tag = opt.replace("-", "").replace(":", "")
    rust = opt.startswith("rust:")
    if rust:
        vbin = build_rust(opt.split(":")[1], os.path.join(OUTDIR, "sc-fault-rs"))
        fbin = None
        if vbin is None:
            return None
        rv = subprocess.run(["rustc", "--version"], capture_output=True, text=True, timeout=60)
        print(f"\n   ({rv.stdout.strip()}, opt-level {opt.split(':')[1]}; skip model only)")
    else:
        vbin, fbin = f"{WORK}/victim_{tag}", f"{WORK}/victimflip_{tag}"
        rc, _, err = wsl(f"gcc {opt} -static -no-pie -fno-stack-protector -o {vbin} '{victim_src}' && "
                         f"gcc {opt} -static -no-pie -fno-stack-protector -DFLIPHOOK -o {fbin} '{victim_src}'",
                         timeout=120)
        if rc:
            print("compile failed", err)
            return None
    syms = symbols(vbin)
    _, hdr, _ = wsl(f"objdump -h {vbin}", timeout=60)
    m = re.search(r"^\s*\d+\s+victim_text\s+([0-9a-f]+)\s+([0-9a-f]+)", hdr, re.M)
    size, start = int(m.group(1), 16), int(m.group(2), 16)
    end = start + size
    lenfile = f"{WORK}/len_{tag}.txt"
    nins = lengths(vbin, lenfile)
    print(f"\n-- {'rustc' if rust else 'gcc'} {opt}: victim_text {start:x}-{end:x}, {nins} static instructions")
    _, info, _ = wsl(f"{vbin} ref info", timeout=30)
    kr = re.search(r"^KR ([0-9a-f]+)", info, re.M).group(1)
    rk = re.search(r"^RK ([0-9a-f]+)", info, re.M).group(1)
    results = {}
    for v in VARIANTS:
        entry = syms[f"rs_tail_{v}" if rust else f"tail_{v}"]
        base = f"{sim_bin} {vbin} {entry:x} {start:x} {end:x} {lenfile}"
        _, o_inv, _ = wsl(f"timeout 20 {base} -1 {v} invalid", timeout=40)
        _, o_val, _ = wsl(f"timeout 20 {base} -1 {v} valid", timeout=40)
        dyn = int(re.search(r"^DYN (\d+)", o_inv, re.M).group(1))
        golden_ok = classify(o_inv, kr, rk) == "REJ" and classify(o_val, kr, rk) == "REAL"
        # One WSL call per variant: loop over all k inside bash, one output block per k.
        script = (f"for k in $(seq 0 {dyn - 1}); do echo \"@@ $k\"; "
                  f"timeout 5 {base} $k {v} invalid; done")
        _, out, _ = wsl(script, timeout=1800)
        counts = {"REAL": [], "MIXK": [], "REJ": [], "OTHER": [], "CRASH": []}
        real_addrs = []
        for block in out.split("@@ ")[1:]:
            k, _, body = block.partition("\n")
            c = classify(body, kr, rk)
            counts[c].append(int(k))
            if c == "REAL":
                m = re.search(r"^SKIPPED ([0-9a-f]+)", body, re.M)
                if m:
                    real_addrs.append(int(m.group(1), 16))
        # Flip model.
        flips = {}
        for t in ([] if rust else FLIP_TARGETS[v]):
            script = (f"for b in $(seq 0 31); do echo \"@@ $b\"; "
                      f"timeout 5 {fbin} {v} invalid {t}:$b; done")
            _, out, _ = wsl(script, timeout=600)
            real = [int(b.partition("\n")[0]) for b in out.split("@@ ")[1:]
                    if classify(b.partition("\n")[2], kr, rk) == "REAL"]
            other = [int(b.partition("\n")[0]) for b in out.split("@@ ")[1:]
                     if classify(b.partition("\n")[2], kr, rk) == "MIXK"]
            flips[t] = (real, other)
        print(f"   {v:9} fault-free invalid->K-bar and valid->K': {'ok' if golden_ok else 'FAIL'}; "
              f"dynamic instructions {dyn}")
        print(f"      skip: REAL(K') {len(counts['REAL'])} {counts['REAL'][:12]}  REJ {len(counts['REJ'])}  "
              f"MIXK {len(counts['MIXK'])} {counts['MIXK'][:12]}  OTHER {len(counts['OTHER'])}  "
              f"CRASH {len(counts['CRASH'])}")
        for t, (real, other) in flips.items():
            print(f"      flip {t:4} bits giving K': {real if real else 'none'}; bits giving part of K': {other if other else 'none'}")
        if counts["REAL"]:
            _, dis, _ = wsl(f"objdump -d --no-show-raw-insn -M intel -j victim_text {vbin}", timeout=60)
            lines = {int(m.group(1), 16): m.group(0).strip() for m in
                     re.finditer(r"^\s+([0-9a-f]+):\t.*$", dis, re.M)}
            funcs = sorted((int(m.group(1), 16), m.group(2)) for m in
                           re.finditer(r"^([0-9a-f]+) <(\w+)>:", dis, re.M))
            for addr in sorted(set(real_addrs)):
                fn = [n for a, n in funcs if a <= addr][-1]
                print(f"         REAL skip at {fn}: {lines.get(addr, hex(addr))}")
        results[v] = (dyn, golden_ok, counts, flips)
    return results


def main():
    opts = (sys.argv[1] if len(sys.argv) > 1 else "-O2,-Os,-O0").split(",")
    victim_src = wslpath(os.path.join(HERE, "sc_fault_victim.c"))
    sim_src = wslpath(os.path.join(HERE, "sc_fault_sim.c"))
    sim_bin = f"{WORK}/sim_{os.getpid()}"   # per run, so parallel runs do not collide
    rc, out, err = wsl(f"mkdir -p {WORK} && gcc --version | head -1 && "
                       f"gcc -O2 -o {sim_bin} '{sim_src}'", timeout=120)
    print(out.strip(), flush=True)
    if rc:
        print("simulator compile failed", err)
        return 1
    allres = {}
    for opt in opts:
        r = run_opt(opt, victim_src, sim_bin)
        if r is None:
            return 1
        allres[opt] = r
    print("\n== summary (invalid ciphertext; REAL = the real key K' came out)")
    print("   opt   variant    dyn  skip->K'  skip->partK'  skip->other  crash  flip->K'  flip->partK'")
    control = True
    for opt, res in allres.items():
        for v, (dyn, ok, counts, flips) in res.items():
            nflip = sum(len(real) for real, _ in flips.values())
            npart = sum(len(part) for _, part in flips.values())
            print(f"   {opt:5} {v:9} {dyn:5} {len(counts['REAL']):8} {len(counts['MIXK']):12} "
                  f"{len(counts['OTHER']):12} {len(counts['CRASH']):6} {nflip:8} {npart:12}")
            if not ok:
                control = False
        if not res["literal"][2]["REAL"]:
            control = False
    print("CHECK fault-free runs correct and the literal order is skip-vulnerable (negative control):",
          "PASS" if control else "FAIL")
    for opt, res in allres.items():
        dyn, ok, counts, flips = res["hardened"]
        leaks = len(counts["REAL"]) + len(counts["MIXK"]) + sum(len(a) + len(b) for a, b in flips.values())
        print(f"RESULT hardened at gcc {opt}: single faults giving all or part of K': {leaks}")
    return 0 if control else 1


if __name__ == "__main__":
    sys.exit(main())
