"""Runs the GPU simulation and the CPU noise measurement side by side for a
while, both adding to their accumulated evidence (tools/CI.md, "soak"):
the GPU draws billions of samples of docs/16's decryption-error law, down
into tails a quick run cannot reach, while every CPU thread encrypts with
the real Turing-1026 code and measures its error against the same law.

    python tools/soak.py --minutes 60
    python tools/simulate.py --status          # the GPU's evidence so far

Logs go to target/soak/<time>/. Both processes save their evidence as they
go, so stopping early (Ctrl+C) keeps what was measured. Exit status 1 if
either check fails.
"""
import argparse
import datetime
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from ci import NOISE_STATE, ROOT, SIM_STATE, gpu_python  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--minutes", type=float, default=60.0, help="how long each check samples (default 60)")
    args = ap.parse_args()
    if args.minutes <= 0:
        ap.error("--minutes must be positive")
    out = ROOT / "target" / "soak" / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    # Build first, so the noise measurement's clock starts with measuring.
    build = subprocess.run(["cargo", "build", "--release", "-p", "bombe"], cwd=ROOT, capture_output=True, text=True, timeout=3600)
    if build.returncode != 0:
        print(build.stderr[-3000:])
        return 1
    minutes = str(args.minutes)
    jobs = {
        "gpu-simulate": [gpu_python(), "tools/simulate.py", "--soak", "--minutes", minutes, "--state", SIM_STATE],
        "cpu-noise": ["cargo", "run", "--release", "-p", "bombe", "--", "noise", "--keys", "2000", "--minutes", minutes, "--state", NOISE_STATE],
    }
    print(f"Soaking for {args.minutes:g} minutes; logs in {out}")
    running = {}
    for name, cmd in jobs.items():
        log = open(out / f"{name}.log", "w", encoding="utf-8", errors="replace")
        running[name] = (subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT), log)
        print(f"  started {name}: {' '.join(cmd)}")
    deadline = time.time() + args.minutes * 60 + 1800
    failed = 0
    try:
        for name, (proc, log) in running.items():
            try:
                code = proc.wait(timeout=max(1.0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                proc.kill()
                code = "timeout"
            log.close()
            lines = (out / f"{name}.log").read_text(encoding="utf-8", errors="replace").splitlines()
            result = next((line for line in reversed(lines) if line.startswith("RESULT")), "no result line")
            print(f"  {name}: exit {code}, {result}")
            failed += code != 0
    except KeyboardInterrupt:
        for proc, _ in running.values():
            proc.terminate()
        print("interrupted; the evidence measured so far is saved")
        return 1
    print("SOAK:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
