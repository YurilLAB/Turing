"""Turing's local CI runner: one command runs every automated check, each
stage under a timeout, and writes a report (tools/CI.md explains each stage,
what it catches and the evidence that it does).

    python tools/ci.py                         # quick profile, the working tree
    python tools/ci.py --profile full          # + negative controls, campaign, Linux in WSL
    python tools/ci.py --profile deep          # + the deep campaign, every planted-bug set
    python tools/ci.py --commit HEAD           # test a commit in a clean worktree instead
    python tools/ci.py --only math-audit,robustness
    python tools/ci.py --list

Reports go to target/ci/<time>/: one log per stage, summary.md and
summary.json. The exit code is 1 if any stage failed or timed out.

--commit runs everything in a throwaway git worktree of that commit, so the
result belongs to a known snapshot and is unaffected by files other people
are editing at the same time. Stages that rewrite source files
(the planted-bug sets of tools/mutate.py) always run in such a worktree,
never in the working tree, because they rewrite files while they run.
"""
import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
PROFILES = ["quick", "full", "deep"]
ITERS = {"quick": "1", "full": "5", "deep": "25"}
MUTATION_SETS = ["", "--step8", "--step9", "--round3", "--round4", "--round5", "--round6", "--round7", "--review1", "--mlkem"]


def stages(profile):
    """(name, first profile it runs in, command, timeout in s, needs a worktree, description)."""
    t_rel, t_ovf = ["CARGO_TARGET_DIR", "target/ci-release"], ["CARGO_TARGET_DIR", "target/ci-overflow"]
    out = [
        ("release", "quick", [t_rel], ["cargo", "test", "--release", "--workspace"], 3600, False,
         "the whole test suite, optimised (as the docs run it)"),
        ("overflow", "quick", [t_ovf], ["cargo", "test", "--workspace"], 3600, False,
         "the whole suite with overflow checks and debug assertions, which --release turns off"),
        ("robustness", "quick", [t_rel, ["TURING_CI_ITERS", ITERS[profile]]],
         ["cargo", "test", "--release", "-p", "bombe", "--test", "robustness"], 1800, False,
         "rare, boundary and out-of-range inputs against the independent references"),
        ("math-audit", "quick", [], [PY, "tools/mathaudit.py"], 1200, False,
         "documented numbers recomputed independently; checks that cannot fail"),
        ("constant-time", "quick", [["CARGO_TARGET_DIR", "target/ci-release"]], [PY, "tools/ct_check.py"], 900, False,
         "the release build's assembly divides no secret in the lattice code (KyberSlash class)"),
        ("math-audit-negative", "full", [], [PY, "tools/mathaudit.py", "--negative-control"], 1200, False,
         "every math-audit comparison must flag a planted wrong value"),
        # `mutate.py --check` alone checks only the default set; every set is
        # checked here (on 2026-09-27, 21 bugs in six sets had gone stale).
        ("mutation-patterns", "full", [],
         [PY, "-c", "import subprocess, sys; sys.exit(max(subprocess.call([sys.executable, 'tools/mutate.py', *s, '--check'])"
          f" for s in {[[f] if f else [] for f in MUTATION_SETS]!r}))"], 600, False,
         "every planted bug of every set still matches the code it is meant to change"),
        ("campaign", "full", [t_rel], ["cargo", "run", "--release", "-p", "bombe", "--", "attack"], 5400, False,
         "the Bombe attack campaign (exit 1 on any failed finding)"),
        ("linux-wsl", "full", [], [PY, "tools/wsl_linux.py", "test", "--release", "-p", "turing", "--lib"], 3600, False,
         "the library's Linux code paths (mlock, madvise, fork), built for Linux and run in WSL"),
        ("campaign-deep", "deep", [t_rel], ["cargo", "run", "--release", "-p", "bombe", "--", "attack", "--deep"], 14400, False,
         "the deep campaign (2^32-text structures, NIST at scale)"),
    ]
    for flag in MUTATION_SETS:
        label = flag.lstrip("-") or "default"
        out.append((f"mutation-{label}", "deep", [["CARGO_TARGET_DIR", str(ROOT / "target" / "ci-mutate")]],
                    [PY, "tools/mutate.py", *([flag] if flag else [])], 14400, True,
                    f"planted-bug set {label}: every planted bug must make a test fail"))
    return out


def kill_tree(p):
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
    else:
        p.kill()


def run_stage(cmd, env_pairs, timeout, cwd, log_path):
    env = dict(os.environ)
    for k, v in env_pairs:
        env[k] = v if os.path.isabs(v) or k != "CARGO_TARGET_DIR" else str(ROOT / v)
    start = time.time()
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        log.write(f"$ {' '.join(cmd)}\n  (cwd {cwd}, env {dict(env_pairs)})\n\n")
        log.flush()
        try:
            p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        except FileNotFoundError as e:
            # A missing tool is a failure, not a skip: a quietly skipped
            # stage is exactly the kind of gap this runner exists to show.
            return "FAIL", time.time() - start, f"cannot start {cmd[0]}: {e}"
        try:
            code = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(p)
            return "TIMEOUT", time.time() - start, f"killed after {timeout} s"
    return ("PASS" if code == 0 else "FAIL"), time.time() - start, f"exit {code}"


def tail(path, n=12):
    lines = pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n:])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=PROFILES, default="quick")
    ap.add_argument("--only", help="comma-separated stage names (any profile)")
    ap.add_argument("--commit", help="run in a clean worktree of this commit")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    level = PROFILES.index(args.profile)
    all_stages = stages(args.profile)
    if args.list:
        for name, first, _, cmd, timeout, wt, desc in all_stages:
            print(f"{name:22s} {first:6s} {timeout // 60:4d} min{'  worktree' if wt else ''}  {desc}")
        return 0
    if args.only:
        wanted = set(args.only.split(","))
        unknown = wanted - {s[0] for s in all_stages}
        if unknown:
            ap.error(f"unknown stage(s): {', '.join(sorted(unknown))}")
        chosen = [s for s in all_stages if s[0] in wanted]
    else:
        chosen = [s for s in all_stages if PROFILES.index(s[1]) <= level]

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = ROOT / "target" / "ci" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "rev-parse", args.commit or "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    subject = f"commit {commit[:12]}" if args.commit else f"working tree at {commit[:12]}{' with uncommitted changes' if dirty else ''}"
    what = f"stages {args.only}" if args.only else f"profile {args.profile}"
    print(f"Turing CI, {what}: {subject}\nreports: {out_dir}\n")

    worktrees = []

    def worktree(tag):
        path = ROOT / "target" / f"ci-wt-{stamp}-{tag}"
        subprocess.run(["git", "worktree", "add", "--detach", str(path), commit], cwd=ROOT, check=True, capture_output=True)
        worktrees.append(path)
        return path

    shared = worktree("main") if args.commit else ROOT
    results = []
    try:
        for name, _, env_pairs, cmd, timeout, needs_wt, desc in chosen:
            if name == "linux-wsl" and shutil.which("wsl.exe") is None and os.name == "nt":
                results.append((name, "SKIP", 0.0, "wsl.exe not found", desc))
                print(f"  SKIP     {name}: wsl.exe not found")
                continue
            cwd = worktree(name) if needs_wt else shared
            print(f"  ...      {name}: {desc}", flush=True)
            status, secs, note = run_stage(cmd, env_pairs, timeout, cwd, out_dir / f"{name}.log")
            results.append((name, status, secs, note, desc))
            print(f"  {status:8s} {name} ({secs:.0f} s, {note})", flush=True)
            if status in ("FAIL", "TIMEOUT"):
                print("           " + tail(out_dir / f"{name}.log").replace("\n", "\n           "))
    finally:
        for path in worktrees:
            subprocess.run(["git", "worktree", "remove", "--force", str(path)], cwd=ROOT, capture_output=True)

    bad = [r for r in results if r[1] in ("FAIL", "TIMEOUT")]
    summary = {"profile": args.profile, "subject": subject, "commit": commit, "dirty": dirty and not args.commit,
               "stages": [{"name": n, "status": s, "seconds": round(t, 1), "note": note, "what": d} for n, s, t, note, d in results]}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md = [f"# Turing CI, profile {args.profile}", "", f"{subject}, {stamp}", "", "| Stage | Result | Time | Note | What it checks |", "|---|---|---|---|---|"]
    md += [f"| {n} | {s} | {t:.0f} s | {note} | {d} |" for n, s, t, note, d in results]
    (out_dir / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\n{len(results) - len(bad)} of {len(results)} stages passed or were skipped; report in {out_dir}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
