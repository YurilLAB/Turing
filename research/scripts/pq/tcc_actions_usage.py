"""Estimate what is visible of YurilLAB's GitHub Actions usage, read-only.

What it reproduces, and from which source: the GitHub REST API
(docs.github.com/rest/actions/workflow-runs), called through the `gh` CLI
with the token already on this machine. It only issues GET requests:
  GET /users/YurilLAB/repos                        (via gh repo list)
  GET /repos/{owner}/{repo}/actions/runs?created=YYYY-MM-DD..YYYY-MM-DD
  GET /repos/{owner}/{repo}/actions/runs/{id}/timing   (billable field)

For each repository it counts workflow runs created in the given month and
sums wall-clock run time (run_started_at to updated_at) per repository. The
/timing endpoint's "billable" block is printed when present. Wall-clock run
time is NOT the billed amount: billing is per job, rounded up to the minute
per job, and multiplied by the runner's rate (docs.github.com billing pages,
cited in research/notes/pq/testing-ci-cd.md). The script says so in its output.

Usage:
    python research/scripts/pq/tcc_actions_usage.py 2026-09 [--timing]

Every gh call has a 60 s timeout; the script is deterministic for a fixed
API state.
"""
import datetime as dt
import json
import subprocess
import sys


def gh(args):
    r = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return None, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "error"
    return r.stdout, None


def parse(ts):
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def main():
    month = sys.argv[1]
    want_timing = "--timing" in sys.argv
    y, m = map(int, month.split("-"))
    start = dt.date(y, m, 1)
    end = (dt.date(y + (m == 12), m % 12 + 1, 1) - dt.timedelta(days=1))
    out, err = gh(["repo", "list", "YurilLAB", "--limit", "100", "--json", "name,visibility"])
    if out is None:
        print("[INFO] repo list failed:", err)
        return
    repos = sorted(json.loads(out), key=lambda r: r["name"])
    total_runs = 0
    total_minutes = 0.0
    for r in repos:
        q = f"repos/YurilLAB/{r['name']}/actions/runs?per_page=100&created={start}..{end}"
        out, err = gh(["api", q])
        if out is None:
            print(f"[INFO] {r['name']}: {err}")
            continue
        j = json.loads(out)
        runs = j.get("workflow_runs", [])
        if not runs:
            continue
        mins = 0.0
        for run in runs:
            if run.get("run_started_at") and run.get("updated_at"):
                mins += (parse(run["updated_at"]) - parse(run["run_started_at"])).total_seconds() / 60
        total_runs += len(runs)
        total_minutes += mins
        print(f"[INFO] {r['visibility']:8s} {r['name']}: {j.get('total_count')} runs in {month}, "
              f"wall-clock {mins:.1f} min (first page of up to 100 runs)")
        if want_timing:
            for run in runs[:5]:
                t, err = gh(["api", f"repos/YurilLAB/{r['name']}/actions/runs/{run['id']}/timing"])
                print(f"        run {run['id']} timing: {t.strip() if t else err}")
    print(f"[INFO] total: {total_runs} runs, {total_minutes:.1f} wall-clock minutes in {month}. "
          "Wall-clock is not billed minutes (per-job rounding and OS rates apply).")


if __name__ == "__main__":
    main()
