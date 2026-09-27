"""Monthly GitHub Actions minutes and cost for candidate Turing CI layouts.

What it reproduces, and from which source:
  * Included minutes (GitHub Free: 2,000 per month for private repositories)
    and per-minute rates (Linux 2-core $0.006, Windows 2-core $0.010, Linux
    arm64 2-core $0.005), with each job's time rounded up to a whole minute:
    docs.github.com/en/billing/concepts/product-billing/github-actions and
    docs.github.com/en/billing/reference/actions-runner-pricing, fetched
    2026-09-27 (see research/notes/pq/testing-ci-cd.md, claims 22 and 24).
  * The local measurement that anchors the job-length ASSUMPTIONS below:
    research/scripts/pq/tcc_time_suite.sh on commit 2071a07 took 22.4 s to
    build all release test targets and 38.5 s to run 193 tests on a 12-thread
    desktop.

Job lengths on a 2-core hosted runner are NOT measured: they are assumptions
(listed in JOBS) and must be replaced by real numbers from the first hosted
runs. The quota is applied in Linux-minute value (dollars), which is the
conservative reading of the current docs (open question 29 in the notes).

Usage:  python research/scripts/pq/tcc_ci_cost.py
Deterministic; prints one table per layout.
"""
import math

RATE = {"linux": 0.006, "windows": 0.010, "linux-arm": 0.005}
FREE_MINUTES = 2000
FREE_VALUE = FREE_MINUTES * RATE["linux"]  # conservative: quota valued at Linux rate

# ASSUMED billed minutes per job on standard private-repo runners (2 CPU, 8 GB).
JOBS = {
    "fmt+clippy+test (linux)": ("linux", 5),
    "test (windows)": ("windows", 8),
    "test (linux arm64)": ("linux-arm", 6),
    "deny+audit (linux)": ("linux", 2),
    "zizmor (linux)": ("linux", 1),
    "miri subset (linux)": ("linux", 20),
    "sanitizers asan+msan (linux)": ("linux", 20),
    "fuzz 3 targets x 10 min (linux)": ("linux", 32),
    "cross s390x+i686 via qemu (linux)": ("linux", 15),
    "cargo-mutants in-diff (linux)": ("linux", 15),
    "release build+sbom (linux)": ("linux", 8),
    "release build (windows)": ("windows", 12),
}

LAYOUTS = {
    "A: per-push Linux only; everything deep runs locally in WSL": {
        "per_push": ["fmt+clippy+test (linux)", "deny+audit (linux)", "zizmor (linux)"],
        "nightly": [],
        "per_release": ["release build+sbom (linux)", "release build (windows)"],
    },
    "B: per-push Linux + Windows; deep tier local": {
        "per_push": ["fmt+clippy+test (linux)", "test (windows)", "deny+audit (linux)", "zizmor (linux)"],
        "nightly": [],
        "per_release": ["release build+sbom (linux)", "release build (windows)"],
    },
    "C: B plus a hosted nightly deep tier": {
        "per_push": ["fmt+clippy+test (linux)", "test (windows)", "deny+audit (linux)", "zizmor (linux)"],
        "nightly": ["miri subset (linux)", "sanitizers asan+msan (linux)", "fuzz 3 targets x 10 min (linux)",
                    "cross s390x+i686 via qemu (linux)", "cargo-mutants in-diff (linux)", "test (linux arm64)"],
        "per_release": ["release build+sbom (linux)", "release build (windows)"],
    },
}


def month(layout, pushes, nights=30, releases=1):
    mins = {k: 0 for k in RATE}
    for key, count in (("per_push", pushes), ("nightly", nights), ("per_release", releases)):
        for job in layout[key]:
            os_, m = JOBS[job]
            mins[os_] += math.ceil(m) * count
    value = sum(mins[k] * RATE[k] for k in RATE)
    over = max(0.0, value - FREE_VALUE)
    return mins, value, over


def main():
    print(f"quota: {FREE_MINUTES} min/month valued at Linux rate = ${FREE_VALUE:.2f}")
    for name, layout in LAYOUTS.items():
        print(f"\n{name}")
        print("  pushes/month | linux min | windows min | arm min | value $ | over quota $ | fits Free?")
        for pushes in (30, 100, 300):
            mins, value, over = month(layout, pushes)
            print(f"  {pushes:12d} | {mins['linux']:9d} | {mins['windows']:11d} | {mins['linux-arm']:7d} |"
                  f" {value:7.2f} | {over:12.2f} | {'yes' if over == 0 else 'no'}")


if __name__ == "__main__":
    main()
