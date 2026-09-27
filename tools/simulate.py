"""Monte Carlo check of docs/16's decryption-failure law on the GPU, or on
the CPU when there is none (tools/CI.md, "simulate").

Turing-1026 decrypts a coefficient correctly while its error
X = x_1 y_1 + ... + x_2n y_2n + z (all independent CBD(eta) samples)
stays in [-q/4, q/4). docs/16's failure rate, 2^-266 per ciphertext, is the
exact law of X computed by convolution in crates/bombe/src/dfr.rs. This
tool checks that computation three ways that share no code with it:

- dfr.rs's own numbers (`bombe dfr-tail`) against an independent FFT
  convolution here, to within the FFT's measured rounding error;
- both against X drawn billions of times with exact CBD sampling (table
  lookups of random bits, no floating point), counting how often X leaves
  [-t, t) for several thresholds t, with an exact Poisson test at a false
  alarm rate of 1e-6 per threshold;
- the same samples against wrong laws, which they must reject (n products
  instead of 2n, the bug `tools/mutate.py --round7` plants in dfr.rs, and
  noise one step narrower). A wrong law the sample is too small to reject
  (even a count five standard deviations its way would not reject it) is
  reported as underpowered, never as a pass.

Two laws are sampled: a small one (2n = 128, CBD(2)) whose thresholds reach
2^-36, and Turing-1026's own (2n = 2052, CBD(18)) down to 2^-28. docs/16's
far tail (2^-274 per coefficient) is beyond any sampling; what sampling
shows is that the exact computation is right wherever it can be checked,
including on the very law whose far tail gives 2^-266.

Every run adds its counts to a state file (research/workfiles/sim/, local),
so the evidence keeps growing and the deep thresholds fill in: `--soak`
samples until stopped or for --minutes, and every CI run adds its sample.
The accumulated counts are re-judged at every look, so over n looks the
chance of a false alarm is at most n x 1e-6 per threshold. The state is
kept per version of the sampler and per law and set of thresholds; any
change starts it afresh.

    python tools/simulate.py                   # one quick run (the CI stage)
    python tools/simulate.py --soak --minutes 60
    python tools/simulate.py --status          # judge the accumulated evidence
    python tools/simulate.py --negative-control
    python tools/simulate.py --device cpu      # PyTorch on the CPU, or NumPy

On a GPU (PyTorch with ROCm or CUDA) a run takes a fixed number of samples;
on a CPU it samples each law for --seconds. tools/ci.py runs this with
TURING_GPU_PYTHON if set, else a ROCm PyTorch environment if one is found,
else its own Python. Exit status 1 if the law is rejected, a powered
control is not, dfr.rs and the FFT disagree, or nothing could be judged.
"""
import argparse
import hashlib
import inspect
import json
import math
import os
import pathlib
import subprocess
import sys
import time

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = ROOT / "research" / "workfiles" / "sim" / "failures-state.json"
ALPHA = 1e-6

# name: (n as in dfr.rs, whose law has 2n products; eta; thresholds;
# samples per run on a GPU)
LAWS = {
    "small-law": (64, 2, [40, 48, 56, 60, 64, 68, 72, 76, 80], 1 << 28),
    "turing-1026-law": (1026, 18, [1200, 1500, 1800, 2000, 2200, 2400], 1 << 24),
}
# Wrong laws the same samples must reject: (label, n, eta).
CONTROLS = {
    "small-law": [("n products instead of 2n", 32, 2), ("CBD(1) instead of CBD(2)", 64, 1)],
    "turing-1026-law": [("n products instead of 2n", 513, 18), ("CBD(17) instead of CBD(18)", 1026, 17)],
}
# What --negative-control samples instead of each law: its CBD(eta - 1)
# control, the subtler of the two.
NEGATIVE = {"small-law": "CBD(1) instead of CBD(2)", "turing-1026-law": "CBD(17) instead of CBD(18)"}


# ---------------------------------------------------------------- exact law

def cbd_pmf(eta):
    return np.array([math.comb(2 * eta, eta + v) for v in range(-eta, eta + 1)], dtype=np.float64) / 4.0**eta


def product_pmf(eta):
    p = cbd_pmf(eta)
    out = np.zeros(2 * eta * eta + 1)
    for a in range(-eta, eta + 1):
        for b in range(-eta, eta + 1):
            out[a * b + eta * eta] += p[a + eta] * p[b + eta]
    return out


def law_fft(n, eta):
    """Raw FFT pmf of 2n products plus one sample (rounding noise included,
    negative entries kept so that it averages out), and the index of 0."""
    m = 2 * n
    prod, z = product_pmf(eta), cbd_pmf(eta)
    length = m * 2 * eta * eta + 2 * eta + 1
    size = 1 << (length - 1).bit_length()
    f = np.fft.rfft(prod, size) ** m * np.fft.rfft(z, size)
    return np.fft.irfft(f, size)[:length], m * eta * eta + eta


def law_direct(n, eta):
    prod, acc = product_pmf(eta), np.array([1.0])
    for _ in range(2 * n):
        acc = np.convolve(acc, prod)
    return np.convolve(acc, cbd_pmf(eta)), 2 * n * eta * eta + eta


def tail(pmf, zero, t):
    """P(X < -t or X >= t) and the number of entries summed."""
    left, right = pmf[:zero - t], pmf[zero + t:]
    return math.fsum(left) + math.fsum(right), len(left) + len(right)


def fft_noise(pmf, zero):
    """The FFT's rounding error per entry: the largest magnitude in the far
    tail, where the true values are astronomically small."""
    far = np.concatenate([pmf[:int(0.1 * zero)], pmf[int(1.9 * zero):]])
    return float(np.abs(far).max())


def rust_tails(n, eta, thresholds):
    """dfr.rs's own numbers, through `bombe dfr-tail`."""
    cmd = ["cargo", "run", "--quiet", "--release", "-p", "bombe", "--", "dfr-tail", str(n), str(eta), *map(str, thresholds)]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    if out.returncode != 0:
        raise SystemExit(f"bombe dfr-tail failed:\n{out.stderr[-2000:]}")
    values = dict(line.split() for line in out.stdout.split("\n") if line.strip())
    return {t: float(values[str(t)]) for t in thresholds}


def exact_tables():
    """Per law: dfr.rs's probabilities, the controls' (by FFT), and the
    checks of dfr.rs against the FFT and of the FFT against direct
    convolution."""
    checks, table = [], {}
    for name, (n, eta, thresholds, _) in LAWS.items():
        rust = rust_tails(n, eta, thresholds)
        pmf, zero = law_fft(n, eta)
        noise = fft_noise(pmf, zero)
        for t in thresholds:
            p_fft, entries = tail(pmf, zero, t)
            allowed = 1e-9 * rust[t] + entries * noise
            ok = abs(p_fft - rust[t]) <= allowed and rust[t] > 100 * entries * noise
            checks.append((ok, f"{name} t={t}: dfr.rs 2^{math.log2(rust[t]):.3f}, FFT differs by {abs(p_fft - rust[t]) / rust[t]:.1e} "
                               f"relative (allowed {allowed / rust[t]:.1e}: {entries} entries of rounding error {noise:.1e})"))
        controls = {}
        for label, cn, ceta in CONTROLS[name]:
            cpmf, czero = law_fft(cn, ceta)
            controls[label] = {t: max(tail(cpmf, czero, t)[0], 0.0) for t in thresholds}
        table[name] = (rust, controls)
    for n, eta in [(64, 2), (32, 2), (20, 3)]:
        a, _ = law_fft(n, eta)
        b, _ = law_direct(n, eta)
        diff = float(np.abs(a - b).max())
        checks.append((diff < 1e-14, f"FFT law equals direct convolution for 2n={2 * n}, CBD({eta}): largest difference {diff:.1e}"))
    return table, checks


# ---------------------------------------------------------------- sampling

def backend(device):
    if device == "numpy":
        return "numpy", None
    try:
        import torch
    except ImportError:
        if device == "gpu":
            raise SystemExit("PyTorch is not installed in this Python")
        return "numpy", None
    if device in ("auto", "gpu") and torch.cuda.is_available():
        return "gpu", torch
    if device == "gpu":
        raise SystemExit("no GPU visible to PyTorch")
    return "torch-cpu", torch


def batches(kind, torch, m, eta, samples, seed):
    """Draws X = x_1 y_1 + ... + x_m y_m + z `samples` times, in batches
    (NumPy arrays or PyTorch tensors of int32). Every value is CBD(eta),
    looked up in a table of all 2 eta-bit strings (the first eta bits count
    +1 each, the rest -1; CBD(18) as the sum of two CBD(9)s)."""
    parts = [9] * (eta // 9) + ([eta % 9] if eta % 9 else [])
    batch = max(1, min(samples, (1 << 25) // m))
    done = 0
    if kind == "numpy":
        rng = np.random.default_rng(seed)
        tables = {e: np.array([bin(i & ((1 << e) - 1)).count("1") - bin(i >> e).count("1") for i in range(1 << (2 * e))], dtype=np.int16)
                  for e in set(parts)}

        def draw(shape):
            return sum(tables[e][rng.integers(0, 1 << (2 * e), shape, dtype=np.int32)] for e in parts).astype(np.int16)

        while done < samples:
            b = min(batch, samples - done)
            yield (draw((b, m)) * draw((b, m))).sum(axis=1, dtype=np.int32) + draw((b,))
            done += b
        return
    dev = torch.device("cuda" if kind == "gpu" else "cpu")
    gen = torch.Generator(device=dev)
    gen.manual_seed(seed)
    tables = {}
    for e in set(parts):
        idx = torch.arange(1 << (2 * e), device=dev)
        lo, hi = idx & ((1 << e) - 1), idx >> e
        tables[e] = (sum((lo >> bit) & 1 for bit in range(e)) - sum((hi >> bit) & 1 for bit in range(e))).to(torch.int16)

    def tdraw(shape):
        out = None
        for e in parts:
            v = tables[e][torch.randint(0, 1 << (2 * e), shape, device=dev, generator=gen, dtype=torch.int32)]
            out = v if out is None else out + v
        return out

    while done < samples:
        b = min(batch, samples - done)
        yield (tdraw((b, m)) * tdraw((b, m))).sum(dim=1, dtype=torch.int32) + tdraw((b,)).to(torch.int32)
        done += b


def sample_counts(kind, torch, m, eta, thresholds, samples, seed):
    """How often X < -t or X >= t, for each threshold t."""
    counts = [0] * len(thresholds)
    for x in batches(kind, torch, m, eta, samples, seed):
        for i, t in enumerate(thresholds):
            counts[i] += int(((x >= t) | (x < -t)).sum())
    return counts


def histogram(kind, torch, m, eta, samples, seed):
    """Counts of every value of X, from its least possible value up."""
    top = m * eta * eta + eta
    h = np.zeros(2 * top + 1, dtype=np.int64)
    for x in batches(kind, torch, m, eta, samples, seed):
        if kind == "numpy":
            h += np.bincount(x + top, minlength=2 * top + 1)
        else:
            h += torch.bincount((x + top).long(), minlength=2 * top + 1).cpu().numpy()
    return h


def fit(h, pmf, min_expected=20):
    """Pearson's chi-square of histogram h against pmf, over bins pooled
    left to right until each expects at least `min_expected` (the leftover
    right tail joins the last bin), and its upper-tail p-value by the
    Wilson-Hilferty normal approximation. That approximation overstates
    small tail p-values a little (checked against SciPy: by at most 30% at
    1e-6 for 20 or more degrees of freedom), so it errs towards passing."""
    n = h.sum()
    expected = n * pmf
    bins_o, bins_e, acc_o, acc_e = [], [], 0, 0.0
    for o, e in zip(h, expected):
        acc_o, acc_e = acc_o + o, acc_e + e
        if acc_e >= min_expected:
            bins_o.append(acc_o)
            bins_e.append(acc_e)
            acc_o, acc_e = 0, 0.0
    bins_o[-1] += acc_o
    bins_e[-1] += acc_e
    o, e = np.array(bins_o, dtype=np.float64), np.array(bins_e)
    chi2, k = float(((o - e) ** 2 / e).sum()), len(o) - 1
    z = ((chi2 / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return chi2, k, 0.5 * math.erfc(z / math.sqrt(2))


def self_test(kind, torch, seed):
    """The sampler against exact laws small enough to test in full: the
    whole histogram of X for 4 products of CBD(18) (two table parts) and of
    CBD(2) (one part) must fit the exact law, and must not fit the law with
    CBD(eta - 1), which tests that the check can fail."""
    samples = 1 << 22 if kind == "gpu" else 1 << 20
    checks = []
    for eta in (18, 2):
        h = histogram(kind, torch, 4, eta, samples, seed + eta)
        right, _ = law_direct(2, eta)
        top = 4 * eta * eta + eta
        wrong, wtop = law_direct(2, eta - 1)
        wrong = np.pad(wrong, (top - wtop, top - wtop))
        chi2, k, p = fit(h, right)
        checks.append((p >= ALPHA, f"sampler: {samples} draws of X for 4 products of CBD({eta}) fit the exact law: chi-square {chi2:.0f} on {k} degrees of freedom, p {p:.2g}"))
        chi2, k, p = fit(h, wrong)
        checks.append((p < ALPHA, f"sampler: the same draws reject the law with CBD({eta - 1}): chi-square {chi2:.0f} on {k} degrees of freedom, p {p:.2g}"))
    return checks


def sampler_version():
    """Accumulated counts are only comparable between runs of the same
    sampler: its source code names the state."""
    return hashlib.sha256((inspect.getsource(batches) + inspect.getsource(sample_counts)).encode()).hexdigest()[:16]


# ---------------------------------------------------------------- statistics

def p_value(k, mu):
    """Two-sided p-value of count k under Poisson(mu): the probability of a
    count no more likely than k. Exact below mu = 1000, normal above."""
    if mu <= 0:
        return 1.0 if k == 0 else 0.0
    if mu >= 1000:
        z = (abs(k - mu) - 0.5) / math.sqrt(mu)
        return math.erfc(max(z, 0.0) / math.sqrt(2))

    def logpmf(j):
        return j * math.log(mu) - mu - math.lgamma(j + 1)

    ref = logpmf(k) + 1e-9
    top = int(mu + 60 * math.sqrt(mu) + 60)
    return min(1.0, math.fsum(math.exp(logpmf(j)) for j in range(top) if logpmf(j) <= ref))


def likely_range(mu, eps=3e-7):
    """(first, last): under Poisson(mu), a count below first or above last
    has probability at most eps on each side. Exact below mu = 1000; above,
    5 standard deviations (2.9e-7 per side for the normal law)."""
    if mu <= 0:
        return 0, 0
    if mu >= 1000:
        s = 5 * math.sqrt(mu)
        return math.floor(mu - s), math.ceil(mu + s)
    pmf = [math.exp(j * math.log(mu) - mu - math.lgamma(j + 1)) for j in range(int(mu + 60 * math.sqrt(mu) + 60))]
    first, below = 0, 0.0
    while below + pmf[first] <= eps:
        below += pmf[first]
        first += 1
    last, above = len(pmf) - 1, 0.0
    while above + pmf[last] <= eps:
        above += pmf[last]
        last -= 1
    return first, last


def powered(mu, cmu):
    """Whether a wrong law expecting cmu is sure to be rejected when the
    truth expects mu: every count but a 3e-7-probability tail on the side
    towards cmu would reject it. (p-values fall monotonically away from
    cmu's mode, so checking the likely count nearest cmu suffices.)"""
    first, last = likely_range(mu)
    if cmu < mu:
        return first > cmu and p_value(first, cmu) < ALPHA
    return last < cmu and p_value(last, cmu) < ALPHA


def judge(table, totals, show=True, negative=False):
    """Verdicts on (samples, counts) per law. Returns the number of
    failures and the number of thresholds judged per law.

    Every count is tested against dfr.rs's law, however few events the law
    expects: the exact test keeps its false alarm rate at any expectation,
    and a count far above a tiny one is the clearest sign of a wrong law.
    Agreement is only claimed, and a threshold counted as judged, where the
    law expects 10 or more events; below that, agreement says little. A
    control is failed only if it is powered (see `powered`) and not
    rejected. For the negative control the counts come from the law's
    CBD(eta - 1) control, and dfr.rs's law must be rejected wherever that
    is sure to happen."""
    bad, judged = 0, {}
    for name, (exact, controls) in table.items():
        if name not in totals:
            continue
        n, counts = totals[name]
        judged[name] = 0
        for (t, p), k in zip(exact.items(), counts):
            mu = n * p
            rejected = p_value(k, mu) < ALPHA
            if negative:
                truth = n * controls[NEGATIVE[name]][t]
                if rejected:
                    status = "rejected, as the negative control must be"
                    judged[name] += 1
                elif powered(truth, mu):
                    status = "NOT REJECTED"
                    bad += 1
                else:
                    status = "underpowered"
            elif rejected:
                status = "DISAGREES"
                bad += 1
                judged[name] += 1
            elif mu < 10:
                status = "accumulating"
            else:
                status = "agrees"
                judged[name] += 1
            ratio = f" (ratio {k / mu:.3f})" if mu >= 10 else ""
            line = f"  {name} t={t}: {k} of {n:.3e} beyond t; dfr.rs expects {mu:.1f} (2^{math.log2(p):.2f}){ratio}: {status}"
            if not negative:
                for label, cp in controls.items():
                    cmu = n * cp[t]
                    if p_value(k, cmu) < ALPHA:
                        verdict = "rejected"
                    elif powered(mu, cmu):
                        verdict = "NOT REJECTED"
                        bad += 1
                    else:
                        verdict = "underpowered"
                    line += f"; control '{label}' (expects {cmu:.1f}): {verdict}"
            if show:
                print(line)
    return bad, judged


# ---------------------------------------------------------------- driver

def load_state(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(path)


def fingerprint(name):
    n, eta, thresholds, _ = LAWS[name]
    return {"sampler": sampler_version(), "n": n, "eta": eta, "thresholds": thresholds}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", choices=["auto", "gpu", "cpu", "numpy"], default="auto")
    ap.add_argument("--soak", action="store_true", help="keep sampling, adding to the state file")
    ap.add_argument("--minutes", type=float, default=0, help="stop the soak after this long (0: until interrupted)")
    ap.add_argument("--scale", type=float, default=1.0, help="multiply the GPU sample sizes")
    ap.add_argument("--seconds", type=float, default=15.0, help="sampling time per law on a CPU")
    ap.add_argument("--seed", type=int, help="seed the sampler (default: fresh)")
    ap.add_argument("--status", action="store_true", help="judge the accumulated evidence only")
    ap.add_argument("--state", type=pathlib.Path, default=STATE, help=f"the state file (default {STATE.relative_to(ROOT)})")
    ap.add_argument("--no-state", action="store_true", help="neither read nor write the state file")
    ap.add_argument("--negative-control", action="store_true",
                    help="sample wrong laws (CBD(eta - 1)) and require the right laws to reject them")
    args = ap.parse_args()

    table, checks = exact_tables()
    print("dfr.rs's law, checked by an independent FFT:")
    for ok, text in checks:
        print(f"  {'PASS' if ok else 'FAIL'} {text}")
    failed = sum(not ok for ok, _ in checks)

    use_state = not (args.no_state or args.negative_control)
    state = load_state(args.state) if use_state else {}
    for name in LAWS:
        if name in state and state[name].get("fingerprint") != fingerprint(name):
            print(f"  (the state for {name} is from another sampler or law: starting it afresh)")
            del state[name]

    def accumulated():
        return {name: (state[name]["samples"], state[name]["counts"]) for name in LAWS if name in state}

    if args.status:
        print(f"Accumulated evidence ({args.state}):")
        bad, judged = judge(table, accumulated())
        return 1 if failed + bad or not all(judged.get(name) for name in LAWS) else 0

    kind, torch = backend(args.device)
    device_name = torch.cuda.get_device_name(0) if kind == "gpu" else {"numpy": "the CPU (NumPy)", "torch-cpu": "the CPU (PyTorch)"}[kind]
    seed = args.seed if args.seed is not None else int.from_bytes(os.urandom(7), "little")
    print(f"The sampler on {device_name}, seed {seed}:")
    for ok, text in self_test(kind, torch, seed):
        print(f"  {'PASS' if ok else 'FAIL'} {text}")
        failed += not ok
    what = " the wrong laws of the negative control" if args.negative_control else ""
    print(f"Sampling{what}:")
    deadline = time.time() + args.minutes * 60 if args.soak and args.minutes else None
    this_run, rounds = {}, 0
    while True:
        for index, (name, (n, eta, thresholds, gpu_samples)) in enumerate(LAWS.items()):
            sample_eta = eta - 1 if args.negative_control else eta
            round_seed = (seed + 1_000_003 * rounds + 7919 * index) % (1 << 63)
            t0 = time.time()
            if kind == "gpu":
                samples = int(gpu_samples * args.scale)
                counts = sample_counts(kind, torch, 2 * n, sample_eta, thresholds, samples, round_seed)
            else:
                # On a CPU: batches until the time budget is spent.
                samples, counts, chunk, part = 0, [0] * len(thresholds), 1 << 16, 0
                while samples == 0 or time.time() - t0 < args.seconds:
                    c = sample_counts(kind, torch, 2 * n, sample_eta, thresholds, chunk, round_seed + 104729 * part)
                    counts = [a + b for a, b in zip(counts, c)]
                    samples += chunk
                    part += 1
            dt = time.time() - t0
            n0, c0 = this_run.get(name, (0, [0] * len(thresholds)))
            this_run[name] = (n0 + samples, [a + b for a, b in zip(c0, counts)])
            if use_state:
                entry = state.setdefault(name, {"fingerprint": fingerprint(name), "samples": 0, "counts": [0] * len(thresholds), "runs": 0, "devices": {}})
                entry["samples"] += samples
                entry["counts"] = [a + b for a, b in zip(entry["counts"], counts)]
                entry["runs"] += 1
                entry["devices"][device_name] = entry["devices"].get(device_name, 0) + samples
                save_state(state, args.state)
            print(f"  {name}: {samples:.3e} samples in {dt:.1f} s ({samples / max(dt, 1e-9) / 1e6:.2f} M/s)", flush=True)
        rounds += 1
        if not args.soak or (deadline and time.time() > deadline):
            break
        if rounds % 5 == 0 and use_state:
            print("Accumulated so far:")
            bad, _ = judge(table, accumulated())
            if bad:
                print("the accumulated evidence contradicts dfr.rs's law: stopping")
                return 1
    print("This run:")
    bad, judged = judge(table, this_run, negative=args.negative_control)
    failed += bad
    for name in LAWS:
        if not judged.get(name):
            print(f"  nothing about {name} could be judged in this run: sample more (--scale, --seconds)")
            failed += 1
    if use_state:
        print(f"All runs so far ({args.state}):")
        failed += judge(table, accumulated())[0]
    print("RESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
