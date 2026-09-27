"""Repository facts for research/notes/pq/turing-integration-constraints.md.

Topic: turing-integration-constraints (prefix tic_). Reads the committed
tree at HEAD with read-only `git show HEAD:<path>` / `git ls-tree` (never the
working tree, which someone else may be editing) and prints every count the
notes cite, with the file and line it comes from:

  1. every cSHAKE label literal starting "Turing v" in tracked files;
  2. the number of mutations in each set of tools/mutate.py;
  3. the packages resolved in Cargo.lock;
  4. every item gated on the `analysis` feature in crates/turing/src;
  5. the Zeroable impls and BURN_BYTES in memory.rs;
  6. the public functions of the turing crate's modules;
  7. Bombe's subcommands and modules;
  8. text counts of "unsafe", "unsafe {" and "SAFETY" per turing source file.

Deterministic: output depends only on the commit. Exits 1 if HEAD cannot be
read.

Usage (from the repository root):
    timeout 120 python research/scripts/pq/tic_repo_facts.py
"""
import ast
import pathlib
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
ROOT = pathlib.Path(__file__).resolve().parents[3]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", timeout=60, check=True).stdout


def show(path):
    return git("show", f"HEAD:{path}")


def main():
    head = git("rev-parse", "--short", "HEAD").strip()
    print(f"HEAD = {head}")
    files = git("ls-tree", "-r", "--name-only", "HEAD").split()

    print("\n== 1. cSHAKE label literals \"Turing v...\" in tracked code ==")
    label_re = re.compile(r'"(Turing v\d[^"]*)"')
    seen = {}
    for f in files:
        if not f.endswith((".rs", ".py")) or f.startswith("research/"):
            continue
        for n, line in enumerate(show(f).splitlines(), 1):
            for lab in label_re.findall(line):
                seen.setdefault(lab, []).append(f"{f}:{n}")
    for lab in sorted(seen):
        print(f"  {lab!r:40} {', '.join(seen[lab][:4])}")
    print(f"  distinct labels: {len(seen)}")

    print("\n== 2. mutation sets in tools/mutate.py ==")
    tree = ast.parse(show("tools/mutate.py"))
    total = 0
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
            name = node.targets[0].id
            if name.startswith("MUTATIONS"):
                count = len(node.value.elts)
                total += count
                print(f"  {name:18} {count:3} mutations (line {node.lineno})")
    print(f"  total planted bugs: {total}")

    print("\n== 3. Cargo.lock packages ==")
    lock = show("Cargo.lock")
    pkgs = re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock)
    for name, ver in pkgs:
        print(f"  {name} {ver}")
    print(f"  packages: {len(pkgs)}")

    print("\n== 4. items gated on the analysis feature (crates/turing/src) ==")
    for f in files:
        if not (f.startswith("crates/turing/src/") and f.endswith(".rs")):
            continue
        lines = show(f).splitlines()
        for n, line in enumerate(lines, 1):
            if 'feature = "analysis"' in line:
                nxt = next((l.strip() for l in lines[n:n + 4] if l.strip() and not l.strip().startswith(("#", "//"))), "")
                print(f"  {f}:{n}: {line.strip()}  ->  {nxt[:90]}")

    print("\n== 5. memory.rs: Zeroable impls and the stack burn ==")
    for n, line in enumerate(show("crates/turing/src/memory.rs").splitlines(), 1):
        if "impl" in line and "Zeroable for" in line or "BURN_BYTES: usize" in line or "align_of::<T>() <=" in line:
            print(f"  memory.rs:{n}: {line.strip()}")
    for f in files:
        if f.startswith("crates/turing/src/") and f.endswith(".rs") and f != "crates/turing/src/memory.rs":
            for n, line in enumerate(show(f).splitlines(), 1):
                if "Zeroable for" in line:
                    print(f"  {f}:{n}: {line.strip()}")

    print("\n== 6. public functions of the turing crate ==")
    for f in files:
        if not (f.startswith("crates/turing/src/") and f.endswith(".rs")):
            continue
        pubs = [(n, l.strip()) for n, l in enumerate(show(f).splitlines(), 1)
                if re.match(r"\s*pub (unsafe )?(fn|const fn|struct|enum|const|type|trait)\b", l)]
        print(f"  {f}: {len(pubs)} public items")
        for n, l in pubs:
            print(f"    {n:4}: {l[:110]}")

    print("\n== 7. Bombe subcommands and modules ==")
    for n, line in enumerate(show("crates/bombe/src/main.rs").splitlines(), 1):
        m = re.search(r'Some\("([a-z-]+)"\) =>', line)
        if m:
            print(f"  main.rs:{n}: bombe {m.group(1)}")
    mods = re.findall(r"^pub mod (\w+);", show("crates/bombe/src/lib.rs"), re.M)
    print(f"  modules ({len(mods)}): {', '.join(mods)}")
    tests = [f for f in files if f.startswith("crates/bombe/tests/") and f.endswith(".rs")]
    print(f"  integration test files ({len(tests)}): {', '.join(pathlib.Path(t).stem for t in tests)}")

    print("\n== 8. unsafe in the turing crate (text counts, comments included) ==")
    totals = [0, 0, 0]
    for f in files:
        if not (f.startswith("crates/turing/src/") and f.endswith(".rs")):
            continue
        text = show(f)
        counts = (text.count("unsafe"), text.count("unsafe {"), text.count("SAFETY"))
        if counts[0]:
            print(f"  {f}: 'unsafe' {counts[0]:3}, 'unsafe {{' {counts[1]:3}, 'SAFETY' {counts[2]:3}")
        totals = [t + c for t, c in zip(totals, counts)]
    print(f"  total: 'unsafe' {totals[0]}, 'unsafe {{' {totals[1]}, 'SAFETY' {totals[2]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as e:
        print(f"git failed: {e}", file=sys.stderr)
        sys.exit(1)
