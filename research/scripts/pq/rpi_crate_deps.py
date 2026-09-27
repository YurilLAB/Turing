"""Print the declared dependencies of specific published crate versions (topic rust-pqc-implementations).

Source: crates.io API https://crates.io/api/v1/crates/NAME/VERSION/dependencies (cached as JSON so a
re-run without --fetch is offline and deterministic). Used in research/notes/pq/rust-pqc-implementations.md
to check which sha3/keccak/rand versions an oracle crate would pull into Turing's dev-dependency graph
(Turing itself pins sha3 0.10 and keccak 0.1.6 in crates/turing/Cargo.toml).

Usage: python rpi_crate_deps.py CACHE_DIR [--fetch] NAME@VERSION [NAME@VERSION ...]
"""
import json
import os
import sys
import time
import urllib.request

UA = {"User-Agent": "turing-research-notes (offline research script)"}


def main():
    cache = sys.argv[1]
    fetch = "--fetch" in sys.argv
    specs = [a for a in sys.argv[2:] if "@" in a]
    os.makedirs(cache, exist_ok=True)
    for spec in specs:
        name, ver = spec.split("@")
        path = os.path.join(cache, f"deps-{name}-{ver}.json")
        if fetch:
            req = urllib.request.Request(f"https://crates.io/api/v1/crates/{name}/{ver}/dependencies", headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                open(path, "wb").write(r.read())
            time.sleep(1.1)
        d = json.load(open(path, encoding="utf-8"))
        print(f"== {name} {ver}")
        for dep in sorted(d["dependencies"], key=lambda x: (x["kind"], x["crate_id"])):
            opt = " optional" if dep["optional"] else ""
            print(f"   {dep['kind']:7s} {dep['crate_id']:22s} {dep['req']:14s}{opt}"
                  + (f" target={dep['target']}" if dep.get("target") else ""))


if __name__ == "__main__":
    main()
