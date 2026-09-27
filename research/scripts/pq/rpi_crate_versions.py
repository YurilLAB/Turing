"""Print the version history (number, date, yanked, MSRV, licence) of selected crates from the cache
written by rpi_crates_meta.py (topic rust-pqc-implementations).

Source: crates.io API JSON (https://crates.io/api/v1/crates/NAME), cached offline.
Used to date when each crate moved from Kyber / FIPS 203 draft to the final FIPS 203 (2024-08-13),
together with the crates' own changelogs (cited in the notes, not parsed here).

Usage: python rpi_crate_versions.py CACHE_DIR CRATE [CRATE ...]
"""
import json
import os
import sys


def main():
    cache = sys.argv[1]
    for c in sys.argv[2:]:
        d = json.load(open(os.path.join(cache, f"crate-{c}.json"), encoding="utf-8"))
        if "versions" not in d:
            print(c, "missing")
            continue
        print(f"== {c}  ({len(d['versions'])} versions)")
        for v in sorted(d["versions"], key=lambda v: v["created_at"]):
            print(f"   {v['num']:24s} {v['created_at'][:10]}  yanked={str(v['yanked']):5s} msrv={v.get('rust_version') or '-':7s} "
                  f"lic={v.get('license')}  crate_size={v.get('crate_size')}")


if __name__ == "__main__":
    main()
