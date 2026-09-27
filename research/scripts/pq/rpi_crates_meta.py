"""Print crates.io metadata for Rust ML-KEM / FrodoKEM / X25519 crates (topic rust-pqc-implementations).

Reproduces the crate table in research/notes/pq/rust-pqc-implementations.md, section 2:
latest version, its publish date, licence, declared MSRV (the `rust_version` field of the
newest non-yanked version), repository, total downloads, and whether the crate matches a search.

Source: the crates.io public API (https://crates.io/api/v1/crates/NAME and
https://crates.io/api/v1/crates?q=QUERY). Raw JSON is cached in a scratch directory so a
re-run without --fetch is deterministic and offline.

Usage:
    python rpi_crates_meta.py CACHE_DIR --fetch     # download (needs network, 30 s timeout each)
    python rpi_crates_meta.py CACHE_DIR             # print from cache only
"""
import json
import os
import sys
import time
import urllib.request

CRATES = [
    "ml-kem", "libcrux-ml-kem", "libcrux-kem", "libcrux", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys",
    "pqcrypto-mlkem", "pqcrypto-kyber", "pqcrypto-traits", "pqcrypto-internals", "oqs", "oqs-sys",
    "fips203", "pqc_kyber", "kyber-rs", "safe_pqc_kyber", "x-wing", "kem",
    "x25519-dalek", "curve25519-dalek",
    "frodo-kem", "frodo-kem-rs", "pqcrypto-frodo", "frodokem", "mlkem-native", "mlkem-native-sys",
    "sha3", "keccak", "hybrid-array",
]
SEARCHES = ["frodo", "mlkem", "ml-kem", "kyber"]
UA = {"User-Agent": "turing-research-notes (offline research script; contact via repo owner)"}


def get(url, path):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    with open(path, "wb") as f:
        f.write(data)
    time.sleep(1.1)  # crates.io crawler policy: at most 1 request per second


def fetch(cache):
    os.makedirs(cache, exist_ok=True)
    for c in CRATES:
        try:
            get(f"https://crates.io/api/v1/crates/{c}", os.path.join(cache, f"crate-{c}.json"))
        except Exception as e:  # 404 = crate does not exist
            with open(os.path.join(cache, f"crate-{c}.json"), "w") as f:
                json.dump({"error": str(e)}, f)
    for q in SEARCHES:
        get(f"https://crates.io/api/v1/crates?q={q}&per_page=50", os.path.join(cache, f"search-{q}.json"))


def show(cache):
    print(f"{'crate':20s} {'newest':12s} {'published':11s} {'msrv':6s} {'license':28s} {'downloads':>11s}  repository")
    for c in CRATES:
        d = json.load(open(os.path.join(cache, f"crate-{c}.json"), encoding="utf-8"))
        if "error" in d or "crate" not in d:
            print(f"{c:20s} DOES NOT EXIST ({d.get('error', d.get('errors'))})")
            continue
        cr = d["crate"]
        vers = [v for v in d["versions"] if not v["yanked"]]
        newest = cr.get("max_stable_version") or cr["max_version"]
        vobj = next((v for v in vers if v["num"] == newest), vers[0] if vers else None)
        pub = vobj["created_at"][:10] if vobj else "?"
        msrv = (vobj or {}).get("rust_version") or "-"
        lic = (vobj or {}).get("license") or "-"
        pre = cr["max_version"] if cr["max_version"] != newest else ""
        print(f"{c:20s} {newest:12s} {pub:11s} {msrv:6s} {lic[:28]:28s} {cr['downloads']:>11,}  {cr.get('repository')}"
              + (f"  [newest incl. pre-release: {cr['max_version']}]" if pre else ""))
    print()
    for q in SEARCHES:
        d = json.load(open(os.path.join(cache, f"search-{q}.json"), encoding="utf-8"))
        names = [(x["name"], x["max_version"], x["downloads"]) for x in d["crates"]]
        print(f"search '{q}': total={d['meta']['total']}; first {len(names)} by relevance:")
        for n, v, dl in names:
            print(f"    {n:32s} {v:14s} {dl:>10,}")


if __name__ == "__main__":
    cache = sys.argv[1]
    if "--fetch" in sys.argv:
        fetch(cache)
    show(cache)
