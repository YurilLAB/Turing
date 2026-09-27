"""Current status of Rust crates relevant to constant-time testing, from crates.io.

Reproduces the crate table in
research/notes/pq/side-channels-faults-and-ct-verification.md (Section 5.4):
for each crate, the newest version, its publication date, whether it is
yanked, the crate's last update, total downloads, description and repository,
as reported by the crates.io API (https://crates.io/api/v1/crates/NAME).
A crate that does not exist is printed as NOT FOUND.

Usage: python sc_crates_status.py [NAME ...]
Network access is needed; 60 s timeout per request, 1.5 s pause between
requests (crates.io asks for at most one request per second).
"""
import json
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

CRATES = ["crabgrind", "valgrind_request", "ctgrind", "timecop", "dudect-bencher",
          "haybale-pitchfork", "libcrux-secrets", "secret_integers", "subtle", "cmov",
          "ctutils", "constant_time_eq", "zeroize", "ml-kem", "libcrux-ml-kem", "pqcrypto-mlkem"]


def get(name):
    req = urllib.request.Request(f"https://crates.io/api/v1/crates/{name}",
                                 headers={"User-Agent": "turing-research (research notes)"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def main():
    for name in sys.argv[1:] or CRATES:
        try:
            d = get(name)
        except urllib.error.HTTPError as e:
            print(f"{name}: NOT FOUND (HTTP {e.code})" if e.code == 404 else f"{name}: HTTP {e.code}")
            time.sleep(1.5)
            continue
        c = d["crate"]
        versions = d.get("versions", [])
        newest = next((v for v in versions if v["num"] == c.get("max_stable_version") or
                       v["num"] == c.get("newest_version")), versions[0] if versions else None)
        print(f"{name}: newest {c.get('newest_version')} (max stable {c.get('max_stable_version')}), "
              f"published {newest['created_at'][:10] if newest else '?'}"
              f"{' YANKED' if newest and newest.get('yanked') else ''}; crate updated "
              f"{c['updated_at'][:10]}; downloads {c['downloads']}")
        print(f"   {(c.get('description') or '').strip()[:200]}")
        print(f"   repo: {c.get('repository')}")
        time.sleep(1.5)


if __name__ == "__main__":
    main()
