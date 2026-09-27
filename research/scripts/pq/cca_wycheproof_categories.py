"""Tabulate the C2SP Wycheproof ML-KEM test vectors by result, flags and
comment, and print the file-level "notes" that explain each flag.

Reproduces: the category breakdown behind Section 9 of
research/notes/pq/cca-transforms-and-binding.md (which invalid ML-KEM inputs
Wycheproof exercises, and why). Source: github.com/C2SP/wycheproof,
testvectors_v1/mlkem_*.json and schemas/mlkem_*_schema.json (main branch,
fetched 2026-09-27 into the scratch directory).

Usage: python cca_wycheproof_categories.py DIR   (DIR holds mlkem_*.json)
Deterministic: reads local files only.
"""
import collections
import glob
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
d = sys.argv[1]
for path in sorted(glob.glob(os.path.join(d, "mlkem_*.json"))):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    name = os.path.basename(path)
    print(f"=== {name}: numberOfTests = {data.get('numberOfTests')}, schema = {data.get('schema')}")
    notes = data.get("notes") or {}
    cats = collections.Counter()
    for g in data["testGroups"]:
        for t in g["tests"]:
            cats[(t["result"], ",".join(t.get("flags", [])) or "-", t.get("comment", "")[:60])] += 1
    for (res, flags, comment), n in sorted(cats.items()):
        print(f"  {n:4d}  {res:8s} flags={flags:30s} comment={comment!r}")
    used = {fl for (_, fls, _) in cats for fl in fls.split(",") if fl != "-"}
    for fl in sorted(used):
        note = notes.get(fl, {})
        desc = note.get("description", "") if isinstance(note, dict) else str(note)
        print(f"  note[{fl}] ({note.get('bugType', '') if isinstance(note, dict) else ''}): {desc[:300]}")
