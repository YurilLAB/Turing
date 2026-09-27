"""Download primary-source PDFs into research/papers/ (gitignored), safely.

For each NAME URL pair: skip if research/papers/NAME exists; otherwise
curl to NAME.tmp (another researcher may fetch the same file), check that it
starts with %PDF-, then rename. Polite delay between requests because the
IACR ePrint server answers 429 under concurrent load.

Usage: python fetch_papers.py LISTFILE
LISTFILE has one "name url" pair per line; lines starting with # are skipped.
"""
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
PAPERS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "papers")
PAPERS = os.path.normpath(PAPERS)

for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name, url = line.split()
    dst = os.path.join(PAPERS, name)
    if os.path.exists(dst):
        print(f"exists  {name}")
        continue
    tmp = dst + f".{os.getpid()}.tmp"
    ok = False
    for attempt in range(4):
        time.sleep(4 + 15 * attempt)
        rc = subprocess.call(
            ["curl", "-sL", "--fail", "--max-time", "180", "-A", "turing-research/1.0", "-o", tmp, url]
        )
        if rc == 0 and os.path.exists(tmp):
            with open(tmp, "rb") as f:
                head = f.read(5)
            if head == b"%PDF-":
                ok = True
                break
            print(f"  {name}: not a PDF (starts {head!r}), retrying")
        else:
            print(f"  {name}: curl rc={rc}, retrying")
    if ok:
        if os.path.exists(dst):
            os.remove(tmp)
            print(f"raced   {name}")
        else:
            os.replace(tmp, dst)
            print(f"got     {name} ({os.path.getsize(dst)} bytes)")
    else:
        if os.path.exists(tmp):
            os.remove(tmp)
        print(f"FAILED  {name} {url}")
