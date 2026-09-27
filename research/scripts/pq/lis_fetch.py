"""Download primary-source PDFs for the lattices-inside-symmetric-primitives notes.

Same contract as fetch_papers.py (skip existing, download to a unique .tmp,
check the %PDF- magic, then rename), but with a shorter per-request limit
(--max-time 90, 2 attempts) so one unresponsive host cannot stall the batch.

Usage: python lis_fetch.py LISTFILE
LISTFILE has one "name url" pair per line; lines starting with # are skipped.
Prints one status line per entry: exists / ok / FAIL.
"""
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
PAPERS = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "papers")
)

for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name, url = line.split()
    dst = os.path.join(PAPERS, name)
    if os.path.exists(dst):
        print(f"exists  {name}", flush=True)
        continue
    tmp = dst + f".{os.getpid()}.tmp"
    ok = False
    for attempt in range(2):
        time.sleep(3 + 10 * attempt)
        rc = subprocess.call(
            ["curl", "-sL", "--fail", "--max-time", "90", "-A", "Mozilla/5.0 turing-research/1.0", "-o", tmp, url]
        )
        if rc == 0 and os.path.exists(tmp):
            with open(tmp, "rb") as f:
                head = f.read(5)
            if head == b"%PDF-":
                ok = True
                break
    if ok:
        os.replace(tmp, dst)
        print(f"ok      {name}  ({os.path.getsize(dst)} bytes)", flush=True)
    else:
        if os.path.exists(tmp):
            os.remove(tmp)
        print(f"FAIL    {name}  {url}", flush=True)
