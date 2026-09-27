"""Fact-checker helper: find a phrase in a PDF and print the physical PDF page (1-based).

Usage: python check_decryption-failures_pgrep.py FILE.pdf CONTEXT REGEX [REGEX ...]
Case-insensitive; whitespace in the page text is collapsed before matching.
"""
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")
path, ctx = sys.argv[1], int(sys.argv[2])
pats = [re.compile(p, re.I) for p in sys.argv[3:]]
doc = fitz.open(path)
for pat in pats:
    print(f"=== /{pat.pattern}/")
    n = 0
    for i in range(doc.page_count):
        t = re.sub(r"\s+", " ", doc[i].get_text())
        for m in pat.finditer(t):
            n += 1
            if n > 8:
                break
            print(f"  [PDF p.{i+1}] ...{t[max(0, m.start()-ctx):m.end()+ctx]}...")
    if n == 0:
        print("  (no hit)")
