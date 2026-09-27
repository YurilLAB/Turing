"""acs_abstracts.py - print the first N characters of page 1 (title + abstract) of PDFs.

Research helper for the attack-cost-estimation notes: lets the author read
and cite the abstract claims of several papers in one bounded call. Uses
pymupdf; whitespace is collapsed. Deterministic.

Usage: python acs_abstracts.py NCHARS FILE.pdf [FILE.pdf ...]
"""
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")
nchars = int(sys.argv[1])
for path in sys.argv[2:]:
    doc = fitz.open(path)
    text = re.sub(r"\s+", " ", doc[0].get_text() + " " + (doc[1].get_text() if doc.page_count > 1 else ""))
    print(f"=== {path} ({doc.page_count} pages)")
    print(text[:nchars])
    print()
