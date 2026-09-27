"""Extract a PDF's text page by page (research helper for the pq notes).

Usage: python pdf2txt.py FILE.pdf OUT.txt

Each page is written as "==== page N ====" followed by its text, so a
claim can be cited by page. Uses pymupdf (fitz), which keeps the reading
order of two-column papers better than pypdf.
"""
# (pymupdf is the current import name of the fitz package.)
import sys

import pymupdf

src, out = sys.argv[1], sys.argv[2]
doc = pymupdf.open(src)
with open(out, "w", encoding="utf-8") as fh:
    for i, page in enumerate(doc, start=1):
        fh.write(f"\n==== page {i} ====\n")
        fh.write(page.get_text())
print(f"{src}: {len(doc)} pages -> {out}")
