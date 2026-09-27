"""lis_findpage.py - print the 1-based PDF page(s) on which each phrase occurs.

Used to pin page citations in
research/notes/pq/lattices-inside-symmetric-primitives.md to the exact PDF
page of the primary source (the printed page numbers of papers differ from
PDF page numbers). Matching ignores whitespace and case, so phrases broken
across lines still match. Uses pymupdf.

Usage: python lis_findpage.py FILE.pdf "phrase one" "phrase two" ...
Prints: phrase -> [pages]  (empty list = not found; not found is also
reported, so a wrong citation is visible).
"""
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")


def norm(s):
    return re.sub(r"\s+", "", s).lower()


path, *phrases = sys.argv[1:]
doc = fitz.open(path)
pages = [norm(doc[i].get_text()) for i in range(doc.page_count)]
print(f"[{path}: {doc.page_count} pages]")
for ph in phrases:
    key = norm(ph)
    hits = [i + 1 for i, t in enumerate(pages) if key in t]
    print(f"  {ph!r} -> {hits}")
