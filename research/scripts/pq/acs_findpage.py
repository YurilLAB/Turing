"""acs_findpage.py - print the 1-based PDF page numbers on which each keyword occurs.

Research helper for the attack-cost-estimation notes: turns a pdfgrep hit into
a page citation. Whitespace in the page text is collapsed before matching, so
a keyword split across a line break still matches. Uses pymupdf.

Usage: python acs_findpage.py FILE.pdf KEYWORD [KEYWORD ...]
Deterministic; prints "keyword: [pages]" per keyword.
"""
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")
path, *keywords = sys.argv[1:]
doc = fitz.open(path)
texts = [re.sub(r"\s+", " ", doc[i].get_text()) for i in range(doc.page_count)]
print(f"[{path}: {doc.page_count} pages]")
for kw in keywords:
    pages = [i + 1 for i, t in enumerate(texts) if kw in t]
    print(f"{kw!r}: {pages}")
