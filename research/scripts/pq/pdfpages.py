"""Print the text of selected pages of a PDF, with page markers (pymupdf).

Research helper: the Read tool cannot render PDFs on this machine (no
poppler), so pages are read as text. Page numbers are 1-based PDF pages,
not the printed page numbers.

Usage: python pdfpages.py FILE.pdf FIRST [LAST]
"""
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")
path = sys.argv[1]
first = int(sys.argv[2])
last = int(sys.argv[3]) if len(sys.argv) > 3 else first
doc = fitz.open(path)
print(f"[{path}: {doc.page_count} pages]")
for p in range(first, min(last, doc.page_count) + 1):
    print(f"\n======== PDF page {p} ========")
    print(doc[p - 1].get_text())
