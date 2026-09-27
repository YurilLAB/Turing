"""Print the 1-based PDF page numbers (and a short context) where each keyword occurs.

Helper for topic rust-pqc-implementations: used to cite page numbers for quotes taken from
papers in research/papers/. Case-insensitive; whitespace in the page text is collapsed first,
so a phrase broken across lines is still found.

Usage: python rpi_pdffind.py FILE.pdf CONTEXT_CHARS KEYWORD [KEYWORD ...]
"""
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")


def main():
    path, ctx = sys.argv[1], int(sys.argv[2])
    doc = fitz.open(path)
    pages = [re.sub(r"\s+", " ", doc[i].get_text()) for i in range(doc.page_count)]
    for kw in sys.argv[3:]:
        hits = 0
        for i, t in enumerate(pages):
            for m in re.finditer(re.escape(kw), t, re.I):
                hits += 1
                a, b = max(0, m.start() - ctx), min(len(t), m.end() + ctx)
                print(f"[{kw!r}] p.{i + 1}: ...{t[a:b]}...")
        if hits == 0:
            print(f"[{kw!r}] no hits")


if __name__ == "__main__":
    main()
