"""Show text spans with font size and height near a keyword, to read exponents.

Text extraction flattens superscripts: "2^13" comes out as "213". This prints
each span on the matching line(s) with its font size and baseline, so a
smaller, raised span can be read as an exponent.

Usage: python pdfspans.py FILE.pdf PAGE KEYWORD
PAGE is 1-based.
"""
import sys

import fitz  # pymupdf

sys.stdout.reconfigure(encoding="utf-8")
path, page, kw = sys.argv[1], int(sys.argv[2]), sys.argv[3]
doc = fitz.open(path)
p = doc[page - 1]
for block in p.get_text("dict")["blocks"]:
    for line in block.get("lines", []):
        text = "".join(s["text"] for s in line["spans"])
        if kw in text:
            print(" | ".join(f"{s['text']!r} size={s['size']:.1f} y={s['origin'][1]:.1f}"
                             for s in line["spans"]))
