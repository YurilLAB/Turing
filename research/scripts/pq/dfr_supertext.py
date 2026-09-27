"""dfr_supertext.py - print PDF page text with superscripts and subscripts marked.

Research helper for the decryption-failures notes. Plain text extraction flattens exponents
("2^139" becomes "2139"). This prints each text line of the given pages, writing a span as
"^{...}" when it is smaller than the line's main font and raised above its baseline, and as
"_{...}" when smaller and lowered. It only reformats what pymupdf reads; it reproduces nothing.

Usage: python dfr_supertext.py FILE.pdf FIRST_PAGE [LAST_PAGE]   (1-based PDF pages)
"""
import sys

import pymupdf

sys.stdout.reconfigure(encoding="utf-8")
path, first = sys.argv[1], int(sys.argv[2])
last = int(sys.argv[3]) if len(sys.argv) > 3 else first
doc = pymupdf.open(path)
for pno in range(first, min(last, doc.page_count) + 1):
    print(f"\n======== PDF page {pno} ========")
    page = doc[pno - 1]
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            spans = [s for s in line["spans"] if s["text"].strip() or s["text"] == " "]
            if not spans:
                continue
            main = max(spans, key=lambda s: (s["size"], len(s["text"])))
            base_y, main_size = main["origin"][1], main["size"]
            out = []
            for s in spans:
                t = s["text"]
                if s["size"] < 0.85 * main_size and t.strip():
                    dy = s["origin"][1] - base_y
                    if dy < -0.15 * main_size:
                        t = "^{" + t.strip() + "}"
                    elif dy > 0.1 * main_size:
                        t = "_{" + t.strip() + "}"
                out.append(t)
            print("".join(out))
