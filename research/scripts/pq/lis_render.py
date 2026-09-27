"""lis_render.py - render PDF pages to PNG so they can be read as images.

Some older PDFs (for example the 1993 Maurer-Massey scan-typeset file) use
fonts whose text layer extracts as garbage; rendering the page and reading
the image is then the only faithful way to check a quotation. Used for
research/notes/pq/lattices-inside-symmetric-primitives.md.

Usage: python lis_render.py FILE.pdf OUTDIR FIRST LAST [DPI]
Writes OUTDIR/<stem>-p<N>.png for each 1-based page N and prints the paths.
"""
import os
import sys

import pymupdf as fitz

path, outdir, first, last = sys.argv[1:5]
dpi = int(sys.argv[5]) if len(sys.argv) > 5 else 110
os.makedirs(outdir, exist_ok=True)
doc = fitz.open(path)
stem = os.path.splitext(os.path.basename(path))[0]
for p in range(int(first), min(int(last), doc.page_count) + 1):
    pix = doc[p - 1].get_pixmap(dpi=dpi)
    out = os.path.join(outdir, f"{stem}-p{p}.png")
    pix.save(out)
    print(out)
