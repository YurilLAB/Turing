"""Print text windows around keywords in a PDF (research helper).

Usage: python pdfgrep.py FILE.pdf WINDOW KEYWORD [KEYWORD ...]
"""
import re
import sys

import pypdf

sys.stdout.reconfigure(encoding="utf-8")
path, window, *keywords = sys.argv[1:]
window = int(window)
reader = pypdf.PdfReader(path)
text = " ".join((page.extract_text() or "") for page in reader.pages)
text = re.sub(r"\s+", " ", text)
for kw in keywords:
    hits = [m.start() for m in re.finditer(re.escape(kw), text)]
    print(f"=== {kw!r}: {len(hits)} hit(s)")
    for start in hits[:3]:
        print("...", text[max(0, start - window // 3): start + window], "...")
        print("---")
