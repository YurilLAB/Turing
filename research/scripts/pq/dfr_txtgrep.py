"""dfr_txtgrep.py - search the page-marked text dumps of papers and print hits with their PDF page.

Research helper for the decryption-failures notes. The text dumps were made with pymupdf and
contain one marker line per page, either '=====PAGE n=====' or '=== PDF PAGE n ==='. Page
numbers are physical (1-based) PDF pages, not printed page numbers.

Usage: python dfr_txtgrep.py FILE.txt CONTEXT_CHARS REGEX [REGEX ...]
Prints every match of any REGEX (case-insensitive) with CONTEXT_CHARS characters around it.
"""
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
path, ctx = sys.argv[1], int(sys.argv[2])
pats = [re.compile(p, re.I) for p in sys.argv[3:]]
text = open(path, encoding="utf-8", errors="replace").read()
marks = [(m.start(), int(m.group(1) or m.group(2)))
         for m in re.finditer(r"=====PAGE (\d+)=====|=== PDF PAGE (\d+) ===", text)]


def page_of(pos: int) -> int:
    pg = 0
    for start, n in marks:
        if start <= pos:
            pg = n
        else:
            break
    return pg


for pat in pats:
    for m in pat.finditer(text):
        a, b = max(0, m.start() - ctx // 2), min(len(text), m.end() + ctx // 2)
        snippet = text[a:b].replace("\n", " ")
        print(f"--- [{pat.pattern}] PDF page {page_of(m.start())}: ...{snippet}...")
