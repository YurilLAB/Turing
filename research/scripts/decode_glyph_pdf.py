"""Decode PDFs whose text extracts as glyph names such as /C1/D1/D4 (old
TeX Type-3 fonts, e.g. the IACR FSE 2003 archive).

Each name is two base-36 digits; value - 360 is the character code in TeX's
OT1 encoding (checked against the known title: C1 -> 'I', D1 -> 'm',
BU -> 'B', AB -> the 'ff' ligature). Mathematical fonts come out garbled, so
formulas must still be read from the page itself.

Usage: python decode_glyph_pdf.py FILE.pdf [KEYWORD ...]
Prints the decoded text, or windows around each keyword.
"""
import re
import sys

import pypdf

LIGATURES = {11: "ff", 12: "fi", 13: "fl", 14: "ffi", 15: "ffl"}


def decode_token(tok: str) -> str:
    try:
        code = int(tok, 36) - 360
    except ValueError:
        return "?"
    if code in LIGATURES:
        return LIGATURES[code]
    if 32 <= code < 127:
        return chr(code)
    return "?"


def decode(text: str) -> str:
    out = []
    for word in text.split():
        toks = re.findall(r"/([0-9A-Z]{2})", word)
        out.append("".join(decode_token(t) for t in toks) if toks else word)
    return " ".join(out)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    path, *keywords = sys.argv[1:]
    reader = pypdf.PdfReader(path)
    text = decode(" ".join((p.extract_text() or "") for p in reader.pages))
    if not keywords:
        print(text)
        return
    for kw in keywords:
        hits = [m.start() for m in re.finditer(re.escape(kw), text)]
        print(f"=== {kw!r}: {len(hits)} hit(s)")
        for start in hits[:4]:
            print("...", text[max(0, start - 200): start + 900], "...\n---")


if __name__ == "__main__":
    main()
