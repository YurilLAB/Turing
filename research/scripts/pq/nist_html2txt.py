"""Convert saved HTML pages (NIST CSRC, NCSC, ANSSI, BSI, ISO) to plain text.

Reproduces nothing numeric: it is a reading aid for the status pages saved in
the working dir (research/workfiles/pq/nist/*.html). It strips <script>/<style>,
turns block tags into newlines, removes tags, unescapes entities and collapses
blank lines. Optional keywords print only the lines that contain one of them
(case-insensitive), with N lines of context.

Usage:
    timeout 60 python research/scripts/pq/nist_html2txt.py PAGE.html [--ctx N] [KEYWORD ...]
"""
import html
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")


def to_text(raw):
    raw = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?i)</?(p|div|li|tr|h[1-6]|table|ul|ol|section|article|dd|dt)[^>]*>", "\n", raw)
    raw = re.sub(r"(?i)</t[dh]>", " | ", raw)
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = html.unescape(raw)
    lines = [re.sub(r"[ \t ]+", " ", ln).strip() for ln in raw.splitlines()]
    return [ln for ln in lines if ln and ln != "|"]


def main():
    args = sys.argv[1:]
    ctx = 1
    if "--ctx" in args:
        i = args.index("--ctx")
        ctx = int(args[i + 1])
        del args[i:i + 2]
    path, keys = args[0], [k.lower() for k in args[1:]]
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = to_text(fh.read())
    if not keys:
        print("\n".join(lines))
        return
    keep = set()
    for i, ln in enumerate(lines):
        if any(k in ln.lower() for k in keys):
            keep.update(range(max(0, i - ctx), min(len(lines), i + ctx + 1)))
    last = -2
    for i in sorted(keep):
        if i != last + 1:
            print("--")
        print(lines[i])
        last = i


if __name__ == "__main__":
    main()
