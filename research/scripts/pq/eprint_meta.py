"""Print title, authors, publication info and history for IACR ePrint IDs.

Reproduces: the metadata block of each paper's ePrint landing page
(https://eprint.iacr.org/YYYY/NNNN), used to verify authors and venues in
research/notes/pq/side-channels-faults-and-ct-verification.md.

Usage: python eprint_meta.py 2024/1049 2020/743 ...
Network access is needed; every request has a 60 s timeout.
"""
import html
import re
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")


def fetch(eid):
    """GET with a polite delay and bounded retries (ePrint answers 429 when
    several researchers query it at once)."""
    req = urllib.request.Request(
        f"https://eprint.iacr.org/{eid}", headers={"User-Agent": "turing-research/1.0"}
    )
    for attempt in range(5):
        time.sleep(3 + 10 * attempt)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
    raise RuntimeError(f"{eid}: still rate-limited after 5 attempts")


def field(s, name):
    m = re.search(r"<dt>\s*" + re.escape(name) + r"\s*</dt>\s*<dd>(.*?)</dd>", s, re.S)
    return re.sub(r"<[^>]+>", "", html.unescape(m.group(1))).strip() if m else ""


for eid in sys.argv[1:]:
    s = fetch(eid)
    title = re.search(r'<meta name="citation_title" content="([^"]+)"', s)
    authors = re.findall(r'<meta name="citation_author" content="([^"]+)"', s)
    hist = re.findall(r"<dd>(\d{4}-\d\d-\d\d: [a-z ]+)</dd>", s)
    print(f"{eid} | {html.unescape(title.group(1)) if title else 'NA'}")
    print(f"    authors: {'; '.join(html.unescape(a) for a in authors)}")
    print(f"    publication info: {field(s, 'Publication info')}")
    print(f"    history: {', '.join(hist)}")
