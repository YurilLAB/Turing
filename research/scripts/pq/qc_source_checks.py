"""Mechanical source checks for research/notes/pq/quantum-crypto-and-quantum-attacks.md.

Reproduces, by reading the saved primary-source PDFs in research/papers/ with
pymupdf, claims of the form "document X does (not) contain phrase Y":

  1. NIST SP 800-90B (January 2018): the word "quantum" does not occur, so the
     entropy-source standard has no quantum-specific class; physical and
     non-physical noise sources are defined in Sec. 2.2.1.
  2. NIST SP 800-90C (September 2025): "quantum" occurs only in the note on
     the classical security-strength definition.
  3. NIST PQC calls (2016 Sec. 4.A.2/4.A.4, 2022 Sec. 4.B.2): NIST is
     "primarily concerned with attacks that use classical (rather than
     quantum) queries" (the Q1 model).
  4. NIST IR 8547 ipd Sec. 4.1.3: the Category 1 sentence for symmetric
     primitives.
  5. Kaplan et al. ToSC 2016 Sec. 8: the k >= 2n sentence.

Each check prints the page number(s) and the matched text, and a PASS/FAIL
line. A negative control searches 90B for a phrase that is known to occur
("min-entropy") so that an empty extraction cannot pass check 1 by accident.

Run:  python research/scripts/pq/qc_source_checks.py
"""
import pathlib
import re
import sys

import fitz  # pymupdf

sys.stdout.reconfigure(encoding="utf-8")
PAPERS = pathlib.Path(__file__).resolve().parents[2] / "papers"


def pages(name):
    doc = fitz.open(PAPERS / name)
    return [re.sub(r"\s+", " ", doc[i].get_text()) for i in range(doc.page_count)]


def find(name, pattern, flags=re.I):
    hits = []
    for i, text in enumerate(pages(name), start=1):
        for m in re.finditer(pattern, text, flags):
            lo, hi = max(0, m.start() - 90), min(len(text), m.end() + 90)
            hits.append((i, text[lo:hi]))
    return hits


def report(label, hits, expect):
    ok = expect(hits)
    print(f"\n--- {label}: {len(hits)} hit(s) -> {'PASS' if ok else 'FAIL'}")
    for page, ctx in hits[:6]:
        print(f"    p.{page}: ...{ctx}...")
    return ok


results = []
b90 = "nist-sp800-90b-entropy-sources.pdf"
results.append(report("control: 'min-entropy' occurs in SP 800-90B", find(b90, r"min-entropy"), lambda h: len(h) > 20))
results.append(report("SP 800-90B contains no 'quantum'", find(b90, r"quantum"), lambda h: len(h) == 0))
results.append(report("SP 800-90B defines physical / non-physical noise sources",
                      find(b90, r"Physical noise sources use dedicated hardware"), lambda h: len(h) == 1))
c90 = "nist-sp800-90c-rbg-constructions.pdf"
results.append(report("SP 800-90C: every 'quantum' occurrence", find(c90, r"quantum"), lambda h: 1 <= len(h) <= 3))
results.append(report("SP 800-90C dated September 2025", find(c90, r"September 2025"), lambda h: len(h) >= 1))
for call in ("nist-pqc-call-for-proposals-2016.pdf", "nist-pqc-call-additional-signatures-2022.pdf"):
    results.append(report(f"{call}: classical (rather than quantum) queries",
                          find(call, r"classical \(rather than quantum\) queries"), lambda h: len(h) >= 1))
results.append(report("NIST IR 8547 ipd: symmetric primitives and Category 1",
                      find("nist-ir-8547-pqc-transition.pdf", r"at least 128 bits of classical security"),
                      lambda h: len(h) == 1))
results.append(report("Kaplan et al. ToSC 2016: k >= 2n sentence",
                      find("2016-kaplan-et-al-quantum-differential-linear-cryptanalysis.pdf",
                           r"with k ?≥ ?2n, the data complexity is always smaller"), lambda h: len(h) == 1))
print(f"\n{sum(results)} of {len(results)} checks passed")
