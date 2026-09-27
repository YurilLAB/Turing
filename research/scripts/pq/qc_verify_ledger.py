"""Mechanical re-check of the claim ledger in
research/notes/pq/quantum-crypto-and-quantum-attacks.md.

For every externally sourced VERIFIED row (L1-L68 from the first pass; L73-L89
and the Kuwakado-Morii original for L42 from the second pass, 2026-09-27),
this script searches the saved primary source for the phrase or number that
the row quotes, and prints
the PDF page (1-based page index of the file, which can differ from the
printed page number) with a short context. A row passes when every one of its
patterns is found. It does not judge meaning; it proves that the quoted words
and numbers are really in the file cited, so a reader can jump to the page.

Sources:
  * PDFs in research/papers/ (read with pymupdf, whitespace collapsed,
    ligatures and soft hyphens removed, and a second copy with end-of-line
    hyphenation joined, because "Even-\\nMansour" and "pro-\\nvided" occur);
  * saved copies of web pages (NSA, NCSC, ANSSI, BSI) as text files in the
    directory given by QC_SCRATCH (default: research/workfiles/pq/qc, the
    local copy kept from this research). Rows that need them are skipped with a
    message if the directory is missing.

Negative controls: made-up sentences that must NOT be found (a matcher that
returned hits for everything would fail them), and one sentence known to
occur must be found.

Run:  python research/scripts/pq/qc_verify_ledger.py
"""
import os
import pathlib
import re
import sys

import pymupdf

sys.stdout.reconfigure(encoding="utf-8")
PAPERS = pathlib.Path(__file__).resolve().parents[2] / "papers"
SCRATCH = pathlib.Path(os.environ.get(
    "QC_SCRATCH",
    str(pathlib.Path(__file__).resolve().parents[2] / "workfiles" / "pq" / "qc")))

_cache = {}


def norm(text):
    text = text.replace("\u00ad", "").replace("\ufb01", "fi").replace("\ufb02", "fl")
    text = text.replace("\ufb00", "ff").replace("\ufb03", "ffi").replace("\ufb04", "ffl")
    text = text.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2013", "-").replace("\u2014", "-").replace("\u2212", "-")
    return text


def pages(name):
    """List of (page_label, text, dehyphenated_text)."""
    if name in _cache:
        return _cache[name]
    if name.endswith(".pdf"):
        doc = pymupdf.open(PAPERS / name)
        raw = [norm(doc[i].get_text()) for i in range(doc.page_count)]
        labels = [str(i + 1) for i in range(doc.page_count)]
    else:
        path = SCRATCH / name
        if not path.exists():
            _cache[name] = None
            return None
        raw = [norm(path.read_text(encoding="utf-8", errors="replace"))]
        labels = ["web"]
    out = []
    for lab, t in zip(labels, raw):
        joined = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", t)
        out.append((lab, re.sub(r"\s+", " ", t), re.sub(r"\s+", " ", joined)))
    _cache[name] = out
    return out


def find(name, pattern):
    pg = pages(name)
    if pg is None:
        return None
    hits = []
    rx = re.compile(pattern, re.I)
    for lab, t, j in pg:
        m = rx.search(t) or rx.search(j)
        if m:
            src = t if rx.search(t) else j
            lo, hi = max(0, m.start() - 60), min(len(src), m.end() + 60)
            hits.append((lab, src[lo:hi]))
    return hits


# (row, file, [patterns]) - every pattern must be found somewhere in the file.
PDF = {
    "zalka": "1999-zalka-grover-search-optimal.pdf",
    "grover": "1996-grover-fast-quantum-database-search.pdf",
    "c16": "nist-pqc-call-for-proposals-2016.pdf",
    "c22": "nist-pqc-call-additional-signatures-2022.pdf",
    "jaq": "2020-jaques-et-al-grover-oracles-aes-lowmc.pdf",
    "ir8547": "nist-ir-8547-pqc-transition.pdf",
    "bb84": "1984-bennett-brassard-bb84-quantum-cryptography.pdf",
    "pir": "2020-pirandola-et-al-advances-in-quantum-cryptography.pdf",
    "joint": "2024-anssi-bsi-nlncsa-sma-position-paper-qkd.pdf",
    "liu": "2023-liu-et-al-twin-field-qkd-1000-km.pdf",
    "lyd": "2010-lydersen-et-al-hacking-commercial-qkd-bright-illumination.pdf",
    "hc": "2017-herrero-collantes-garcia-escartin-quantum-random-number-generators.pdf",
    "kdl": "2016-kaplan-et-al-quantum-differential-linear-cryptanalysis.pdf",
    "klln": "2016-kaplan-et-al-breaking-symmetric-quantum-period-finding.pdf",
    "off": "2019-bonnetain-et-al-offline-simon-quantum-attacks.pdf",
    "bss": "2022-bonnetain-schrottenloher-sibleyras-beyond-quadratic-speedups.pdf",
    "aesq": "2019-bonnetain-naya-plasencia-schrottenloher-quantum-security-aes.pdf",
    "rs": "2015-rotteler-steinwandt-quantum-related-key-attacks.pdf",
    "anand": "2016-anand-et-al-post-quantum-security-modes-of-operation.pdf",
    "bz": "2013-boneh-zhandry-quantum-secure-macs.pdf",
    "sy": "2017-song-yun-quantum-security-nmac.pdf",
    "bb": "2017-banegas-bernstein-low-communication-parallel-quantum-multi-target-preimage-search.pdf",
    "bt": "2016-bellare-tackmann-multi-user-security-aes-gcm-tls13.pdf",
    "slide": "2019-bonnetain-naya-plasencia-schrottenloher-quantum-slide-attacks.pdf",
    # second pass (2026-09-27)
    "abkm": "2021-alagic-bai-katz-majenz-post-quantum-security-even-mansour.pdf",
    "jst": "2021-jaeger-song-tessaro-quantum-key-length-extension.pdf",
    "lm": "2017-leander-may-grover-meets-simon-fx.pdf",
    "bem": "2024-bai-esmaili-mantri-key-alternating-ciphers-quantum-lower-bounds.pdf",
    "degre": "2026-degre-et-al-improved-quantum-attacks-iterated-even-mansour.pdf",
    "sat": "2019-canteaut-et-al-saturnin-spec-round2.pdf",
    "qcb": "2020-bhaumik-et-al-qcb-quantum-secure-authenticated-encryption.pdf",
    "hos": "2025-hosoyamada-post-quantum-keyed-sponge-kmac-ascon.pdf",
    "acmt": "2025-alagic-carolan-majenz-tokat-sponge-quantum-indifferentiable.pdf",
    "gcm": "2026-hosoyamada-post-quantum-multi-key-security-gcm.pdf",
    "si": "2026-shiba-iwata-multi-key-quantum-tem-fx.pdf",
    "ais31": "2024-bsi-ais-31-functionality-classes-rng-v3.pdf",
    "km10": "2010-kuwakado-morii-quantum-distinguisher-3-round-feistel.pdf",
}

CHECKS = [
    ("L1", "zalka", [r"Grover.{0,80}optimal", r"4.{0,6}N"]),
    # Grover's formulas are images in this file (no text layer), so only the words around them can be matched;
    # the number (pi/4) sqrt(N) is checked in Zalka above.
    ("L1", "grover", [r"can be obtained in only", r"within a small constant factor of the fastest possible"]),
    ("L2", "zalka", [r"parallel"]),
    ("L5", "c16", [r"presently envisioned quantum computing architectures", r"current classical computing architectures",
                   r"atomic scale qubits with speed of light propagation times"]),
    ("L5", "c22", [r"presently envisioned quantum computing architectures", r"atomic scale qubits"]),
    ("L6", "jaq", [r"MAXDEPTH|D\s*max"]),
    ("L8", "c16", [r"key search on a block cipher with a 128-bit key", r"key search on a block cipher with a 256-bit key",
                   r"collision search on a 256-bit hash", r"all metrics that NIST deems to be potentially relevant"]),
    ("L9", "c16", [r"2\s*\^?\s*170\s*/\s*MAXDEPTH", r"2\s*\^?\s*233\s*/\s*MAXDEPTH", r"2\s*\^?\s*298\s*/\s*MAXDEPTH",
                   r"2\s*\^?\s*143", r"2\s*\^?\s*207", r"2\s*\^?\s*272", r"Grassl"]),
    ("L10", "c22", [r"2\s*\^?\s*157\s*/\s*MAXDEPTH", r"2\s*\^?\s*221\s*/\s*MAXDEPTH", r"2\s*\^?\s*285\s*/\s*MAXDEPTH",
                    r"Jaques"]),
    ("L11", "jaq", [r"246\.9", r"224\.4", r"192\.4", r"2\s*\^?\s*288\s*/\s*MAXDEPTH|288"]),
    ("L12", "c16", [r"may understate the quantum security of AES"]),
    ("L12", "c22", [r"may understate the quantum security of AES"]),
    ("L13", "ir8547", [r"at least 128 bits of classical security", r"does not expect to need to transition away"]),
    ("L14", "c16", [r"classical \(rather than quantum\) queries to the decryption oracle"]),
    ("L15", "jaq", [r"spurious"]),
    ("L19", "bb84", [r"expected bit", r"1/4|one fourth|one-fourth|quarter"]),
    ("L21", "bb84", [r"Wegman", r"relaxed"]),
    ("L22", "pir", [r"CHSH", r"Ekert"]),
    ("L24", "joint", [r"can never apply to actual implementations", r"niche use cases",
                      r"not yet sufficiently mature from a security perspective", r"few hundred kilomet",
                      r"one-time pad", r"trusted nodes"]),
    ("L27", "pir", [r"PLOB", r"0\.2 ?dB/km"]),
    ("L29", "liu", [r"1002 ?km", r"0\.0034", r"952", r"0\.157"]),
    ("L30", "lyd", [r"remote.?control", r"tracelessly", r"Clavis2", r"QPN ?5505"]),
    ("L31", "lyd", [r"lower than 1/2|much lower than"]),
    ("L33", "joint", [r"Swedish Armed Forces", r"Swedish National Communications Security Authority"]),
    ("L34", "hc", [r"most mature quantum technologies", r"device.independent"]),
    ("L38", "kdl", [r"standard security", r"quantum security", r"seems difficult"]),
    ("L39", "kdl", [r"rather extreme and perhaps even unrealistic", r"more realistic"]),
    ("L40", "klln", [r"completely broken", r"CLOC", r"Minalpher", r"obfuscat"]),
    ("L42", "klln", [r"Kuwakado", r"ISIT"]),
    ("L43", "klln", [r"Even-?Mansour"]),
    ("L42", "km10", [r"first application of Simon.s algorithm to cryptographic analysis",
                     r"define a function W as the first n bits of V", r"independent random permutations",
                     r"ISIT 2010, Austin, Texas"]),
    ("L45", "klln", [r"first known exponential quantum speed.?up of a classical attack"]),
    ("L46", "klln", [r"OFB and CTR remain secure"]),
    ("L49", "off", [r"offline Simon", r"n/3"]),
    ("L50", "off", [r"Problem 3"]),
    ("L51", "off", [r"\(m ?\+ ?n\) ?/ ?3"]),
    ("L52", "bss", [r"2\.5 quantum speedup", r"cannot be used to generically strengthen block ciphers"]),
    ("L53", "kdl", [r"3/2"]),
    ("L55", "kdl", [r"2\s*h\s*S?\s*/\s*2\s*\+\s*1\.?\s*\(4\)"]),
    ("L56", "kdl", [r"with k ?.? ?2n, the data complexity is always smaller"]),
    ("L58", "aesq", [r"bigger security margin", r"8.round|eight rounds"]),
    ("L59", "rs", [r"unlikely to pose a practical threat"]),
    ("L61", "aesq", [r"too powerful"]),
    ("L62", "anand", [r"OFB", r"CTR", r"XTS"]),
    ("L63", "bz", [r"four-wise|4-wise", r"pairwise"]),
    ("L64", "sy", [r"NMAC", r"AMAC", r"HMAC"]),
    ("L65", "bb", [r"need to be revised"]),
    ("L67", "bt", [r"randomi[sz]"]),
    ("L68", "slide", [r"key schedule", r"four rounds|4 rounds"]),
    # second pass (2026-09-27)
    ("L73", "abkm", [r"explicit interface granting such access", r"implement f using a classical computer",
                     r"we will refer to it simply as the post-quantum setting"]),
    ("L74", "abkm", [r"any attack in that setting requires", r"two-key and single-key variants"]),
    ("L75", "jst", [r"arguably more realistic and less controversial than Q2", r"non-adaptive security of a blockcipher suffices",
                    r"\(k ?` ?n ?q ?\{ ?3|\(k ?\+ ?n\) ?/ ?3|2pk`nq\{3"]),
    ("L76", "lm", [r"does not increase the security in the quantum-CPA setting significantly",
                   r"essentially the same time complexity as Grover"]),
    ("L77", "jst", [r"list disjointness", r"highly successful attacker must make", r"restricting to the weaker partially-quantum model would not improve the bound"]),
    ("L78", "bem", [r"exponential Q1-Q2 gap collapses", r"independent permutations and independent round keys",
                    r"non-adaptive"]),
    ("L79", "degre", [r"two keys \(the key-schedule alternates between two inde", r"4 to 6 rounds",
                      r"classical known-plaintext queries"]),
    ("L80", "sat", [r"depending only on the block size", r"does not provide security against related-key superposition attacks",
                    r"easily emulated using a classical one", r"quantum birthday bound", r"quantum random-access memory",
                    r"no quantum attack in the single-key setting", r"our quantum security claims are all in this model"]),
    ("L82", "bb", [r"no known quantum collision-finding algorithms were faster than the non-quantum parallel rho"]),
    ("L83", "qcb", [r"prove its security against quantum superposition queries", r"Block ciphers of 256 bits seem more convenient",
                    r"Key-tweak Insertion", r"Proposition 1", r"related-key secure", r"LRW mode is not a quantum-secure TBC even if we allow only classical"]),
    ("L84", "hos", [r"KMAC", r"Assume that κ > r", r"quantum ideal permutation model", r"160-bit security"]),
    ("L85", "acmt", [r"indifferentiable from a random oracle against quantum adversaries", r"loose O\(poly\(q\)",
                     r"Theorem 1\.2"]),
    ("L86", "gcm", [r"maximum number of keys under which the same nonce appears", r"randomized nonce-generation",
                    r"first non-trivial post-quantum multi-key security bound", r"not tight"]),
    ("L87", "si", [r"regardless of the number of target", r"Q1MK", r"independent keys are in use"]),
    ("L89", "ais31", [r"does not distinguish between quan-? ?tum entropy and entropy from physical phenomena",
                      r"considers quantum RNGs as PTRNGs", r"most physical noise sources exploit effects from quantum mechanics",
                      r"DRG\.2, DRG\.3, DRG\.4, DRT\.1, PTG\.2, PTG\.3, and NTG\.1", r"September 10, 2024",
                      r"successful attack shall still be infeasible", r"will likely become insecure"]),
]

WEB = [
    ("L25", "ncsc-qnt.txt", [r"nor do any other quantum techniques",
                             r"will not support the use of QKD for government or military applications",
                             r"PQC is the best mitigation", r"5 August 2025",
                             r"keen that research on QRNGs continues to progress"]),
    ("L26", "nsa-qkd.txt", [r"does not recommend the usage of quantum key distribution",
                            r"cannot be implemented in software", r"implementation-dependent",
                            r"more cost effective and easily maintained"]),
    ("L32", "ncsc-qst.txt", [r"does not endorse the use of QKD", r"do not provide any new mitigation",
                             r"continue to meet our needs", r"24 March 2020"]),
    ("L33", "anssi-qkd.txt", [r"25 January 2024|January 25, 2024|25/01/2024"]),
    ("L33", "bsi-qkd.txt", [r"26\.01\.2024"]),
]

NEGATIVE = [
    ("neg", "joint", r"QKD is recommended for all government use"),
    ("neg", "c16", r"primarily concerned with attacks that use quantum \(rather than classical\) queries"),
    ("neg", "klln", r"Turing"),
]


def run(checks, table):
    passed = total = 0
    for row, key, pats in checks:
        name = table[key] if table else key
        all_ok = True
        lines = []
        for p in pats:
            hits = find(name, p)
            if hits is None:
                lines.append(f"      SKIP (file not found: {name})")
                all_ok = None
                break
            if not hits:
                all_ok = False
                lines.append(f"      MISSING /{p}/")
            else:
                pgs = ",".join(h[0] for h in hits[:8]) + ("..." if len(hits) > 8 else "")
                lines.append(f"      /{p}/ pages {pgs}: ...{hits[0][1]}...")
        if all_ok is None:
            print(f"{row} {name}: SKIPPED")
            print("\n".join(lines))
            continue
        total += 1
        passed += bool(all_ok)
        print(f"{row} {name}: {'PASS' if all_ok else 'FAIL'}")
        print("\n".join(lines))
    return passed, total


if __name__ == "__main__":
    print(f"papers: {PAPERS}\nweb copies: {SCRATCH}\n")
    p1, t1 = run(CHECKS, PDF)
    print()
    p2, t2 = run(WEB, None)
    print("\n--- negative controls (must find nothing) and positive control")
    neg_ok = 0
    for row, key, p in NEGATIVE:
        hits = find(PDF[key], p)
        ok = not hits
        neg_ok += ok
        print(f"{row} {PDF[key]} /{p}/: {'PASS (0 hits)' if ok else 'FAIL ' + str(hits[:2])}")
    pos = find(PDF["c16"], r"primarily concerned with attacks that use classical")
    print(f"positive control: {'PASS' if pos else 'FAIL'}")
    print(f"\n{p1 + p2} of {t1 + t2} source checks passed; {neg_ok} of {len(NEGATIVE)} negative controls passed")
