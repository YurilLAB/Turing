"""Spot-check quoted phrases in research/notes/pq/cca-transforms-and-binding.md
against the local primary sources.

Reproduces: for each ledger row listed below, the exact phrase the notes quote
(or the number they cite) is searched for in the named local file after
whitespace normalisation. A PASS means the phrase occurs in the source; it
does not re-check the surrounding interpretation. Sources are the PDFs in
research/papers/ and the text copies in the scratch directory (pqc-forum
threads, RFC 9935, RFC 8937, CCTV README).

Usage: python cca_source_spotcheck.py SCRATCH_PQ_DIR
       (SCRATCH_PQ_DIR = research/workfiles/pq)
Deterministic: reads local files only. pymupdf is used for PDFs.
"""
import os
import re
import sys

import pymupdf as fitz

sys.stdout.reconfigure(encoding="utf-8")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "papers")
SCRATCH = sys.argv[1]


def norm(s):
    s = s.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    s = s.replace("ﬁ", "fi").replace("ﬀ", "ff").replace("ﬂ", "fl").replace("ﬃ", "ffi")
    s = re.sub(r"-\s+", "-", s)
    return re.sub(r"\s+", " ", s).lower()


_cache = {}


def text_of(src):
    if src in _cache:
        return _cache[src]
    if src.startswith("scratch:"):
        path = os.path.join(SCRATCH, src[len("scratch:"):])
        with open(path, encoding="utf-8", errors="replace") as f:
            t = f.read()
    else:
        doc = fitz.open(os.path.join(ROOT, src))
        t = " ".join(p.get_text() for p in doc)
    _cache[src] = norm(t)
    return _cache[src]


CHECKS = [
    ("K3", "2016-fluhrer-cryptanalysis-rlwe-key-exchange-key-reuse.pdf", "perhaps 4,000 queries"),
    ("K4", "2016-fluhrer-cryptanalysis-rlwe-key-exchange-key-reuse.pdf", "drop in replacement"),
    ("K6", "2019-bauer-gilbert-renault-rossi-key-reuse-newhope.pdf", "even for an extremely short duration"),
    ("L1", "nist-fips-203-ml-kem.pdf", "shall not be used as a stand-alone cryptographic scheme"),
    ("L4", "nist-fips-203-ml-kem.pdf", "no longer includes a hash of the ciphertext in the derivation of the shared secret"),
    ("L13", "nist-fips-203-ml-kem.pdf", "in any form is not permitted"),
    ("L16", "nist-fips-203-ml-kem.pdf", "same safeguards as a decapsulation key"),
    ("L22", "nist-fips-203-ml-kem.pdf", "estimated based on current cryptanalysis"),
    ("C8", "2017-hofheinz-hovelmanns-kiltz-modular-analysis-fo-transformation.pdf",
     "all our reductions in the quantum random oracle model are non-tight"),
    ("C10", "2018-saito-xagawa-yamakawa-tight-kem-qrom.pdf", "less than half"),
    ("C12", "2019-bindel-et-al-tighter-proofs-cca-qrom.pdf", "might be impossible to avoid"),
    ("C16", "2022-don-fehr-majenz-schaffner-online-extractability-qrom.pdf",
     "first complete post-quantum security proof of the textbook fujisaki-okamoto transformation"),
    ("C19", "2024-almeida-et-al-formally-verifying-kyber-episode-v-ml-kem-easycrypt.pdf", "closely (but not exactly)"),
    ("C22", "2023-barbosa-hulsing-security-of-kyber-fo-transform.pdf", "cannot be justified by the proven bound"),
    ("C24", "2025-hovelmanns-kudinov-explicit-vs-implicit-rejection-fo.pdf",
     "can easily deteriorate into explicit rejection in practice"),
    ("C26", "2013-fujisaki-okamoto-secure-integration-asymmetric-symmetric-encryption.pdf", "by fixing bugs"),
    ("F2", "2021-alkim-et-al-frodokem-round3-specification-20210604.pdf", "enables key recovery"),
    ("F3", "2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf", "revision: 2025-09-29"),
    ("F4", "2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf", "small number of ciphertexts"),
    ("F9", "2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf", "all-for-the-price-of-one"),
    ("M3", "2021-duman-et-al-generic-fo-prefix-hashing.pdf", "32 byte"),
    ("M8", "2025-glabush-hovelmanns-stebila-tight-multi-challenge-kem.pdf",
     "can only achieve 192 bits of multi-target security"),
    ("M10", "2025-glabush-hovelmanns-stebila-tight-multi-challenge-kem.pdf", "we do not bound the multi-target"),
    ("M14", "2025-glabush-hovelmanns-stebila-tight-multi-challenge-kem.pdf", "refuted by bernstein"),
    ("M12", "2022-bernstein-multi-ciphertext-security-degradation-lattices.pdf",
     "typical lattice pkes asymptotically degrade"),
    ("B8", "2024-schmieg-unbindable-kemmy-schmidt-ml-kem-binding.pdf", "mal-bind-k-pk"),
    ("B10", "2024-schmieg-unbindable-kemmy-schmidt-ml-kem-binding.pdf", "appear well-formed"),
    ("B12", "2023-cremers-dax-medinger-keeping-up-with-the-kems.pdf", "just by performing simple sanity checks"),
    ("B26", "2025-kramer-struck-weishaupl-binding-implicitly-rejecting-kems.pdf",
     "two invalid ciphertexts that differ only in the salt"),
    ("B27", "2025-kramer-struck-weishaupl-binding-implicitly-rejecting-kems.pdf", "is irrelevant for our fo"),
    ("B29", "2022-grubbs-maram-paterson-anonymous-robust-pq-pke.pdf", "an implicit rejection kem cannot be robust"),
    ("B30", "2022-grubbs-maram-paterson-anonymous-robust-pq-pke.pdf",
     "decrypts to the chosen m under any classic mceliece private key"),
    ("V6", "2025-glabush-et-al-verifiable-decapsulation-faulty-kem-implementations.pdf", "only noticed after 19 months"),
    ("V7", "2025-glabush-et-al-verifiable-decapsulation-faulty-kem-implementations.pdf", "at most 3.4% overhead"),
    ("R3", "2012-heninger-et-al-mining-your-ps-and-qs-weak-keys.pdf", "0.75%"),
    ("R4", "2021-avanzi-et-al-kyber-round3-specification.pdf", "reuse the same randomness in encapsulation"),
    ("R9", "2009-bellare-et-al-hedged-public-key-encryption.pdf", "hedge"),
    ("M15", "2016-alkim-ducas-poppelmann-schwabe-newhope.pdf", "would be disas"),
    ("L12", "scratch:forum_fo1.txt", "essentially gives an attacker explicit rejection"),
    ("L8", "scratch:forum_fo2.txt", "does not help at all with any formal security property"),
    ("R14", "scratch:rfc9935.txt", "mal-bind-k-pk"),
    ("R13", "scratch:rfc9935.txt", "recommended"),
    ("V1", "scratch:cctv-mlkem-README.now.md", "the chance of it occurring randomly is 2"),
]

# Negative controls: altered numbers/phrases that must NOT be found, to show
# the matcher is not trivially accepting everything.
NEGATIVE = [
    ("K3-neg", "2016-fluhrer-cryptanalysis-rlwe-key-exchange-key-reuse.pdf", "perhaps 40,000 queries"),
    ("V6-neg", "2025-glabush-et-al-verifiable-decapsulation-faulty-kem-implementations.pdf",
     "only noticed after 9 months"),
    ("M8-neg", "2025-glabush-hovelmanns-stebila-tight-multi-challenge-kem.pdf",
     "can only achieve 128 bits of multi-target security"),
]

fails = 0
for row, src, phrase in NEGATIVE:
    found = norm(phrase) in text_of(src)
    fails += found
    print(f"[{'FAIL' if found else 'PASS'}] {row:6s} altered phrase {phrase!r} correctly absent from {src}")
for row, src, phrase in CHECKS:
    try:
        ok = norm(phrase) in text_of(src)
    except Exception as e:  # missing file or unreadable PDF
        ok = False
        src = f"{src} ({type(e).__name__})"
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] {row:4s} {phrase!r} in {src}")
print(f"TOTAL FAILURES: {fails} of {len(CHECKS) + len(NEGATIVE)}")
