"""Look up venue, volume/issue, pages and DOI of papers in Crossref.

Reproduces: the venue columns of the Sources table in
research/notes/pq/side-channels-faults-and-ct-verification.md. Crossref is
the DOI registration agency used by IACR TCHES, Springer (LNCS), ACM and
IEEE, so its record is the publisher's own metadata. dblp was not usable
(it answers automated requests with a bot check).

Usage: python sc_venues.py            (queries the built-in title list)
       python sc_venues.py "Title" ... (queries the given titles)
For each title it prints the best Crossref match whose title agrees with the
query (case-insensitive, punctuation ignored); a mismatch is printed as
NO MATCH so it cannot be mistaken for a verification. Network access is
needed; every request has a 60 s timeout and a 2 s pause between requests.
"""
import json
import re
import sys
import time
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

TITLES = [
    "Generic Side-channel attacks on CCA-secure lattice-based PKE and KEMs",
    "Curse of Re-encryption: A Generic Power/EM Analysis on Post-Quantum KEMs",
    "Masking Kyber: First- and Higher-Order Implementations",
    "First-Order Masked Kyber on ARM Cortex-M4",
    "Attacking and Defending Masked Polynomial Comparison for Lattice-Based Cryptography",
    "Fault Attacks on CCA-secure Lattice KEMs",
    "Fault-Enabled Chosen-Ciphertext Attacks on Kyber",
    "Fault-Injection Attacks Against NIST's Post-Quantum Cryptography Round 3 KEM Candidates",
    "Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber",
    "Chosen Ciphertext k-Trace Attacks on Masked CCA2 Secure Kyber",
    "Single-Trace Side-Channel Attacks on Masked Lattice-Based Encryption",
    "More Practical Single-Trace Attacks on the Number Theoretic Transform",
    "Defeating NewHope with a Single Trace",
    "Breaking a Fifth-Order Masked Implementation of CRYSTALS-Kyber by Copy-Paste",
    "When Frodo Flips: End-to-End Key Recovery on FrodoKEM via Rowhammer",
    "Dude, is my code constant time?",
    "Binsec/Rel: Efficient Relational Symbolic Execution for Constant-Time at Binary-Level",
    "MicroWalk: A Framework for Finding Side Channels in Binaries",
    "Microwalk-CI: Practical Side-Channel Analysis for JavaScript Applications",
    "Verifying Constant-Time Implementations",
    "A Systematic Evaluation of Automated Tools for Side-Channel Vulnerabilities Detection in Cryptographic Libraries",
    "They're not that hard to mitigate: What Cryptographic Library Developers Think About Timing Attacks",
    "A Key-Recovery Timing Attack on Post-quantum Primitives Using the Fujisaki-Okamoto Transformation and Its Application on FrodoKEM",
    "Don't Reject This: Key-Recovery Timing Attacks Due to Rejection-Sampling in HQC and BIKE",
    "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations",
    "Breaking Bad: How Compilers Break Constant-Time Implementations",
    "LWE with Side Information: Attacks and Concrete Security Estimation",
]


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def query(title):
    url = ("https://api.crossref.org/works?rows=5&select=DOI,title,container-title,volume,issue,"
           "page,published,author,type&query.bibliographic=" + urllib.parse.quote(title))
    req = urllib.request.Request(url, headers={"User-Agent": "turing-research/1.0 (mailto:none)"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["message"]["items"]


def main():
    titles = sys.argv[1:] or TITLES
    for t in titles:
        try:
            items = query(t)
        except Exception as e:  # network errors are reported, not hidden
            print(f"ERROR {t}: {e}")
            continue
        hit = None
        for it in items:
            if norm((it.get("title") or [""])[0]) == norm(t):
                hit = it
                break
        if hit is None:
            print(f"NO MATCH: {t}")
            for it in items[:2]:
                print(f"   nearest: {(it.get('title') or [''])[0]} | {(it.get('container-title') or [''])[0]}")
        else:
            y = hit.get("published", {}).get("date-parts", [[None]])[0][0]
            authors = ", ".join(f"{a.get('given', '')} {a.get('family', '')}".strip()
                                for a in hit.get("author", []))
            print(f"{t}\n   {(hit.get('container-title') or [''])[0]} | vol {hit.get('volume', '')} "
                  f"issue {hit.get('issue', '')} pages {hit.get('page', '')} | {y} | "
                  f"DOI {hit['DOI']} | {hit.get('type')}\n   authors: {authors}")
        time.sleep(2)


if __name__ == "__main__":
    main()
