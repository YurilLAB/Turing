"""Extract median cycle counts for selected KEMs from a saved eBACS per-machine page.

Reproduces the benchmark numbers quoted in research/notes/pq/pq-families-for-diversity.md
(comparison table, "speed" column) from eBACS/SUPERCOP, the benchmarking framework of
Bernstein and Lange (https://bench.cr.yp.to/results-kem.html).

The page is not stored in the repository (third-party data). Save it first, e.g.:
    curl -L --max-time 120 -o PAGE.html "https://bench.cr.yp.to/results-kem/amd64-freshwrap,big.html"
then run:
    python ebacs_kem_extract.py PAGE.html

Each eBACS table row lists (25%, 50%, 75%) quartiles and the primitive name; this script prints
the median (50%) for key generation, encapsulation and decapsulation, plus the flags eBACS
attaches (T: = constant time not listed as a goal; C: = IND-CCA2 not listed as a goal).
Deterministic: pure parsing, no network access.
"""
import html
import re
import sys

WANTED = [
    "mlkem512", "mlkem768", "mlkem1024",
    "sntrup653", "sntrup761", "sntrup857", "sntrup953", "sntrup1013", "sntrup1277",
    "ntrulpr761", "ntrulpr1013", "ntrulpr1277",
    "ntruhps2048677", "ntruhps4096821", "ntruhrss701",
    "frodokem640aes", "frodokem640shake", "frodokem976aes", "frodokem976shake",
    "frodokem1344aes", "frodokem1344shake",
    "hqc128", "hqc192", "hqc256", "hqcrmrs128", "hqcrmrs192", "hqcrmrs256",
    "bikel1", "bikel3", "bikel5",
    "mceliece348864", "mceliece460896", "mceliece6688128", "mceliece6960119", "mceliece8192128",
    "mceliece348864f", "mceliece460896f", "mceliece6688128f", "mceliece6960119f", "mceliece8192128f",
    "lightsaber", "saber", "firesaber",
]

TABLES = {
    "Cycles to generate a key pair": "keygen",
    "Cycles for encapsulation": "enc",
    "Cycles for decapsulation": "dec",
}


def parse(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    titles = re.findall(r"on one machine:([^\[]*?)\[Page version", re.sub(r"<[^>]+>", " ", text), re.S)
    title = titles[-1].split("on one machine:")[-1] if titles else None
    results = {}
    for m in re.finditer(r'<th colspan="4">([^<]+)</th>(.*?)</table>', text, re.S):
        head = m.group(1).strip()
        key = None
        for prefix, k in TABLES.items():
            if head.startswith(prefix):
                key = k
        if key is None:
            continue
        for row in re.finditer(
            r"<tr align=right><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td align=left>(.*?)</td></tr>",
            m.group(2), re.S,
        ):
            cell = row.group(4)
            flags = "".join(sorted(set(re.findall(r"(T!!!|T:|C:)", cell))))
            name = html.unescape(re.sub(r"<[^>]+>", "", cell)).replace("T:", "").replace("C:", "")
            name = name.replace("T!!!", "").strip()
            medcell = re.sub(r"<[^>]+>", "", row.group(2))
            med = re.sub(r"[^0-9]", "", medcell)
            if "?" in medcell:
                flags += "?"  # eBACS marks a large interquartile range in red with '?'
            results.setdefault(name, {})[key] = (int(med) if med else None, flags)
    return (title.strip() if title else "?"), results


def main():
    machine, res = parse(sys.argv[1])
    print("machine:", re.sub(r"\s+", " ", machine))
    print(f"{'primitive':22s} {'keygen':>12s} {'encaps':>10s} {'decaps':>10s}  flags")
    for name in WANTED:
        if name not in res:
            print(f"{name:22s} {'(not on this machine)':>34s}")
            continue
        r = res[name]
        kg, en, de = (r.get(k, (None, ""))[0] for k in ("keygen", "enc", "dec"))
        flags = " ".join(sorted({f for v in r.values() for f in [v[1]] if f}))
        fmt = lambda v: f"{v:,}" if v is not None else "-"
        print(f"{name:22s} {fmt(kg):>12s} {fmt(en):>10s} {fmt(de):>10s}  {flags}")


if __name__ == "__main__":
    main()
