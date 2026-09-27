"""Check the shape of a FrodoKEM NIST-style KAT file (.rsp): number of
records and the byte length of seed, pk, sk, ct, ss, and say which FrodoKEM
variant the lengths belong to.

What it reproduces, and from which source:
  * FrodoKEM ISO proposal (2025-09-29), Table A.5 "Size (in bytes) of inputs
    and outputs of FrodoKEM" (research/papers/
    2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf, p. 16):
    FrodoKEM-640 sk 19,888, pk 9,616, ct 9,752, ss 16 (salted variant).
  * FrodoKEM CiC paper Table 5 (research/papers/
    2025-alkim-et-al-frodokem-cic-practical-lwe-kem.pdf, p. 20):
    eFrodoKEM-640 ct 9,720 (the ephemeral variant, same as the Round 3
    FrodoKEM ciphertext in the 2021 specification, Table p. 25).
  It does NOT recompute any KAT (no FrodoKEM oracle here); it only checks that
  the file is complete and which variant's sizes it carries.

Usage:
    python research/scripts/pq/tcc_frodo_kat_shape.py FILE.rsp [FILE.rsp ...]
Deterministic; one line per file.
"""
import sys

SIZES = {
    # (sk, pk, ct, ss): name
    (19888, 9616, 9752, 16): "FrodoKEM-640 (salted, ISO proposal / CiC Table 5)",
    (19888, 9616, 9720, 16): "eFrodoKEM-640 or Round-3 FrodoKEM-640",
    (31296, 15632, 15792, 24): "FrodoKEM-976 (salted)",
    (31296, 15632, 15744, 24): "eFrodoKEM-976 or Round-3 FrodoKEM-976",
    (43088, 21520, 21696, 32): "FrodoKEM-1344 (salted)",
    (43088, 21520, 21632, 32): "eFrodoKEM-1344 or Round-3 FrodoKEM-1344",
}


def main():
    bad = 0
    for path in sys.argv[1:]:
        recs, cur = [], {}
        for line in open(path, encoding="ascii"):
            line = line.strip()
            if line.startswith("count"):
                if cur:
                    recs.append(cur)
                cur = {}
            if " = " in line:
                k, v = line.split(" = ", 1)
                cur[k] = v
        if cur:
            recs.append(cur)
        shapes = {tuple(len(r[k]) // 2 for k in ("sk", "pk", "ct", "ss")) for r in recs}
        seeds = {len(r["seed"]) // 2 for r in recs}
        counts = [int(r["count"]) for r in recs]
        ok = len(shapes) == 1 and counts == list(range(len(recs)))
        shape = next(iter(shapes)) if len(shapes) == 1 else None
        name = SIZES.get(shape, "unknown sizes")
        bad += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {path.split('/')[-1]}: {len(recs)} records, counts 0..{counts[-1]}, "
              f"seed {seeds} B, (sk, pk, ct, ss) = {shape} -> {name}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
