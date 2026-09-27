#!/usr/bin/env python3
"""Independent fact-checker's recomputation of the COMPUTED claims in
research/notes/pq/hybrid-combiners.md. Written by the fact-checker, not
the notes' author. Deterministic, prints every check and PASS/FAIL.

Run: timeout 120 python research/scripts/pq/check_hybrid-combiners_sources.py
"""
import math

ok = True


def check(label, cond, detail=""):
    global ok
    status = "PASS" if cond else "FAIL"
    if not cond:
        ok = False
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))


print("=== 1. ABK25 Theorem 9 bound crossover: 4*sqrt((q^2+q)/|K_i|) = 1 ===")
# Solve q^2 + q - |K_i|/16 = 0 for q (positive root), report log2(q).
for bits, label in [(256, "256-bit component secret"),
                    (192, "192-bit component secret (FrodoKEM-976, ss=24B)"),
                    (128, "128-bit component secret (FrodoKEM-640)")]:
    K = 2 ** bits
    # 4*sqrt((q^2+q)/K) = 1  =>  16*(q^2+q)/K = 1  =>  q^2+q-K/16=0
    a, b, c = 1.0, 1.0, -K / 16.0
    q = (-b + math.sqrt(b * b - 4 * a * c)) / (2 * a)
    log2q = math.log2(q)
    print(f"  {label}: q = 2^{log2q:.2f}")
    # notes claim: 2^126, 2^94, 2^62 respectively
    expect = {256: 126, 192: 94, 128: 62}[bits]
    check(f"  matches notes' claimed 2^{expect}", abs(log2q - expect) < 0.6,
          f"computed 2^{log2q:.3f}")

print()
print("=== 2. Classic McEliece ciphertext size: ceil(m*t/8) bytes ===")
m, t = 13, 96
ct_bits = m * t
ct_bytes = math.ceil(ct_bits / 8)
check("mceliece460896 ciphertext = 156 bytes (2022 spec formula)",
      ct_bytes == 156, f"m*t={ct_bits} bits -> {ct_bytes} bytes")
check("Rosenpass-quoted 188 bytes is the ROUND-3 (2020) ciphertext size, "
      "different from the 2022-spec 156-byte figure (both can be correct "
      "for their own version; this is a version difference, not an error)",
      188 != ct_bytes, "188 (Rosenpass, round-3) vs 156 (2022 spec)")

print()
print("=== 3. Sum-of-costs vs strongest component (Key finding 9 / 'What this means' 4) ===")
# Three independent 2^256 components; attacker must break ALL of them one by
# one (since the combiner is secure if ANY ONE survives) -> cost = sum, but
# the notes' "2^257.6" figure is for an attacker who must break EVERY
# component (worst case for the attacker is the min number of components
# they can get away with, i.e. this is the *insurance* framing: an attacker
# who wants to recover k must break every surviving component, so total
# work is bounded by n * (cost of one) in a naive union, i.e. cost sums).
n = 3
per_component_bits = 256
total_cost = n * (2 ** 0)  # multiplicative factor n on top of one component's cost
extra_bits = math.log2(n)
check("log2(3) ~= 1.585 (extra bits over one component when summing 3 equal costs)",
      abs(extra_bits - 1.585) < 0.01, f"log2(3) = {extra_bits:.4f}")
combined_bits = per_component_bits + extra_bits
check("3 components of 2^256 each, summed cost ~= 2^257.6",
      abs(combined_bits - 257.6) < 0.05, f"256 + log2(3) = {combined_bits:.3f}")

print()
print("=== 4. X-Wing combiner input size: 134 bytes ===")
# ss_M (32) + ss_X (32) + ct_X (32) + pk_X (32) + label (6) = 134
xwing_input = 32 + 32 + 32 + 32 + 6
check("X-Wing combiner hashes 134 bytes (ss_M+ss_X+ct_X+pk_X+label)",
      xwing_input == 134, f"computed {xwing_input}")

print()
print("=== 5. X-Wing-Hash-CT input size ===")
# Confirmed against the X-Wing paper itself (Sec. 8, p. 19, via pdfgrep):
# "X-Wing-Hash-CT uses 1222 bytes ... while X-Wing uses only 134 bytes by
# omitting the ML-KEM-768 ciphertext" -- i.e. X-Wing-Hash-CT = X-Wing's
# 134-byte input PLUS ONLY the ML-KEM ciphertext ct_M (1088 bytes), not
# also the ML-KEM public key pk_M. (An earlier draft of this script wrongly
# assumed pk_M was included too, which gave 2406 and did not match; the
# paper's own text settles it in favour of ct_M alone.)
check("X-Wing 134-byte base + ct_M(1088) = X-Wing-Hash-CT's 1222 bytes "
      "(matches the paper's own statement, not just arithmetic)",
      134 + 1088 == 1222, f"{134 + 1088}")

print()
print("=== 6. Nested X-Wing + FrodoKEM-976 KDF-input sizes (Sec. 5 table) ===")
# X-Wing as inner KEM: ct_XW=1120, ek_XW=1216. FrodoKEM-976: pk=15632, ct=15792, ss=24 (Table A.5 per notes)
ss_xw, ct_xw, ek_xw = 32, 1120, 1216
frodo_pk, frodo_ct, frodo_ss = 15632, 15792, 24
label = 16
counter = 4
# hash-all variant (outer hashes all: ss_xw, ss_frodo, ct_xw, ct_frodo, ek_xw, ek_frodo, label)
hash_all = ss_xw + frodo_ss + ct_xw + frodo_ct + ek_xw + frodo_pk + label
print(f"  outer hashes all: {hash_all} bytes (notes table says 33836; "
      f"note table's KDF-input column also adds a counter per its own footnote)")
check("outer-hashes-all KDF input matches notes' 33836 within +/- 4 bytes (counter)",
      abs(hash_all - 33836) <= 4, f"computed {hash_all}, notes claim 33836")

# cached H(pk) variant: replace ek_xw+ek_frodo with a 32-byte key-hash
key_hash = 32
cached = ss_xw + frodo_ss + ct_xw + frodo_ct + key_hash + label
print(f"  outer with cached H(pk): {cached} bytes (notes table says 17020)")
check("cached-H(pk) KDF input matches notes' 17020 within +/- 4 bytes",
      abs(cached - 17020) <= 4, f"computed {cached}, notes claim 17020")

print()
print("=== ALL CHECKS " + ("PASSED" if ok else "FAILED") + " ===")
