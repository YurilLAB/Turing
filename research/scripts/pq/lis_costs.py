"""lis_costs.py - cost and consistency arithmetic for the note
research/notes/pq/lattices-inside-symmetric-primitives.md (sections 3b, 8).

Deterministic, no network, runs in well under a second. Every input number is
quoted from a primary source (named next to it); every output is arithmetic.
Each check prints PASS/FAIL; the script exits 1 if any check fails.

A. LEAP (Zhang et al., ToSC 2025(3); research/papers/2025-zhang-et-al-leap-
   lattice-based-prng.pdf, Table 1, PDF p. 5): the abstract's "reduce the key
   size by 1.71X while improving performance by 3.30X" versus SPRING-RS.
B. GGM module-LWR PRF (Chuengsatiansup-Stehle, SAC 2019; research/papers/
   2019-chuengsatiansup-stehle-ggm-prf-module-lwr.pdf): Theorem 1 (PDF p. 4)
   says the GGM PRF is (q*d*eps)-indistinguishable; with the implemented
   parameters (security 167, depth 32; Table 2 PDF p. 15) the text's
   "up to 2^34 PRF queries" for 128-bit PRF security (PDF p. 16) follows.
   Also checks whether the per-call cycle counts in the text (PDF p. 16)
   reproduce the 39.4 cycles/byte of Table 3 (PDF p. 17).
C. Turing's own speed (docs/10: 3.0 us per block, 16 rounds, v1;
   docs/13: plain cipher 4.5 us per block, v2) converted to cycles/byte at the
   clock this machine reports (AMD Ryzen 5 5600X, WMI MaxClockSpeed 4276 MHz,
   read 2026-09-27). ASSUMPTION: the docs' timings were taken on this machine
   at about that clock; the real clock under load is not known.
D. Relative cost of adding a lattice keystream to Turing-CTR (XOR combiner),
   using the published lattice speeds (different machines: order of magnitude
   only).
E. SWIFFT speed (Lyubashevsky et al., FSE 2008, PDF p. 7: "close to 40 MB/s"
   on a 3.2 GHz Pentium 4) in cycles/byte.
"""
import math
import sys

sys.stdout.reconfigure(encoding="utf-8")
ALL_OK = True


def check(label, cond):
    global ALL_OK
    ALL_OK &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


# ------------------------------------------------------------------ A
print("A. LEAP vs SPRING-RS ratios (LEAP Table 1, PDF p. 5)")
spring_rs_key, spring_rs_cpb = 385, 5.32   # bytes, cycles/byte AVX2
leap128_key, leap_cpb_avx2 = 224, 1.61
key_ratio = spring_rs_key / leap128_key
speed_ratio = spring_rs_cpb / leap_cpb_avx2
print(f"  key 385/224 = {key_ratio:.4f}  (abstract: 1.71X)")
print(f"  speed 5.32/1.61 = {speed_ratio:.4f}  (abstract: 3.30X)")
check("key ratio truncates to 1.71", math.floor(key_ratio * 100) / 100 == 1.71)
check("speed ratio rounds to 3.30", round(speed_ratio, 2) == 3.30)
aes256_ni, leap256_avx512 = 0.45, 1.14
print(f"  LEAP-256 AVX512 / AES256-CTR AES-NI = {leap256_avx512 / aes256_ni:.2f}x slower")

# ------------------------------------------------------------------ B
print("\nB. GGM module-LWR PRF query budget (CS SAC 2019, Thm 1 PDF p. 4; PDF p. 15-16)")
sec_bits = 167            # Table 2 row d=256, m=16, n=3, logB=4
input_bits, log_omega = 128, 4   # 128-bit input, omega = 16
depth = input_bits // log_omega
print(f"  depth = 128 / log2(16) = {depth}  (Table 2 lists depth 32)")
check("depth is 32", depth == 32)
log_q_max = sec_bits - 128 - math.log2(depth)
print(f"  q*d*eps <= 2^-128  =>  log2 q <= 167 - 128 - log2(32) = {log_q_max:.1f}")
check("reproduces the text's 2^34 queries", round(log_q_max) == 34)
main_loop_ctr, output_cost, out_bytes = 242347, 236390, 6144
cpb_text = (main_loop_ctr + output_cost) / out_bytes
print(f"  (242347 + 236390) / 6144 = {cpb_text:.1f} cycles/byte from the text's counts;"
      f" Table 3 gives 39.4")
check("text counts do NOT reproduce 39.4 (a factor ~2 gap, recorded as open)",
      abs(cpb_text - 39.4) > 10)

# ------------------------------------------------------------------ C
print("\nC. Turing speed in cycles/byte (docs/10, docs/13) at an assumed clock")
f_hz = 4.276e9            # WMI MaxClockSpeed on this machine
for label, us in (("v1, 16 rounds (docs/10)", 3.0), ("v2, 24 rounds (docs/13)", 4.5)):
    cpb = us * 1e-6 * f_hz / 16
    mbs = 16 / (us * 1e-6) / 1e6
    print(f"  {label}: {us} us/block = {mbs:.2f} MB/s = {cpb:.0f} cycles/byte at 4.276 GHz")
turing_v2_cpb = 4.5e-6 * f_hz / 16
check("Turing v2 is roughly 1000 cycles/byte (between 500 and 2000)", 500 < turing_v2_cpb < 2000)

# ------------------------------------------------------------------ D
print("\nD. Added cost of an XOR-combined lattice keystream, relative to Turing v2")
lattice = {
    "LEAP-256 (AVX2, LEAP Table 1)": 1.61,
    "SPRING-RS (AVX2, LEAP Table 1)": 5.32,
    "SPRING-CRT CTR (Ivy Bridge, SPRING Table 1)": 23.5,
    "GGM module-LWR (Skylake, CS Table 3)": 39.4,
    "GGM plain LWR (Skylake, CS Table 3)": 64.2,
}
for name, cpb in lattice.items():
    print(f"  {name:45s} {cpb:6.2f} c/B -> +{100 * cpb / turing_v2_cpb:5.1f}% on top of Turing v2")
check("even the slowest listed lattice PRF adds < 10% to Turing v2 as measured",
      max(lattice.values()) / turing_v2_cpb < 0.10)
print("  (Turing is not yet speed-optimised; against an AES-NI-class cipher at ~0.5 c/B")
print(f"   the same lattice keystreams would cost {1.61 / 0.45:.1f}x (LEAP) to"
      f" {64.2 / 0.45:.0f}x (plain-LWR GGM) the cipher's own time.)")
check("39.4 / 0.45 is about 88x; 64.2/0.45 about 143x", round(39.4 / 0.45) == 88 and round(64.2 / 0.45) == 143)

# ------------------------------------------------------------------ E
print("\nE. SWIFFT speed (FSE 2008, PDF p. 7)")
swifft_cpb = 3.2e9 / 40e6
print(f"  3.2 GHz / 40 MB/s = {swifft_cpb:.0f} cycles per input byte")
check("SWIFFT is about 80 cycles/byte", round(swifft_cpb) == 80)

print("\nOVERALL:", "PASS" if ALL_OK else "FAIL")
sys.exit(0 if ALL_OK else 1)
