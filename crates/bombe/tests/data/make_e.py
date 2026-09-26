"""Writes e-1000000.bin: the first 1,000,000 bits of the binary expansion of e.

NIST SP 800-22 publishes reference P-values for its tests run on this
sequence ("data.e", Appendix B), and exact bit counts in the serial-test
example (500029 ones; 250116 "00" pairs). Bombe's test implementations are
checked against those numbers, which also confirms this file.

e * 2^N = sum over k of 2^N / k!, computed with integers. Each floor loses
less than 1, and with about 70,000 terms the error stays far inside the 64
guard bits. The bits are the binary expansion starting with the integer part
"10" (e = 10.1011011111...), packed most-significant-bit first.

Run: python make_e.py   (about 20 seconds)
"""
import hashlib
import pathlib

BITS = 1_000_000
GUARD = 64

n = BITS + GUARD
term = 1 << n
total = 0
k = 0
while term:
    total += term
    k += 1
    term //= k

expansion = bin(total)[2:]  # "10" (the integer part 2) then the fraction
assert expansion.startswith("1010110111111000010101000101100"), expansion[:32]
bits = expansion[:BITS]
data = int(bits, 2).to_bytes(BITS // 8, "big")
out = pathlib.Path(__file__).with_name("e-1000000.bin")
out.write_bytes(data)
print(f"{k} terms, {bits.count('1')} ones, sha256 {hashlib.sha256(data).hexdigest()}")
