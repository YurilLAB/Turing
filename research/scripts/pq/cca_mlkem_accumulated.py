"""CCTV "accumulated pq-crystals" check for cca_mlkem_ref.py.

Reproduces the procedure in C2SP/CCTV ML-KEM/README.md ("Accumulated
pq-crystals vectors"): a deterministic RNG (one SHAKE-128 instance with empty
input) supplies d, z, m and a random invalid ciphertext for each test; ek, dk,
ct, K (encaps) and K (decaps of the random ciphertext) are absorbed into a
running SHAKE-128 whose 32-byte output must equal the published hash for
10 000 tests:
  ML-KEM-512  845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4
  ML-KEM-768  f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3
  ML-KEM-1024 47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543
It also checks Decaps(dk, ct) == K for every honest ciphertext.

Usage: python cca_mlkem_accumulated.py PARAMSET [N] [--ipd]   (N defaults to 10000)

Note (checked 2026-09-27): the CCTV README states its vectors target FIPS 203
ipd with the matrix-index fix, i.e. key generation uses G(d), not the final
standard's G(d || k) (FIPS 203 App. C.2). So the published hashes are
expected to match only with --ipd; the default (final FIPS 203) run gives a
different hash. The Decaps(dk, ct) == K check is meaningful in both modes.
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cca_mlkem_ref as M  # noqa: E402

EXPECTED = {
    "ML-KEM-512": "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
    "ML-KEM-768": "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
    "ML-KEM-1024": "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
}

args = [a for a in sys.argv[1:] if a != "--ipd"]
IPD = "--ipd" in sys.argv
ps = args[0]
n = int(args[1]) if len(args) > 1 else 10000
print("mode:", "FIPS 203 ipd key generation G(d)" if IPD else "FIPS 203 final key generation G(d||k)")
p = M.PARAMS[ps]
k, _, _, du, dv = p
ct_len = 32 * (du * k + dv)
stream = hashlib.shake_128(b"").digest(n * (96 + ct_len))
print("RNG stream starts with", stream[:16].hex(), "(README: 7f9c2ba4e88f827d616045507605853e)")
acc = hashlib.shake_128()
pos = 0
bad_decaps = 0
t0 = time.time()
for i in range(n):
    d = stream[pos:pos + 32]; pos += 32
    z = stream[pos:pos + 32]; pos += 32
    m = stream[pos:pos + 32]; pos += 32
    ct_rand = stream[pos:pos + ct_len]; pos += ct_len
    ek, dk = M.keygen_internal(d, z, p, ipd=IPD)
    K, ct = M.encaps_internal(ek, m, p)
    bad_decaps += M.decaps_internal(dk, ct, p) != K
    K_rand = M.decaps_internal(dk, ct_rand, p)
    acc.update(ek); acc.update(dk); acc.update(ct); acc.update(K); acc.update(K_rand)
    if (i + 1) % 1000 == 0:
        print(f"  {i + 1} tests, {time.time() - t0:.0f} s", flush=True)
got = acc.digest(32).hex()
print(f"{ps} N={n} hash={got}")
if n == 10000:
    print(f"[{'PASS' if got == EXPECTED[ps] else 'FAIL'}] matches CCTV published hash")
print(f"[{'PASS' if bad_decaps == 0 else 'FAIL'}] Decaps(dk, ct) == K for all {n} honest ciphertexts")
