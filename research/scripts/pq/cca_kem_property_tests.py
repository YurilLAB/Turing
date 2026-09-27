"""Property tests for an FO-based KEM, run on the FIPS 203 reference
(cca_mlkem_ref.py). Each test is a regression test a custom Turing KEM should
also pass (or knowingly fail), with the source of the property it checks.

 1. Qin et al. (ASIACRYPT 2021, ePrint 2021/123) Table 1 lower bounds for
    key-mismatch queries (1216 / 1632 / 2176) equal n*k times the Huffman
    average code length of the centred binomial distribution, and the
    eta = 2 entropy is 2.03 bits (their Sec. 3). Pure arithmetic.
 2. FIPS 203 Alg. 13 line 1 / footnote 1 (pdf p. 38): G(d || k) separates the
    parameter sets: one seed d gives unrelated (rho, sigma) for k = 2, 3, 4.
 3. FIPS 203 Alg. 17: Encaps_internal is deterministic in (ek, m), and
    H(ek) enters G, so the same m under two keys gives unrelated K and r.
 4. Kyber round-3 spec Sec. 4.5.4 (pdf p. 24): the FO re-encryption check
    detects an encapsulator whose noise sampler is broken (all-zero noise).
 5. Binding (Cremers-Dax-Medinger, ePrint 2023/1933, Fig. 6 MAL game;
    Schmieg, ePrint 2024/523, Alg. 2 and 3; Kramer-Struck-Weishaupl,
    ePrint 2024/1233, Sec. 5.1 FO_M):
    5a MAL-BIND-K-CT with an attacker-built expanded key whose stored hash h
       is swapped: holds only if the decapsulator recomputes or checks h.
    5b MAL-BIND-K-PK with two attacker-built keys sharing z: fails for the
       FIPS 203 rejection key J(z || c); holds for the FO_M rejection key
       J(z || H(ek) || c) and for keys derived from ONE seed.
 6. Salted FO (Kramer-Struck-Weishaupl, ePrint 2024/1233, Sec. 4.2-4.3,
    Theorems 10, 12, 13): a toy salted FO over K-PKE. If the salt is in the
    ciphertext but not in the key hash (round-4 HQC style), two invalid
    ciphertexts that differ only in the salt give the same key (HON-BIND-K-CT
    broken), and with a leaked rejection secret a valid and a rejected
    ciphertext collide (LEAK-BIND-K,PK-CT broken). Hashing the whole
    ciphertext, salt included (HQC* / salted FrodoKEM style), prevents both.

Usage: python cca_kem_property_tests.py   (deterministic; seeds are fixed)
"""
import hashlib
import heapq
import math
import os
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cca_mlkem_ref as M  # noqa: E402

fails = 0


def report(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def det(label, n=32):
    """Deterministic test bytes (not a secure RNG)."""
    return hashlib.shake_256(b"cca-property-tests/" + label.encode()).digest(n)


# --------------------------------------------------------------- 1. Qin et al.
def cbd_probs(eta):
    return {x: Fraction(math.comb(2 * eta, eta + x), 4 ** eta) for x in range(-eta, eta + 1)}


def huffman_avg_len(probs):
    heap = [(p, i, 0) for i, p in enumerate(probs)]  # (weight, tiebreak, cost)
    heapq.heapify(heap)
    total = Fraction(0)
    tb = len(probs)
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        total += a[0] + b[0]          # each merge adds one bit to all leaves below
        heapq.heappush(heap, (a[0] + b[0], tb, 0))
        tb += 1
    return total


for name, eta, unknowns, expected in [("Kyber512", 3, 512, 1216), ("Kyber768", 2, 768, 1632),
                                      ("Kyber1024", 2, 1024, 2176)]:
    pr = cbd_probs(eta)
    L = huffman_avg_len(list(pr.values()))
    H_bits = -sum(float(p) * math.log2(p) for p in pr.values())
    got = L * unknowns
    report(f"Qin et al. Table 1 {name}: Huffman bound", got == expected,
           f"avg code length {L} = {float(L)} bits/coeff x {unknowns} = {got} (paper {expected}); "
           f"entropy {H_bits:.4f} bits/coeff -> {H_bits * unknowns:.0f}")

# ------------------------------------------------------ 2. G(d || k) separation
d, z = det("d"), det("z")
rhos = {}
for ps, p in M.PARAMS.items():
    ek, _ = M.keygen_internal(d, z, p)
    rhos[ps] = ek[-32:]
report("FIPS 203 G(d||k): same d gives different rho for 512/768/1024",
       len(set(rhos.values())) == 3, " ".join(f"{k}:{v[:4].hex()}" for k, v in rhos.items()))

# ---------------------------------------------- 3. determinism and H(ek) input
p = M.PARAMS["ML-KEM-768"]
ekA, dkA = M.keygen_internal(det("dA"), det("zA"), p)
ekB, dkB = M.keygen_internal(det("dB"), det("zB"), p)
m = det("m")
K1, c1 = M.encaps_internal(ekA, m, p)
K2, c2 = M.encaps_internal(ekA, m, p)
report("Encaps_internal deterministic: repeated m repeats (K, c)", K1 == K2 and c1 == c2)
K3, _ = M.encaps_internal(ekB, m, p)
report("same m under two keys gives different K (H(ek) in G)", K1 != K3)

# --------------------------------------------- 4. broken noise sampler caught
def zero_noise(y, e1, e2):
    zero = [0] * M.N
    return y, [zero] * len(e1), zero


caught = 0
TRIALS = 5
for t in range(TRIALS):
    Kb, cb = M.encaps_internal(ekA, det(f"m{t}"), p, noise_hook=zero_noise)
    caught += M.decaps_internal(dkA, cb, p) != Kb
report("FO re-encryption detects all-zero e1, e2 at the encapsulator", caught == TRIALS,
       f"{caught}/{TRIALS} key mismatches (implicit rejection)")

# ---------------------------------------------------------------- 5. binding
k = p[0]


def split_dk(dk):
    return (dk[:384 * k], dk[384 * k:768 * k + 32], dk[768 * k + 32:768 * k + 64],
            dk[768 * k + 64:])


# 5a. MAL-BIND-K-CT, g = 2 (party 0 encapsulates, party 1 decapsulates),
#     following Schmieg Alg. 2: sk1 carries party 0's key hash h0.
ek0, dk0 = M.keygen_internal(det("d0"), det("z0"), p)
ek1, dk1 = M.keygen_internal(det("d1"), det("z1"), p)
s1, e1_, h1, z1 = split_dk(dk1)
h0 = M.H(ek0)
dk1_bad = s1 + e1_ + h0 + z1                       # malformed: h != H(ek1)
m0 = det("m0")
K0, c0 = M.encaps_internal(ek0, m0, p)
_, r = M.G(m0 + h0)
c1_ = M.kpke_encrypt(ek1, m0, r, p)                  # built from party 1's ek
K1_ = M.decaps_internal(dk1_bad, c1_, p)
report("5a expanded key, no hash check: MAL-BIND-K-CT violated (expected)",
       K0 == K1_ and c0 != c1_, "(same K, different ciphertexts)")
report("5a FIPS 203 Sec 7.3 hash check rejects the malformed key", not M.check_dk(dk1_bad, p))
dk1_regen = dk1                                     # seed format: dk recomputed from (d1, z1)
K1_seed = M.decaps_internal(dk1_regen, c1_, p)
report("5a seed format (dk regenerated): binding holds", K1_seed != K0)

# 5b. MAL-BIND-K-PK, g = 1 (both decapsulate), Schmieg Alg. 3: shared z.
zs = det("shared-z")
ekP, dkP = M.keygen_internal(det("dP"), zs, p)
ekQ, dkQ = M.keygen_internal(det("dQ"), zs, p)
c = det("random-ct", 32 * (p[3] * k + p[4]))
KP, KQ = M.decaps_internal(dkP, c, p), M.decaps_internal(dkQ, c, p)
report("5b FIPS 203 rejection key J(z||c): MAL-BIND-K-PK violated (expected)",
       KP == KQ and ekP != ekQ, "(two public keys, same K)")
report("5b ... even in seed format, because z is an independent seed half",
       M.keygen_internal(det("dP"), zs, p)[1] == dkP)


def fo_m_rejection(zv, cv, ekv):                    # KSW FO_M: H(sigma, hpk, c)
    return M.J(zv + M.H(ekv) + cv)


KPm = M.decaps_internal(dkP, c, p, rejection_key=fo_m_rejection)
KQm = M.decaps_internal(dkQ, c, p, rejection_key=fo_m_rejection)
report("5b FO_M rejection key J(z||H(ek)||c): binding holds", KPm != KQm)


def one_seed_keygen(seed):                          # X-Wing style: (d, z) from one seed
    x = hashlib.shake_256(seed).digest(64)
    return M.keygen_internal(x[:32], x[32:], p)


eP1, dP1 = one_seed_keygen(det("seedP"))
eQ1, dQ1 = one_seed_keygen(det("seedQ"))
report("5b single-seed keys: distinct seeds give distinct z",
       split_dk(dP1)[3] != split_dk(dQ1)[3])

# ------------------------------------------------ 6. salted FO and binding
# Toy salted FO on top of K-PKE (NOT a proposed scheme): coins from
# G(m || H(ek) || salt) as in salted FrodoKEM / HQC; ciphertext = c* || salt.
# Variant "salt-out" mirrors round-4 HQC (KSW Fig. 6/7): the key hash covers
# c* but not the salt, on both the accept and reject path (one hash H_U with
# m or sigma). Variant "salt-in" mirrors HQC* / salted FrodoKEM: the whole
# ciphertext including the salt is hashed.
SALT = 32


def salted_encaps(ek, m, salt, salt_in):
    _, r = M.G(m + M.H(ek) + salt)
    cstar = M.kpke_encrypt(ek, m, r, p)
    tail = cstar + salt if salt_in else cstar
    return M.J(b"HU" + m + tail), cstar + salt


def salted_decaps(dk, ct, salt_in, want_flag=False):
    dk_pke, ek_pke, h, zv = split_dk(dk)
    cstar, salt = ct[:-SALT], ct[-SALT:]
    m_ = M.kpke_decrypt(dk_pke, cstar, p)
    _, r_ = M.G(m_ + h + salt)
    ok = M.kpke_encrypt(ek_pke, m_, r_, p) == cstar
    tail = cstar + salt if salt_in else cstar
    key = M.J(b"HU" + (m_ if ok else zv) + tail)
    return (key, ok) if want_flag else key


ekS, dkS = M.keygen_internal(det("dS"), det("zS"), p)
salt1, salt2 = det("salt1"), det("salt2")
for salt_in in (False, True):
    Ks, cts = salted_encaps(ekS, det("mS"), salt1, salt_in)
    report(f"6 salted FO ({'salt-in' if salt_in else 'salt-out'}): honest round trip",
           salted_decaps(dkS, cts, salt_in) == Ks)
# 6a HON-BIND-K-CT (KSW Thm 12): two invalid ciphertexts differing only in salt.
cbad = det("random-cstar", 32 * (p[3] * k + p[4]))
Ka = salted_decaps(dkS, cbad + salt1, False)
Kb = salted_decaps(dkS, cbad + salt2, False)
report("6a salt-out: HON-BIND-K-CT violated, no secret needed (expected)", Ka == Kb,
       "(two different ciphertexts, same K)")
Ka = salted_decaps(dkS, cbad + salt1, True)
Kb = salted_decaps(dkS, cbad + salt2, True)
report("6a salt-in: the two ciphertexts give different keys", Ka != Kb)
# 6b LEAK-BIND-K,PK-CT (KSW Thm 10, App. C.2): encapsulate m = sigma (= z
#     here), then change the salt: valid and rejected ciphertext share K.
zS = split_dk(dkS)[3]
for salt_in in (False, True):
    K_valid, ct_valid = salted_encaps(ekS, zS, salt1, salt_in)
    ct_changed = ct_valid[:-SALT] + salt2
    K_rej, accepted = salted_decaps(dkS, ct_changed, salt_in, want_flag=True)
    report(f"6b ({'salt-in' if salt_in else 'salt-out'}): changed-salt ciphertext is rejected",
           not accepted)
    same = K_valid == K_rej and salted_decaps(dkS, ct_valid, salt_in) == K_valid
    if salt_in:
        report("6b salt-in: leaked sigma no longer gives a K-CT collision", not same)
    else:
        report("6b salt-out: LEAK-BIND-K,PK-CT violated with m = sigma (expected)", same)

print("TOTAL FAILURES:", fails)
sys.exit(1 if fails else 0)
