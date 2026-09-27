"""Weak randomness in an FO KEM: a worked demonstration on ML-KEM-512.

Reproduces, by running it, the reasoning of Section 7 of
research/notes/pq/cca-transforms-and-binding.md:
  * FIPS 203 Alg. 17: (K, r) = G(m || H(ek)). H(ek) is public, so K has no
    more unpredictability than m: whoever can enumerate m recomputes (K, c)
    from public data alone and recognises the right m by comparing with c.
  * FIPS 203 Alg. 13/16: the whole key pair is a function of the seed d (and
    z), so a low-entropy d lets an attacker rebuild dk from ek.
  * Round-3 Kyber's m <- H(m) (Kyber v3.02 Alg. 8 line 2; dropped in FIPS 203
    App. C.1) hides raw RNG output but adds no entropy: enumeration still works.
  * Hedging (Bellare et al. 2009, ePrint 2012/220; RFC 8937 Sec. 3): mixing a
    secret long-term value into m stops the enumeration.
The "weak RNG" here is a toy with a 12-bit (encapsulation) or 8-bit (key
generation) internal state, chosen so the demo runs in minutes; a real RNG
failure (e.g. Heninger et al. 2012) is the same attack with a larger count.

Usage: python cca_weak_randomness_demo.py     (deterministic; prints PASS/FAIL)
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cca_mlkem_ref as M  # noqa: E402

P = M.PARAMS["ML-KEM-512"]
fails = 0


def report(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def weak_rng(state, label):
    """Toy broken RNG: 32 output bytes determined by a small integer state."""
    return hashlib.shake_256(b"weak-rng/" + label + state.to_bytes(2, "big")).digest(32)


ENC_BITS, KG_BITS = 12, 8
victim_ek, victim_dk = M.keygen_internal(hashlib.sha3_256(b"victim-d").digest(),
                                         hashlib.sha3_256(b"victim-z").digest(), P)

# 1. Weak m: the attacker sees only (ek, c) and knows the RNG design.
t_victim = 3001
m_victim = weak_rng(t_victim, b"enc")
K_victim, c_victim = M.encaps_internal(victim_ek, m_victim, P)
t0 = time.time()
found = None
for t in range(1 << ENC_BITS):
    K_try, c_try = M.encaps_internal(victim_ek, weak_rng(t, b"enc"), P)
    if c_try == c_victim:
        found = (t, K_try)
        break
report(f"1 weak m ({ENC_BITS}-bit RNG state): shared key recovered from (ek, c) alone",
       found is not None and found[1] == K_victim,
       f"after {found[0] + 1 if found else 'n/a'} Encaps calls, {time.time() - t0:.0f} s")

# 2. Round-3 style m <- H(m): same attack, one extra hash per guess.
m_hashed = M.H(weak_rng(t_victim, b"enc"))
K_h, c_h = M.encaps_internal(victim_ek, m_hashed, P)
found_h = None
for t in range(1 << ENC_BITS):
    K_try, c_try = M.encaps_internal(victim_ek, M.H(weak_rng(t, b"enc")), P)
    if c_try == c_h:
        found_h = (t, K_try)
        break
report("2 hashing the RNG output first (round-3 m <- H(m)) adds no entropy",
       found_h is not None and found_h[1] == K_h,
       f"recovered after {found_h[0] + 1 if found_h else 'n/a'} guesses")

# 3. Hedged m = SHAKE256(secret state || RNG output || ek): same weak RNG, but
#    the encapsulator also holds a 32-byte secret the attacker does not know.
hedge_secret = hashlib.sha3_256(b"encapsulator long-term secret").digest()


def hedged_m(rng_out, ek):
    return hashlib.shake_256(b"hedge/" + hedge_secret + rng_out + ek).digest(32)


K_hd, c_hd = M.encaps_internal(victim_ek, hedged_m(weak_rng(t_victim, b"enc"), victim_ek), P)
hits = 0
for t in range(1 << ENC_BITS):                    # attacker's best guess without the secret
    _, c_try = M.encaps_internal(victim_ek, weak_rng(t, b"enc"), P)
    hits += c_try == c_hd
    _, c_try = M.encaps_internal(victim_ek, M.H(weak_rng(t, b"enc")), P)
    hits += c_try == c_hd
report("3 hedged m: enumerating the weak RNG no longer finds the key", hits == 0,
       f"{hits} matches in {2 << ENC_BITS} guesses")
K_check = M.decaps_internal(victim_dk, c_hd, P)
report("3 hedged m is still an ordinary ML-KEM encapsulation (receiver unchanged)",
       K_check == K_hd)

# 4. Weak key generation: d and z from an 8-bit RNG state; attacker sees ek.
tk = 77
ek_w, dk_w = M.keygen_internal(weak_rng(tk, b"d"), weak_rng(tk, b"z"), P)
rebuilt = None
for t in range(1 << KG_BITS):
    ek_t, dk_t = M.keygen_internal(weak_rng(t, b"d"), weak_rng(t, b"z"), P)
    if ek_t == ek_w:
        rebuilt = dk_t
        break
K_s, c_s = M.encaps_internal(ek_w, hashlib.sha3_256(b"honest sender m").digest(), P)
report(f"4 weak d ({KG_BITS}-bit RNG state): decapsulation key rebuilt from ek",
       rebuilt is not None and M.decaps_internal(rebuilt, c_s, P) == K_s,
       "(attacker then decapsulates an honest ciphertext)")

print(f"TOTAL FAILURES: {fails}")
sys.exit(1 if fails else 0)
