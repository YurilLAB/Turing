"""Evaluate published quantum security bounds at Turing's sizes, for
research/notes/pq/quantum-crypto-and-quantum-attacks.md (sections 5.6-5.7).

Every formula below is copied from the primary source named next to it; this
script only plugs in numbers (n = block size, k = key size) and prints log2
values. Nothing here is a new security claim.

  1. FX / whitening keys. Jaeger, Song, Tessaro, "Quantum key-length
     extension", TCC 2021 (ePrint 2021/579), Sec. 1.1 p. 3: non-adaptive Q1
     bound O(sqrt(p^2 q / 2^(k+n))), so breaking needs about 2^((k+n)/3)
     queries in total; this matches the offline-Simon attack of Bonnetain et
     al. ASIACRYPT 2019 (Table 1). In Q2 the Leander-May attack (ASIACRYPT
     2017) costs about 2^(k/2) (whitening adds nothing).
  2. Double encryption with independent keys. Jaeger-Song-Tessaro Sec. 1.2
     pp. 4-5: Omega(2^(2k/3)) queries even in Q2 (claw finding, Kaplan 2014:
     Theta(N^(2/3)) with N = 2^k).
  3. t-round key-alternating cipher (random permutations, independent round
     keys, non-adaptive adversary). Bai, Esmaili, Mantri, arXiv 2412.05026v3,
     abstract p. 1: Q1 Omega(2^(tn/(2t+1))), classical Omega(2^(tn/(t+1))),
     Q2 Omega(2^((t-1)n/(2t))); Q1 key recovery O(2^(alpha n)) with
     alpha = t(t+1)/((t+1)^2+1) against classical alpha' = t/(t+1).
  4. Two-key iterated Even-Mansour (LED-like). Degre, Lafontaine,
     Pichollet--Mugnier, Schrottenloher, ePrint 2026/930, abstract: 4 rounds
     in quantum time 2^(7n/9), 6 rounds in 2^n/sqrt(log n), against 2^n for
     exhaustive search on the 2n-bit key.
  5. Quantum PRP/PRF switching (Zhandry 2015, as used in the Saturnin
     specification, round 2, Sec. 4.3.3 p. 31): a random permutation is
     distinguishable from a random function with about 2^(n/3) superposition
     queries (advantage C q^3 / 2^n); classically 2^(n/2).
  6. Saturnin claims (spec round 2, p. 8): quantum CTR-Cascade claim
     D^3 + T^2 + D^2 2^(256-t) / p < 2^224 -> data limit D < 2^(224/3).
  7. Key-tweak insertion TBC (QCB, Bhaumik et al. ASIACRYPT 2021, ePrint
     2020/1304, Proposition 1, PDF p. 15): advantage
     <= 8 sqrt(m q'^2 / 2^k) + sqrt(q2 s0 / (2 * 2^k)).
  8. Keyed sponges in the quantum ideal permutation model (Hosoyamada,
     ASIACRYPT 2025, ePrint 2025/1059, abstract and Theorem 7 p. 29):
     inner-/full-keyed about min(2^(c/3), 2^(kappa/3)) queries; outer-keyed
     (KMAC) about min(2^(c/3), 2^((kappa-r)/2), 2^(r/2)) and only for
     kappa > r.
  9. Sponge quantum indifferentiability (Alagic, Carolan, Majenz, Tokat,
     ePrint 2025/731, Theorem 1.2 p. 6): O(l^3 (q^9 2^(-min(r,c)))^(1/4)).

Run:  python research/scripts/pq/qc_constructions.py
"""
import math

log2 = math.log2
N_TURING, K_TURING = 128, 256


def fx():
    print("=== 1. FX: E_k(x ^ k1) ^ k1 with extra n-bit whitening (Jaeger-Song-Tessaro; Leander-May) ===")
    for k, n, label in ((128, 128, "AES-128-like"), (256, 128, "Turing-like"), (256, 256, "256-bit block")):
        q1 = (k + n) / 3
        print(f"{label}: k = {k}, n = {n}: Q1 needs about 2^{q1:.2f} queries; Grover on k alone 2^{k/2:.0f}; "
              f"Q2 (Leander-May) about 2^{k/2:.0f}; gain over Grover in Q1: {q1 - k/2:+.2f} bits")
    print("Reading: for k = 2n (Turing), (k + n)/3 = k/2, so extra independent whitening adds nothing in Q1 either.")


def double_encryption():
    print("\n=== 2. Double encryption with independent keys (Jaeger-Song-Tessaro Sec. 1.2) ===")
    for k in (128, 256):
        print(f"two {k}-bit keys: Omega(2^(2k/3)) = 2^{2*k/3:.2f} queries (Q2 lower bound, matches Kaplan's "
              f"claw-finding attack); single cipher 2^{k/2:.0f}; Grover on the 2k-bit pair would be 2^{k}")


def kac():
    print("\n=== 3. t-round key-alternating cipher, n = 128 (Bai-Esmaili-Mantri, non-adaptive, ideal model) ===")
    n = N_TURING
    for t in (1, 2, 3, 4, 8, 24):
        q1 = t * n / (2 * t + 1)
        cl = t * n / (t + 1)
        q2 = (t - 1) * n / (2 * t)
        alpha = t * (t + 1) / ((t + 1) ** 2 + 1)
        alpha_c = t / (t + 1)
        print(f"t = {t:2d}: classical >= 2^{cl:6.2f}; Q1 >= 2^{q1:6.2f}; Q2 >= 2^{q2:6.2f}; "
              f"Q1 key recovery 2^{alpha*n:6.2f} vs classical 2^{alpha_c*n:6.2f}")
    print("All three lower bounds stay below 2^(n/2) = 2^64 and 2^n: they are generic block-size bounds for")
    print("random round permutations, not key-search bounds for a 256-bit key. t = 1 gives Q2 >= 2^0 (the")
    print("known polynomial Simon break); from t = 2 on the Q2 bound is exponential.")


def two_key_iem():
    print("\n=== 4. Two-key iterated Even-Mansour (Degre et al., ePrint 2026/930 abstract), n = 128 ===")
    n = N_TURING
    print(f"4 rounds: 2^(7n/9) = 2^{7*n/9:.2f}; 6 rounds: 2^n/sqrt(log2 n) = 2^{n - 0.5*log2(log2(n)):.2f}; "
          f"exhaustive search on 2n key bits: 2^{n}")


def prp_prf():
    print("\n=== 5-6. Block size: PRP/PRF switching and Saturnin's data limit ===")
    for n in (128, 256):
        print(f"n = {n}: classical birthday 2^{n/2:.2f} queries; quantum (superposition) 2^{n/3:.2f}")
    print(f"Saturnin quantum CTR-Cascade claim: D^3 < 2^224 -> D < 2^{224/3:.2f} blocks of 256 bits")
    blocks = 2 ** (N_TURING // 2)
    print(f"Turing CTR, classical birthday: 2^{N_TURING // 2} blocks x 16 bytes = 2^{log2(blocks * 16):.0f} bytes per key")


def key_tweak():
    print("\n=== 7. Key-tweak insertion TBC E_(K^T), QCB Prop. 1 (ideal cipher model), k = 256 ===")
    k = K_TURING
    for m_log, qp_log in ((32, 96), (48, 100), (64, 96)):
        adv = 8 * math.sqrt(2.0 ** (m_log + 2 * qp_log - k))
        print(f"m = 2^{m_log} tweaks, q' = 2^{qp_log} offline queries: first term 8*sqrt(m q'^2 / 2^k) = 2^{log2(adv):.2f}")
    print("The bound depends on the key length k, not on the block size n; tweaks must be classical.")


def sponges():
    print("\n=== 8-9. Keyed sponges and sponge indifferentiability (Keccak-f[1600]) ===")
    for name, c, r in (("cSHAKE128/KMAC128", 256, 1344), ("cSHAKE256/KMAC256", 512, 1088)):
        for kappa in (256, 2 * r):
            inner = min(c / 3, kappa / 3)
            if kappa > r:
                outer = f"2^{min(c/3, (kappa - r)/2, r/2):.2f}"
            else:
                outer = "not covered (Theorem 7 needs kappa > r)"
            print(f"{name}: c = {c}, r = {r}, key kappa = {kappa}: inner/full-keyed ~2^{inner:.2f}; "
                  f"outer-keyed (KMAC) {outer}")
        m = min(r, c)  # l = 1: (q^9 2^-m)^(1/4) < 1  <=>  q < 2^(m/9)
        print(f"   indifferentiability, l = 1: advantage ~ (q^9 2^-{m})^(1/4) < 1 needs q < 2^{m/9:.2f}")


def multi_key():
    """10. Hosoyamada, "On post-quantum multi-key security of GCM", ePrint 2026/1718 (preprint), abstract p. 1:
    the trivial multi-key key-search term u p^2 / 2^k can be replaced by sqrt(d p^2 / 2^k) (plus other loss
    terms), d = the largest number of keys under which one nonce appears. Shiba-Iwata, ToSC 2026 (ePrint
    2026/382), abstract: FX with 2^u keys in Q1MK needs Omega(2^((kappa + n - u)/3)) queries; TEM Omega(2^(kappa/3))
    whatever the number of keys."""
    print("\n=== 10. Multi-key quantum key search (Hosoyamada GCM 2026 preprint; Shiba-Iwata ToSC 2026) ===")
    for u_log, k in ((32, 128), (32, 192)):
        p_log = (k - u_log) / 2
        print(f"check against the abstract: u = 2^{u_log}, k = {k}: u p^2 / 2^k = 1 at p = 2^{p_log:.0f}")
    k = K_TURING
    for u_log in (32, 64):
        triv = (k - u_log) / 2
        print(f"Turing-sized key k = {k}, u = 2^{u_log} keys: trivial term reaches 1 at p = 2^{triv:.0f}")
        for d_log in (0, 8, 16):
            print(f"   with nonce randomisation, d = 2^{d_log}: sqrt(d p^2 / 2^k) reaches 1 at p = 2^{(k - d_log)/2:.0f}")
    n = N_TURING
    for u_log in (0, 32, 64):
        print(f"FX in Q1MK, kappa = 256, n = {n}, 2^{u_log} keys: Omega(2^{(k + n - u_log)/3:.2f}) queries")


if __name__ == "__main__":
    fx()
    double_encryption()
    kac()
    two_key_iem()
    prp_prf()
    key_tweak()
    sponges()
    multi_key()
