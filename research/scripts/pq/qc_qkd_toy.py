"""Worked examples for the QKD part of research/notes/pq/quantum-crypto-and-quantum-attacks.md.

Reproduces:
  1. BB84 (Bennett, Brassard, Proc. IEEE Int. Conf. Computers, Systems and
     Signal Processing, Bangalore 1984, pp. 175-179; the eavesdropping
     trade-off is on p. 177): sifting keeps about half the detected photons;
     an intercept-resend eavesdropper who measures in a random basis learns
     about half the sifted bits and causes about 25% errors (the paper:
     measuring every photon in the rectilinear basis learns half and disturbs
     1/4 of re-measured bits; no measurement yields more than 1/2 bit).
  2. The detector-control ("blinding") attack of Lydersen et al., Nature
     Photonics 4 (2010) 686, arXiv 1008.4593 p. 2: Eve re-sends bright trigger
     pulses; Bob's blinded detector clicks only when his basis equals Eve's,
     and then shows Eve's bit. Result: Eve knows every sifted bit, the error
     rate stays at the channel's own level, and Bob's detection rate halves
     (the paper notes this loss hides inside normal channel loss).
     This is a model of the published mechanism, not of the hardware.
  3. E91 (Ekert, PRL 67, 661 (1991)) as described by Pirandola et al., Adv.
     Opt. Photon. 12, 1012 (2020), arXiv 1906.01645, eqs. (48)-(51), p. 14:
     the CHSH combination for the singlet with the given angles is -2*sqrt(2),
     computed here from 4x4 matrices; for the isotropic state
     p|psi><psi| + (1-p) I/4 it is -2*sqrt(2)*p, so the Bell test is passed
     (|E| > 2) only for p > 1/sqrt(2).
  4. Rate-distance: the PLOB bound -log2(1 - eta) (Pirandola et al. eq. (134)-
     (135), p. 62) for fibre with 0.2 dB/km (the "standard fibre-loss rate"
     used in the review's Fig. 11 caption), and the time to agree one 256-bit
     key at the 1002 km twin-field rate of 0.0034 bps (Liu et al., PRL 130,
     210801 (2023), arXiv 2303.15795 p. 9). Caveats from that paper: the
     1002 km key is positive only in the asymptotic regime (finite-size keys
     reach 952 km, 0.0031 bps, p. 10), over ultra-low-loss fibre spools with
     average attenuation below 0.157 dB/km (p. 5), not the 0.2 dB/km used in
     the PLOB table below.

Seeded; prints every number it checks. Run:
    python research/scripts/pq/qc_qkd_toy.py
"""
import math

import numpy as np

SEED = 20260926
rng = np.random.default_rng(SEED)
N_PHOTONS = 200_000


def bb84(eve, channel_error=0.0):
    """Simulate N photons of BB84. eve in {None, 'intercept', 'blind'}.

    Returns (sifted fraction of sent photons, QBER, Eve's knowledge of sifted bits).
    Bases: 0 = rectilinear, 1 = diagonal. Measuring in the wrong basis gives a
    uniformly random bit (the paper's 'random answer').
    """
    a_bits = rng.integers(2, size=N_PHOTONS)
    a_basis = rng.integers(2, size=N_PHOTONS)
    b_basis = rng.integers(2, size=N_PHOTONS)
    detected = np.ones(N_PHOTONS, dtype=bool)
    eve_bits = np.full(N_PHOTONS, -1)

    if eve is None:
        arriving_bits, arriving_basis = a_bits, a_basis
    else:
        e_basis = rng.integers(2, size=N_PHOTONS)
        e_bits = np.where(e_basis == a_basis, a_bits, rng.integers(2, size=N_PHOTONS))
        eve_bits = e_bits
        arriving_bits, arriving_basis = e_bits, e_basis
        if eve == "blind":
            # Blinded detectors: a click only when Bob's basis equals Eve's,
            # and then exactly Eve's bit (Lydersen et al. 2010, p. 2).
            detected = b_basis == e_basis

    b_bits = np.where(b_basis == arriving_basis, arriving_bits, rng.integers(2, size=N_PHOTONS))
    flips = rng.random(N_PHOTONS) < channel_error
    b_bits = b_bits ^ flips
    if eve == "blind":
        b_bits = np.where(detected, np.where(b_basis == e_basis, e_bits, b_bits), b_bits)

    sift = detected & (a_basis == b_basis)
    qber = float(np.mean(a_bits[sift] != b_bits[sift]))
    eve_know = float(np.mean(eve_bits[sift] == b_bits[sift])) if eve else 0.0
    return float(sift.mean()), qber, eve_know


def bb84_demo():
    print("=== 1-2. BB84: sifting, intercept-resend, detector blinding ===")
    for label, eve in (("no eavesdropper", None), ("intercept-resend", "intercept"), ("detector blinding", "blind")):
        sifted, qber, know = bb84(eve)
        extra = ""
        if eve == "intercept":
            # Eve 'knows' a bit only when she chose Alice's basis (1/2); in the
            # other half her guess matches Bob's bit by chance half the time.
            extra = " (Eve measured in the right basis for about 50% of sifted bits)"
        print(f"{label:18s}: sifted/sent = {sifted:.3f}, QBER = {qber:.3f}, "
              f"Eve's bit equals Bob's for {know:.3f} of sifted bits{extra}")
    print("Expected: sifted 0.5, QBER 0; sifted 0.5, QBER 0.25, Eve = Bob on 0.75; sifted 0.25, QBER 0, Eve = Bob on 1.0.")


def e91_demo():
    print("\n=== 3. E91: CHSH value of the singlet (Pirandola et al. eq. 50) ===")
    X = np.array([[0, 1], [1, 0]], dtype=float)
    Z = np.array([[1, 0], [0, -1]], dtype=float)

    def obs(theta):
        # Spin measurement in the X-Z plane at Bloch angle theta: Z at 0, X at pi/2.
        return math.cos(theta) * Z + math.sin(theta) * X

    psi = np.array([0, 1, -1, 0]) / math.sqrt(2)        # (|01> - |10>)/sqrt 2
    rho_singlet = np.outer(psi, psi)

    def corr(rho, a, b):
        return float(np.trace(rho @ np.kron(obs(a), obs(b))))

    a1, a3 = 0.0, math.pi / 2                           # eq. (48)
    b1, b3 = math.pi / 4, 3 * math.pi / 4               # eq. (49)

    def chsh(rho):
        return corr(rho, a1, b1) - corr(rho, a1, b3) + corr(rho, a3, b1) + corr(rho, a3, b3)

    print(f"singlet: E = {chsh(rho_singlet):.6f}; -2*sqrt(2) = {-2*math.sqrt(2):.6f}")
    for p in (1.0, 0.8, 1 / math.sqrt(2), 0.6):
        rho = p * rho_singlet + (1 - p) * np.eye(4) / 4  # eq. (51)
        e = chsh(rho)
        print(f"isotropic p = {p:.4f}: E = {e:.4f}, violates |E| <= 2: {abs(e) > 2 + 1e-12}")


def rate_demo():
    print("\n=== 4. Loss, the PLOB bound and key time ===")
    alpha_db_per_km = 0.2
    for km in (50, 100, 200, 500, 1000):
        eta = 10 ** (-alpha_db_per_km * km / 10)
        plob = -math.log1p(-eta) / math.log(2)   # -log2(1 - eta) without underflow
        print(f"{km:5d} km: transmissivity eta = {eta:.3e}; PLOB bound = {plob:.3e} bits per channel use "
              f"(1.44*eta = {1.4427*eta:.3e}); at 1e9 uses/s at most {plob*1e9:.3e} bit/s")
    rate_bps = 0.0034
    seconds = 256 / rate_bps
    print(f"1002 km twin-field experiment: 0.0034 bps -> one 256-bit key every {seconds:.0f} s = {seconds/3600:.1f} h")


if __name__ == "__main__":
    print(f"seed = {SEED}, photons per run = {N_PHOTONS}")
    bb84_demo()
    e91_demo()
    rate_demo()
