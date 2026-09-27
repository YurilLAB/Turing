"""Pure-Python ML-KEM (FIPS 203) reference, written for research experiments.

Reproduces: FIPS 203 (August 13, 2024), Algorithms 2-21, including the
Section 7 input checks (type check, modulus check, hash check) and the
implicit-rejection decapsulation of Algorithm 18.
Source: research/papers/nist-fips-203-ml-kem.pdf, Sections 4-8.

This is NOT production code: it is slow, not constant time, and keeps
secrets in Python integers. It exists so the notes in
research/notes/pq/cca-transforms-and-binding.md can check claims by running
them (validated against NIST ACVP vectors and C2SP/CCTV vectors by
mlkem_validate.py).

Hooks for experiments (default = FIPS 203 behaviour):
  * decaps_internal(..., compare=...) lets a test swap the ciphertext
    comparison (e.g. a strcmp-like early exit) to show which vectors catch it.
  * decaps_internal(..., rejection_key=...) lets a test swap the implicit
    rejection key derivation (e.g. the FO_M variant of Kramer-Struck-
    Weishaupl that also hashes H(ek)).
"""
import hashlib

N = 256
Q = 3329
ZETA = 17

PARAMS = {
    # name: (k, eta1, eta2, du, dv)   FIPS 203 Table 2
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


ZETAS = [pow(ZETA, bitrev7(i), Q) for i in range(128)]           # Alg 9/10
GAMMAS = [pow(ZETA, 2 * bitrev7(i) + 1, Q) for i in range(128)]  # Alg 11


# ---------------------------------------------------------------- hashes (4.1)
def H(s):
    return hashlib.sha3_256(s).digest()


def J(s):
    return hashlib.shake_256(s).digest(32)


def G(s):
    d = hashlib.sha3_512(s).digest()
    return d[:32], d[32:]


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# ------------------------------------------------------- encodings (4.2.1)
def byte_encode(F, d):
    """Algorithm 5: ByteEncode_d (little-endian bit order)."""
    out = bytearray(32 * d)
    bit = 0
    for a in F:
        for j in range(d):
            if (a >> j) & 1:
                out[bit >> 3] |= 1 << (bit & 7)
            bit += 1
    return bytes(out)


def byte_decode(B, d):
    """Algorithm 6: ByteDecode_d. For d = 12 the result is reduced mod q."""
    m = Q if d == 12 else (1 << d)
    bits = int.from_bytes(B, "little")
    mask = (1 << d) - 1
    return [((bits >> (i * d)) & mask) % m for i in range(N)]


def compress(x, d):
    # round((2^d / q) * x) mod 2^d, exact integer arithmetic (q is odd)
    return ((2 * (x << d) + Q) // (2 * Q)) % (1 << d)


def decompress(y, d):
    # round((q / 2^d) * y)
    return (Q * y + (1 << (d - 1))) >> d


# ----------------------------------------------------------- sampling (4.2.2)
def sample_ntt(B):
    """Algorithm 7: rejection sampling from SHAKE128(B) into T_q."""
    length = 840
    while True:
        stream = hashlib.shake_128(B).digest(length)
        a, pos = [], 0
        while len(a) < N and pos + 3 <= length:
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = (c1 // 16) + 16 * c2
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < N:
                a.append(d2)
        if len(a) == N:
            return a
        length *= 2  # "unlucky" seeds: squeeze more (prefix-consistent XOF)


def sample_cbd(B, eta):
    """Algorithm 8: centred binomial distribution D_eta."""
    bits = int.from_bytes(B, "little")
    f = []
    for i in range(N):
        x = sum((bits >> (2 * i * eta + j)) & 1 for j in range(eta))
        y = sum((bits >> (2 * i * eta + eta + j)) & 1 for j in range(eta))
        f.append((x - y) % Q)
    return f


# ---------------------------------------------------------------- NTT (4.3)
def ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = z * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def mul_ntt(f, g):
    """Algorithms 11-12: MultiplyNTTs / BaseCaseMultiply."""
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def psub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


# ----------------------------------------------------------------- K-PKE (5)
def kpke_keygen(d, params, ipd=False):
    k, eta1, _, _, _ = params
    # Alg 13 line 1. FIPS 203 final: G(d || k). The ipd (Aug 2023) used G(d);
    # ipd=True reproduces it, for the CCTV accumulated hashes (App. C.2).
    rho, sigma = G(d) if ipd else G(d + bytes([k]))
    A = [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]
    n = 0
    s = []
    for _ in range(k):
        s.append(sample_cbd(PRF(eta1, sigma, n), eta1)); n += 1
    e = []
    for _ in range(k):
        e.append(sample_cbd(PRF(eta1, sigma, n), eta1)); n += 1
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    t_hat = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = padd(acc, mul_ntt(A[i][j], s_hat[j]))
        t_hat.append(padd(acc, e_hat[i]))
    ek = b"".join(byte_encode(t, 12) for t in t_hat) + rho
    dk = b"".join(byte_encode(x, 12) for x in s_hat)
    return ek, dk


def kpke_encrypt(ek, m, r, params, noise_hook=None):
    k, eta1, eta2, du, dv = params
    t_hat = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:384 * k + 32]
    A = [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]
    n = 0
    y = []
    for _ in range(k):
        y.append(sample_cbd(PRF(eta1, r, n), eta1)); n += 1
    e1 = []
    for _ in range(k):
        e1.append(sample_cbd(PRF(eta2, r, n), eta2)); n += 1
    e2 = sample_cbd(PRF(eta2, r, n), eta2)
    if noise_hook is not None:                 # experiments only: break noise
        y, e1, e2 = noise_hook(y, e1, e2)
    y_hat = [ntt(x) for x in y]
    u = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = padd(acc, mul_ntt(A[j][i], y_hat[j]))   # A^T o y
        u.append(padd(ntt_inv(acc), e1[i]))
    mu = [decompress(b, 1) for b in byte_decode(m, 1)]
    acc = [0] * N
    for j in range(k):
        acc = padd(acc, mul_ntt(t_hat[j], y_hat[j]))
    v = padd(padd(ntt_inv(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, du) for x in ui], du) for ui in u)
    c2 = byte_encode([compress(x, dv) for x in v], dv)
    return c1 + c2


def kpke_decrypt(dk, c, params):
    k, _, _, du, dv = params
    c1, c2 = c[:32 * du * k], c[32 * du * k:32 * (du * k + dv)]
    u = [[decompress(x, du) for x in byte_decode(c1[32 * du * i:32 * du * (i + 1)], du)]
         for i in range(k)]
    v = [decompress(x, dv) for x in byte_decode(c2, dv)]
    s_hat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * N
    for j in range(k):
        acc = padd(acc, mul_ntt(s_hat[j], ntt(u[j])))
    w = psub(v, ntt_inv(acc))
    return byte_encode([compress(x, 1) for x in w], 1)


# ------------------------------------------------------- ML-KEM internal (6)
def keygen_internal(d, z, params, ipd=False):
    ek, dk_pke = kpke_keygen(d, params, ipd)              # Alg 16
    return ek, dk_pke + ek + H(ek) + z


def encaps_internal(ek, m, params, noise_hook=None):
    K, r = G(m + H(ek))                                   # Alg 17
    return K, kpke_encrypt(ek, m, r, params, noise_hook)


def _ct_equal(a, b):
    return a == b


def _rejection_key_fips203(z, c, ek):
    return J(z + c)                                       # Alg 18 line 7


def decaps_internal(dk, c, params, compare=_ct_equal,
                    rejection_key=_rejection_key_fips203):
    k = params[0]
    dk_pke = dk[0:384 * k]                                # Alg 18
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m_ = kpke_decrypt(dk_pke, c, params)
    K_, r_ = G(m_ + h)
    K_bar = rejection_key(z, c, ek_pke)
    c_ = kpke_encrypt(ek_pke, m_, r_, params)
    return K_ if compare(c, c_) else K_bar


# ----------------------------------------------------- input checks (7.2/7.3)
def check_ek(ek, params):
    k = params[0]
    if len(ek) != 384 * k + 32:                           # type check
        return False
    for i in range(k):                                    # modulus check (7.1)
        chunk = ek[384 * i:384 * (i + 1)]
        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            return False
    return True


def check_dk(dk, params):
    k = params[0]
    if len(dk) != 768 * k + 96:                           # type check
        return False
    return H(dk[384 * k:768 * k + 32]) == dk[768 * k + 32:768 * k + 64]  # (7.2)


def check_ct(c, params):
    k, _, _, du, dv = params
    return len(c) == 32 * (du * k + dv)


# ------------------------------------------------ public API with checks (7)
def keygen(params, rng):
    d, z = rng(32), rng(32)
    return keygen_internal(d, z, params)


def encaps(ek, params, rng):
    if not check_ek(ek, params):
        raise ValueError("encapsulation key check failed")
    return encaps_internal(ek, rng(32), params)


def decaps(dk, c, params):
    if not (check_ct(c, params) and check_dk(dk, params)):
        raise ValueError("decapsulation input check failed")
    return decaps_internal(dk, c, params)
