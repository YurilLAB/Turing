"""Small pure-Python ML-KEM (FIPS 203, August 2024) used as a test-vector oracle
by the testing-ci-cd notes (research/notes/pq/testing-ci-cd.md).

(The "tcc_" prefix keeps it apart from other researchers' scripts in this
folder; cca_mlkem_ref.py is a separate, independently written ML-KEM.)

This is a test oracle, not an implementation to ship: it is slow, it is not
constant-time, and it keeps secrets in Python integers. It follows the
algorithms of FIPS 203 as numbered in the final standard
(research/papers/nist-fips-203-ml-kem.pdf):

  Alg. 3-6  BitsToBytes, BytesToBits, ByteEncode_d, ByteDecode_d (Sec. 4.2.1)
  Alg. 7    SampleNTT (pdf page 32)       Alg. 8  SamplePolyCBD_eta
  Alg. 9-12 NTT, NTT^-1, MultiplyNTTs, BaseCaseMultiply
  Alg. 13   K-PKE.KeyGen (pdf page 38)    Alg. 14 K-PKE.Encrypt (page 39)
  Alg. 15   K-PKE.Decrypt
  Alg. 16-18 ML-KEM.KeyGen/Encaps/Decaps_internal (Decaps: pdf page 43)
  Sec. 7.2 / 7.3 input checks (ek modulus check, dk hash check, lengths)
  Table 2 (pdf page 48) parameter sets.

The flag ipd=True reproduces the initial public draft behaviour for key
generation: G(d) instead of G(d || k). FIPS 203 Appendix C.2 (pdf page 56,
printed page 47) says domain separation "was added to K-PKE.KeyGen" in the
final version. The matrix index order is the final one in both modes
(A[i,j] = SampleNTT(rho || j || i)), matching the "A-hat fix" that the C2SP
CCTV README describes.

Run the checks with research/scripts/pq/tcc_check_pq_vectors.py.
"""
import hashlib

Q = 3329
N = 256

PARAMS = {
    # name: (k, eta1, eta2, du, dv), FIPS 203 Table 2
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]


def H(s):
    return hashlib.sha3_256(s).digest()


def J(s):
    return hashlib.shake_256(s).digest(32)


def G(s):
    h = hashlib.sha3_512(s).digest()
    return h[:32], h[32:]


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def byte_encode(f, d):
    """Alg. 5: little-endian bit packing of 256 d-bit integers."""
    acc = 0
    for i, a in enumerate(f):
        acc |= (a % (1 << d) if d < 12 else a % Q) << (i * d)
    return acc.to_bytes(32 * d, "little")


def byte_decode(b, d):
    """Alg. 6: inverse of byte_encode; for d = 12 the values are reduced mod q."""
    acc = int.from_bytes(b, "little")
    mask = (1 << d) - 1
    m = (1 << d) if d < 12 else Q
    return [((acc >> (i * d)) & mask) % m for i in range(N)]


def compress(x, d):
    # round(2^d / q * x) mod 2^d, ties rounded up (FIPS 203 eq. 4.7)
    return ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)


def decompress(y, d):
    # round(q / 2^d * y), ties rounded up (FIPS 203 eq. 4.8)
    return (Q * y + (1 << (d - 1))) >> d


def sample_ntt(b, stats=None):
    """Alg. 7. The XOF output is read three bytes at a time; stats, if given,
    records how many XOF bytes were consumed."""
    need = 840
    while True:
        stream = hashlib.shake_128(b).digest(need)
        a, j, pos = [], 0, 0
        while j < N and pos + 3 <= need:
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = c1 // 16 + 16 * c2
            if d1 < Q:
                a.append(d1)
                j += 1
            if d2 < Q and j < N:
                a.append(d2)
                j += 1
        if j == N:
            if stats is not None:
                stats.append(pos)
            return a
        need *= 2


def sample_cbd(b, eta):
    """Alg. 8."""
    bits = int.from_bytes(b, "little")
    f = []
    for i in range(N):
        x = sum((bits >> (2 * i * eta + j)) & 1 for j in range(eta))
        y = sum((bits >> (2 * i * eta + eta + j)) & 1 for j in range(eta))
        f.append((x - y) % Q)
    return f


def ntt(f):
    """Alg. 9."""
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
    """Alg. 10."""
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
    """Alg. 11 and 12."""
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def gen_matrix(rho, k, stats=None):
    return [[sample_ntt(rho + bytes([j, i]), stats) for j in range(k)] for i in range(k)]


class MLKEM:
    def __init__(self, name, ipd=False):
        self.name = name
        self.k, self.eta1, self.eta2, self.du, self.dv = PARAMS[name]
        self.ipd = ipd
        k, du, dv = self.k, self.du, self.dv
        self.ek_len = 384 * k + 32
        self.dk_len = 768 * k + 96
        self.ct_len = 32 * (du * k + dv)

    # --- K-PKE ---------------------------------------------------------
    def pke_keygen(self, d, stats=None):
        k = self.k
        rho, sigma = G(d) if self.ipd else G(d + bytes([k]))
        A = gen_matrix(rho, k, stats)
        n = 0
        s, e = [], []
        for _ in range(k):
            s.append(sample_cbd(PRF(self.eta1, sigma, n), self.eta1))
            n += 1
        for _ in range(k):
            e.append(sample_cbd(PRF(self.eta1, sigma, n), self.eta1))
            n += 1
        s_hat = [ntt(p) for p in s]
        e_hat = [ntt(p) for p in e]
        t_hat = []
        for i in range(k):
            acc = [0] * N
            for j in range(k):
                acc = add(acc, mul_ntt(A[i][j], s_hat[j]))
            t_hat.append(add(acc, e_hat[i]))
        ek = b"".join(byte_encode(p, 12) for p in t_hat) + rho
        dk = b"".join(byte_encode(p, 12) for p in s_hat)
        return ek, dk

    def pke_encrypt(self, ek, m, r):
        k, du, dv = self.k, self.du, self.dv
        t_hat = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
        rho = ek[384 * k:384 * k + 32]
        A = gen_matrix(rho, k)
        n = 0
        y, e1 = [], []
        for _ in range(k):
            y.append(sample_cbd(PRF(self.eta1, r, n), self.eta1))
            n += 1
        for _ in range(k):
            e1.append(sample_cbd(PRF(self.eta2, r, n), self.eta2))
            n += 1
        e2 = sample_cbd(PRF(self.eta2, r, n), self.eta2)
        y_hat = [ntt(p) for p in y]
        u = []
        for i in range(k):
            acc = [0] * N
            for j in range(k):
                acc = add(acc, mul_ntt(A[j][i], y_hat[j]))  # A-transpose
            u.append(add(ntt_inv(acc), e1[i]))
        mu = [decompress(b, 1) for b in byte_decode(m, 1)]
        acc = [0] * N
        for j in range(k):
            acc = add(acc, mul_ntt(t_hat[j], y_hat[j]))
        v = add(add(ntt_inv(acc), e2), mu)
        c1 = b"".join(byte_encode([compress(x, du) for x in p], du) for p in u)
        c2 = byte_encode([compress(x, dv) for x in v], dv)
        return c1 + c2

    def pke_decrypt(self, dk, c):
        k, du, dv = self.k, self.du, self.dv
        c1, c2 = c[:32 * du * k], c[32 * du * k:]
        u = [[decompress(x, du) for x in byte_decode(c1[32 * du * i:32 * du * (i + 1)], du)] for i in range(k)]
        v = [decompress(x, dv) for x in byte_decode(c2, dv)]
        s_hat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
        acc = [0] * N
        for j in range(k):
            acc = add(acc, mul_ntt(s_hat[j], ntt(u[j])))
        w = sub(v, ntt_inv(acc))
        return byte_encode([compress(x, 1) for x in w], 1)

    # --- ML-KEM internal algorithms ------------------------------------
    def keygen(self, d, z, stats=None):
        ek, dk_pke = self.pke_keygen(d, stats)
        return ek, dk_pke + ek + H(ek) + z

    def encaps(self, ek, m):
        K, r = G(m + H(ek))
        return K, self.pke_encrypt(ek, m, r)

    def decaps(self, dk, c):
        k = self.k
        dk_pke = dk[:384 * k]
        ek_pke = dk[384 * k:768 * k + 32]
        h = dk[768 * k + 32:768 * k + 64]
        z = dk[768 * k + 64:768 * k + 96]
        m2 = self.pke_decrypt(dk_pke, c)
        K2, r2 = G(m2 + h)
        Kbar = J(z + c)
        c2 = self.pke_encrypt(ek_pke, m2, r2)
        return K2 if c2 == c else Kbar

    # --- input checks of Sec. 7.2 and 7.3 -------------------------------
    def ek_check(self, ek):
        """Type check (length) and modulus check."""
        if len(ek) != self.ek_len:
            return False
        k = self.k
        for i in range(k):
            chunk = ek[384 * i:384 * (i + 1)]
            if byte_encode(byte_decode(chunk, 12), 12) != chunk:
                return False
        return True

    def dk_check(self, dk):
        """Type check (length) and hash check."""
        if len(dk) != self.dk_len:
            return False
        k = self.k
        return H(dk[384 * k:768 * k + 32]) == dk[768 * k + 32:768 * k + 64]
