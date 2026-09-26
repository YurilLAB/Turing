# 02 — Public-key crypto, RSA and quantum safety

## Symmetric vs asymmetric

| | Symmetric (Turing) | Asymmetric (RSA, ECC, ML-KEM) |
|---|---|---|
| Keys | One shared secret key | Public key encrypts, private key decrypts |
| Speed | Fast (GB/s) | Thousands of times slower |
| Job | Encrypt the data | Deliver a key to someone you never met |

Real systems use both (**hybrid encryption**): public-key crypto delivers a
random file key, a symmetric cipher encrypts the data with it.

## RSA

1. Choose secret primes p, q. Compute n = p·q.
2. φ = (p-1)(q-1). Choose e; compute d with e·d ≡ 1 (mod φ).
3. Encrypt c = m^e mod n. Decrypt m = c^d mod n.

Worked example: p=61, q=53 → n=3233, φ=3120, e=17, d=2753.
m=65 → c = 65^17 mod 3233 = 2790 → 2790^2753 mod 3233 = 65.

Security rests on factoring n. Textbook RSA is deterministic and malleable
(ciphertexts can be multiplied), so real RSA needs OAEP padding. Raw maths is
not a secure system.

## What quantum computers break

- **Shor's algorithm** factors and solves discrete logarithms in polynomial
  time. RSA and elliptic curves are completely broken; larger keys don't help.
  The threat is already live: "harvest now, decrypt later".
- **Grover's algorithm** gives a square-root speedup on key search. A 256-bit
  key keeps ~128-bit security. **Decision: Turing uses 256-bit keys.**

## Post-quantum replacements (NIST FIPS 203/204/205, 2024)

- **Lattices — ML-KEM (Kyber), ML-DSA (Dilithium).** Learning With Errors:
  given b = A·s + e (mod q) with small random noise e, recover s. Without the
  noise it is linear algebra; with it, no known classical or quantum algorithm
  is efficient. Same principle as an S-box: non-linearity defeats the algebra.
- **Hash-based — SLH-DSA (SPHINCS+).** Secure if the hash is secure.
- **Code-based — Classic McEliece, HQC.** McEliece (1978) is still unbroken.

## Why Turing does not invent the public-key part

Rainbow (broken on a laptop over a weekend, 2022) and SIKE (key recovery in
about an hour on one core, 2022) were post-quantum finalists that fell after
years of expert review. Public-key schemes carry far more algebraic structure
than symmetric ciphers, and structure is what attackers exploit.

Turing's public-key layer therefore uses vetted implementations; the data
itself is encrypted with the Turing cipher.
