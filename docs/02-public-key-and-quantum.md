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

Two schemes that survived years of expert review in the NIST competition fell
in 2022:

- **Rainbow**, a round-3 finalist signature scheme: Beullens recovered a
  secret key for the level-1 parameters in about 53 hours on a laptop
  ("Breaking Rainbow Takes a Weekend on a Laptop", CRYPTO 2022).
- **SIKE**, which had advanced to round 4 as a key-exchange candidate:
  Castryck and Decru broke SIKEp434 in about 10 minutes on a single core
  ("An Efficient Key Recovery Attack on SIDH", EUROCRYPT 2023, preprint
  July 2022).

Public-key schemes carry far more algebraic structure than symmetric
ciphers, and structure is what attackers exploit.

Turing's public-key layer therefore uses vetted implementations; the data
itself is encrypted with the Turing cipher. The planned hybrid KEM, X-Wing
(X25519 + ML-KEM-768), is specified in an IETF CFRG Internet-Draft
(draft-connolly-cfrg-xwing-kem, version 10, March 2026). It is not an RFC,
so the implementation must track the draft version it follows.

Correction (review during step 7): an earlier version of this document said
SIKE fell "in about an hour" and called both schemes finalists. The paper's
own figure is about 10 minutes, and SIKE was a round-4 candidate, not a
finalist.
