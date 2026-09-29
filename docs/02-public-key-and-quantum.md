# 02. Public-key crypto, RSA and quantum safety

## Symmetric vs asymmetric

| | Symmetric (Turing) | Asymmetric (RSA, ECC, ML-KEM) |
|---|---|---|
| Keys | One shared secret key | Public key encrypts, private key decrypts |
| Speed | Fast (GB/s) | Thousands of times slower |
| Job | Encrypt the data | Deliver a key to someone you never met |

Real systems use both, an arrangement called hybrid encryption: public-key
crypto delivers a random file key, and a symmetric cipher encrypts the data
with it.

## RSA

1. Choose secret primes p, q. Compute n = p·q.
2. Compute φ = (p-1)(q-1), choose e, and compute d with e·d ≡ 1 (mod φ).
3. Encrypt c = m^e mod n. Decrypt m = c^d mod n.

A worked example: p=61 and q=53 give n=3233 and φ=3120, and we use e=17 and
d=2753. Encrypting m=65 gives c = 65^17 mod 3233 = 2790, and decrypting with
2790^2753 mod 3233 gives 65 again.

Security rests on factoring n. Textbook RSA is deterministic and malleable
(ciphertexts can be multiplied), so real RSA needs OAEP padding. The raw maths
alone is not a secure system.

## What quantum computers break

Shor's algorithm factors and solves discrete logarithms in polynomial time.
That breaks RSA and elliptic curves completely, and larger keys don't help.
The threat is already live: "harvest now, decrypt later".

Grover's algorithm gives a square-root speedup on key search, so a 256-bit
key keeps about 128-bit security. We decided that Turing uses 256-bit keys.

## Post-quantum replacements (NIST FIPS 203/204/205, 2024)

Lattices give ML-KEM (Kyber) and ML-DSA (Dilithium). Their hard problem is
Learning With Errors: given b = A·s + e (mod q), with small random noise e,
recover s. Without the noise this is linear algebra, and with it no known
classical or quantum algorithm is efficient. It is the same principle as an
S-box: non-linearity defeats the algebra.

SLH-DSA (SPHINCS+) is hash-based and is secure if the hash is secure. Classic
McEliece and HQC are code-based, and McEliece (1978) is still unbroken.

## Why Turing does not invent the public-key part

Two schemes that survived years of expert review in the NIST competition fell
in 2022. Rainbow was a round-3 finalist signature scheme, and Beullens
recovered a secret key for the level-1 parameters in about 53 hours on a
laptop ("Breaking Rainbow Takes a Weekend on a Laptop", CRYPTO 2022). SIKE had
advanced to round 4 as a key-exchange candidate, and Castryck and Decru broke
SIKEp434 in about 10 minutes on a single core ("An Efficient Key Recovery
Attack on SIDH", EUROCRYPT 2023, preprint July 2022).

Public-key schemes carry far more algebraic structure than symmetric
ciphers, and structure is what attackers exploit.

Turing's public-key layer therefore uses vetted implementations; the data
itself is encrypted with the Turing cipher. The planned hybrid KEM, X-Wing
(X25519 + ML-KEM-768), is specified in an IETF CFRG Internet-Draft
(draft-connolly-cfrg-xwing-kem, version 10, March 2026). It is not an RFC,
so the implementation must track the draft version it follows.

Update (step 12): we decided that Turing's post-quantum part should be its
own rather than X-Wing. Turing-1026 (docs/16) keeps the lesson above by
inventing no new structure. Its hard problem is plain LWE, the one FrodoKEM
rests on, with no ring or module. Its encryption is the textbook
Lindner-Peikert scheme, and its chosen-ciphertext security comes from a
published transform. What is Turing's own is the parameters (chosen with
reproduced attack-cost and exact failure computations), the hashing, the
combination of transform ingredients and the implementation, each checked by
Bombe. The risks that remain are listed in docs/16.

Correction (review during step 7): an earlier version of this document said
SIKE fell "in about an hour" and called both schemes finalists. The paper's
own figure is about 10 minutes, and SIKE was a round-4 candidate, not a
finalist.
