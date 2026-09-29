# 17. Turing-1026's security argument

docs/16 chose Turing-1026's parameters and tested its code. This document
does the other half. It writes the scheme down exactly, names the security
theorem that is meant to apply, and goes through each way Turing-1026
departs from the construction that theorem covers, checking that the
theorem's hypotheses still hold after each departure. It ends by sorting the
result into what is proven, what is only argued and what is not covered at
all.

The theorem statements are taken from the research note
`research/notes/pq/cca-transforms-and-binding.md`, whose claim ledger
records where each was read (its C-, F-, M- and B-numbers are cited here).
The papers themselves are not in the repository.

## 1. The scheme, exactly

X(label, input, len) is cSHAKE256 with an empty function name N and
customization string S = "Turing-1026 v1 " + label, producing `len` bytes.
Every label below is distinct, and cSHAKE encodes S with its length, so no
two uses can get the same Keccak input. The parameters are n = 1026,
q = 2^15, nbar = 32, mbar = 8 and noise CBD(18). Pack writes 15-bit
coefficients, least significant bit first (docs/16).

The encryption scheme LP (Lindner-Peikert, `turing::lwe`):

```text
LP.KG(seed_a, r):      A = rows X("matrix", seed_a || le16(i), 2n) mod q, i < n
                       (S, E) = CBD(18) samples from X("key noise", r, ·), S first
                       B = A S + E mod q
                       pk = seed_a || Pack(B);  sk = S
LP.Enc(pk, mu; rho):   (S', E', E'') = CBD(18) samples from X("encryption noise", rho, ·)
                       B' = S' A + E';  C = S' B + E'' + Encode(mu),  Encode(bit) = bit q/2
                       return Pack(B') || Pack(C)
LP.Dec(S, c1):         mu' = Decode(C - B' S), each coefficient to the nearer of 0 and q/2
```

The KEM (`turing::turing1026`; lengths in bytes):

```text
KG(seed):              (seed_a || r || z) = X("key generation", seed, 32+32+32)
                       (pk, S) = LP.KG(seed_a, r);  h = X("public key", pk, 32)
                       (mu_c || salt_c) = X("key check", seed, 32+64)
                       if Decaps(Encaps_d(pk, mu_c, salt_c)) differs: fail     [pair-wise check]
                       return pk, sk = seed   (the expansion is kept in locked memory)
Encaps(pk):            (mu || salt) = X("encapsulation", 64 bytes from the OS, 32+64)
                       return Encaps_d(pk, mu, salt)
Encaps_d(pk, mu, salt):
                       (rho || k) = X("coins", h || mu || salt, 64+32)
                       c = LP.Enc(pk, mu; rho) || salt
                       K = X("shared key", c || k, 32)
                       return (c, K)
Decaps(sk, c):         if |c| != 15,934: error (the only error)
                       (c1 || salt) = c;  mu' = LP.Dec(S, c1)
                       (rho' || k') = X("coins", h || mu' || salt, 64+32)
                       Kbar = X("rejection key", z || h || c, 32)
                       K' = X("shared key", c || k', 32)
                       return K' if LP.Enc(pk, mu'; rho') = c1 else Kbar
                       (both keys always computed; the output starts as Kbar and
                       a mask built from the comparison installs K')
```

Any byte string of the right length is a valid public key or ciphertext.
Each 15-bit field is a coefficient mod 2^15 with no bit left over, so
comparing packed bytes is exactly comparing coefficients.

## 2. The claim and the game

The claim is that Turing-1026 is IND-CCA secure in the classical
random-oracle model (ROM), with every cSHAKE256 label treated as an
independent random oracle, assuming decision-LWE for its two instances. The
bound is dominated by the lattice term, whose concrete size comes from
cryptanalysis (docs/16), as it does for ML-KEM and FrodoKEM (research note,
section 3.3).

In the IND-CCA game, (pk, sk) <- KG(seed) for a uniform seed, b is uniform,
(c*, K_0) <- Encaps(pk), and K_1 is uniform in {0,1}^256. The attacker gets
pk, c*, K_b, the random oracles and a decapsulation oracle for every
c != c*, and outputs b'. Its advantage is |Pr[b' = b] - 1/2|.

## 3. The theorem meant to apply

Turing-1026's transform is the one salted FrodoKEM uses (FrodoKEM ISO
proposal, sections 8.2-8.3 [F5, F6]):

```text
salted FrodoKEM:  seedSE || k = SHAKE(pkh || u || salt);  c = (c1, c2, salt);  ss = SHAKE(c1 || c2 || salt || k)
                  rejection: ss = SHAKE(c1 || c2 || salt || s)
```

This is FrodoKEM round 3's FO-not-bot' (HHK17's FO with implicit rejection,
with the public key's hash in the coin hash and the ciphertext in the key
hash [F1]) plus a public salt in the coins and, through c, in the key.
Proofs for this shape:

- In the classical ROM, tight from IND-CPA: FrodoKEM's specification,
  Theorem 5.1, for the unsalted shape [F11]; and Glabush, Hövelmanns and
  Stebila (IACR CiC 2026) for the salted one. They get multi-target IND-CCA
  tightly from multi-target IND-CPA of the encryption scheme, which
  contains the single-target case [M6].
- The generic form of the bound (HHK17 section 3.3, FO with implicit
  rejection from IND-CPA [C5]) is
  Adv^IND-CCA <= q_RO delta + 3 q_RO / |M| + 3 Adv^IND-CPA.
  With |M| = 2^256, delta = 2^-266.06 and q_RO = 2^64, the first two terms
  are 2^-202.06 and 2^-190.4. The transform costs nothing measurable, and
  the lattice term decides.
- The hypotheses of that bound are IND-CPA of the encryption scheme,
  delta-correctness (delta = E_keys[max_m Pr(decryption of an encryption of
  m fails)]) and a large message space. The explicit-rejection variants
  also need gamma-spread [C4].

## 4. Each departure, and why the hypotheses still hold

| # | Turing-1026 | Reference | Hypothesis at stake | Why it holds |
|---|---|---|---|---|
| D1 | LP with CBD(18), n = 1026, q = 2^15, nbar = 32, mbar = 8, one bit per coefficient | FrodoPKE (also Lindner-Peikert), Gaussian-table noise, nbar = mbar = 8, several bits per coefficient | IND-CPA, delta, \|M\| | The theorems are generic in the encryption scheme. For IND-CPA, the Lindner-Peikert argument (below) reduces it to decision-LWE for the key instance (32 secrets, n samples each) and for the ciphertext instance (8 secrets, n + 32 samples each), the two instances docs/16 prices. delta = 2^-266.06, exactly, and it doesn't depend on the message (the error S'E - E'S + E'' does not involve m), so the max over m is the same number. \|M\| = 2^256. |
| D2 | Rejection key X("rejection key", z \|\| h \|\| c) | SHAKE(c \|\| s) | none: this is the first game hop | Every proof of implicit rejection starts by replacing the rejection value with a truly random function of c. For Turing-1026 that hop costs at most q_rej / 2^256 (the attacker must query the rejection oracle at the secret z), and for the reference q_F / 2^256. After it the two games are the same game. Adding h changes only a public input (Krämer, Struck and Weishäupl make the same argument for FO_M [B16]). It matters for binding (section 5), not for IND-CCA. |
| D3 | Separate labelled oracles for coins, shared key, rejection key, public-key hash, matrix and noise | SHAKE with inputs of different shapes | independent random oracles | The proofs model these as independent oracles. cSHAKE's encoded customization string makes the separation exact. This is the oracle cloning that Bellare, Davis and Günther found done wrongly in three NIST submissions (research note [D1]). |
| D4 | One seed gives (seed_a, r, z); the pair-wise check | independent random s, seedSE, z; no check | key distribution | With X a random oracle, (seed_a, r, z) are uniform and independent unless the attacker queries X at the seed, which has probability q / 2^256. The check makes KG fail only when the check's own ciphertext fails to decrypt, which has probability delta on average over keys. So the distribution of the keys KG returns is within 2^-266 of the unchecked one. |
| D5 | (mu, salt) from X("encapsulation", 64 OS bytes) | uniform u and salt | uniform message and salt | Uniform in the ROM, given at least 256 bits of OS entropy (the seed has 512 bits). |
| D6 | The coins are rho (64 bytes), expanded by a second oracle into S', E', E'' | seedSE, expanded by SHAKE | coins from a random oracle of (h, mu, salt) | Composing two random oracles gives a random oracle from (h, mu, salt) to the coin space, the same structure as the reference. |
| D7 | K = X("shared key", c \|\| k) with k from the coin oracle | the same (ss = SHAKE(c1 \|\| c2 \|\| salt \|\| k)) | none | Identical shape. (HHK17's K = H(m, c) differs from both. K = F(c, G_k(h, m, salt)) is a random function of (m, salt, c) up to a collision of the 256-bit k, q^2 / 2^257, and Bindel et al. show that it does not matter whether K is derived from (m, c) or from m [C13].) |
| D8 | Default-fail constant-time selection | constant-time selection | none | The same function of the inputs. It only changes which way a skipped instruction fails. |
| D9 | Length is the only input check | the same for FrodoKEM | Decaps defined on every ciphertext | Every string of the right length decodes, and the rejection key hashes the whole string, salt included. |

The Lindner-Peikert step (D1) uses two hybrids. Hybrid 1 replaces
B = A S + E by a uniform matrix; the attacker notices only by solving
decision-LWE for one of the 32 columns of S (32 hybrids, each an instance
with n samples). In hybrid 2, with [A | B] uniform,
[B' | S'B + E''] = S'[A | B] + [E' | E''] is decision-LWE with 8 secret
rows and n + 32 samples each (8 hybrids). Then C is Encode(mu) plus a
uniform matrix, which is a one-time pad. So
Adv^IND-CPA <= 32 Adv^LWE(key) + 8 Adv^LWE(ciphertext), with A from its
seed modelled as a random oracle.

The explicit-rejection results in section 5 need gamma-spread. For a fixed
message, the probability of one ciphertext is at most the largest CBD(18)
probability to the power 8 x 1026, counting B' alone:
(C(36, 18) / 2^36)^8208 = 2^-23,973. So gamma >= 23,973 bits.

The statement itself: in the classical ROM, for an attacker making q
random-oracle and decapsulation queries in total,

Adv^IND-CCA(Turing-1026) <= Adv^IND-CCA(salted FO'[LP]) + 3q / 2^256,

where the added term covers the rejection hop in each of the two games (D2)
and the seed hop (D4). The first term is bounded by the theorems of
section 3, and in the generic HHK17 form the whole bound is

<= q delta + 3q / 2^256 + 3 (32 Adv^LWE(key) + 8 Adv^LWE(ciphertext)) + q^2 / 2^257 + 3q / 2^256.

## 5. What this covers and what it does not

Proven, in the classical ROM and by the cited theorems plus the hops above:
single-user IND-CCA from decision-LWE, and the multi-target version
through Glabush, Hövelmanns and Stebila, down to the multi-target IND-CPA
security of LP, which nobody has bounded (next point).

Argued, not proven:

- The quantum random-oracle model. The generic QROM theorems for implicit
  rejection (Jiang et al. 2018; Bindel et al. 2019; Hövelmanns, Hülsing and
  Majenz 2022 [C11-C20]) cover HHK17's shape, and FrodoKEM proves a
  non-tight QROM theorem for its unsalted shape (Theorem 5.8 [F11]). The
  hops above are syntactic (D2 is a PRF-to-random-function switch, which
  QROM proofs also make), so they should carry over, but no paper states
  the QROM theorem for the salted shape with this rejection key. The
  research note's worked example also shows that QROM bounds are
  qualitative: HHK17's says nothing beyond about 2^41 quantum queries, even
  for a perfect lattice.
- Binding. Krämer, Struck and Weishäupl give every MAL binding notion to
  FO_M (rejection key H(z, hpk, c)) with single-seed keys (Schmieg), and
  say salted coins do not change their results [B15, B25-B27]. The research
  note's open question 4 is that no paper proves salted FO_M as one
  theorem.
- Explicit rejection. In a file format a wrong key shows up as a failed
  authentication, so rejection is explicit at the system level. Hövelmanns
  and Kudinov prove explicit rejection as secure as implicit rejection in
  the classical ROM, up to a rare edge case [C24]. With gamma >= 23,973
  bits and delta = 2^-266, the explicit-rejection terms stay negligible.

Not covered:

- The multi-ciphertext security of LWE itself. Bernstein argues it degrades
  with the number of ciphertexts, and Glabush, Hövelmanns and Stebila leave
  it unbounded [M10, M12-M14]. The salt removes the generic collision
  attack, but not this. That is why docs/16 advises a limit on ciphertexts
  per key, stated by the file format.
- Unlucky keys. delta is an average over keys, as the theorems require. How
  the failure rate spreads over individual keys is the subject of docs/16's
  fixed-key section, which proves (Markov, and Chernoff with Jensen over
  the column norms) that at most a 2^-13.6 fraction of keys could exceed
  the 2^-252.4 security level, and finds none near it in 100,000 keys.
- Implementation attacks: faults, power and timing (docs/16 and the
  campaign). The decapsulation fault map (`bombe fault-map`) shows that the
  re-encryption check has no single-fault bypass. The check is two
  independent re-encryptions, compared three ways, with chained default-fail
  selections and the accepted key bound to the comparison.
  `tools/ct_check.py` checks that the release build keeps the verdicts
  apart (it once fused them, research/
  reviews/2026-09-28 R2). Two single faults used to leak without a bypass,
  and redundancy closes both: the rejection key is computed twice and a
  disagreement infected (skipping z in it gave a validity oracle), and
  decryption runs three times in random orders and is voted (a skipped
  rounding step revealed the sign of a noise coefficient, Pessl and Prokop,
  TCHES 2021(2)). Every leak the fault map finds now takes two correlated
  faults (docs/16).
- The concrete lattice term. No reduction gives a number for Adv^LWE, but
  docs/16's attack-cost analysis does.
