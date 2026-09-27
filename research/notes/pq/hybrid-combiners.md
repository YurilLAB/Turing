# Hybrid and multi-KEM combiners, and how real systems deploy post-quantum hybrids

This note covers how two or more key-encapsulation mechanisms (KEMs) are combined into one
KEM that stays secure while at least one component is secure: the published combiner
theorems (Giacon-Heuer-Poettering 2018, Bindel et al. 2019, X-Wing 2024, later work), the
IETF/IRTF drafts and RFCs, NIST SP 800-227's approved way of combining keys, and what deployed
systems (TLS, OpenSSH, Signal, iMessage, Rosenpass, age, OpenPGP) actually do. It ends with
what this means for a Turing KEM layer that combines a standard KEM, a custom lattice component
and X25519. Status checked on 2026-09-27. Mathematics of lattices, decryption failures, FO
transforms, attack costs and candidate families are sibling topics; this note points to them
rather than repeating them. Revision note: a continued run on the same day applied an
independent fact-check (publication status of ABK25 and KSW25, the n-KEM proof being only a
sketch, the key-reuse gap in GHP18, a second X25519 second-preimage, the flat-versus-nested
proof coverage, and several number corrections); those changes are marked "continued run" in
the text and in ledger rows 92-120.

## Key findings

1. **The rule that makes a combiner robust is published and simple:** hash every component's
   shared secret *and* every ciphertext that is not provably C2PRI, plus a domain label, with a
   KDF that behaves like a random oracle / split-key PRF. Then the hybrid is IND-CCA if any one
   component is IND-CCA (GHP18 Theorem 1, any number of KEMs, KDF as a random oracle; ABK25
   Theorems 8-9 against quantum adversaries, published at ACNS 2026, where the n-KEM theorem
   has only a proof sketch). One extra condition was found in the continued run: GHP18 assumes
   the component key pairs exist *only* inside the hybrid. If a component key is also used
   elsewhere (for example an X-Wing key that is also an age recipient), the extended model of
   Millerjord-Stebila-Steckel (IACR CiC 2(4), 2026) applies, and it needs each component's
   output post-processed with a PRF before combining (Sec. 3a).
2. **XOR and "hash the secrets only" are broken** as soon as long-term keys meet a decapsulation
   oracle: two queries recover the key against XOR even when both KEMs are sound (Bindel et al.
   2019 p. 11); NIST says KDF(K1, K2) "does not preserve IND-CCA security, regardless of the
   properties of the KDF" (SP 800-227 Sec. 4.6.3). Reproduced against real ML-KEM-768 + X25519.
3. **Leaving a ciphertext out is an optimisation that needs a proof.** X-Wing omits the ML-KEM
   ciphertext because ML-KEM is C2PRI (X-Wing Theorem 3); raw X25519 is not C2PRI, so its
   ciphertext must be hashed. A custom lattice component has no C2PRI proof, so its ciphertext
   must be hashed; the scripts show the one-query break otherwise.
4. **Status on 2026-09-27:** X-Wing is draft-connolly-cfrg-xwing-kem-11 (23 Sept 2026, Independent
   Submission stream, "Submission Received", intended Informational; technically unchanged from
   -10). The CFRG generic drafts are draft-irtf-cfrg-hybrid-kems-12 and
   draft-irtf-cfrg-concrete-hybrid-kems-04 (both "Waiting for Document Shepherd"); they cover
   exactly two components. TLS hybrids are now RFC 9954 and RFC 10024 (X25519MLKEM768 = 0x11EC);
   SSH hybrids RFC 9941 (sntrup761x25519-sha512) and RFC 10042 (mlkem768x25519-sha256 etc.);
   OpenPGP PQC is RFC 9980 (June 2026).
5. **NIST's position (SP 800-227, Sept 2025):** combine with an SP 800-56C KDF over all secrets
   plus ciphertexts, keys and a domain separator; approved "for any t > 1" if one secret comes
   from an approved KEM (eq. (14)); more than two components are allowed "in the obvious way".
   SP 800-56C Rev. 2 is being revised (announced 6 Jan 2026) to fold KEM secrets and hybrid
   formats in explicitly; no draft yet.
6. **Files have no transcript.** TLS and SSH hash only the concatenated secrets and rely on a
   signed/hashed transcript to bind ciphertexts (RFC 10024 Sec. 6: one "cannot assume a similar
   hybridization is secure in other protocols"). File formats (age, OpenPGP RFC 9980) put the
   binding inside the KEM combiner. Turing's file tool must do the same.
7. **Closest precedents for Turing's file tool:** age v1.3.0 (27 Dec 2025) encrypts file keys to
   X-Wing via HPKE (MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305); RFC 9980 uses an X-Wing-style
   SHA3-256 combiner with AES key wrap and independently generated component keys.
8. **Three or more components are covered by theory and by deployments, not by an IETF/CFRG
   construction.** Proofs: GHP18 (n KEMs, classical ROM), ABK25 (n KEMs against quantum
   adversaries, but Theorem 8 has only a proof sketch). Both need every surviving component to be
   an IND-CCA KEM, which raw X25519 is not. Deployed: Rosenpass (Classic McEliece + Kyber into one
   chaining key, then X25519 in WireGuard) and Mullvad (ML-KEM-1024 XOR HQC-256 with single-use
   keys, then X25519). No three-KEM file format was found.
9. **Where Turing's "twist" can sit safely:** as a third KEM beside X-Wing under a GHP-style
   outer KDF that hashes both ciphertexts and a digest of both public keys (the nested form).
   Every branch of that design rests on a published two-component theorem (X-Wing Theorems 1-3
   inside, GHP18 Theorem 1 outside; the composition is argued in this note, not in a paper,
   ledger row 115). In the published models the result is at least as strong as
   X-Wing whatever the custom component does, but not stronger than its strongest component:
   breaking three 2^256 components one by one costs 2^257.6, not 2^768.
10. **What the proofs do not cover** (my reading, flagged as such): a component implementation
    that shares memory, seed or RNG with the others; decryption-failure probability of the custom
    component (enters the bound as δ); availability (a buggy component makes files
    undecryptable); implementation bugs in extra parsing/arithmetic code. These are the ways an
    added component can hurt.
11. **Binding:** hashing both public keys and both ciphertexts gives all "K binds ..." properties
    from collision resistance alone (KSW25, SCN 2026); Classic McEliece does not bind its public
    key on its own, so hash the key digest. HQC's C2PRI/binding status depends on the spec version
    (fixed in the 22 Aug 2025 HQC spec per KSW25; proved C2PRI for that version by Starfighters).
12. **Component keys must live only inside the hybrid.** GHP18's theorem assumes it; Millerjord,
    Stebila and Steckel (IACR CiC 2(4), 2026) show the combined notion becomes unsatisfiable
    when a component key is also used stand-alone with no post-processing, and give a PRF-based
    fix. hybrid-kems-12 Sec. 5.2 forbids such reuse and derives component keys from one seed to
    prevent it. For Turing: derive the X-Wing and custom seeds from one master seed, and never
    make a Turing X-Wing key also an age recipient key.
13. **Hash a recipient digest for a second reason: many recipients.** Without a per-recipient
    salt, a multi-target attacker's success grows with the number of recipients N (N·Q/2^κ);
    hashing a recipient identifier removes the factor (Kang-Lee-Son 2026, preprint, Lemma 2 and
    Corollary 1). Raw X25519 fails C2PRI in a second way too: c′ = (c*)^-1 mod p gives the same
    secret (their Theorem 1; reproduced by `hyb_x25519_torsion.py`).
14. **Publication status changed in 2026:** ABK25 is in the ACNS 2026 proceedings, KSW25 in SCN
    2026 (first online 27 Sept 2026), StarFortress in IACR CiC 3(1); StarHunters and Kang-Lee-Son
    are still preprints. Two RFCs in this area carry reported technical errata: RFC 10042 #9159
    and RFC 9980 #9023 (the decryptor must have its own ECDH public key for the combiner).

## Plain summary for the owner

A combiner is the small function that turns several shared secrets into the one key Turing uses.
Get it wrong and a weak part leaks the whole key; get it right and a weak part costs nothing.
Getting it right means: hash everything that identifies the exchange (secrets, ciphertexts,
public keys, a label), in fixed-length fields, with SHA-3/KMAC. That is exactly what the
standards and the proofs say, and it is cheap. Two more rules come with it: each component key
is used only inside the hybrid (derive them all from one master seed), and a combiner never
makes the result stronger than its strongest part; it only stops a weak part from doing harm.

## 1. What a KEM combiner is, in plain terms

A KEM (key-encapsulation mechanism) has three algorithms. KeyGen makes a key pair (ek, dk).
Encaps(ek) outputs a fresh random shared secret k and a ciphertext c that carries it. Decaps(dk, c)
recovers k. The sender never chooses k; the KEM does. Turing would then use k (through a KDF) as
the 256-bit key of the symmetric cipher.

A hybrid (or composite, or multi-algorithm) KEM runs several KEMs side by side on the same message:
the public key is (ek1, ek2, ...), the ciphertext is (c1, c2, ...), and the component shared
secrets k1, k2, ... are mixed into one key k by a *combiner* (GHP18 call it the "core function" W,
SP 800-227 calls it KeyCombine). This is GHP18's "parallel combiner" (their Fig. 4, p. 6). The
goal is robustness: the hybrid should be as secure as its strongest component, whichever that
turns out to be.

The security target is IND-CCA. The attacker sees the public key and a challenge ciphertext c*,
receives either the real key k* or a random string, and must say which. It may also ask a
decapsulation oracle to decapsulate any ciphertext except c* itself. A combiner is judged by
whether the hybrid stays IND-CCA when *one* component is IND-CCA and the others are arbitrarily
weak, even chosen by the attacker (GHP18 Sec. 3; X-Wing paper Sec. 3, p. 4).

Why the choice of combiner matters: the decapsulation oracle lets the attacker send a *modified*
hybrid ciphertext that keeps one component of c* and changes another. If the combiner does not
notice which ciphertexts went in, the oracle can be tricked into returning information about k*.

Worked example (recomputed by `hyb_worked_examples.py`, part 1): XOR combiner k = k1 XOR k2 with
two sound KEMs. The attacker holds c* = (c1*, c2*). It makes its own encapsulations (k1', c1') and
(k2', c2'), for which it knows k1' and k2'. It asks the oracle for (c1', c2*) — allowed, because it
differs from c* — and gets k1' XOR k2*; XOR with k1' gives k2*. The query (c1*, c2') gives k1* the
same way. Then k* = k1* XOR k2*. Two queries, no cryptanalysis. This is the "mix-and-match" attack
of Bindel et al. 2019 (Sec. 3.1, p. 11); `hybrid_combiner_checks.py` part B1 runs it against real
ML-KEM-768 and X25519 and recovers the challenge key in 5/5 runs, and fails in 0/5 runs once the
combiner hashes both ciphertexts.

## 2. The published combiner theorems

**GHP18 — Giacon, Heuer, Poettering, "KEM Combiners", PKC 2018 (ePrint 2018/024, full version in
research/papers/).**
- Works for any number n of ingredient KEMs, not just two (Sec. 3, Fig. 4).
- XOR combiner: keeps IND-CPA (Lemma 1, p. 7) but not IND-CCA: one bad ingredient breaks it with
  a single decapsulation query (Lemma 2, p. 7).
- Theorem 1 (p. 10): if the core function W(k1..kn, c1..cn) is a *split-key PRF*, the parallel
  combination is IND-CCA whenever at least one ingredient is IND-CCA, with
  Adv(A) ≤ 2 · (Adv_IND-CCA(K_i)(B) + Adv_skPRF(W, i)(C)), and C makes at most q_d + 1 queries.
- Split-key PRF (Sec. 3.3, Fig. 5, pp. 9-10): W behaves like a random function as long as *one*
  key slot k_i is uniform and secret, even if the attacker chooses all other key slots per query.
- Lemma 6 (p. 22): H(g(k1..kn), x) is a split-key PRF in the random-oracle model if g is
  ε-almost uniform, with advantage at most q_H · ε. Example 3 (p. 22): plain concatenation
  g = k1 || ... || kn qualifies. With a uniform 256-bit k_i this gives q_H · 2^-256 (classical).
- The proof assumes perfectly correct KEMs ("Noting that the KEMs we consider are perfectly
  correct", proof sketch of Theorem 1, p. 10). Lattice KEMs have a small decryption-failure
  probability δ; later proofs (X-Wing Theorem 2, ABK25 Theorems 1, 3, 6-8) carry an explicit δ term.
- Remark after Lemma 1 (p. 7): one could strip the FO transform from each ingredient, XOR the
  IND-CPA KEMs, and apply one FO transform to the result. GHP18 do not pursue this; they cite
  doubts about instantiating FO in the presence of indistinguishability obfuscation and say they
  want generic combiners "that retain CCA security independently of how the ingredient KEMs
  achieve their security". (My addition: such a merged KEM is a new, non-black-box scheme whose
  single FO and joint decryption become a shared point of failure.)

**Bindel, Brendel, Fischlin, Goncalves, Stebila, "Hybrid Key Encapsulation Mechanisms and
Authenticated Key Exchange", PQCrypto 2019 (ePrint 2018/903, full version in research/papers/).**
- Adds adversaries whose quantum power changes over time (notation XcZ: e.g. QcQ = quantum
  adversary with classical access to the decapsulation oracle) (Sec. 2).
- Shows the mix-and-match attack on XOR even when both KEMs are IND-CCA (Sec. 3.1, p. 11).
- Three combiners (Sec. 3, pp. 5, 11-16): XtM (XOR-then-MAC: XOR of key halves plus a one-time MAC
  over c1||c2 keyed by the other halves, Theorem 1); dualPRF, k = PRF(dPRF(k1, k2), c1||c2)
  (Theorem 2, p. 16; models HKDF-Extract then Expand as in TLS 1.3); and a nested combiner N
  modelled on a TLS key schedule.
- Theorem 2 bound: Adv ≤ 2 · (min{Adv(K1), Adv(K2)} + Adv_dPRF + Adv_PRF). These are
  standard-model results (dual-PRF assumption on HKDF/HMAC), for two KEMs.
- The main proofs are for QcQ (post-quantum, classical oracle access) (p. 11). The exception
  is XtM: the paper also argues that XtM reaches full quantum security (QqQ) if one input KEM
  is QqQ-secure and the MAC is QcQ-secure (summary p. 3, discussion in Sec. 3.1.4, p. 15). XtM
  adds a MAC tag to the ciphertext, so it is not the plain "hash everything" shape used by the
  drafts.

**X-Wing — Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, IACR Communications in
Cryptology 1(1), 2024 (research/papers/2024-barbosa-et-al-x-wing-hybrid-kem.pdf).**
- Theorem 1 (p. 9): in the ROM, the generic construction ("QSF": a KEM plus a nominal group,
  hashing k1, k2, the DH ciphertext and DH public key) is IND-CCA with
  Adv ≤ 2Δ_N + Adv_SDH(B) + Adv_C2PRI(KEM, C): classical security from strong Diffie-Hellman,
  *provided the post-quantum KEM is C2PRI*.
- Theorem 2 (p. 13, standard model): Adv ≤ Adv_IND-CCA(KEM, B) + Adv_IND-CCA(KEM, C) + Adv_PRF(H, D)
  + Adv_PRF(H, E) + 2δ, with δ the KEM's correctness bound; the proof "follows closely the proof
  for [GHP18, Theorem 1]".
- Theorem 3 (pp. 16-17): ML-KEM-768 is C2PRI with Adv ≤ (q_g + q_j + 2) / 2^256 when its hashes
  G and J are (classical) random oracles.
- The abstract warns that the guarantees and optimisations are "only possible due to the concrete
  choices that were made, and it may not apply in the general case".

**ABK25 — Alagic, Bajaj, Kocoglu, "The Best of Both KEMs: Securely Combining KEMs in Post-Quantum
Hybrid Schemes", ePrint 2025/1444 (version dated 8 August 2025 in research/papers/). Published in
the ACNS 2026 proceedings (Applied Cryptography and Network Security, LNCS, pp. 32-74,
DOI 10.1007/978-3-032-32560-0_2, first online 22 July 2026; Crossref record). The ePrint page
still labels the paper "Preprint", and the local PDF is the ePrint version, not the published
text.**
- Generalises the X-Wing shortcut to n KEMs in the quantum setting (QPT adversaries).
- How the results are layered (p. 3 and p. 15). Theorems 1, 3 and 8 are *generic*: they assume
  only that the core function F is a split-key PRF, and they hold against quantum (QPT)
  adversaries that query the decapsulation oracle classically. The random-oracle part is
  separate: Theorem 9 shows that a hash modelled as a quantum random oracle is such an F.
- Two caveats on the n-KEM result. Theorem 8 comes with a "Proof sketch" only (p. 15), and
  the paper says it "was submitted to TCC 2025, except for Sections 3.3 and 4, which were added
  shortly after" (p. 5). Sec. 3.3 holds the n-KEM extension and Sec. 4 the KDF analysis. So the
  n-KEM statement was not in the text first reviewed for TCC; whether the ACNS version has a full
  proof was not checked (the published chapter is behind Springer's paywall).
- Theorem 3 (informal, p. 3) / Theorem 8 (formal, p. 15): with
  W = F(k1, ..., kn, c_{ℓ+1}, ..., c_n) — that is, the ciphertexts of KEMs 1..ℓ are omitted — and F
  a split-key PRF, the hybrid is IND-CCA if some KEM_i is IND-CCA and every *other* omitted-
  ciphertext KEM is C2PRI; the bound has a sum of C2PRI advantages, the IND-CCA advantage of
  KEM_i, the split-key-PRF advantage and δ, all times 2.
- Theorem 4 (p. 4) / Theorem 9 (p. 15): H(k1 || ... || kn || x) with H a random oracle and q
  *quantum* queries is a split-key PRF with advantage at most 4·sqrt((q² + q)/|K_i|). The paper
  also sketches that NIST SP 800-56C KDFs (HKDF, KMAC, hash-based) are split-key PRFs in this
  model (Sec. after Theorem 9, p. 15 onward).
- Theorem 2 (informal, p. 3): the "secrets only" combiner W = F(k1, k2), with F a dual PRF, is
  IND-CCA if KEM1 is IND-CCA *and* KEM2 is C2PRI, or the other way round. So hashing only the
  secrets is safe only when the component you are *not* relying on is still C2PRI; it gives no
  protection against a component that fails completely (a broken or malicious KEM need not be
  C2PRI). Raw X25519 is never C2PRI (Sec. 3a), so the TLS/SSH secret-only shape needs its
  transcript.
- Theorem 5 (p. 4): KEMs built with the FO variants U⊥, U̸⊥, U⊥_m, U̸⊥_m are C2PRI in the ROM
  (Adv ≤ (q+1)/|K|) and QROM (Adv ≤ 4·sqrt((q²+q)/|K|)); the paper adapts this to Classic McEliece,
  HQC and ML-KEM, and notes HQC is C2PRI although it is not ciphertext-collision-resistant.

**Other 2026 preprints seen, not needed for Turing's design** (ePrint abstracts read, papers not
read in full): Zhou, Zhang, Jiang, Zhao, "Hybrid KEM Constructions from Classical PKEs and
Post-Quantum KEMs" (ePrint 2026/569) combine a classical *public-key encryption* scheme (ECIES,
PSEC, SM2) with a C2PRI post-quantum KEM and claim IND-CCA in the standard model; Krämer,
Weishäupl, Winderl, "On the Binding Security of KEMs based on RSA and DH" (ePrint 2026/407)
study binding of classical KEMs. Both are preprints (ledger row 108).

What the QROM bound means numerically (`hybrid_combiner_checks.py` part D and
`hyb_factcheck_math.py` part 4, COMPUTED): the Theorem 9 bound 4·sqrt((q² + q)/|K_i|) reaches 1
at q = 2^126 quantum hash queries for a 256-bit component key, at q = 2^94 for a 192-bit key
(FrodoKEM-976's shared secret is 24 bytes) and at q = 2^62 for a 128-bit key (FrodoKEM-640).
This is a limit of the proof, not an attack. It matters only for the component that is meant
to carry the security claim: the bound uses |K_i| of the one secure component i.

Worked reading: the bound is about sqrt(q²/|K_i|) = q/2^(b/2) for a b-bit secret. A b-bit secret
therefore gives at most b/2 bits in this proof, which is the Grover-style square root. So a
128-bit post-quantum claim needs b ≥ 256.

Correction to the earlier draft of this note: hashing a short secret "up" to 256 bits before
combining does *not* help. A b-bit secret hashed to 256 bits still takes at most 2^b values, so
the almost-uniformity ε of GHP18 Lemma 6 stays 2^-b and exhaustive search still costs 2^b
(`hyb_factcheck_math.py` part 5 shows this with b = 16). If the secure component's secret is
short, the only fix is a component with a longer secret (FrodoKEM-1344 and ML-KEM have 32-byte
secrets).

## 3. When ciphertexts and public keys must be hashed, and when they may be left out

The rule that follows from Sections 1-2:

1. **Always hash the ciphertext of any component that is not C2PRI.** Otherwise one broken or
   malleable component gives a legal decapsulation query that returns the challenge key
   (X-Wing paper p. 4, the "pedestrian combiner"; SP 800-227 Sec. 4.6.3 on KDF(K1, K2)).
2. **Raw Diffie-Hellman (X25519 used as a KEM) is not C2PRI.** X-Wing paper p. 4: "X25519, if seen
   as a KEM, is not ciphertext second preimage resistant". A concrete reason: RFC 7748 masks the top
   bit of a received u-coordinate, so flipping bit 255 of the ephemeral key gives a different
   ciphertext with the same DH output. `hybrid_combiner_checks.py` part B2 shows that a combiner
   SHA3(ss_M || ss_X) is broken with one query in 5/5 runs, and X-Wing's combiner (which hashes
   ct_X and pk_X) in 0/5.
3. **An FO-transformed KEM with implicit rejection can be C2PRI** (ML-KEM: X-Wing Theorem 3;
   U⊥-family FO KEMs: ABK25 Theorem 5, applied there to BIKE and adapted to Classic McEliece, HQC
   and ML-KEM; "ML-KEM, (e)FrodoKEM, HQC, Classic McEliece, and various NTRU variants":
   Starfighters abstract, ePrint 2025/1397, IEEE S&P 2026; also cited by
   draft-irtf-cfrg-hybrid-kems-12 Sec. 6.1.2). C2PRI comes from the re-encryption check: a different ciphertext either fails the
   check (and gets a pseudorandom rejection key) or requires a hash collision. A KEM *without*
   the FO re-encryption check is not C2PRI in general; `hybrid_combiner_checks.py` part B3 shows a
   toy LWE KEM (n = 64, q = 3329) where adding 1 to one ciphertext coefficient gives the same key
   in 64/64 trials without FO and 0/64 with FO.
4. **Leaving a ciphertext out is an optimisation, not a security gain.** It saves hashing (X-Wing:
   134 instead of 1222 bytes of SHA3-256 input, paper Sec. 8, p. 19) at the price of an extra
   assumption (C2PRI) and a proof tied to the specific component. For a *custom* lattice component
   nobody has proved C2PRI; its ciphertext must be hashed.
5. **Public keys.** GHP18 and NIST's KeyCombineCCA do not need them for IND-CCA (SP 800-227
   p. 31-32). X-Wing includes pk_X "as a measure of security against multi-target attacks"
   (paper p. 4). The CFRG UniversalCombiner hashes both encapsulation keys, and hashing keys is
   what gives the binding properties (the key k then commits to the public key: LEAK/MAL-BIND-K-PK;
   draft-irtf-cfrg-hybrid-kems-12 Sec. 6.2.2). For large keys one can hash a fixed-length digest
   of the keys instead (ML-KEM itself does this internally: Encaps_internal computes
   (K, r) ← G(m ‖ H(ek)), FIPS 203 Algorithm 17). None of the combiner papers read here proves the
   digest variant directly. Two published facts make it a small step: IND-CCA does not need the
   keys at all (SP 800-227 pp. 31-32; GHP18), and KSW25's binding results need only collision
   resistance of the hash, which a collision-resistant digest preserves. Still, state it as a
   design assumption.
6. **Encoding.** All inputs fixed-length (or length-prefixed), label last, label set suffix-free
   (draft-irtf-cfrg-hybrid-kems-12 Secs. 6.5.1-6.5.2; SP 800-227 pp. 28-29).
   `hybrid_combiner_checks.py` part E shows the collision ("ab"||"c" = "a"||"bc") that variable-length
   concatenation allows, and that per-field length encoding removes it.

**Binding properties (beyond IND-CCA).** Cremers-Dax-Medinger's X-BIND-P-Q notions ask whether
the output key K pins down the public key (K-PK) and the ciphertext (K-CT), against an honest
(HON), key-leaking (LEAK) or key-choosing (MAL) attacker. Findings:
- Krämer-Struck-Weishäupl, "Binding Security of Combined KEMs: An Analysis of Real-World KEM
  Combiners" (ePrint 2025/1416, revised 2025-11-20; published in the SCN 2026 proceedings,
  LNCS pp. 455-473, DOI 10.1007/978-3-032-36264-3_23, first online 27 September 2026, Crossref;
  page numbers below are from the ePrint version; research/papers/2025-kramer-struck-weishaupl-binding-properties-of-kem-combiners.pdf,
  pp. 2, 19-21): a combiner that hashes both public keys and both ciphertexts achieves all 12
  notions of the form "K binds ..." from collision resistance of the hash alone, for any two
  KEMs. If an input is dropped, the combined KEM needs that component to have the property
  itself. Their Table 2 (p. 21) and the text below it record that all KEMs they consider except
  HQC satisfy X-BIND-K-CT, while X-BIND-K-PK holds only in the HON setting for HQC, HQC* and
  BIKE, and not at all for Classic McEliece. "for several combinations, feeding the public key to Combine is more
  important than the ciphertext" (p. 21).
- draft-irtf-cfrg-hybrid-kems-12 Sec. 6.1.4 agrees on McEliece ("provides MAL-BIND-K-CT, but no
  assurance at all of X-BIND-K-PK") and says ML-KEM provides only LEAK-level binding.
- HQC is version-sensitive. KSW25 footnote 11 (p. 20) says their LEAK-BIND-K,PK-CT attack on HQC
  also breaks C2PRI, so HQC cannot be the ciphertext-omitted component; their footnote 9 (p. 19)
  says the HQC team adopted the fixed HQC* variant in the specification of 22 August 2025.
  Starfighters (ePrint 2025/1397, IEEE S&P 2026) proves C2PRI for HQC as specified in that
  August 2025 version (Sec. 4.2, p. 32). ABK25 also claims HQC is C2PRI (p. 4). A Turing design
  that uses HQC must name the exact HQC version.
- For Turing this settles a detail: hashing a digest of all public keys into the combiner is
  cheap and gives K-PK binding for any component choice (including McEliece), which matters for
  a multi-recipient file format.

## 3a. Two conditions added in the continued run: key reuse and many recipients

**Key reuse outside the hybrid (Millerjord, Stebila, Steckel, "Split-key PRFs and Extended
Hybrid Security for KEM Combiners", IACR Communications in Cryptology 2(4), 2026,
DOI 10.62056/ah890lmol, received 2025-10-06, accepted 2025-12-02; file
2026-millerjord-stebila-steckel-split-key-prfs-extended-hybrid-security.pdf).**
- The gap they close (abstract; pp. 2-3): GHP18's theorem "assumes that public keys of the
  combined KEM are generated independently from any instances of the ingredient KEMs". If a
  user also uses a component key pair on its own, an attacker can talk to that component
  directly, and plain IND-CCA of the hybrid does not model this.
- Their model (Sec. 4.1, Definition 12, Figure 10, pp. 15-16): the attacker gets the usual
  decapsulation oracle for the hybrid, plus an *unrestricted* oracle for each component, but
  each component oracle returns a post-processed key Γ_i(K_i). If the Γ_i are identity
  functions the notion is unsatisfiable: the attacker decapsulates each part of the challenge
  ciphertext through the component oracles and runs the combiner itself (p. 15).
- Their construction (Figure 11, p. 17; Theorem 2, p. 16): the hybrid computes
  k = W(PRF_1(k_1, lbl), ..., PRF_n(k_n, lbl), c) with W a split-key PRF and c = c_1 ‖ ... ‖ c_n;
  stand-alone use of component i outputs PRF_i(k_i, c_i). Theorem 2: this is secure in the
  extended model if at least one component is IND-CCA, W is a split-key PRF and the PRF_i are
  PRFs; the bound is a minimum over components of two copies of
  Adv_PRF + Adv_IND-CCA + Adv_W. This is a standard-model result.
- The application they have in mind is S/MIME with KEMs (Sec. 4.3, pp. 22-23): a recipient
  may publish a combined KEM and its ingredient KEMs with the same keys, and the per-message
  key derivation (k to kek) is the post-processing Γ.

What this means for Turing (my reading; the paper does not discuss X-Wing or age). The nested
design in "What this means for Turing" keeps X-Wing byte-identical so that libraries and
vectors can be reused. That is fine. Reusing the *same X-Wing key pair* both inside Turing's
three-way hybrid and as a stand-alone age recipient is the key-reuse case this paper models.
Two safe choices:
1. Do not reuse component key pairs outside the hybrid. draft-irtf-cfrg-hybrid-kems-12 Sec. 5.2
   already says a component key pair "MUST NOT" be reused that way. This is the simple rule.
2. If reuse is wanted, follow Figure 11: pass each component secret through a PRF with a
   Turing-specific label before the combiner, and make sure every stand-alone use also
   post-processes the secret with a PRF over its ciphertext. Whether age's HPKE key schedule
   counts as such a Γ_i was not analysed here (open question 9).

**Many recipients: why hash the recipient public key (Kang, Lee, Son, "On the Necessity of
Public Contexts in Hybrid KEMs: A Case Study of X-Wing", ePrint 2026/140, preprint, received
2026-01-29; file 2026-kang-lee-son-public-contexts-hybrid-kems-x-wing.pdf).**
- Separates two jobs that the public inputs of a combiner do (Sec. I, pp. 1-2): C2PRI (binds
  the key to the ciphertext, for one recipient) and multi-target security (keeps an attacker's
  work against N recipients from adding up).
- A second C2PRI break of raw X25519 (Theorem 1, p. 6): c′ = (c*)^-1 mod p is the
  x-coordinate of P* + T, with T = (0, 0) the point of order 2. Clamping makes the secret
  scalar a multiple of 8, so [sk]T = O and c′ decapsulates to the same secret. The earlier
  script used a different trick (bit 255 is masked); `hyb_x25519_torsion.py` checks this
  one.
- Multi-target (Sec. V, Lemma 2 and Corollary 1, pp. 7-8, random-oracle model, proof
  sketches): if K_i = H(K_shared,i), an attacker with Q hash queries hits one of N recipients
  with probability up to N·Q/2^κ. Salting with a distinct recipient identifier,
  K_i = H(ID(pk_i) ‖ K_shared,i), brings this back to Q/2^κ. Table I (p. 2): with raw X25519 the
  outer combiner must include both c_2 and pk_2; with an HPKE-style DHKEM it needs neither.
- For Turing's file format, where one recipient key receives many files and many recipients
  exist, this is the concrete reason to hash a digest of all recipient public keys into the
  combiner, beyond binding.

## 4. Standards and drafts (status on 2026-09-27)

Status was read from the IETF datatracker API on 2026-09-27
(`https://datatracker.ietf.org/api/v1/doc/document/<name>/?format=json`, state ids decoded with
`/api/v1/doc/state/<id>/`), and every RFC and draft text was re-downloaded from rfc-editor.org /
ietf.org on 2026-09-27 and compared byte for byte with the copies the earlier run saved (all
identical). Copies: scratch `pq/hyb/recheck/`.

Re-checked at the end of the continued run (datatracker API, 2026-09-27): the revisions and
states of the X-Wing, hybrid-kems, concrete-hybrid-kems, hpke-pq, lamps composite-kem and
tls-mlkem drafts are unchanged from the table below.

| document | what it is | status on 2026-09-27 |
|---|---|---|
| draft-connolly-cfrg-xwing-kem-11 (23 Sept 2026) | X-Wing: ML-KEM-768 + X25519, SHA3-256 combiner | Active Internet-Draft, rev 11. Stream: Independent Submission (ISE), ISE state "Submission Received". Intended status Informational (draft header). Not an RFC, not an IRTF/CFRG research-group document (no `draft-irtf-cfrg-xwing-kem` exists: the API returns 404). |
| draft-irtf-cfrg-hybrid-kems-12 (6 July 2026) | generic two-component frameworks UG, UK, CG, CK | Active IRTF (CFRG) document, rev 12, IRTF state "Waiting for Document Shepherd", intended Informational. |
| draft-irtf-cfrg-concrete-hybrid-kems-04 | concrete instantiations of those frameworks | Active IRTF (CFRG) document, rev 04, "Waiting for Document Shepherd", intended Informational. |
| RFC 9954 (July 2026), from draft-ietf-tls-hybrid-design | Hybrid key exchange in TLS 1.3 (generic design) | Published RFC, Informational. |
| RFC 10024 (August 2026), from draft-ietf-tls-ecdhe-mlkem | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 for TLS 1.3 | Published RFC, Standards Track. |
| draft-ietf-tls-mlkem-11 | pure (non-hybrid) ML-KEM in TLS 1.3 | In the RFC Editor queue, state "Blocked"; intended Informational. |
| RFC 9941 (April 2026) | SSH sntrup761x25519-sha512 | Published RFC, Informational. |
| RFC 10042 (August 2026), from draft-ietf-sshm-mlkem-hybrid-kex | SSH hybrid ML-KEM + ECDH methods | Published RFC, Informational. |
| RFC 9980 (June 2026), from draft-ietf-openpgp-pqc | Post-quantum cryptography in OpenPGP (ML-KEM + ECDH composite encryption) | Published RFC, Standards Track. |
| draft-ietf-hpke-pq-05 | PQ and PQ/T hybrid KEMs for HPKE | Active IETF working-group document, rev 05. |
| draft-ietf-lamps-pq-composite-kem-21 | composite ML-KEM for X.509/CMS | Active, in IESG Evaluation, intended Proposed Standard. |
| RFC 9935 (March 2026) | X.509 algorithm identifiers for ML-KEM | Published RFC, Standards Track (context only). |

**Errata on the RFCs above** (rfc-editor.org errata search, fetched 2026-09-27; copies in scratch
`pq/fc-hyb/errata-*.html`):
- RFC 9954: erratum 9136, Verified, Editorial (a section reference to TLS 1.3 corrected from
  4.2.8 to 4.3.8 in Sec. 3.2).
- RFC 10042: erratum 9160, Verified, Editorial ("P/T Hybrid" should read "PQ/T Hybrid" in
  Sec. 5); erratum 9159, Reported (not yet verified), Technical: in Sec. 2.1 the party that must
  abort after failed checks should be the server, not the client.
- RFC 9980: erratum 9023, Reported (not yet verified), Technical: the decryption procedure
  (Sec. 4.2.4) never obtains the recipient's own ecdhPublicKey, although step 9 feeds it to
  multiKeyCombine. The report notes there is no interoperability impact, because the value is in
  the recipient's own public key. The lesson for Turing is general: a combiner that hashes the
  recipient's public key (or a digest of it) needs that key, or its digest, stored with the
  decapsulation key. SP 800-227 Sec. 4.6.1 says the same (ledger row 27).
- RFC 9941 and RFC 10024: no errata found.

### 4.1 X-Wing (draft-connolly-cfrg-xwing-kem-11)

X-Wing fixes every choice: ML-KEM-768, X25519, SHA3-256, a 6-byte label. Sizes (draft Sec. 5.1):
decapsulation key 32 bytes (a seed), encapsulation key 1216 bytes, ciphertext 1120 bytes,
shared secret 32 bytes. The combiner (Sec. 5.3) is

    ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel),   XWingLabel = 5c2e2f2f5e5c ("\.//^\")

Note what is missing: the ML-KEM ciphertext ct_M and the ML-KEM public key pk_M are not hashed.
The draft says (Sec. 6) this is safe only because of how ML-KEM's Fujisaki-Okamoto transform
works, and that "the X-Wing combiner cannot be assumed to be secure, when used with different
KEMs". The security statement (Sec. 6): if SHA3-256, SHA3-512 and SHAKE-256 are modelled as random
oracles, the IND-CCA security of X-Wing is bounded by the IND-CCA security of ML-KEM-768 and the
gap-CDH security of Curve25519. Binding (Sec. 6.1): X-Wing claims MAL-BIND-K-PK and MAL-BIND-K-CT,
with "(TODO: reference to proof)" still in the text, and notes that ML-KEM alone does not achieve
MAL-BIND-K-PK, MAL-BIND-K-CT nor MAL-BIND-K,PK-CT.

Two details a Turing implementer must not get wrong:
- The byte order in the draft (label last) differs from the order printed in the 2024 paper
  (label first, see Sec. 8 below). The draft's test vectors use label-last; the paper's order does
  not reproduce them (checked by script, Sec. 8).
- Key generation expands the 32-byte seed with SHAKE256 to 96 bytes: bytes 0..64 are the ML-KEM
  (d, z) seed, bytes 64..96 the X25519 scalar (Sec. 5.2).

### 4.2 CFRG generic hybrid KEMs (draft-irtf-cfrg-hybrid-kems-12)

This draft defines four frameworks along two axes (its Table 1): is the traditional part a
"nominal group" (raw Diffie-Hellman) or a KEM, and does the design rely on the post-quantum KEM
being C2PRI (ciphertext second-preimage resistant)?

| name | relies on PQ C2PRI? | traditional part |
|---|---|---|
| UG | no | nominal group |
| UK | no | KEM |
| CG | yes | nominal group (X-Wing is a CG instance) |
| CK | yes | KEM |

The two combiners (Sec. 5.1.3):

    UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label) = KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
    C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label)                  = KDF(ss_PQ || ss_T || ct_T || ek_T || label)

Rules the draft sets that matter for Turing:
- The KDF MUST be indifferentiable from a random oracle, also against quantum attackers
  (Sec. 6.1.5); SHA-3 sponges qualify; HKDF only under stated domain conditions.
- All shared secrets MUST be fixed-length; the draft uses plain concatenation and says
  variable-length inputs would need a length prefix or other injective encoding (Sec. 6.5.2).
- Labels go last and the registered label set MUST be suffix-free (Sec. 6.5.1, Sec. 7).
- Default key generation derives both component key pairs from one seed with a PRG (Sec. 5.2);
  separate component keys weaken binding from MAL-BIND to LEAK-BIND, and a component key pair
  MUST NOT be reused outside the hybrid (Sec. 5.2). The draft adds that separate key generation
  "should only be used in environments where implementations of component algorithms do not
  allow decapsulation keys to be imported or exported"; otherwise "additional measures" are
  needed against key reuse. The shared seed prevents reuse by construction, "because the
  per-component private keys are derived internally to the hybrid KEM" (Sec. 5.2).
- The binding claims are "informal justifications" by the editorial team, with "rigorous
  proofs" deferred to "a forthcoming paper" (Sec. 6.4.2).
- Scope is exactly two components: "More than two components" is listed as out of scope (Sec. 8).
- Proof status (Sec. 6.4.1): CG is proved in the X-Wing paper; UK rests on GHP18 Theorem 1 with an
  argued "trivial modification" to include public keys; UG in [CG26] (StarFortress, IACR CiC
  vol. 3 no. 1, May 2026) and CK in [COS_26] (StarHunters, ePrint 2026/427) are described as
  "technically novel" analyses by the editorial team. The proofs treat the two component key
  pairs as independent; the shared-seed key generation is covered by an added PRG hybrid argument.

### 4.3 NIST SP 800-227 (final, September 2025) and SP 800-56C Rev. 2

SP 800-227 Sec. 4.6 ("Multi-Algorithm KEMs and PQ/T Hybrids", PDF pp. 34-40, printed pp. 26-32)
is NIST's guidance on combining KEMs. What it says, in order:

1. Build a composite KEM C[Π1, Π2] by running both KEMs, concatenating keys and ciphertexts, and
   feeding K1, K2, c1, c2, ek1, ek2 and the parameter set into a KeyCombine function (Sec. 4.6.1,
   equations (9), (10)). The decapsulating party must keep (or be able to recompute) the composite
   encapsulation key, because KeyCombine takes it.
2. More than two components: "The above construction can be extended in the obvious way to
   composite constructions that use more than two component KEMs" (Sec. 4.6.1, printed p. 28).
   Pre-shared keys and QKD secrets are named as possible components of general schemes, and an
   approved key combiner "shall be used".
3. Approved key combiners (Sec. 4.6.2) come from two places: SP 800-56C key-derivation methods
   and SP 800-133 key-combination methods.
   - SP 800-56C route, equation (14): K ← KDM((S1, S2, ..., St), OtherInput), approved "for any
     t > 1 if at least one shared secret ... is generated from the key-establishment methods in
     SP 800-56A or SP 800-56B or an approved KEM" (printed p. 30). If the KDM is two-step,
     extraction takes all shared secrets as input. Ciphertexts, keys, parameter sets and domain
     separators go into FixedInfo.
   - Example, equation (15): KeyCombine(K1, K2, c1, c2, ek1, ek2, p) := H(K1, K2, c1, c2, ek1, ek2, domain_sep)
     with H an approved hash in one-step key derivation.
   - SP 800-133 route (concatenation, XOR, HMAC extraction): only when every component key was
     generated by an approved method, so it does not cover a custom (non-approved) lattice
     component. A concatenation result must go through a KDF before use (printed p. 30).
4. Encoding: comma-separated inputs H(x, y) are not the same as H(x || y); with variable lengths
   plain concatenation can collide, so the encoding must be fixed and unambiguous (printed
   pp. 28-29, "Concatenation of inputs").
5. Security (Sec. 4.6.3, printed pp. 31-32): the combiner K ← KDF(K1, K2) "does not preserve
   IND-CCA security, regardless of the properties of the KDF" (citing X-Wing [24]). NIST
   "encourages" combiners that generically preserve IND-CCA; its example KeyCombineCCA_H is
   H(K1, K2, c1, c2, ek1, ek2, domain_sep) with H from the SHA-3 family, and it cites GHP18 [25]
   for the proof in the random-oracle model. GHP18 does not hash the encapsulation keys; NIST
   notes that adding them is not needed for IND-CCA but can bind the key to the parties.
   The domain separator should identify the components, their order, the parameter sets, the
   combiner and the KDF.
6. It warns that composite schemes add complexity and new protocol choices (downgrade
   attacks) (printed p. 32).

SP 800-56C Rev. 2 (August 2020) is still the current version on 2026-09-27. Its Sec. 2 (PDF
p. 10) already allows a "hybrid" shared secret Z′ = Z || T, a standard shared secret Z followed by
an auxiliary secret T generated some other way. The one-step KDF (Sec. 4.1) computes
H(counter || Z || FixedInfo); Option 3 uses KMAC, and for KMAC256 the default salt is 132 zero
bytes (printed p. 13, PDF p. 21). On 6 January 2026 NIST announced it will revise SP 800-56C Rev. 2
to "Allow the shared secret Z to incorporate a shared secret obtained from an approved key-
encapsulation mechanism (KEM)", "Allow greater flexibility in the formatting of hybrid shared
secrets" and "Approve KMAC ... as an option in the two-step key derivation method" (CSRC news item
"nist-to-revise-key-establishment-recommendations"). No draft or date was given.

What this means for a three-component Turing KEM: a single SHA-3/KMAC-based KDF over all shared
secrets plus all ciphertexts, the public keys (or a hash of them) and a domain separator is both
the NIST-approved shape (equation (14) with t = 3) and the shape the proofs cover (Sec. 2 above),
as long as one component (ML-KEM) is approved and its secret enters directly. A custom lattice
component is allowed as one of the "other" secrets; it does not make the combination unapproved,
but it adds nothing to the approved security claim either.

Other bodies, for context only: ABK25 (p. 1) notes that "Using hybrid protocols is explicitly
recommended by European agencies"; the agencies' own documents are the nist-pqc-standards topic.
The LAMPS composite ML-KEM draft (rev 21, IESG Evaluation) uses the same X-Wing shape,
ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label) (draft-21 Sec. 3.4), and also allows
RSA-OAEP as the traditional KEM.

## 5. Combining more than two KEMs

**What the theory covers.**
- GHP18 is written for n ingredient KEMs from the start (Fig. 4, p. 6), and Theorem 1 (p. 10)
  holds for every n: one IND-CCA ingredient plus a split-key PRF core function gives an IND-CCA
  combination. Lemma 6 / Example 3 (p. 22) make H(k1 || ... || kn, x) such a core function in the
  ROM.
- ABK25 Theorem 8 (p. 15) is the n-KEM version with ciphertext omission, in the quantum setting:
  hash every shared secret, and hash the ciphertext of every component that is not known to be
  C2PRI. Theorem 9 (p. 15) gives the QROM split-key-PRF bound 4·sqrt((q²+q)/|K_i|) for
  H(k1 || ... || kn || x), which depends only on the size of the *secure* component's key space.
- Bindel et al. 2019 and the X-Wing paper are two-component results.
- SP 800-227: "The above construction can be extended in the obvious way to composite
  constructions that use more than two component KEMs" (Sec. 4.6.1); equation (14) approves
  KDM((S1, ..., St), OtherInput) for any t > 1 (Sec. 4.6.2).
- draft-irtf-cfrg-hybrid-kems-12 explicitly excludes more than two components (Sec. 8), so there
  is no CFRG construction or label registry for a three-way hybrid.
- RFC 9954 (TLS) allows "two or more" algorithms concatenated (Sec. 3.2-3.3); RFC 10024 defines
  only two-component groups.
- ETSI TS 103 744 V1.2.1 (2025-03) defines CatKDF (concatenate) and CasKDF (cascade) hybrid key
  combiners whose context includes the exchanged messages MA, MB, and says that "In the case
  where more than two key establishment schemes are being used, MB shall contain all of the
  corresponding public keys and ciphertexts" (Sec. 8.2, PDF p. 23).

- Industry expectation, for context: an Ericsson paper at NIST's Workshop on Guidance for KEMs
  (Mattsson et al., "ML-KEM is Great! What's Missing?", February 2025, p. 2) welcomes NIST's plan
  to allow K1 ‖ K2 ‖ ... ‖ Kn with one approved component and anticipates "that hybrid shared
  secrets consisting of more than two components will be relatively common", pointing to a
  Swedish NCSA recommendation that combines symmetric, post-quantum and classical keying. This
  is an opinion paper, not guidance.

**Two ways to build a three-way KEM.**
1. *Flat*: one combiner over all three components,
   K = KDF(ss_1, ss_2, ss_3, ct_1, ct_2, ct_3, H(ek_1 || ek_2 || ek_3), label). GHP18 Theorem 1 /
   ABK25 Theorem 8 with n = 3 cover the branches where an *IND-CCA KEM* survives, and SP 800-227
   equation (14) with t = 3 covers the NIST mapping. Caveat (from the continued run): raw X25519
   used as a KEM is not IND-CCA (one flipped bit or the inversion trick of Sec. 3a gives the same
   secret, `hyb_factcheck_math.py` part 3, `hyb_x25519_torsion.py`), so GHP18 does not carry the
   branch "both post-quantum components broken, X25519 intact". That branch needs an X-Wing
   Theorem 1 style (nominal group, strong DH, random oracle) argument, which is published for two
   components (X-Wing; StarFortress for UG) but not for three. Two fixes: use an X25519 KEM that
   is meant to be IND-CCA, such as HPKE's DHKEM(X25519, HKDF-SHA256) (RFC 9180 Sec. 4.1), which
   hashes the DH output together with the encapsulated key and the recipient key; or use the
   nested form. Evidence level for the DHKEM route: RFC 9180 Sec. 1 says the HPKE construction is
   IND-CCA2-secure "under classical assumptions" citing [HPKEAnalysis] and [ABHKLR20], and
   Sec. 9.1 says [ABHKLR20]'s bounds for the *Auth* mode use gap Diffie-Hellman with HKDF as a
   random oracle. A stand-alone IND-CCA theorem for Base-mode DHKEM Encap/Decap was not read
   here (ledger row 101).
2. *Nested*: treat X-Wing as one KEM and combine it with the third KEM:
   K = KDF(ss_XWing, ss_3, ct_XWing, ct_3, H(ek_XWing || ek_3), label). X-Wing is IND-CCA if
   ML-KEM-768 is IND-CCA (X-Wing Theorem 2, standard model), or if strong DH holds on Curve25519
   and ML-KEM-768 is C2PRI (X-Wing Theorems 1 and 3, random-oracle model). The outer combiner is
   IND-CCA if X-Wing or KEM_3 is (GHP18 Theorem 1 with n = 2). Composing the two gives "secure
   if any of the three is", with bounds that add, and every branch, including the X25519-only
   branch, rests on a published theorem. Advantage: the inner X-Wing stays byte-for-byte the
   standard (test vectors, audited libraries, the same algorithm as age's recipient type); the
   new part is a plain two-input GHP combiner. It must not reuse an age recipient *key*
   (Sec. 3a).

**What it costs** (`hybrid_combiner_checks.py` part C, COMPUTED from the verified sizes: ML-KEM
FIPS 203 Table 3; X-Wing draft-11 Sec. 5.1; FrodoKEM preliminary standardisation proposal
2025-09-29 Table A.5; Classic McEliece 460896 from the Rosenpass whitepaper Sec. 2.1.4):

| composition | public key (B) | ciphertext (B) | KDF input (B) | Keccak-f calls |
|---|---|---|---|---|
| X-Wing (C2PRI combiner) | 1216 | 1120 | 134 | 1 |
| ML-KEM-768 + X25519, UG (hash all) | 1216 | 1120 | 2416 | 18 |
| nested: X-Wing + FrodoKEM-976, outer hashes all | 16848 | 16912 | 33836 | 249 |
| nested: X-Wing + FrodoKEM-976, outer with cached H(pk) | 16848 | 16912 | 17020 | 126 |
| flat: ML-KEM-1024 + X25519 + FrodoKEM-976, hash all | 17232 | 17392 | 34732 | 256 |
| nested: X-Wing + McEliece-460896, outer with cached H(pk) | 525376 | 1308 | 1424 | 11 |

(The KDF-input column counts shared secrets + ciphertexts + keys or a 32-byte key hash + a
16-byte label + a 4-byte SP 800-56C counter; "Keccak-f" counts sponge absorb calls at rate 136.
Two corrections from the continued run, `hyb_factcheck_math.py` parts 8-9: (a) KMAC256 with the
SP 800-56C default 132-byte salt adds 3 fixed Keccak-f calls (1 cSHAKE prefix block, 2 key
blocks) not counted above. (b) The McEliece row uses the round-3 ciphertext of 188 bytes that
Rosenpass states. In the 2022 Classic McEliece specification a ciphertext is ⌈mt/8⌉ bytes
(Sec. 6.2) and mceliece460896 has m = 13, t = 96 (Sec. 7.3), so the ciphertext is 156 bytes and
the row becomes ct 1276 B, KDF input 1392 B, still 11 Keccak-f calls.)
Hashing 17-35 kB costs on the order of a hundred Keccak-f permutations, small next to FrodoKEM's
own matrix work, so for Turing the hashing cost is not a reason to omit a ciphertext. Wire size
is dominated by whichever third component is chosen (sizes of the candidate families are the
pq-families-for-diversity topic).

**Deployed multi-KEM examples** (details in Sec. 6): Rosenpass (Classic McEliece 460896 +
Kyber-512 mixed into one chaining key, then X25519 inside WireGuard) and Mullvad (ML-KEM-1024 XOR
HQC-256 into the WireGuard PSK, then X25519). Both are interactive VPN key exchanges; neither is
a file format. No standard file-encryption format with three KEM components was found (age and
RFC 9980 use two).

## 6. Deployed systems

A pattern runs through this section. Interactive protocols (TLS, SSH, Signal) often combine
secrets with a plain hash of the concatenated shared secrets and rely on a *transcript* (a hash of
all messages, signed or MACed) to bind the ciphertexts and keys. File and message encryption
(OpenPGP, age, HPKE) has no transcript, so the ciphertext/key binding must sit inside the KEM
combiner itself. Turing's file tool is in the second group.

### 6.1 TLS 1.3

- RFC 9954 (July 2026, Informational), "Hybrid Key Exchange in TLS 1.3": "two or more"
  algorithms; key shares are concatenated without length fields (fixed lengths required), and
  `concatenated_shared_secret = MyECDH.shared_secret || MyPQKEM.shared_secret` replaces the (EC)DHE
  secret in the TLS 1.3 key schedule (Sec. 3.3). Its Security Considerations (Sec. 6) say this
  corresponds to Bindel et al.'s dual-PRF combiner, secure if the hash (HKDF-Extract) is a
  dual-PRF, and that the KEMs must be IND-CCA (or FO-protected) if public keys are reused. The
  ciphertexts are bound by the TLS transcript, not by the combiner.
- RFC 10024 (August 2026, Standards Track): X25519MLKEM768 (codepoint 4588, 0x11EC),
  SecP256r1MLKEM768 (4587, 0x11EB), SecP384r1MLKEM1024 (4589, 0x11ED). For X25519MLKEM768 the
  client share is ML-KEM-768 ek || X25519 share (1184 + 32 = 1216 bytes), the server share is
  ML-KEM ct || X25519 share (1088 + 32 = 1120 bytes), and the shared secret is ML-KEM ss || X25519 ss.
  (RFC 10024 Secs. 4.1-4.3, 7.1-7.3).
- Order matters for FIPS approval. RFC 10024 Sec. 5: SP 800-56C Rev. 2 approves HKDF over two
  shared secrets "with the condition that the first one is computed by a FIPS-approved
  key-establishment scheme", so the ML-KEM secret is first in X25519MLKEM768 and the ECDHE
  secret first in the P-256/P-384 groups.
- RFC 10024 Sec. 6: "The security analysis relies crucially on the TLS 1.3 message transcript,
  and one cannot assume a similar hybridization is secure in other protocols." It also notes that
  ML-KEM's encapsulation randomness m is recovered exactly by the decapsulating party, so RNG
  output is disclosed to the peer, and "If the same insecure RNG is used by both algorithms, then
  a disclosure of state by one of the algorithms will also affect the security of the other
  algorithm." A hybrid is only as independent as its randomness.
- The X-Wing draft warns (Sec. 1.5.1) that the TLS-only "X25519Kyber768Draft00" combination
  "should not be used outside of TLS, as it assumes the presence of the TLS transcript to ensure
  non malleability". That warning applies to any Turing reuse of the TLS combiner shape.

### 6.2 OpenSSH and the SSH RFCs

From the OpenSSH release notes (openssh.com/releasenotes.html, fetched 2026-09-27):
- 8.9 (2022-02-23): sntrup761x25519-sha512@openssh.com added to the default KEXAlgorithms list.
- 9.0 (2022-04-08): sntrup761x25519-sha512@openssh.com made the default key exchange.
- 9.9 (2024-09-19): mlkem768x25519-sha256 added and "available by default"; sntrup761x25519-sha512
  also available under that IANA name.
- 10.0 (2025-04-09): "the hybrid post-quantum algorithm mlkem768x25519-sha256 is now used by
  default for key agreement".
- 10.1 (2025-10-06): ssh warns when a non-post-quantum key agreement is negotiated.
- The latest release on 2026-09-27 is 10.5 (2026-08-11); 10.3 sped up sntrup761 keying and 10.4
  added an experimental ML-DSA-44 + Ed25519 composite signature.

The combiners (plain hash of concatenated secrets, no ciphertexts):
- RFC 9941 (April 2026): K = SHA-512(sntrup761 ss (32 bytes) || X25519 ss (32 bytes)); client
  sends 1158-byte sntrup761 pk || 32-byte X25519 share (1190 bytes); server sends 1039-byte
  ciphertext || 32 bytes (1071 bytes) (Sec. 3).
- RFC 10042 (August 2026): mlkem768nistp256-sha256, mlkem1024nistp384-sha384, mlkem768x25519-sha256,
  with K = HASH(K_PQ || K_CL) (Sec. 2.4). The exchange hash H covers both parties' messages
  (C_INIT, S_REPLY) and K and is signed by the server host key (Sec. 2.5), which is what binds the
  ciphertexts.

### 6.3 OpenPGP: RFC 9980 (June 2026, Standards Track)

The closest file-encryption precedent after age. Algorithm IDs 35 (ML-KEM-768+X25519, MUST) and
36 (ML-KEM-1024+X448, SHOULD). The combiner (Sec. 4.2.1) is an X-Wing-style "QSF" combiner:

    KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey || algId || domSep || len(domSep)),
    domSep = "OpenPGPCompositeKDFv1" (21 bytes)

The KEK then wraps the session key with AES-256 key wrap (RFC 3394). The ML-KEM ciphertext and
key are not hashed (the X-Wing C2PRI argument, citing [BCD_24]); the ECDH ciphertext and public
key are. Component keys MUST be generated independently (Sec. 4.2.2) — unlike X-Wing's single
seed. Sec. 9.2 argues IND-CCA2 from ML-KEM IND-CCA2 or strong DH, and Sec. 9.2.1 explains the
length byte after domSep: it keeps the domain-separator set suffix-free.

### 6.4 age v1.3.0 (27 December 2025)

The GitHub release notes for age v1.3.0 (published 2025-12-27) announce "native post-quantum
recipients based on HPKE with a hybrid ML-KEM-768 KEM" (`age1pq1...` recipients,
`AGE-SECRET-KEY-PQ-1...` identities, `age-keygen -pq`). The latest release on 2026-09-27 is v1.3.2
(2026-08-29). The C2SP age specification (C2SP/C2SP age.md, fetched 2026-09-27) defines the
"MLKEM768-X25519 (i.e. X-Wing) hybrid post-quantum recipient type": the file key is sealed
with HPKE SealBase (RFC 9180), KEM MLKEM768-X25519 from draft-ietf-hpke-pq-03 / filippo.io/hpke-pq,
KDF HKDF-SHA256, AEAD ChaCha20Poly1305, info "age-encryption.org/mlkem768x25519"; the encapsulated
key must be exactly 1120 bytes. The identity is 32 random bytes (a seed). Note the file key
itself: age uses "a 128-bit symmetric file key", "16 bytes of CSPRNG output" (age.md "File
key"), also for post-quantum recipients; Turing's design uses a 256-bit file key (docs/03),
which is the conservative choice against Grover. The spec says the same
file SHOULD NOT also be encrypted to non-quantum-resistant recipients (that would reopen the
harvest-now-decrypt-later hole).

draft-ietf-hpke-pq-05 (Sec. 4) maps MLKEM768-X25519 (HPKE KEM id 0x647a, Nenc 1120, Npk 1216) to
draft-irtf-cfrg-concrete-hybrid-kems, which defines MLKEM768-X25519 as the CG framework with
SHAKE256 as PRG and SHA3-256 as KDF and states it "is identical to the X-Wing" construction, with
label \.//^\ (concrete-hybrid-kems-04 Sec. 4 and Sec. 4.2). So age's post-quantum recipient is X-Wing
inside HPKE. For Turing this is the most direct precedent: a file tool that encrypts a random
file key to X-Wing via HPKE. It is a precedent for the algorithm, not for sharing a key between
age and Turing (Sec. 3a).

### 6.5 Signal: PQXDH and the Triple Ratchet (SPQR)

- PQXDH (signal.org/docs/specifications/pqxdh/, "Revision 3, 2023-05-24, Last Updated:
  2024-01-23"): SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS), where SS is the post-quantum KEM
  shared secret (the spec's example pqkem is CRYSTALS-KYBER-1024). KDF is HKDF with a prefix F of
  32 0xFF bytes (curve25519) so the input never starts with a valid scalar or point encoding.
  The KEM ciphertext is not in the KDF input; it travels with an AEAD-encrypted initial message
  whose associated data AD holds both identity keys, and "If pqkem does not incorporate PQPK_B
  into the ciphertext, Alice must also append EncodeKEM(PQPK_B) to AD" (Sec. 3.3). Sec. 4.12
  ("Preventing KEM Re-encapsulation Attacks") explains why: a KEM re-encapsulation attack can make
  two sessions share a key unless the KEM (like Kyber, which "incorporates the KEM public key into
  the generation of the shared secret") binds its public key, or the key is added to AD. The spec
  points to formal analyses in ProVerif and CryptoVerif (its refs [11]-[13]); a separate
  computational analysis is Fiedler-Günther 2024
  (research/papers/2024-fiedler-gunther-security-analysis-signal-pqxdh.pdf).
- Double Ratchet spec "Revision 4, 2025-11-04" adds Sec. 5 "The Sparse Post-Quantum Ratchet"
  (SPQR, built on the ML-KEM Braid SCKA protocol, spec "Revision 1, 2025-02-21") and Sec. 6
  "The Triple Ratchet: combining Secure Messaging protocols for hybrid security". Each message
  key is mk = KDF_HYBRID(ec_mk, pq_mk): "a KDF keyed by the concatenation of two 32-byte secrets
  [applied] to some unique constant specifying the protocol in use and its parameters" (Sec. 6.3,
  6.5). Both headers go into the AEAD associated data. The combination is at the level of whole
  ratchets, not single KEMs: an attacker "must break both" (Sec. 6).

### 6.6 Apple iMessage PQ3 (Apple Security Research blog, 21 February 2024)

Each device registers a Kyber-1024 KEM public key and a P-256 ECDH public key (signed via the
Secure Enclave key). Rekeying ratchets use Kyber-768 "approximately every 50 messages" and at
least once every 7 days. The combiner: "we first extract their entropy by invoking
HKDF-SHA384-Extract twice — once for each of the keys. The resulting 48-byte secret is further
combined with a domain separation string and session information — which includes the user's
identifiers, the public keys used in the key exchange, and the encapsulated secret — by invoking
HKDF-SHA384-Extract again". So PQ3 hashes public keys and the encapsulated secret into the key,
the GHP18/SP 800-227 shape. The post says PQ3 was verified symbolically with Tamarin (Basin's
group) and analysed by Stebila. (Source is Apple's own blog, a primary source for what Apple
deployed; the construction details there are prose, not a specification.)

### 6.7 Rosenpass (whitepaper version 89a8805, 2026-09-24; research/papers/rosenpass-whitepaper.pdf)

A deployed *three-family* design. Rosenpass runs two different post-quantum KEMs — Classic
McEliece 460896 (round-3 version) for the static keys and Kyber-512 (round-3 version) for the
ephemeral key — and hands its output key to WireGuard as the pre-shared key, while WireGuard itself
still runs X25519 (whitepaper Sec. 1 and Sec. 2.1.4-2.1.5, pp. 4-7). Sizes stated there: McEliece
ciphertext 188 bytes, secret key 13568 bytes, public key 524160 bytes; Kyber-512 ciphertext 768,
public key 800, secret key 1632 bytes. "A single secure encapsulation is sufficient to provide
secrecy" (Sec. 1, p. 4); authenticity rests on Classic McEliece alone; forward secrecy on Kyber.
The combiner is sequential, Noise-style: every KEM output goes through
`encaps_and_mix(pk)`: `(ct, shk) = T::enc(pk); mix(pk, shk, ct)` into one chaining key, and "we
include the entire protocol transcript in the chaining key" (Sec. 2.5.3, p. 10; function listing
p. 20). So each KEM's public key, shared key and ciphertext are hashed, one after another.
Rosenpass has a ProVerif symbolic analysis; a CryptoVerif proof is described as work in progress
(abstract).

### 6.8 Mullvad VPN (source code, mullvad/mullvadvpn-app main, last commit to the file 2026-09-22)

A deployed two-post-quantum-KEM XOR combiner. `talpid-tunnel-config-client/src/lib.rs`
generates a fresh ML-KEM-1024 key pair and a fresh HQC-256 key pair per negotiation, decapsulates
both server ciphertexts and XORs the two 32-byte secrets into the WireGuard PSK (`xor_assign`);
HQC's 64-byte secret is first hashed to 32 bytes with SHA-256 (`hqc.rs`). WireGuard then adds
X25519. XOR is acceptable here only because each key pair is used for exactly one
decapsulation (no decapsulation oracle to exploit, so GHP18 Lemma 1's IND-CPA preservation is
the relevant result) and the exchange runs inside an already-authenticated tunnel. It is not a
pattern for a long-term file-encryption key, where the recipient's key decapsulates many
ciphertexts.

### 6.9 Summary table

| system | components | combiner input | where ciphertexts/keys are bound |
|---|---|---|---|
| X-Wing (draft-11), age v1.3 (via HPKE), concrete-hybrid-kems MLKEM768-X25519 | ML-KEM-768 + X25519 | SHA3-256(ss_M, ss_X, ct_X, pk_X, label) | in the KEM (X25519 parts); ML-KEM by C2PRI |
| OpenPGP RFC 9980 | ML-KEM-768 + X25519, ML-KEM-1024 + X448 | SHA3-256(ss_M, ss_E, ct_E, pk_E, algId, domSep, len) | in the KEM (ECDH parts); ML-KEM by C2PRI |
| TLS RFC 9954 / RFC 10024 | ECDHE + ML-KEM | ss_1 || ss_2 into HKDF key schedule | TLS transcript |
| SSH RFC 9941 / RFC 10042 | sntrup761 or ML-KEM + X25519/ECDH | SHA-512 / HASH(ss_PQ || ss_CL) | signed exchange hash |
| Signal PQXDH / Triple Ratchet | X25519 DHs + Kyber/ML-KEM | HKDF(F || DH... || SS); KDF_HYBRID(ec_mk, pq_mk) | AEAD associated data, KEM pk binding |
| Apple PQ3 | P-256 ECDH + Kyber-1024/768 | HKDF-Extract ×3 with keys and encapsulated secret | in the KDF |
| Rosenpass (+WireGuard) | McEliece-460896 + Kyber-512, then X25519 | chaining key: mix(pk, shk, ct) per KEM | in the KDF (whole transcript) |
| Mullvad | ML-KEM-1024 XOR HQC-256, then X25519 | XOR into WireGuard PSK | ephemeral single-use keys, authenticated tunnel |
| CFRG hybrid-kems UG/UK | PQ + T | KDF(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label) | in the KEM |
| SP 800-227 KeyCombineCCA_H | any t ≥ 2 | H(K1, K2, c1, c2, ek1, ek2, domain_sep) | in the KEM |

## 7. Pitfalls, and what happens when a component is broken or malicious

**Pitfalls with published evidence.**

| pitfall | evidence | consequence |
|---|---|---|
| XOR of shared secrets with long-term keys | GHP18 Lemma 2 (p. 7); Bindel et al. 2019 p. 11 (both components IND-CCA); `hybrid_combiner_checks.py` B1 | challenge key recovered with 1-2 decapsulation queries |
| KDF(ss_1, ss_2) without ciphertexts | SP 800-227 Sec. 4.6.3 ("does not preserve IND-CCA security, regardless of the properties of the KDF"); X-Wing paper p. 4 | one malleable/broken component breaks the hybrid |
| Leaving out a ciphertext of a non-C2PRI component (raw DH, IND-CPA KEM, custom KEM) | X-Wing paper p. 4; draft-connolly-cfrg-xwing-kem-11 Sec. 6; `hybrid_combiner_checks.py` B2, B3 | one query recovers the key |
| Relying on a protocol transcript that a file format does not have | X-Wing draft Sec. 1.5.1; RFC 10024 Sec. 6 | TLS/SSH combiners are not secure as stand-alone KEMs |
| Variable-length or ambiguous encoding | SP 800-227 pp. 28-29; RFC 9954 Sec. 6; hybrid-kems-12 Sec. 6.5.2; `hybrid_combiner_checks.py` E | two different input tuples hash identically; timing leaks from length-dependent hashing |
| Labels that are suffixes of each other | hybrid-kems-12 Secs. 6.5.1, 7; RFC 9980 Sec. 9.2.1 | loss of domain separation between constructions |
| Reusing a component key pair outside the hybrid | hybrid-kems-12 Sec. 5.2 ("MUST NOT"); Millerjord-Stebila-Steckel 2026 (the combined notion is unsatisfiable with unprocessed stand-alone use) | cross-protocol attacks; outside the GHP18 model; a component key used alone can be attacked alone |
| Not binding the KEM public key when the protocol needs it | PQXDH Sec. 4.12 (re-encapsulation); hybrid-kems-12 Sec. 6.2.2; KSW25 | two sessions/recipients can be made to share a key |
| Shared weak RNG | RFC 10024 Sec. 6 | state disclosure through one component (e.g. ML-KEM's m) affects the others |
| Omitting the recipient public key in a many-recipient setting | Kang-Lee-Son 2026 Lemma 2 / Corollary 1 (preprint) | attacker work adds up across N recipients (factor N in the bound) |
| Treating raw X25519 as an IND-CCA ingredient in a flat n-way proof | `hyb_factcheck_math.py` part 3; X-Wing paper p. 4 | the "only X25519 survives" branch is not covered by GHP18 |
| Downgrade: more negotiable choices | SP 800-227 p. 32 | an attacker steers peers to a weaker option |
| KDF with a too-short secret for a QROM claim | ABK25 Theorem 9; `hybrid_combiner_checks.py` D | 192-bit secret gives a vacuous bound near 2^94 quantum queries (proof limit, not attack) |

**If one component is completely broken.** The whole point of GHP18 Theorem 1 is that the other
ingredients may be anything, even adversarially designed (Lemma 2's counter-example uses a KEM
with a constant key). As long as (a) one component is IND-CCA and its secret key is independent,
(b) the combiner is a split-key PRF over all shared secrets and all non-C2PRI ciphertexts, the
hybrid remains IND-CCA. A broken component therefore costs nothing in confidentiality in this
model.

**What the model does not cover (and where a "twist" component adds risk).** These points are
my analysis of the proofs' assumptions, not statements from a paper; they are marked as such in
the ledger.
1. *Shared state.* The proofs model components as separate algorithms with independent keys.
   If a buggy or backdoored component implementation can read another component's secret key,
   seed or RNG state (same process, same memory), the proof says nothing. X-Wing and the CFRG
   frameworks derive all component keys from one 32-byte seed through SHAKE256; this is covered
   by a PRG argument (hybrid-kems-12 Sec. 6.4.1). RFC 9980 instead requires independent
   component key generation (Sec. 4.2.2). The CFRG draft prefers the shared seed, because it
   stops a component key from being reused outside the hybrid and gives MAL-level binding
   (Sec. 5.2); the key-reuse risk is real (Millerjord-Stebila-Steckel, Sec. 3a). A leak of
   the master seed exposes every component, but so does a leak of a key file that stores
   independent component keys side by side; a leak of one *derived* component key does not
   reveal the seed if the expansion is a one-way PRG. So the shared seed is not weaker in
   practice, provided the seed is only touched by the expansion step.
2. *Decryption failures.* GHP18 assumes perfect correctness; X-Wing Theorem 2 and ABK25 carry a
   δ term. A custom lattice component with a larger δ adds δ to the hybrid's bound; failure
   attacks against it only recover *its* key (the decryption-failures topic covers the attacks).
3. *Availability.* If any component's decapsulation fails or returns ⊥, the hybrid fails
   (GHP18 Fig. 4 line 15). A buggy third component can make files undecryptable. With implicit
   rejection, a mismatch shows up as a wrong key and an AEAD failure, not an error code.
4. *Implementation attack surface.* Every extra component is more parsing, more arithmetic and
   more constant-time obligations in the decryptor. A memory-safety or timing bug in the custom
   component's code can leak more than that component's key if it shares a process with the
   others. This is the one way a weak added component can make the whole hybrid *weaker*, and the
   combiner theorems cannot rule it out.
5. *No gain beyond the strongest component.* The bounds are "min"-type (Bindel et al. Theorem 2:
   2·(min{Adv(K1), Adv(K2)} + ...)): a hybrid is as hard to break as its hardest component, not
   harder. A third component buys insurance against one family failing; it does not add security
   bits on top of an unbroken ML-KEM.

## 8. Reproduced checks

Two scripts, both re-run on 2026-09-27 with exit code 0 ("ALL CHECKS PASSED"). Logs:
scratch `pq/hyb/recheck/checks-rerun.log` and `pq/hyb/recheck/hyb_worked_examples.log`.

`research/scripts/pq/hybrid_combiner_checks.py` (from the interrupted run; read line by line
and re-run; its claims were re-checked against the sources in this note):

    timeout 300 python research/scripts/pq/hybrid_combiner_checks.py research/papers/ietf-draft-connolly-cfrg-xwing-kem-11.txt

(57 checks marked [PASS], 0 FAIL; an earlier draft said 58 by counting the final "ALL CHECKS PASSED" line. Re-run again at the end of the continued run with the same result; log scratch `pq/hyb/cont/checks-final.log`.)

- A. X-Wing draft-11 Appendix C: 3 test vectors parsed; for each, key generation from the 32-byte
  seed reproduces the 1216-byte public key, ct_X = X25519(eseed[32:64], base) matches bytes
  1088..1120 of the ciphertext, and decapsulation reproduces the shared secret. Negative
  controls: the paper's label-first order does not reproduce the vectors; a flipped ML-KEM
  ciphertext bit changes the key; flipping bit 255 of ct_X leaves the raw X25519 output unchanged
  (RFC 7748 masking) but changes the X-Wing key because ct_X is hashed.
- B1. XOR combiner of real ML-KEM-768 and X25519: mix-and-match recovers the challenge key 5/5;
  the UniversalCombiner layout 0/5.
- B2. SHA3(ss_M || ss_X) without ct_X: one query wins 5/5; X-Wing's combiner 0/5.
- B3. Toy LWE KEM (n = 64, q = 3329, NOT secure): without FO, a +1 on one ciphertext
  coefficient gives the same key in 64/64 trials (not C2PRI); with FO re-encryption and implicit
  rejection, 0/64.
- C. Size and hashing-cost table (Sec. 5).
- D. ABK25 Theorem 9 bound values (Sec. 2).
- E. Pure-Python Keccak/cSHAKE256/KMAC256 checked against hashlib and against the NIST cSHAKE256
  samples #3-#4 and KMAC256 samples #4-#6 (PDFs in research/papers/); then an SP 800-56C
  one-step KMAC256 combiner over 3 secrets, 3 ciphertexts and a key hash: every one of the 7
  inputs changes the output when one bit flips; variable-length concatenation collides and
  per-field encode_string removes the collision.

`research/scripts/pq/hyb_worked_examples.py` (new):

    timeout 300 python research/scripts/pq/hyb_worked_examples.py

- 1. The XOR mix-and-match attack by hand with 8-bit keys (k* = 0x3a XOR 0xc5 = 0xff recovered
  from two oracle answers 0xd4 and 0x4d).
- 2. ML-KEM-768 + X25519 + toy lattice KEM, four combiners, one-query malleation attack on the
  toy ciphertext (5 runs each):

  | combiner | toy without FO (not C2PRI) | toy with FO (C2PRI) |
  |---|---|---|
  | flat, hashes all ciphertexts | 0/5 | 0/5 |
  | flat, omits toy ciphertext | 5/5 broken | 0/5 |
  | nested X-Wing + toy, hashes both | 0/5 | 0/5 |
  | nested, omits toy ciphertext | 5/5 broken | 0/5 |

  This is ABK25 Theorem 8 in executable form: a ciphertext may be left out only if that
  component is C2PRI, and a custom component without a proof must be hashed.
- 3. Three-way XOR of three sound KEMs: the three-query mix-and-match recovers the key 3/3.
  (Two queries are enough for any n, see the next script, part 2.)

`research/scripts/pq/hyb_factcheck_math.py` (written by an independent fact-checker during the
first run; read and re-run in the continued run, exit code 0, "ALL CHECKS PASSED"):

    timeout 300 python research/scripts/pq/hyb_factcheck_math.py

- Part 2: an n-way XOR combiner of sound hashed DH-KEMs is broken with *two* decapsulation
  queries for n = 2, 3, 4, 5 (4/4 runs each). Query A replaces only c_1 by the attacker's own
  ciphertext (known key k_1′) and returns k_1′ XOR k_2* XOR ... XOR k_n*, so the attacker learns
  k_2* XOR ... XOR k_n*. Query B keeps c_1* and replaces all the others by its own ciphertexts,
  which reveals k_1*. XOR of the two results is k*. The hash-all combiner defeats the same
  queries (0/4).
- Part 3: raw X25519 as a KEM (key = raw u-coordinate) is not IND-CCA (the bit-255 query returns
  k* in 200/200) and its output is not even uniform (top bit 0 in 200/200); a hashed DH-KEM
  resists the same query (0/200).
- Part 4: where the ABK25 Theorem 9 bound reaches 1: q = 2^126, 2^94, 2^62 for 256-, 192- and
  128-bit component secrets.
- Part 5: hashing a b-bit secret up to 256 bits leaves 2^b possible values (b = 16 demo).
- Part 7: a generic attack on a hash-all hybrid that breaks every component separately costs the
  *sum* of the component costs, so at most log2(n) bits more than the strongest component.
- Parts 8-9: McEliece 2022 ciphertext size and KMAC fixed overhead (Sec. 5 table note).

`research/scripts/pq/hyb_x25519_torsion.py` (new in the continued run):

    timeout 120 python research/scripts/pq/hyb_x25519_torsion.py

- Kang-Lee-Son Theorem 1 with pyca/cryptography's X25519: c′ = (c*)^-1 mod p gives the same
  secret in 50/50 trials; the bit-255 flip also 50/50; the negative control c* + 1 in 0/50. An
  X-Wing-style combiner that hashes ct_X and pk_X separates both second preimages (50/50). The
  script also checks the curve identity x(P + T) = x(P)^-1 for T = (0, 0) on the base point.

## What this means for Turing

The design phase decides; these are options with their evidence.

**1. Keep X-Wing as the standard core; nothing in the new sources argues against it.**
draft-11 (23 September 2026) changes nothing technical from draft-10, which docs/03 names
(COMPUTED diff: only dates, one re-wrapped hex line and an affiliation). The test vectors
reproduce. age v1.3 ships the same construction for files, and concrete-hybrid-kems-04 calls its
MLKEM768-X25519 "identical to the X-Wing construction". Status to record: X-Wing is an
Independent-Submission-stream Internet-Draft ("Submission Received"), not an IRTF/CFRG document
and not an RFC, so a Turing file format must pin draft-11 (or its successor) byte for byte.

Two wording corrections for docs/03 (for the owner/editor, not made here): (a) the draft version
is now 11; (b) docs/03 says the combiner "also binds the ciphertexts and public keys". X-Wing
hashes only the X25519 ciphertext and public key; the ML-KEM ciphertext is covered by ML-KEM's
C2PRI (X-Wing Theorem 3), and binding is a separate claim (draft Sec. 6.1, proof still "TODO").

**2. Where a custom lattice component can go without lowering security: a third component under
a GHP-style outer combiner (nested).**

    (ss_XW, ct_XW) = X-Wing.Encaps(ek_XW)            # standard, draft-11, test vectors
    (ss_L,  ct_L ) = Custom.Encaps(ek_L)             # the "twist"; FO + implicit rejection; 32-byte secret
    K = KMAC256(key = 132 zero bytes, X = 0x00000001 || ss_XW || ss_L || encode_string(label)
                || ct_XW || ct_L || SHA3-256(ek_XW || ek_L), L = 256, S = "KDF")

Every field is fixed-length and the label is length-encoded (so its position is unambiguous;
with plain concatenation it would have to go last and be suffix-free, hybrid-kems-12 Sec. 6.5.1),
the custom ciphertext is hashed (it has no C2PRI proof), the public
keys enter as a digest (gives K-PK binding whatever the component, KSW25), and the approved-KEM
secret comes first (SP 800-56C Z′ = Z || T; RFC 10024 Sec. 5). KMAC256 is SP 800-56C Option 3 and
is built on cSHAKE256, the primitive Turing already uses for all its derivations (docs/03). A
SHA3-256 Option 1 form, SHA3-256(counter || ss_XW || ss_L || ct_XW || ct_L || H_ek || label),
would be equally covered. (Note: SP 800-227's example (15) has no counter; SP 800-56C's one-step
KDF prefixes a 4-byte counter. Including it costs nothing.)

Four rules that go with this construction (added in the continued run):
- *Keys.* Derive the X-Wing seed and the custom component's seed from one master seed with a
  PRG under distinct labels (the CFRG default, hybrid-kems-12 Sec. 5.2), and never use either
  component key pair outside this hybrid (hybrid-kems-12 Sec. 5.2 "MUST NOT"; Sec. 3a). In
  particular, a Turing X-Wing key is not also an age recipient key.
- *Recipient digest.* SHA3-256(ek_XW || ek_L) does two jobs: K-PK binding (KSW25) and the
  per-recipient salt that stops multi-target work from adding up across recipients
  (Kang-Lee-Son Corollary 1). The decryptor needs it, so store it with the decapsulation key or
  recompute it from the stored public key (the RFC 9980 erratum 9023 is exactly this omission).
- *Randomness.* Each component's encapsulation randomness comes from the OS CSPRNG separately,
  never from one shared stream whose state a component could reveal (RFC 10024 Sec. 6).
- *If key reuse is ever wanted*, switch to the Millerjord-Stebila-Steckel shape: each component
  secret first goes through a PRF with a Turing label, K = W(PRF(ss_XW, lbl), PRF(ss_L, lbl), c),
  and every stand-alone use post-processes with PRF(ss, c) (their Fig. 11, Theorem 2).

Proofs Turing could cite, with their limits:
- Inner: X-Wing Theorems 1-2 (IACR CiC 1(1), 2024), IND-CCA if ML-KEM-768 is IND-CCA (standard
  model, PRF assumption on SHA3-256) or if SDH holds in Curve25519 (ROM, needs ML-KEM C2PRI,
  Theorem 3).
- Outer: GHP18 Theorem 1 (PKC 2018) with Lemma 6 / Example 3 (ROM): IND-CCA if X-Wing or the
  custom KEM is IND-CCA. Classical-ROM only, and GHP18 assumes perfect correctness, so the
  custom component's δ must be added as in X-Wing Theorem 2 / ABK25. GHP18 also assumes the
  component keys live only inside the hybrid (Millerjord-Stebila-Steckel 2026); the key rules
  above keep Turing inside that assumption.
- Quantum setting, two components (the nested outer step): ABK25 Theorem 1 (QPT adversaries,
  split-key PRF, δ term; in the part of the paper submitted to TCC 2025) plus Theorem 9 for the
  KMAC/SHA-3 instantiation in the QROM.
- Quantum setting, three components in one KDF (the flat form): ABK25 Theorems 8-9 (n KEMs,
  explicit δ; Theorem 9 is the QROM step),
  published at ACNS 2026 (LNCS pp. 32-74). The n-KEM Theorem 8 has only a proof sketch and was
  added after the paper's TCC 2025 submission (ABK25 p. 5, p. 15), so for n = 3 cite it as a
  sketched result. The nested form avoids needing it: two-KEM results compose.
- NIST: SP 800-227 equation (14) approves KDM((S1, ..., St), OtherInput) when at least one S_j
  comes from an approved KEM. In the *flat* form, ML-KEM's own shared secret is S1, which fits
  (14) directly. In the *nested* form the outer S1 is X-Wing's output, and X-Wing is not itself a
  NIST-approved KEM; whether a validation lab accepts "an SP 800-56C-style derivation of an
  approved KEM's secret" as S1 is not answered by the text I read (open question). If FIPS
  conformance ever matters, the flat form is the cleaner mapping.

Nested or flat? Nested keeps X-Wing byte-identical to the standard (same algorithm as age's
recipient type, vectors, audited libraries), makes the new code a two-input KDF that is easy to
test, and its proof is a composition of published two-component theorems that covers every
branch, including "only X25519 survives". Flat (ML-KEM + X25519 + custom under one KDF, ML-KEM
secret first) maps directly onto SP 800-227 equation (14), but gives up X-Wing's vectors, and
with raw X25519 its X25519-only branch is not covered by GHP18 (raw X25519 is not an IND-CCA
KEM; Sec. 5, ledger row 115); it would need DHKEM(X25519) as the classical component or a new
three-component proof. Earlier drafts of this note called the two "equally provable"; that was
too strong. On the evidence read, nested is the better-covered choice; flat is the better NIST
mapping.

**3. Options that add risk, with the evidence.**
- *Omitting the custom ciphertext* (X-Wing-style shortcut): broken in one query if the custom KEM
  is not C2PRI (`hyb_worked_examples.py` part 2; X-Wing draft Sec. 6; ABK25 Theorem 8 needs C2PRI).
  Only acceptable after a published C2PRI proof for the exact custom FO variant (Starfighters /
  ABK25 Theorem 5 cover standard U⊥/U̸⊥ FO variants; a custom FO needs its own).
- *XOR or plain concatenation without ciphertexts*: broken (GHP18 Lemma 2; SP 800-227 Sec. 4.6.3;
  scripts B1, part 3). Mullvad's XOR is acceptable only because its keys are single-use.
- *Merging at the IND-CPA level* (strip each FO, combine, apply one FO: GHP18's Remark p. 7): a
  homemade KEM with no black-box robustness; a flaw in the joint FO or the joint decryption breaks
  all components at once. Avoid.
- *Copying the TLS/SSH shape* (hash of concatenated secrets): relies on a transcript a file does
  not have (RFC 10024 Sec. 6; X-Wing draft Sec. 1.5.1).
- *Shared RNG / shared process*: the proofs do not cover a component implementation that can
  read the others' secrets (Sec. 7). Keep the custom component's decapsulation constant-time and
  treat its parser as hostile-input code. For key generation there are two published styles:
  (a) one master seed expanded by a PRG (SHAKE256 or KMAC with distinct labels) into the X-Wing
  seed and the custom component's seed, the CFRG default (hybrid-kems-12 Sec. 5.2), which
  prevents stand-alone reuse of a component key and gives MAL-level binding; (b) independent
  component keys, as in RFC 9980 Sec. 4.2.2, which the CFRG draft accepts only where component
  keys cannot be imported or exported. With (b), hashing the public-key digest keeps K-binding
  (KSW25), but key reuse must be prevented by other means. Style (a) is the better fit for a
  file tool whose key files hold all components anyway. Draw per-encapsulation randomness for
  each component separately from the OS CSPRNG, not from one shared DRBG stream (RFC 10024
  Sec. 6 warns about shared RNG state).
- *Reusing an X-Wing key pair both inside Turing's hybrid and as an age recipient*: this is the
  key-reuse setting of Millerjord-Stebila-Steckel (Sec. 3a). GHP18's theorem does not cover it,
  and hybrid-kems-12 Sec. 5.2 forbids it ("MUST NOT"). Interop with age should mean "same
  X-Wing algorithm and vectors", not "same key".
- *A 24-byte (192-bit) component secret* (e.g. FrodoKEM-976, Table A.5): fine classically, but the
  QROM split-key-PRF bound becomes vacuous near 2^94 queries (script part D). If a QROM statement
  is wanted, prefer a 32-byte secret (e.g. FrodoKEM-1344, ss = 32 bytes, Table A.5) or state the
  bound honestly. Hashing the 24-byte secret up to 32 bytes does not fix this (Sec. 2,
  `hyb_factcheck_math.py` part 5).

**4. What "harder to break" can honestly mean here.** The combined KEM is as hard to break as its
*strongest* component, not harder (Bindel et al. Theorem 2 has a min{...} term; GHP18 Theorem 1
reduces to any one secure ingredient). Worked number (`hyb_factcheck_math.py` part 7): an
attacker who must break every component of a hash-all hybrid separately pays the sum of the
costs, so three components of 2^256 each cost 2^257.6, only log2(3) = 1.6 bits more than one. A third component is insurance against one family
failing. It helps most if its failure modes are *different* from ML-KEM's: for example an
unstructured-LWE component would survive an attack that exploits the module/ring structure of
ML-KEM, while a custom module-lattice component with ML-KEM-like parameters would likely fall to
the same attack. (This last point is reasoning, not a sourced result; the lattice-foundations,
attack-cost-estimation and pq-families-for-diversity topics hold the evidence on structure and
cost.) The same combiner also lets a *code-based* third component (Classic McEliece, HQC) be
used instead of or beside a lattice one; KSW25 and Starfighters say which of those are C2PRI and
binding.

**5. Tests the combiner layer needs** (for the testing-ci-cd topic):
- X-Wing draft-11 Appendix C vectors (already reproduced by script part A) as a CI gate.
- Negative controls as regression tests: flipping any byte of any ciphertext part, any key
  byte of the key hash, or the label must change K; the malleation and mix-and-match attacks
  from both scripts must fail against the real implementation.
- Length checks: reject any ciphertext part whose length is not exactly the fixed length (age
  rejects anything that is not "a 1120-byte value"; RFC 9941/10042 abort on wrong lengths).
- Label set suffix-free (a unit test over all labels in the codebase).
- Differential tests of ML-KEM and X25519 against an independent oracle (pyca/cryptography was
  used here; the rust-pqc-implementations topic covers Rust oracles).

## Sources

All "online" items were fetched on 2026-09-27; copies are in the scratch directory
`pq/hyb/recheck/` unless a research/papers/ file is named.

| file in research/papers/ or "online" | reference | URL | used for |
|---|---|---|---|
| 2018-giacon-heuer-poettering-kem-combiners.pdf | F. Giacon, F. Heuer, B. Poettering, "KEM Combiners", PKC 2018 (full version, ePrint 2018/024) | https://eprint.iacr.org/2018/024 | parallel combiner, XOR lemmas, Theorem 1, Lemma 6 |
| 2019-bindel-et-al-hybrid-kems-and-authenticated-key-exchange.pdf | N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila, "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange", PQCrypto 2019 (ePrint 2018/903) | https://eprint.iacr.org/2018/903 | mix-and-match, XtM, dual-PRF, two-stage adversaries |
| 2024-barbosa-et-al-x-wing-hybrid-kem.pdf | M. Barbosa, D. Connolly, J. D. Duarte, A. Kaiser, P. Schwabe, K. Varner, B. Westerbaan, "X-Wing: The Hybrid KEM You've Been Looking For", IACR CiC 1(1), 2024 (ePrint 2024/039) | https://doi.org/10.62056/a3qj89n4e | Theorems 1-3, C2PRI, Fig. 12, Sec. 8 |
| 2025-alagic-bajaj-kocoglu-best-of-both-kems-combining.pdf | G. Alagic, F. Bajaj, A. Kocoglu, "The Best of Both KEMs: Securely Combining KEMs in Post-Quantum Hybrid Schemes", ePrint 2025/1444 (version of 8 Aug 2025); published ACNS 2026, LNCS pp. 32-74, DOI 10.1007/978-3-032-32560-0_2 | https://eprint.iacr.org/2025/1444 ; https://doi.org/10.1007/978-3-032-32560-0_2 | n-KEM combiner (quantum adversaries), QROM split-key PRF, C2PRI of FO KEMs |
| 2025-connolly-et-al-starfighters-general-applicability-of-x-wing.pdf | D. Connolly, K. Hövelmanns, A. Hülsing, S. Kousidis, M. Meijers, "Starfighters—On the General Applicability of X-Wing", ePrint 2025/1397, IEEE S&P 2026 | https://eprint.iacr.org/2025/1397 | QSF with other KEMs, HQC C2PRI |
| 2025-kramer-struck-weishaupl-binding-properties-of-kem-combiners.pdf | J. Krämer, P. Struck, M. Weishäupl, "Binding Security of Combined KEMs: An Analysis of Real-World KEM Combiners", ePrint 2025/1416 (revised 2025-11-20); published SCN 2026, LNCS pp. 455-473, DOI 10.1007/978-3-032-36264-3_23 | https://eprint.iacr.org/2025/1416 | binding of combiners, HQC caveat |
| 2026-connolly-ounsworth-schmieg-stebila-starhunters-hybrid-kems-from-pke.pdf | D. Connolly, M. Ounsworth, S. Schmieg, D. Stebila, "StarHunters", ePrint 2026/427 (preprint) | https://eprint.iacr.org/2026/427 | CK framework analysis |
| 2026-connolly-grubbs-starfortress-hybrid-kems-dh-inlining.pdf | D. Connolly, P. Grubbs, "StarFortress: Hybrid KEMs with Diffie-Hellman Inlining", ePrint 2026/125; IACR CiC 3(1), 2026-05-04, DOI 10.62056/ahmp-49p1 | https://eprint.iacr.org/2026/125 | UG framework analysis |
| nist-sp800-227-kem-recommendations.pdf | NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms, Sept 2025 | https://doi.org/10.6028/NIST.SP.800-227 | Sec. 4.6 composite KEMs and approved combiners |
| nist-sp800-56c-r2-key-derivation-via-key-establishment.pdf | NIST SP 800-56C Rev. 2, Aug 2020 | https://doi.org/10.6028/NIST.SP.800-56Cr2 | Z′ = Z‖T, one-step KDF options, KMAC salt |
| online | NIST CSRC, SP 800-56C Rev. 2 page (planning note 01/06/2026) and news "NIST to revise key-establishment recommendations" | https://csrc.nist.gov/pubs/sp/800/56/c/r2/final ; https://csrc.nist.gov/News/2026/nist-to-revise-key-establishment-recommendations | revision status |
| nist-fips-203-ml-kem.pdf | NIST FIPS 203, ML-KEM, Aug 2024 | https://doi.org/10.6028/NIST.FIPS.203 | Table 3 sizes |
| 2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf | FrodoKEM preliminary standardization proposal, 2025-09-29 | (file) | Table A.5 sizes |
| nist-cshake-kmac-example-values.pdf, nist-kmac-example-values.pdf, nist-sp800-185-sha3-derived-functions.pdf | NIST SP 800-185 and its example values | csrc.nist.gov | KMAC256 check in script part E |
| ietf-draft-connolly-cfrg-xwing-kem-11.txt | D. Connolly, P. Schwabe, B. E. Westerbaan, draft-connolly-cfrg-xwing-kem-11, 23 Sept 2026 | https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt | X-Wing spec and test vectors |
| online | draft-connolly-cfrg-xwing-kem-10 (2 March 2026), for the diff | https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.txt | -10 vs -11 changes |
| ietf-draft-irtf-cfrg-hybrid-kems-12.txt | D. Connolly, R. Barnes, P. Grubbs, draft-irtf-cfrg-hybrid-kems-12, 6 July 2026 | https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.txt | UG/UK/CG/CK frameworks |
| ietf-draft-irtf-cfrg-concrete-hybrid-kems-04.txt | draft-irtf-cfrg-concrete-hybrid-kems-04 | https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.txt | MLKEM768-X25519 = X-Wing |
| ietf-draft-ietf-hpke-pq-05.txt | draft-ietf-hpke-pq-05 | https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt | HPKE mapping, KEM id 0x647a |
| ietf-draft-ietf-lamps-pq-composite-kem-21.txt | draft-ietf-lamps-pq-composite-kem-21 | https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-kem-21.txt | composite ML-KEM combiner |
| online | IETF datatracker API, document and state records | https://datatracker.ietf.org/api/v1/doc/document/ | all draft/RFC status rows |
| ietf-rfc9954-hybrid-key-exchange-tls13.pdf | D. Stebila, S. Fluhrer, S. Gueron, RFC 9954, July 2026 | https://www.rfc-editor.org/rfc/rfc9954 | TLS hybrid design |
| ietf-rfc10024-pqt-hybrid-ecdhe-mlkem-tls13.pdf | K. Kwiatkowski, P. Kampanakis, B. E. Westerbaan, D. Stebila, RFC 10024, Aug 2026 | https://www.rfc-editor.org/rfc/rfc10024 | X25519MLKEM768 etc. |
| ietf-rfc9941-sntrup761x25519-sha512-ssh.pdf | M. Friedl, J. Mojzis, S. Josefsson, RFC 9941, April 2026 | https://www.rfc-editor.org/rfc/rfc9941 | SSH sntrup761 hybrid |
| ietf-rfc10042-mlkem-hybrid-kex-ssh.pdf | P. Kampanakis, D. Stebila, T. Hansen, RFC 10042, Aug 2026 | https://www.rfc-editor.org/rfc/rfc10042 | SSH ML-KEM hybrids |
| ietf-rfc9980-openpgp-pqc.pdf | S. Kousidis, J. Roth, F. Strenzke, A. Wussler, RFC 9980, June 2026 | https://www.rfc-editor.org/rfc/rfc9980 | OpenPGP composite KEM combiner |
| online | OpenSSH release notes | https://www.openssh.com/releasenotes.html | default KEX history |
| online | C2SP age specification (age.md) | https://github.com/C2SP/C2SP/blob/main/age.md | age PQ recipient |
| online | age GitHub releases (API) | https://api.github.com/repos/FiloSottile/age/releases | v1.3.0 / v1.3.2 dates |
| signal-spec-pqxdh.pdf | E. Kret, R. Schmidt, "The PQXDH Key Agreement Protocol", Revision 3, 2023-05-24 (updated 2024-01-23) | https://signal.org/docs/specifications/pqxdh/ | PQXDH KDF, AD, Sec. 4.12 |
| signal-spec-doubleratchet.pdf | "The Double Ratchet Algorithm", Revision 4, 2025-11-04 | https://signal.org/docs/specifications/doubleratchet/ | SPQR, Triple Ratchet |
| signal-spec-mlkembraid.pdf | "The ML-KEM Braid Protocol", Revision 1, 2025-02-21 (updated 2025-09-26) | https://signal.org/docs/specifications/mlkembraid/ | SCKA context |
| online | Apple Security Research, "iMessage with PQ3", 21 Feb 2024 | https://security.apple.com/blog/imessage-pq3/ | PQ3 combiner |
| rosenpass-whitepaper.pdf | K. Varner et al., Rosenpass whitepaper, version 89a8805 (2026-09-24) | https://rosenpass.eu/ | McEliece + Kyber + WireGuard |
| online | mullvad/mullvadvpn-app, talpid-tunnel-config-client/src/lib.rs and hqc.rs (last commit 536291d4f3ac, 2026-09-22) | https://github.com/mullvad/mullvadvpn-app | ML-KEM-1024 XOR HQC-256 PSK |
| etsi-ts-103-744-v1.2.1-quantum-safe-hybrid-key-establishment.pdf | ETSI TS 103 744 V1.2.1 (2025-03) | etsi.org | CatKDF/CasKDF, >2 schemes |
| 2024-fiedler-gunther-security-analysis-signal-pqxdh.pdf | R. Fiedler, F. Günther, PQXDH analysis (2024) | (file) | pointer only (not re-read here) |
| 2026-millerjord-stebila-steckel-split-key-prfs-extended-hybrid-security.pdf | L. Millerjord, D. Stebila, C. Steckel, "Split-key PRFs and Extended Hybrid Security for KEM Combiners", IACR CiC 2(4), 2026 | https://doi.org/10.62056/ah890lmol | key reuse between hybrid and components (Sec. 3a) |
| 2026-kang-lee-son-public-contexts-hybrid-kems-x-wing.pdf | T. Kang, C. Lee, Y. Son, "On the Necessity of Public Contexts in Hybrid KEMs: A Case Study of X-Wing", ePrint 2026/140 (preprint) | https://eprint.iacr.org/2026/140 | X25519 inversion second preimage, multi-target salting (Sec. 3a) |
| 2024-schmieg-unbindable-kemmy-schmidt-ml-kem-binding.pdf | S. Schmieg, "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK", 3 April 2024 | https://eprint.iacr.org/2024/523 | ML-KEM MAL binding (open question 4) |
| 2025-mattsson-et-al-ml-kem-is-great-whats-missing.pdf | J. Preuß Mattsson et al. (Ericsson), "ML-KEM is Great! What's Missing?", NIST Workshop on Guidance for KEMs, Feb 2025 | https://csrc.nist.gov/csrc/media/Events/2025/workshop-on-guidance-for-kems/documents/papers/ml-kem-is-great-paper.pdf | industry view on more than two components |
| 2022-bernstein-et-al-classic-mceliece-spec-20221023.pdf | Classic McEliece team, "Classic McEliece: conservative code-based cryptography: cryptosystem specification", 2022-10-23 | https://classic.mceliece.org/ | ciphertext encoding and mceliece460896 parameters |
| online | R. Barnes, K. Bhargavan, B. Lipp, C. Wood, RFC 9180, "Hybrid Public Key Encryption", Feb 2022 (copy in scratch pq/hyb/cont/rfc9180.txt) | https://www.rfc-editor.org/rfc/rfc9180.txt | DHKEM and its security claims (Secs. 1, 4.1, 9.1) |
| online | RFC Editor errata pages for RFC 9954, 10024, 9941, 10042, 9980 | https://www.rfc-editor.org/errata/rfc9980 (and likewise) | errata list (Sec. 4) |
| online | Crossref records for DOIs 10.1007/978-3-032-32560-0_2, 10.1007/978-3-032-36264-3_23, 10.62056/ahmp-49p1 | https://api.crossref.org/works/<DOI> | publication status of ABK25, KSW25, StarFortress |

## Claim ledger

| # | claim | status | source |
|---|---|---|---|
| 1 | draft-connolly-cfrg-xwing-kem-11 is dated 23 Sept 2026, expires 27 March 2027, intended status Informational | VERIFIED | ietf-draft-connolly-cfrg-xwing-kem-11.txt, header |
| 2 | X-Wing draft: rev 11, Active, stream ISE, ISE state "Submission Received", IESG "I-D Exists" | VERIFIED | datatracker API doc record + states 1, 150, 68 (fetched 2026-09-27) |
| 3 | No document named draft-irtf-cfrg-xwing-kem exists | VERIFIED | datatracker API returned HTTP 404 for that name (2026-09-27) |
| 4 | draft-11 differs from draft-10 only in dates, one re-wrapped hex line and an affiliation | COMPUTED | `diff` of the two texts (headers/footers stripped), Sec. "What this means" 1 |
| 5 | X-Wing sizes: dk 32, ek 1216, ct 1120, ss 32 bytes | VERIFIED | draft-11 Sec. 5.1 |
| 6 | X-Wing combiner = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel), label hex 5c2e2f2f5e5c | VERIFIED | draft-11 Sec. 5.3 |
| 7 | The 2024 paper prints the label first | VERIFIED | X-Wing paper Fig. 12, p. 18 |
| 8 | draft-11 test vectors reproduce with label-last and not with label-first | COMPUTED | hybrid_combiner_checks.py part A (command in Sec. 8) |
| 9 | Draft security statement: with SHA3-256/SHA3-512/SHAKE-256 as ROs, IND-CCA bounded by ML-KEM-768 IND-CCA and Curve25519 gap-CDH; combiner "cannot be assumed to be secure, when used with different KEMs" | VERIFIED | draft-11 Sec. 6 |
| 10 | Draft claims MAL-BIND-K-PK and MAL-BIND-K-CT with "(TODO: reference to proof)" | VERIFIED | draft-11 Sec. 6.1 |
| 11 | X-Wing paper Theorem 1: Adv ≤ 2Δ_N + Adv_SDH + Adv_C2PRI (ROM) | VERIFIED | X-Wing paper p. 9 |
| 12 | X-Wing paper Theorem 2: Adv ≤ Adv_IND-CCA(KEM, B) + Adv_IND-CCA(KEM, C) + Adv_PRF(H, D) + Adv_PRF(H, E) + 2δ, δ the KEM correctness bound (standard model) | VERIFIED | X-Wing paper p. 13 |
| 13 | ML-KEM-768 C2PRI advantage ≤ (q_g + q_j + 2)/2^256 | VERIFIED | X-Wing paper Theorem 3, pp. 16-17 |
| 14 | "X25519, if seen as a KEM, is not ciphertext second preimage resistant" | VERIFIED | X-Wing paper Sec. 2, p. 4 |
| 15 | X-Wing hashes 134 bytes; X-Wing-Hash-CT 1222 bytes | VERIFIED | X-Wing paper Sec. 8, p. 19; recomputed in script part C |
| 16 | hybrid-kems-12: rev 12 (6 July 2026), IRTF stream, "Waiting for Document Shepherd", intended Informational | VERIFIED | datatracker API (states 1, 150, 59) + draft header |
| 17 | Four frameworks UG, UK, CG, CK along two axes | VERIFIED | hybrid-kems-12 Sec. 5, Table 1 |
| 18 | UniversalCombiner and C2PRICombiner inputs as quoted | VERIFIED | hybrid-kems-12 Sec. 5.1.3 |
| 19 | KDF MUST be indifferentiable from a RO, also to quantum attackers | VERIFIED | hybrid-kems-12 Sec. 6.1.5 |
| 20 | Fixed-length secrets MUST; labels suffix-free MUST | VERIFIED | hybrid-kems-12 Secs. 6.5.2, 7 |
| 21 | More than two components out of scope | VERIFIED | hybrid-kems-12 Sec. 8 |
| 22 | Separate key generation reduces MAL-BIND to LEAK-BIND; component key reuse MUST NOT | VERIFIED | hybrid-kems-12 Sec. 5.2 |
| 23 | Proof status: CG in [XWING], UK via GHP18 with argued modification, UG in [CG26], CK in [COS_26] | VERIFIED | hybrid-kems-12 Sec. 6.4.1 |
| 24 | StarFortress published in IACR CiC vol. 3 no. 1, 2026-05-04, DOI 10.62056/ahmp-49p1 (ePrint 2026/125 still says "Preprint") | VERIFIED | Crossref record for DOI 10.62056/ahmp-49p1 (scratch pq/fc-hyb/doi-starfortress.json); ePrint metadata via eprint_meta.py 2026/125 |
| 25 | concrete-hybrid-kems-04: rev 04, "Waiting for Document Shepherd"; MLKEM768-X25519 is CG with SHAKE256/SHA3-256 and "identical to the X-Wing construction", label \.//^\ | VERIFIED | datatracker API; concrete-hybrid-kems-04 Sec. 4, 4.2 |
| 26 | SP 800-227 published September 2025 | VERIFIED | CSRC SP 800-227 page; PDF cover |
| 27 | SP 800-227 composite construction and KeyCombine inputs (eqs. (9), (10)); dk holder must retain ek | VERIFIED | SP 800-227 Sec. 4.6.1, printed pp. 27-28 |
| 28 | More than two components: "extended in the obvious way" | VERIFIED | SP 800-227 Sec. 4.6.1, printed p. 28 |
| 29 | Eq. (14) approved for any t > 1 if one secret is from SP 800-56A/B or an approved KEM | VERIFIED | SP 800-227 Sec. 4.6.2, printed p. 30 |
| 30 | Example (15) H(K1, K2, c1, c2, ek1, ek2, domain_sep) | VERIFIED | SP 800-227 printed p. 30 |
| 31 | SP 800-133 combiners require all keys approved; concatenation output must pass a KDF | VERIFIED | SP 800-227 printed p. 30 |
| 32 | KDF(K1, K2) "does not preserve IND-CCA security, regardless of the properties of the KDF"; KeyCombineCCA_H with SHA-3; GHP18 cited; ek not needed for IND-CCA | VERIFIED | SP 800-227 Sec. 4.6.3, printed pp. 31-32 |
| 33 | Composite schemes add complexity and downgrade risk | VERIFIED | SP 800-227 printed p. 32 |
| 34 | SP 800-56C Rev. 2 (Aug 2020) still current; planning note 6 Jan 2026 to revise (KEM secrets in Z, hybrid formats, KMAC in two-step) | VERIFIED | CSRC SP 800-56C r2 page and linked news item |
| 35 | SP 800-56C Rev. 2 allows Z′ = Z ‖ T | VERIFIED | SP 800-56C r2 Sec. 2, PDF p. 10 |
| 36 | One-step KDF options 1-3; Option 3 KMAC with S = "KDF"; KMAC256 default salt 132 zero bytes | VERIFIED | SP 800-56C r2 Sec. 4.1, printed pp. 11-13 (PDF 19-21) |
| 37 | Option 1 output lengths in {160, 224, 256, 384, 512} (fixed-output hashes, so SHAKE is not an Option 1 choice) | VERIFIED | SP 800-56C r2 Sec. 4.1, printed p. 12 (the SHAKE conclusion is my reading of that list) |
| 38 | GHP18 parallel combiner for n KEMs | VERIFIED | GHP18 Sec. 3, Fig. 4, p. 6 |
| 39 | XOR keeps IND-CPA (Lemma 1), not IND-CCA (Lemma 2) | VERIFIED | GHP18 p. 7 |
| 40 | GHP18 Theorem 1 and its bound 2·(Adv_KEM_i + Adv_skPRF), C makes ≤ q_d + 1 queries | VERIFIED | GHP18 p. 10 |
| 41 | GHP18 proof assumes perfectly correct KEMs | VERIFIED | GHP18 proof sketch of Theorem 1, p. 10 |
| 42 | Lemma 6: H(g(k), x) skPRF in ROM with Adv ≤ q_H·ε; Example 3: concatenation is almost uniform | VERIFIED | GHP18 p. 22 (definition p. 21) |
| 43 | GHP18 = PKC 2018, ePrint 2018/024 | VERIFIED | ePrint metadata (eprint_meta.py 2018/024) |
| 44 | Bindel et al.: PQCrypto 2019, ePrint 2018/903 | VERIFIED | ePrint metadata |
| 45 | Mix-and-match on XOR works even if both KEMs are IND-CCA | VERIFIED | Bindel et al. Sec. 3.1, p. 11 |
| 46 | Dual-PRF combiner bound with min{...} (Theorem 2); proofs cover QcQ, not QqQ | VERIFIED | Bindel et al. p. 16; p. 11 |
| 47 | ABK25: ePrint 2025/1444, received 2025-08-08; published in ACNS 2026 proceedings, LNCS pp. 32-74, DOI 10.1007/978-3-032-32560-0_2, first online 2026-07-22 (ePrint page still says "Preprint") | VERIFIED | ePrint page; Crossref record for the DOI (scratch pq/hyb/cont/abk25-crossref.json) |
| 48 | ABK25 Theorem 8 (n KEMs, ciphertext omission for C2PRI components, δ term) | VERIFIED | ABK25 Theorem 3 p. 3, Theorem 8 p. 15 |
| 49 | ABK25 Theorem 9: 4·sqrt((q²+q)/\|K_i\|) for H(k1‖…‖kn‖x), quantum queries | VERIFIED | ABK25 Theorem 4 p. 4, Theorem 9 p. 15 |
| 50 | ABK25 Theorem 5 C2PRI bounds (q+1)/\|K\| (ROM), 4·sqrt((q²+q)/\|K\|) (QROM) for U⊥-family FO KEMs | VERIFIED | ABK25 p. 4 |
| 51 | Theorem 9 bound reaches 1 at q = 2^126 (256-bit key), 2^94 (192-bit), 2^62 (128-bit) | COMPUTED | hyb_factcheck_math.py part 4 (mpmath root); consistent with hybrid_combiner_checks.py part D |
| 52 | Starfighters: QSF compatible with ML-KEM, (e)FrodoKEM, HQC, Classic McEliece, NTRU variants; IEEE S&P 2026 | VERIFIED | Starfighters abstract p. 1; ePrint 2025/1397 metadata |
| 53 | Starfighters proves HQC C2PRI for the Aug 2025 HQC spec (salted FO) | VERIFIED | Starfighters Sec. 4.2, p. 32 |
| 54 | KSW25: hashing both pks and cts gives all 12 K-binds notions from collision resistance | VERIFIED | KSW25 p. 2 |
| 55 | KSW25: all their KEMs but HQC have X-BIND-K-CT; McEliece lacks X-BIND-K-PK; HQC/HQC*/BIKE K-PK only HON | VERIFIED | KSW25 Table 2 and text, p. 21 |
| 56 | KSW25: HQC attack also breaks C2PRI; HQC team adopted HQC* in the 22 Aug 2025 spec | VERIFIED | KSW25 footnotes 11 (p. 20) and 9 (p. 19) |
| 57 | RFC 9954: July 2026, Informational; "two or more"; concatenated secrets into key schedule; dual-PRF argument | VERIFIED | RFC 9954 header, Secs. 3.2, 3.3, 6 |
| 58 | RFC 10024: Aug 2026, Standards Track; codepoints 4588/4587/4589; 1216/1120-byte shares; ML-KEM first in X25519MLKEM768 for FIPS reasons | VERIFIED | RFC 10024 header, Secs. 4.1-4.3, 5, 7.1-7.3 |
| 59 | RFC 10024 Sec. 6 transcript warning and shared-RNG warning | VERIFIED | RFC 10024 Sec. 6 |
| 60 | draft-ietf-tls-mlkem-11 in RFC Editor queue, state "Blocked" | VERIFIED | datatracker API (states 17, 217) |
| 61 | OpenSSH 8.9 added, 9.0 defaulted sntrup761x25519; 9.9 added mlkem768x25519-sha256; 10.0 made it default; 10.1 warns on non-PQ KEX; 10.5 released 2026-08-11 | VERIFIED | openssh.com/releasenotes.html (fetched 2026-09-27) |
| 62 | RFC 9941 (April 2026): K = SHA-512(ss_sntrup ‖ ss_X25519); share sizes 1190/1071 bytes | VERIFIED | RFC 9941 Sec. 3 |
| 63 | RFC 10042 (Aug 2026): K = HASH(K_PQ ‖ K_CL); exchange hash covers C_INIT, S_REPLY, K | VERIFIED | RFC 10042 Secs. 2.4, 2.5 |
| 64 | RFC 9980 (June 2026, Standards Track): IDs 35 (MUST) / 36 (SHOULD); KEK = SHA3-256(...domSep ‖ len); AES-256 key wrap; independent component keygen | VERIFIED | RFC 9980 Secs. 4.2.1-4.2.3, 9.2, 9.2.1, algorithm table |
| 65 | age v1.3.0 released 2025-12-27 with native PQ recipients; latest v1.3.2 (2026-08-29) | VERIFIED | GitHub releases API for FiloSottile/age |
| 66 | age PQ recipient = HPKE SealBase, MLKEM768-X25519 (hpke-pq-03), HKDF-SHA256, ChaCha20Poly1305, info "age-encryption.org/mlkem768x25519", enc 1120 bytes | VERIFIED | C2SP age.md "MLKEM768-X25519 (i.e. X-Wing)" section |
| 67 | hpke-pq-05 maps MLKEM768-X25519 to concrete-hybrid-kems; KEM id 0x647a, Nenc 1120, Npk 1216 | VERIFIED | hpke-pq-05 Sec. 4 and IANA table |
| 68 | PQXDH Rev. 3 (2023-05-24, updated 2024-01-23): SK = KDF(DH1‖DH2‖DH3[‖DH4]‖SS); pk into AD if KEM does not bind it; Sec. 4.12 | VERIFIED | signal-spec-pqxdh.pdf / online spec Secs. 2.2, 3.3, 4.12 |
| 69 | Double Ratchet Rev. 4 (2025-11-04) defines SPQR and Triple Ratchet with mk = KDF_HYBRID(ec_mk, pq_mk) | VERIFIED | signal-spec-doubleratchet.pdf Secs. 5, 6.3, 6.5 |
| 70 | Apple PQ3: Kyber-1024 + P-256 registration keys, Kyber-768 rekeys ~every 50 messages / ≥ once per 7 days, three HKDF-SHA384-Extract calls incl. public keys and encapsulated secret | VERIFIED | Apple Security Research blog, 21 Feb 2024 (vendor primary source; prose, not a spec) |
| 71 | Rosenpass: McEliece-460896 (r3) static + Kyber-512 (r3) ephemeral, sizes as quoted, output as WireGuard PSK, mix(pk, shk, ct) per KEM | VERIFIED | rosenpass-whitepaper.pdf pp. 4-7, 10, 20 |
| 72 | Mullvad XORs ML-KEM-1024 and SHA-256(HQC-256 ss) into the WireGuard PSK with per-negotiation key pairs | VERIFIED | mullvadvpn-app lib.rs and hqc.rs at commit 536291d4f3ac (2026-09-22) |
| 73 | ETSI TS 103 744 V1.2.1 (2025-03) CatKDF/CasKDF; MB must contain all pks/cts with > 2 schemes | VERIFIED | ETSI TS 103 744 Sec. 8.2, PDF p. 23 |
| 74 | LAMPS composite KEM rev 21 in IESG Evaluation; ss = SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label) | VERIFIED | datatracker API (state 12); draft-21 Sec. 3.4 |
| 75 | ML-KEM sizes (ek/dk/ct/ss): 512: 800/1632/768/32; 768: 1184/2400/1088/32; 1024: 1568/3168/1568/32 | VERIFIED | FIPS 203 Table 3 (PDF p. 48) |
| 76 | FrodoKEM-976 pk 15,632, ct 15,792, ss 24; FrodoKEM-1344 pk 21,520, ct 21,696, ss 32 | VERIFIED | FrodoKEM proposal 2025-09-29 Table A.5 (PDF p. 16) |
| 77 | Size/hash-cost table for 2- and 3-component hybrids | COMPUTED | hybrid_combiner_checks.py part C |
| 78 | Real ML-KEM-768 + X25519 XOR broken 5/5; UG layout 0/5; X-Wing without ct_X broken 5/5, with 0/5; toy non-FO KEM not C2PRI 64/64, FO 0/64 | COMPUTED | hybrid_combiner_checks.py parts B1-B3 |
| 79 | Three-way hybrids: omitting a non-C2PRI component's ciphertext breaks in one query (5/5); hashing it, or FO on the component, gives 0/5; three-way XOR broken 3/3; n-way XOR (n = 2..5) broken with 2 queries 4/4, hash-all 0/4 | COMPUTED | hyb_worked_examples.py parts 2-3; hyb_factcheck_math.py part 2 |
| 80 | KMAC256 implementation matches NIST samples; per-field encoding removes concatenation collisions | COMPUTED | hybrid_combiner_checks.py part E |
| 81 | Proofs do not cover component implementations sharing memory/seed/RNG; extra components add implementation and availability risk | UNVERIFIED | author's reading of the proof models (GHP18, X-Wing, ABK25); would be settled by a published analysis of hybrids under implementation compromise |
| 82 | A custom module-lattice component with ML-KEM-like structure would likely fall to the same structural attack as ML-KEM | UNVERIFIED | reasoning; evidence belongs to the lattice-foundations / attack-cost-estimation topics |
| 83 | No standard file-encryption format with three KEM components exists | UNVERIFIED | negative result of this survey (age, RFC 9980, HPKE-PQ, LAMPS all two-component); a wider search could overturn it; a web search on 2026-09-27 for three-KEM / triple-hybrid file encryption also found no standard |
| 84 | Whether a nested (X-Wing output as S1) combination satisfies SP 800-227 eq. (14) for FIPS purposes | UNVERIFIED | SP 800-227 text does not address derived secrets as S_j; needs NIST/CMVP guidance |
| 85 | age file key is 128 bits (16 bytes of CSPRNG output), also with PQ recipients | VERIFIED | C2SP age.md, "File key" section |
| 86 | LAMPS composite ML-KEM also promotes RSA-OAEP into a KEM as the traditional component | VERIFIED | draft-ietf-lamps-pq-composite-kem-21 Sec. 2.1 heading and Sec. 3.4 |
| 87 | "Using hybrid protocols is explicitly recommended by European agencies" | VERIFIED | ABK25 p. 1 (the agencies' documents themselves: nist-pqc-standards topic) |
| 88 | ML-KEM Encaps_internal computes (K, r) ← G(m ‖ H(ek)); dk stores H(ek) | VERIFIED | FIPS 203 Algorithms 16-17 |
| 89 | docs/03 names X-Wing draft version 10 and says the combiner "also binds the ciphertexts and public keys" | VERIFIED | docs/03-design-spec.md lines 13-17, 90-92 (read 2026-09-27) |
| 90 | The ML-KEM Braid spec was last updated 2025-09-26 | VERIFIED | signal-spec-mlkembraid.pdf, p. 1 |
| 91 | GHP18 gives iO-related doubts about FO and a preference for generic combiners as reasons not to merge at the CPA level | VERIFIED | GHP18 Remark after Lemma 1, p. 7 |
| 92 | GHP18's result assumes the combined KEM's keys are generated independently of any stand-alone use of the ingredient KEMs | VERIFIED | Millerjord-Stebila-Steckel 2026 (CiC 2(4)), abstract and pp. 2-3 |
| 93 | MSS26: with identity post-processing the extended (ind-hycca) notion is unsatisfiable; Figure 11 construction k = W(PRF_i(k_i, lbl)..., c), stand-alone output PRF_i(k_i, c_i); Theorem 2: secure if one ingredient is IND-CCA, W split-key PRF, PRF_i PRFs | VERIFIED | MSS26 Sec. 4.1 Def. 12 and Fig. 10 (pp. 15-16); Theorem 2 (p. 16); Fig. 11 (p. 17) |
| 94 | MSS26: IACR CiC vol. 2 no. 4, DOI 10.62056/ah890lmol, received 2025-10-06, accepted 2025-12-02, dated 2026-01-08 | VERIFIED | MSS26 PDF p. 1; CiC article page metadata (scratch pq/fc-hyb/cic-2-4-17.html) |
| 95 | Reusing an X-Wing key pair both inside a Turing hybrid and as an age recipient falls in MSS26's key-reuse model and is outside GHP18 | UNVERIFIED | author's application of MSS26 (the paper discusses S/MIME, not X-Wing or age); settle by an analysis of HPKE's key schedule as the post-processing Γ |
| 96 | hybrid-kems-12: separate key generation "should only be used in environments where implementations of component algorithms do not allow decapsulation keys to be imported or exported"; shared seed prevents reuse | VERIFIED | draft-irtf-cfrg-hybrid-kems-12 Sec. 5.2 |
| 97 | hybrid-kems-12 binding analyses are informal; rigorous proofs deferred | VERIFIED | draft-irtf-cfrg-hybrid-kems-12 Sec. 6.4.2 |
| 98 | Raw X25519 KEM fails C2PRI via c′ = (c*)^-1 mod p (2-torsion shift; clamped scalar is a multiple of 8) | VERIFIED | Kang-Lee-Son, ePrint 2026/140, Theorem 1, p. 6 |
| 99 | The inversion and bit-255 second preimages give the same raw X25519 secret in 50/50 trials each; c* + 1 in 0/50; hashing ct_X separates them | COMPUTED | hyb_x25519_torsion.py (command in Sec. 8) |
| 100 | Kang-Lee-Son: without a per-recipient salt a multi-target attacker gains a factor N (N·Q/2^κ); salting with ID(pk_i) gives Q/2^κ; Table I (raw X25519: include c2 and pk2; HPKE DHKEM: neither) | VERIFIED | Kang-Lee-Son Lemma 2 and Corollary 1 (pp. 7-8, proof sketches, ROM); Table I (p. 2); ePrint 2026/140 is a preprint (received 2026-01-29) |
| 101 | HPKE DHKEM(X25519) can serve as an IND-CCA X25519 component in a flat combiner | UNVERIFIED | RFC 9180 Sec. 1 claims HPKE is IND-CCA2 under classical assumptions [HPKEAnalysis][ABHKLR20]; Sec. 9.1 gives GDH + HKDF-as-RO bounds for the Auth mode. A stand-alone Base-mode DHKEM IND-CCA theorem was not read; settle by reading [ABHKLR20] |
| 102 | ABK25 Theorem 8 (n KEMs) has only a proof sketch; Secs. 3.3 and 4 were added after the TCC 2025 submission | VERIFIED | ABK25 p. 15 ("Proof sketch"), p. 5 ("Recent related work") |
| 103 | ABK25 Theorems 1-3 and 8 are generic (split-key PRF) against QPT adversaries with classical oracle queries; the QROM enters only through Theorem 9 | VERIFIED | ABK25 pp. 2-3 and p. 15 |
| 104 | ABK25 Theorem 2: the secrets-only dual-PRF combiner is IND-CCA if KEM1 is IND-CCA and KEM2 C2PRI, or vice versa | VERIFIED | ABK25 p. 3 (informal statement) |
| 105 | Bindel et al. argue XtM is QqQ-secure if one KEM is QqQ and the MAC QcQ | VERIFIED | Bindel et al. p. 3 (summary) and Sec. 3.1.4, p. 15 |
| 106 | KSW25 full title "... : An Analysis of Real-World KEM Combiners"; published SCN 2026, LNCS pp. 455-473, DOI 10.1007/978-3-032-36264-3_23, first online 2026-09-27 | VERIFIED | eprint_meta.py 2025/1416; Crossref record for the DOI (scratch pq/hyb/cont/ksw-cr.json) |
| 107 | KSW25: the generic combiner achieves all 12 "K binds ..." notions (HON, LEAK and MAL) from collision resistance of Combine if both pks and cts are inputs | VERIFIED | KSW25 ePrint version, p. 2 (contributions) |
| 108 | StarHunters (2026/427) and Kramer-Weishaupl-Winderl (2026/407) are preprints; Starfighters (2025/1397) is IEEE S&P 2026 | VERIFIED | eprint_meta.py 2026/427 2026/407 2025/1397 (fetched 2026-09-27) |
| 109 | Hashing a b-bit secret up to 256 bits leaves at most 2^b values, so GHP18 Lemma 6's ε stays 2^-b | COMPUTED | hyb_factcheck_math.py part 5 (b = 16) |
| 110 | A generic attack on a hash-all hybrid that breaks components one by one costs the sum of their costs, at most log2(n) bits above the strongest | COMPUTED | hyb_factcheck_math.py part 7 |
| 111 | Raw X25519 as a KEM is not IND-CCA (bit-255 query returns k* in 200/200) and not pseudorandom (top output bit always 0) | COMPUTED | hyb_factcheck_math.py part 3 |
| 112 | Classic McEliece 2022: ciphertext is ⌈mt/8⌉ bytes; mceliece460896 has m = 13, t = 96, so 156 bytes (round 3 as quoted by Rosenpass: 188) | VERIFIED (parameters, encoding) / COMPUTED (156) | 2022-bernstein-et-al-classic-mceliece-spec-20221023.pdf Secs. 6.2, 7.3; hyb_factcheck_math.py part 8 |
| 113 | KMAC256 with a 132-byte salt adds 3 fixed Keccak-f calls | COMPUTED | hyb_factcheck_math.py part 9 |
| 114 | RFC errata: 9954 #9136 Verified Editorial; 10042 #9160 Verified Editorial and #9159 Reported Technical; 9980 #9023 Reported Technical (decryption omits ecdhPublicKey); none for 9941, 10024 | VERIFIED | rfc-editor.org errata search pages (fetched 2026-09-27; scratch pq/fc-hyb/errata-*.html) |
| 115 | In the flat three-way combiner with raw X25519, GHP18 does not cover the X25519-only branch; the nested form covers every branch with published two-component theorems | UNVERIFIED | author's reading of GHP18 Theorem 1 (needs an IND-CCA ingredient) and X-Wing Theorems 1-3; no published three-component nominal-group proof was found |
| 116 | Starfighters Table 2: QSF satisfies HON/LEAK-BIND-K-CT, K,PK-CT (needs KEM0 property, H CR), K-PK, K,CT-PK (needs ϵpk, H CR), CT-PK (KEM0 CT-PK, ϵpk); CT-K marked ✗*; MAL-BIND-K-CT, K,PK-CT, K-PK, K,CT-PK ✓ if KEM0 has them and H is CR; MAL-BIND-CT-K, CT-PK ✗ | VERIFIED | 2025-connolly-et-al-starfighters-general-applicability-of-x-wing.pdf Table 2, p. 21 (rendered page image); prose p. 15 |
| 117 | ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK (malformed private keys); a proof is sketched for less manipulable keys | VERIFIED | 2024-schmieg-unbindable-kemmy-schmidt-ml-kem-binding.pdf, abstract p. 1 |
| 118 | HPKE DHKEM computes shared_secret = ExtractAndExpand(dh, kem_context) with kem_context = enc ‖ pkRm (Base mode) | VERIFIED | RFC 9180 Sec. 4.1 |
| 119 | Ericsson (Mattsson et al.) anticipate hybrid secrets with more than two components to be relatively common | VERIFIED | 2025-mattsson-et-al-ml-kem-is-great-whats-missing.pdf p. 2 (opinion paper, NIST KEM workshop Feb 2025) |
| 120 | SP 800-56C Rev. 2 is still current on 2026-09-27; the CSRC page shows only the 01/06/2026 planning note, no Rev. 3 draft | VERIFIED | CSRC SP 800-56C Rev. 2 page (fetched 2026-09-27, scratch pq/fc-hyb/nist-56c.html) |

## Open questions

1. **Nested vs flat for NIST mapping.** Does SP 800-227 eq. (14) accept X-Wing's output (an
   SP 800-56C-style derivation of ML-KEM's secret) as the approved S1? Only relevant if FIPS
   validation is ever a goal; the revised SP 800-56C (announced 6 Jan 2026, no draft yet) may
   answer it.
2. **C2PRI for a custom component.** If the owner wants the X-Wing-style shortcut for the custom
   lattice KEM, its exact FO variant needs a C2PRI proof (ABK25 Theorem 5 / Starfighters cover
   standard U⊥ / U̸⊥ / salted FO variants). Until then, hash its ciphertext (the cost is small).
3. **QROM statement for the three-way KEM.** ABK25 (ACNS 2026) is the only n-KEM combiner proof
   against quantum adversaries found, and its n-KEM theorem is only sketched. The nested design
   needs only the two-KEM Theorem 1. For a clean 128-bit QROM statement the secure component's
   secret should be at least 256 bits.
4. **X-Wing binding proof.** draft-11 Sec. 6.1 still says "(TODO: reference to proof)" for
   MAL-BIND-K-PK / MAL-BIND-K-CT. Partly answered in the continued run: Starfighters Table 2
   (p. 21) shows the QSF shape (X-Wing's) has MAL-BIND-K-CT, K,PK-CT, K-PK and K,CT-PK *if* the
   post-quantum KEM has those MAL properties and the hash is collision resistant, and it fails
   MAL-BIND-CT-K and MAL-BIND-CT-PK. ML-KEM with expanded decapsulation keys lacks MAL-BIND-K-CT
   and MAL-BIND-K-PK (Schmieg 2024, abstract); Schmieg sketches a proof for keys the attacker
   cannot manipulate "as liberally" (X-Wing stores only a 32-byte seed). So X-Wing's MAL claim
   rests on a sketched ML-KEM result plus Starfighters. The Turing outer combiner hashes both
   public keys and both ciphertexts, so its own K-binding follows from collision resistance
   (KSW25) without this chain. (Starfighters' prose on p. 15 says QSF does not preserve HON/LEAK
   CT-PK, while Table 2 puts the ✗* under CT-K; the table and text disagree.)
5. **HQC version.** If HQC is considered as a component, pin the 22 Aug 2025 (or FIPS 207)
   version and re-check C2PRI and binding (KSW25 vs Starfighters vs ABK25 disagree on older
   versions).
6. **StarFortress venue.** Resolved: IACR CiC 3(1), 2026-05-04 (ledger row 24).
7. **Key generation style.** Resolved in favour of one master seed expanded by a PRG into the
   component seeds (hybrid-kems-12 Sec. 5.2; Sec. 7 and "What this means" 2-3). Still open: how
   Turing's key files store the seed, the public-key digest and any derived component keys
   (turing-integration-constraints topic).
8. **Multi-recipient files.** How many stanzas per file, and whether each stanza needs its own
   ephemeral values, is a file-format question (docs/03 Layer 3); binding the recipient public
   key (via the key digest) matters there. Not analysed here.
9. **Is age's HPKE key schedule a valid post-processing Γ in the Millerjord-Stebila-Steckel
   model?** Only matters if the owner wants one X-Wing key to serve both as an age recipient and
   inside Turing's hybrid. The simple answer is not to reuse keys.
10. **A three-component proof with a nominal-group (raw DH) component.** X-Wing and StarFortress
    cover two components. A flat ML-KEM + X25519 + custom design needs either DHKEM(X25519) as
    the classical component (whose stand-alone IND-CCA theorem in [ABHKLR20] was not read here,
    ledger row 101) or a new proof. The nested design avoids the question.
11. **Did the published ACNS version of ABK25 add a full proof of Theorem 8?** The chapter is
    behind Springer's paywall; the ePrint version has a sketch.
