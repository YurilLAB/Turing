# Quantum cryptography (QKD, QRNG) and quantum attacks on symmetric designs like Turing

Status: second pass complete, 2026-09-27. The first pass was written by an earlier, interrupted run. The second
pass re-ran every script (all reproduce, the seeded toys byte for byte), re-checked every externally sourced
VERIFIED row mechanically with `qc_verify_ledger.py` (69 of 69 source checks and 3 of 3 negative controls pass),
compared the formula tables with rendered PDF pages, corrected one page citation (L65), closed OQ2 and OQ8, and
added sections 5.6-5.7 (proven quantum bounds for whitening, cascades, key-alternating ciphers, block size, modes,
keyed sponges and multi-key security) with ledger rows L72-L90. Every number is in the claim ledger at the end.

This file covers two things. First, "quantum cryptography" in the sense of hardware that uses quantum physics
(quantum key distribution, QKD; quantum random number generators, QRNG): what it gives, what it needs, how it has
been broken in practice, and what government agencies say about it. Second, what a quantum computer can do against
a symmetric block cipher such as Turing: Grover key search and NIST's security categories, Simon-based
superposition attacks, offline Simon, quantum differential/linear cryptanalysis and quantum related-key attacks,
the proven quantum bounds that say which "twists" (whitening, cascades, key schedules, block size, MACs) help and
which do not, each mapped onto Turing's structure. Date checked: 2026-09-27.

## Key findings

1. **QKD does not fit Turing and is not recommended by any agency read.** It needs an authenticated classical
   channel (pre-shared keys or post-quantum signatures), dedicated optical hardware, and trusted relays beyond about
   100 km (commercial) or a few hundred km (demonstrations); it cannot run in software and gives nothing for data at
   rest. NSA (web page, snapshot 2026-09-18), UK NCSC (2020 and 5 August 2025) and the joint ANSSI / BSI / NLNCSA /
   Swedish NCSA-Swedish Armed Forces position paper (25 January 2024) all put post-quantum cryptography first
   [L24]-[L26], [L32], [L33].
2. **"Provably secure" QKD has been broken in practice.** Lydersen et al. (2010) remote-controlled the detectors of
   two commercial systems with bright light and obtained the full key without raising the error rate [L30], [L31].
3. **QRNGs are not required by any standard read.** NIST SP 800-90B has no quantum class (the word does not occur;
   a QRNG is a physical noise source like any other), BSI AIS 31 (2024) explicitly treats QRNGs as ordinary physical
   TRNGs and "does not distinguish between quantum entropy and entropy from physical phenomena based on other
   physical models", and the NCSC says classical RNGs meet government needs [L32], [L35], [L36], [L89]. Turing needs
   no QRNG.
4. **Grover sets the generic bound: about 2^127.65 sequential cipher calls for a 256-bit key, and it parallelises
   badly.** NIST's category 5 is defined as key search on a 256-bit-key block cipher; for AES-256 the revised Jaques
   et al. estimates (the circuits NIST's 2022 call cites) give 2^246.9, 2^224.4 and 2^192.4 gates at MAXDEPTH 2^40,
   2^64, 2^96 [L1]-[L3], [L8], [L10], [L11]. Later AES circuit papers were not compared (OQ10). No structural
   "twist" changes the 2^(k/2) query count; only the key length does. A heavier cipher only raises the cost per
   call (for Turing, about 5 bits on an S-box proxy [L18]).
5. **NIST evaluates classical-query (Q1) attacks.** Its calls say it is "primarily concerned with" classical queries
   to private-key functionality, and IR 8547 ipd keeps AES-256 as category 5 [L13], [L14].
6. **Superposition-query (Q2) attacks are exponential but need quantum access to the keyed device.** Simon's
   algorithm breaks Even-Mansour, 3-round Feistel, CBC-MAC/PMAC/GMAC/GCM/OCB and self-similar (slidable) ciphers
   with O(n) queries [L40]-[L45]. A file cipher running on a classical computer does not offer such access; Q2 is a
   robustness margin, not Turing's threat model.
7. **Turing's structure already blocks the structural Q2 attacks.** No independent whitening keys (every round key
   comes from K' through a nonlinear schedule), no self-similarity (distinct pseudorandom round keys, alternating
   linear layers, a different last round), and an SPN data path, not a 3-round Feistel (section 6).
8. **The quantum related-key attack breaks every block cipher in its model, whatever the key schedule** [L59]-[L61].
   cSHAKE whitening does not help (toy check). Turing is safe only because its use never offers related-key
   superposition queries; the documents should not suggest otherwise.
9. **Offline Simon brings Simon's algorithm into Q1 for XOR-whitened structures**, and in 2022 gave the first Q1
   break with more than a quadratic speed-up (2XOR-Cascade, 2.5x) [L49]-[L52]. Any "twist" that wraps Turing and
   another layer with XOR masks, or cascades them with independent XOR sub-keys, must be analysed against it.
10. **For Turing the classical margin is the quantum (Q1) margin.** Quantum differential and linear attacks cost at
    least the square root of the classical ones, and with k >= 2n (Turing: 256 = 2 x 128) classical breaks tend to
    become Q1 breaks [L54]-[L57]. The best use of "quantum" effort is therefore more classical cryptanalysis. On
    AES-256 the quantised attacks reach 8 rounds against 9 classically [L58].
11. **The AEAD choice decides the Q2 story for modes.** CTR is IND-qCPA secure from a classically secure PRF; CBC and
    CFB need a quantum-secure PRF; HMAC/NMAC/AMAC are quantum-secure PRFs; CBC-MAC, PMAC, GMAC/GCM and OCB are
    broken in Q2 [L40], [L62]-[L64].
12. **Multi-target search is the one generic quantum loss that design can avoid, and docs/03 does not yet avoid it.**
    If 2^64 files encrypt the same known block under their own keys, one key falls in about 2^112 steps (mesh model)
    [L65], [L66]. docs/03's chunk nonce holds only the counter and the last-chunk flag [L90], so chunk 0 of every
    file shares one block-cipher input. A per-file random value in the block-cipher input removes the shared block;
    the benefit is proven classically [L67] and, for GCM in the quantum ideal cipher model, in a 2026 preprint
    [L86].
13. **The key-relation check that the slide argument leans on holds for version 2.** docs/12's text still says
    "0 relations among 2,432 bits" (version 1: 17 round keys) [L71], but the version-2 Bombe campaign output reports
    0 relations among 3,456 bits (key + 25 round keys) from 3,585 random keys, and 0 for the Feistel stage alone
    [L72]. Only the wording in docs/12 is stale.
14. **Extra whitening keys buy no quantum margin; a plain cascade with an independent key does.** The tight Q1 bound
    for FX is 2^((k+n)/3), which for Turing's k = 2n equals Grover's 2^128, and Leander-May remove whitening in Q2
    [L75], [L76], [L81]. Double encryption with independent keys needs Omega(2^(2k/3)) queries even in Q2, 2^170.67
    for two 256-bit keys [L77], [L81]. Both results are generic (ideal-cipher model).
15. **Multi-round key-alternating structure defeats the polynomial Q2 attacks in the ideal model.** From two rounds on,
    the non-adaptive Q2 lower bound is exponential [L78]; two-key alternating schedules, by contrast, lose to Q1
    attacks at 4 to 6 rounds [L79]. Turing has 24 rounds and 25 distinct round keys [L69], [L72].
16. **A 128-bit block is enough in Q1 but limits Q2 claims for block-cipher MACs.** CTR stays secure up to the
    classical birthday bound even in Q2 [L80]; a feed-forward MAC built from a 128-bit block cipher is limited by
    quantum PRP/PRF switching at about 2^42.67 superposition queries [L80], [L81]. Q2-oriented designs (Saturnin, QCB)
    use 256-bit blocks [L80], [L83].
17. **KMAC's post-quantum proof does not cover a 256-bit key.** Hosoyamada's KMAC theorem (Q1, quantum ideal
    permutation) assumes a key longer than the rate, 1088 bits for KMAC256; inner- and full-keyed sponges are covered
    up to about 2^85.33 queries with a 256-bit key [L84], [L81]. The unkeyed sponge is quantum-indifferentiable with a
    loose bound [L85].

## 1. Quantum key distribution (QKD)

### 1.1 BB84 in brief

BB84 (Bennett and Brassard, 1984) sends single photons, each polarised in one of two bases: rectilinear
(0 or 90 degrees) or diagonal (45 or 135 degrees). Alice picks a random bit and a random basis for each photon.
Bob measures each photon in a random basis of his own. If his basis matches Alice's he reads her bit; if not, the
laws of quantum mechanics give him a random answer. Over a public channel they then compare bases (not bits) and
keep only the positions where the bases matched ("sifting"), about half of them.

Why an eavesdropper is detected: she cannot copy an unknown photon, so she must measure it and send a replacement.
The paper states that no measurement on a photon in transit, by an eavesdropper who learns the basis only
afterwards, gives more than 1/2 expected bit about the key bit, and a measurement giving b bits (b <= 1/2) causes a
disagreement with probability at least b/2. Measuring every photon in the rectilinear basis learns half the
polarisations and causes disagreement in 1/4 of re-measured bits [L19]. Alice and Bob sacrifice a random sample of
sifted bits to estimate the error rate (QBER); a high QBER means someone was listening.

Worked example (`qc_qkd_toy.py`, 200,000 simulated photons, seed 20260926) [L20]:

| scenario | sifted / sent | QBER | Eve's bit equals Bob's |
|---|---|---|---|
| no eavesdropper | 0.499 | 0.000 | (no Eve) |
| intercept-resend, random basis | 0.500 | 0.251 | 0.747 of sifted bits |
| detector blinding (section 1.4) | 0.250 | 0.000 | 1.000 of sifted bits |

The public channel must be authenticated. BB84 itself says so: the requirement that the public channel resist
active eavesdropping "can be relaxed if" Alice and Bob "have agreed beforehand on a small secret key", used for
Wegman-Carter authentication tags [L21]. Without authentication, an attacker simply runs BB84 separately with
Alice and with Bob (a man-in-the-middle).

### 1.2 E91 in brief

E91 (Ekert, 1991) uses a source of entangled photon pairs in the singlet state (|01> - |10>)/sqrt 2. Alice measures
at angles a1 = 0, a2 = pi/4, a3 = pi/2 and Bob at b1 = pi/4, b2 = pi/2, b3 = 3 pi/4. Rounds with different bases are
used for a Bell test with the CHSH quantity E = <a1 b1> - <a1 b3> + <a3 b1> + <a3 b3>. If -2 <= E <= 2 holds, the
photons are not truly entangled (possibly because of an eavesdropper) or a device is faulty; with no eavesdropper
and perfect devices E reaches the maximal violation -2 sqrt 2 [L22]. The E91 paper itself (Ekert, 1991) was not
read; this description is the Pirandola et al. review's.

The script computes E from 4 x 4 density matrices: -2.828427 for the singlet, and for the depolarised state p |singlet><singlet| + (1 - p) I/4 it gets E = -2 sqrt(2) p, so the Bell test fails once
p <= 1/sqrt 2 (p = 0.7071 gives exactly -2.0000) [L23].

### 1.3 What QKD provides and what it needs

What it provides, in theory: a key whose secrecy rests on physics, not on a hard maths problem, so it resists a
future quantum computer and "store now, decrypt later" [L24].

What it needs, and where the theory stops:

- **An authenticated classical channel.** QKD "does not provide authentication, nor do any other quantum
  techniques" (NCSC 2025) [L25]. Authentication needs pre-shared symmetric keys or post-quantum signatures [L24],
  [L26]; with signatures, the system's security again rests on a post-quantum scheme [L24].
- **Special hardware and dedicated links.** Single-photon sources and detectors; dedicated fibre or free-space
  links; "It cannot be implemented in software or as a service on a network" (NSA) [L26], [L24].
- **Short distances or trusted nodes.** Fibre loss grows exponentially with distance. Demonstrations reach "at most
  a few hundred kilometres" and commercial systems "typically reach about one hundred kilometres"; beyond that,
  trusted nodes relay the key, so there is no end-to-end security; satellites are usually trusted nodes too [L24].
  The PLOB bound caps any point-to-point protocol over a pure-loss channel of transmissivity eta at
  -log2(1 - eta), about 1.44 eta secret bits per channel use at high loss [L27]. At the standard 0.2 dB/km that is
  1.4e-4 bits per use at 200 km and 1.4e-20 at 1000 km (the script also multiplies by an assumed, illustrative
  1e9 uses per second) [L28]. Twin-field QKD beats PLOB with a middle relay: Liu et al. reached 1002 km with
  0.0034 bit/s, asymptotic regime only, over ultra-low-loss fibre spools (< 0.157 dB/km); finite-size keys reached
  952 km at 0.0031 bit/s [L29]. At 0.0034 bit/s one 256-bit key takes about 20.9 hours [L28].
- **A one-time pad to keep the "unconditional" claim.** Information-theoretic security holds only if the data is
  encrypted with a one-time pad, which needs a QKD key rate equal to the data rate; in practice QKD keys feed AES,
  and "such a scheme would invalidate the claim of absolute security" [L24].
- **Denial of service is built in.** Detecting eavesdropping means any interference stops the key flow [L24],
  [L26].

### 1.4 Implementation attacks: detector blinding

Lydersen et al. (Nature Photonics 4, 686-689, 2010) showed that the single-photon detectors (avalanche photodiodes)
in two commercial systems, ID Quantique's id3110 Clavis2 and MagiQ's QPN 5505, can be "fully remote-controlled"
with bright light: continuous illumination blinds them into classical linear detectors, and bright trigger pulses
then make Bob's detector click exactly when Eve wants. With matching bases Bob detects exactly Eve's bit; with
incompatible bases nothing is detected. The authors say this makes it possible "to tracelessly acquire the full
secret key", with an eavesdropper built from off-the-shelf parts, and that the loophole is likely present in most
QKD systems using avalanche photodiodes [L30]. The lost half of Bob's detections is not noticed, because the real
transmittance to Bob's detectors is much lower than 1/2 anyway [L31]. The toy simulation above reproduces the
signature: QBER 0, Eve knows every sifted bit, and the sifted fraction falls from 1/2 to 1/4 [L20].

The lesson matches classical side channels: the proof covers a model, the hardware deviates from it. The joint
European position paper says "Claims about 'absolute' or 'unconditional' security allegedly offered by QKD can
never apply to actual implementations" [L24].

### 1.5 Official positions

| agency, document, date | position |
|---|---|
| NSA, "Quantum Key Distribution (QKD) and Quantum Cryptography (QC)" web page (read via the Wayback Machine copy of 2026-09-18; the live page returns HTTP 403 to scripts) | "NSA does not recommend the usage of quantum key distribution and quantum cryptography for securing the transmission of data in National Security Systems (NSS) unless the limitations below are overcome." Limitations listed: only a partial solution (no source authentication), special-purpose equipment, trusted relays raise cost and insider risk, security is "highly implementation-dependent rather than assured by laws of physics", denial-of-service risk. NSA views post-quantum cryptography as "more cost effective and easily maintained" [L26] |
| UK NCSC, "Quantum security technologies" white paper, 24 March 2020 | "does not endorse the use of QKD for any government or military applications"; cautions against sole reliance on QKD for business-critical networks; a QKD system may not contribute to Cyber Assessment Framework principle B3.b [L32] |
| UK NCSC, "Quantum networking technologies" white paper, 5 August 2025, v1.0 | "The NCSC will not support the use of QKD for government or military applications. PQC is the best mitigation"; for other sectors QKD "should not be solely relied upon" and should not count as evidence for data-in-transit under the CAF [L25] |
| ANSSI (France), BSI (Germany), NLNCSA (Netherlands), Swedish National Communications Security Authority, Swedish Armed Forces: "Position Paper on Quantum Key Distribution", published 25 January 2024 (ANSSI page; BSI page dated 26.01.2024) | QKD "can however currently only be used in practice in some niche use cases" and "is not yet sufficiently mature from a security perspective"; no QKD protocol has been through a standardisation process like NIST's; no comprehensive security proof for a practically relevant protocol exists in the required form; priority is migration to post-quantum cryptography, in hybrid with symmetric keying or classical public-key cryptography [L24], [L33] |

Authorship check: the paper's title page lists exactly the four bodies above, with the Swedish body given as
"Swedish National Communications Security Authority, Swedish Armed Forces" [L33]. The PDF carries no date; the date
comes from the ANSSI and BSI publication pages [L33].

### 1.6 Conclusion for a software file cipher

QKD does not fit Turing's use case at all. Turing encrypts files at rest, in software, for a recipient who may be
offline or may read the file years later. QKD agrees keys between two online endpoints joined by a dedicated
quantum link; it cannot run in software [L26], it needs an authenticated channel that itself needs pre-shared keys
or post-quantum signatures [L24], [L25], and it gives nothing for data at rest. Every agency position read above
recommends post-quantum cryptography instead [L24], [L25], [L26], [L32]. **Recommendation: no QKD component, and
no documentation claim that relates Turing to QKD.** The existing plan (a post-quantum KEM for key transport, docs/02
and 03) is the direction all four positions point to.

## 2. Quantum random number generators

### 2.1 What they offer

A QRNG draws its randomness from a quantum measurement (for example which way a photon goes at a beam splitter,
or vacuum noise). The review by Herrero-Collantes and Garcia-Escartin (Rev. Mod. Phys. 2017) calls quantum random
number generation "one of the most mature quantum technologies", and describes the need for randomness extraction
and the possibility of device-independent generation, where the randomness is certified by a Bell test even with
untrusted hardware [L34].

The NCSC's 2020 paper gives the balanced view [L32]:

- QRNGs "do not provide any new mitigation against the threat from quantum computers";
- in many classical RNGs "the dominant hardware noise source is also a consequence of quantum processes";
- in practice the ideal unpredictability "is hard to realise", because the quantum part sits inside classical
  circuitry that adds noise and is open to the same implementation attacks;
- "classical RNGs will continue to meet our needs for government and military applications for the foreseeable
  future".

The 2025 NCSC paper adds two possible advantages: higher generation rate and fast detection of source degradation
through precise modelling of the quantum components. It is "keen that research on QRNGs continues to progress",
with a focus on the assurance of the raw sources and their integration into engineered devices; it does not make
QRNGs a requirement [L25].

### 2.2 Do standards require them?

No standard read here requires a quantum source.

- **NIST SP 800-90B** (January 2018), NIST's entropy-source recommendation (its health tests refer to FIPS 140
  validation), divides noise sources into physical (dedicated hardware) and non-physical (system data, human input) and assesses both by min-entropy
  estimation and health tests [L35]. It does not treat quantum sources as a separate class: the word "quantum" does
  not occur in its text [L36]. A QRNG is simply a physical noise source and must pass the same assessment.
- **NIST SP 800-90C** (September 2025, not marked as a draft) builds random bit generators from 90B entropy sources and 90A DRBGs
  (classes RBG1, RBG2, RBG3, RBGC) [L37]. Its only mention of "quantum" is a note that its security-strength
  definition is classical and "will be revised to address quantum issues in the future" [L37]. That note concerns
  the cost of breaking the DRBG, not the entropy source.
- **BSI AIS 20/31, functionality classes version 3.0** (Peter and Schindler, BSI, 10 September 2024) says the same
  thing in so many words. Its paragraph 1124: "This document does not distinguish between quantum entropy and
  entropy from physical phenomena based on other physical models"; AIS 31 treats quantum RNGs as physical true RNGs
  (PTRNGs), and "most physical noise sources exploit effects from quantum mechanics (even if not explicitly
  mentioned)". Its seven classes (DRG.2, DRG.3, DRG.4, DRT.1, PTG.2, PTG.3, NTG.1) are technology-agnostic. Where
  it does mention quantum computers, it is about the deterministic part: DRNG designs resting on factoring or discrete
  logarithms "will likely become insecure", and for DRG.3 an attacker with a quantum computer may gain (for example
  by Grover's algorithm) "but a successful attack shall still be infeasible" [L89].

### 2.3 Relevance to Turing

Turing draws file keys from the operating system (`turing::random::new_key`: cSHAKE256 with S = "Turing v2 key
generation" of a 64-byte seed from the getrandom crate, which uses ProcessPrng on Windows and getrandom(2) on Linux;
`crates/turing/src/random.rs` header and lines 45-66). A 256-bit key's quantum security is set by Grover on the key
space (section 3), which is the same whether the seed's entropy came from a quantum or a classical physical process.
A QRNG would help only if the OS generator were weak, and then the fix is the OS generator. **Recommendation: no
QRNG dependency.** If an optional external entropy source is ever supported, it should be mixed into (never
replace) the OS seed, and treated like any other physical source under SP 800-90B or AIS 31 [L35], [L89]. The
testing side (entropy health checks) belongs to the sibling topic testing-ci-cd.

## 3. Grover key search and NIST's security categories

### 3.1 What Grover's algorithm does

A block cipher key search is an unstructured search: there are N = 2^k keys and one of them is "marked" (it maps
known plaintexts to the known ciphertexts). A classical computer needs about N/2 trials on average. Grover's
algorithm finds the marked key with about (pi/4) * sqrt(N) evaluations of the cipher, done in superposition
[L1]. Zalka proved this is exactly optimal: no quantum algorithm with that many oracle calls has a higher success
probability [L2].

For Turing, k = 256: (pi/4) * 2^128 is about 2^127.65 sequential cipher evaluations [L3]. This is where the
common statement "a 256-bit key keeps about 128-bit security" comes from.

Worked example (`qc_simon_grover_toy.py`, section 1, a full statevector simulation): with N = 2^10 items and one
marked item, 25 Grover iterations give success probability 0.9995, against about 512 expected classical guesses.
Running twice as many iterations drops the success probability to 0.0002, because Grover's algorithm rotates the
state past the target. The attacker must know roughly how many solutions exist [L4].

### 3.2 Why "128-bit security" understates the cost

Two facts make Grover much less effective in practice than the square root suggests.

1. **It does not parallelise well.** Zalka showed that S quantum computers cannot do better than splitting the
   key space into S parts and searching each part with Grover [L2]. Each machine then needs (pi/4) * sqrt(N/S)
   iterations, so the total work is about sqrt(N * S): the more machines, the more total work. For k = 256 and
   S = 2^64 machines, each runs 2^95.65 iterations and the total is 2^159.65 oracle calls [L3].
2. **The iterations are sequential.** The whole of Grover's algorithm is one long serial computation. NIST
   therefore bounds the circuit depth of an attack by a parameter MAXDEPTH, with plausible values from 2^40
   logical gates ("presently envisioned quantum computing architectures ... in a year") through 2^64 ("current
   classical computing architectures ... in a decade") to "no more than" 2^96 ("atomic scale qubits with speed of
   light propagation times ... in a millennium") [L5].

Under a depth limit D_max the total gate count of key search is G = c_p^2 * 2^k * G_D * G_G / D_max, where G_D and
G_G are the depth and the gate count of one oracle call (one cipher evaluation) [L6]. The attacker's cost grows with
the product "oracle depth x oracle size". Jaques et al. also derive NIST's formula this way: a serial search of
depth D = x * MAXDEPTH needs about x^2 machines, each using about G/x gates, so the total is G * D / MAXDEPTH [L7].

### 3.3 NIST's security categories

NIST defines five categories by reference primitives. Category 1 is "key search on a block cipher with a 128-bit
key (e.g. AES128)", category 3 the same with a 192-bit key, category 5 "key search on a block cipher with a
256-bit key (e.g. AES 256)"; categories 2 and 4 are collision search on 256-bit and 384-bit hashes [L8]. An attack
must cost at least as much as the reference "with respect to all metrics that NIST deems to be potentially relevant
to practical security" [L8].

NIST's gate-count estimates for key search (log2 of the number of quantum gates):

| primitive | 2016 call (Grassl et al. circuits) | 2022 call (Jaques et al. circuits) | Jaques et al. ePrint revision, Table 13 | classical gates |
|---|---|---|---|---|
| AES-128 | 2^170 / MAXDEPTH | 2^157 / MAXDEPTH | about 2^159 / MAXDEPTH | 2^143 |
| AES-192 | 2^233 / MAXDEPTH | 2^221 / MAXDEPTH | about 2^224 / MAXDEPTH | 2^207 |
| AES-256 | 2^298 / MAXDEPTH | 2^285 / MAXDEPTH | about 2^288 / MAXDEPTH | 2^272 |

Sources: [L9], [L10], [L11]. For AES-256 the revised Jaques et al. G-costs are 2^246.9, 2^224.4 and 2^192.4 at
MAXDEPTH = 2^40, 2^64 and 2^96 [L11]. Both calls add footnote 5: the estimates "may understate the quantum security
of AES for very large values of MAXDEPTH" [L12]; Jaques et al. say this is the case for AES-128 at MAXDEPTH = 2^96,
where no parallelisation is needed [L11].

NIST's transition report draft (NIST IR 8547 ipd, November 2024) keeps this frame: AES-128, AES-192 and AES-256 are
listed as categories 1, 3 and 5, and "all NIST-approved symmetric primitives that provide at least 128 bits of
classical security are believed to meet the requirements of at least Category 1" [L13]. It also says NIST "does not
expect to need to transition away from" its symmetric standards [L13]. (Whether IR 8547 is final as of 2026-09-27
is the sibling topic nist-pqc-standards.)

NIST's calls also say which query model it cares about: NIST "is primarily concerned with attacks that use
classical (rather than quantum) queries to the decryption oracle or other private-key functionality" [L14]. In the
language of section 4 below, NIST evaluates in the Q1 model.

### 3.4 How many known blocks a Grover attack on Turing needs

Grover needs a test that singles out the key. With r known plaintext/ciphertext blocks of n bits, the expected
number of wrong keys that also fit is about (2^k - 1) * 2^(-rn). If k = b * n, taking r = b + 1 gives a unique key
with probability at least 1 - 2^-n; r must be at least ceil(k/n) [L15]. Turing has k = 256 and n = 128, so r = 3:
the expected number of spurious keys is 2^-128. With r = 2 the expected number is about 1, and the key is unique
only with probability 1/e = 0.368 [L16]. The toy check with k = 12, n = 8 finds 17, 1 and 1 consistent keys for r = 1, 2, 3 [L17].

### 3.5 Grover oracle cost of Turing compared with AES-256 (a proxy, not an estimate)

No quantum circuit for Turing exists, so no real Grover cost can be given. As an order-of-magnitude proxy,
`qc_grover_costs.py` counts S-box evaluations in one oracle call with r = 3 [L18]:

| cipher | S-boxes per oracle call | S-box layers in sequence |
|---|---|---|
| AES-256 (14 rounds, 13 SubWord x 4 in the key expansion) | 724 | about 14 |
| Turing, 24 rounds, 109 key-schedule Feistel rounds (working tree) | 2896 | about 110 |

Under a depth limit the cost scales with size x depth (section 3.2), so Turing's oracle would cost about 4.0 x 7.9
= 31 times more, about 5 bits [L18]. This counts only S-boxes; it ignores the linear layers and every circuit
optimisation. The cSHAKE256 whitening is left out on purpose: K' = cSHAKE256(K) alone fixes every round key, so an
attacker can run Grover over the 2^256 values of K' and never evaluate Keccak. The whitening defends against
chosen key differences (docs/07), not against key search [L18]. The proxy is not a security claim.

The statement the evidence supports is: **generic quantum key search on Turing is key search on a 256-bit key,
which is NIST's category 5 reference, provided no structural quantum attack beats Grover.** The proxy suggests
Turing's oracle is larger and deeper than AES-256's, which could only add cost, but without a quantum circuit that
is not established (open question OQ1). Sections 4 and 5 are about the proviso.

## 4. Superposition (Q2) attacks: Simon's algorithm

### 4.1 The two query models, Q1 and Q2

Kaplan, Leurent, Leverrier and Naya-Plasencia (ToSC 2016) name the two models used throughout the literature,
following Zhandry's definitions of quantum PRF security [L38]:

- **Q1 ("standard security")**: the attacker has a quantum computer but gets only classical queries: ordinary
  plaintext/ciphertext pairs. Data is collected classically and processed quantumly.
- **Q2 ("quantum security")**: the attacker can send the keyed oracle a quantum superposition of inputs and gets
  the superposition of outputs, i.e. the state sum_x |x>|E_k(x)>.

Q2 is the stronger model. A cipher secure in Q2 is secure in any setting [L39]. Its practical meaning is debated:
the same authors call Q2 "rather extreme and perhaps even unrealistic", because it is unclear how an attacker
would get superposition access, and call Q1 "more realistic" [L39]. The case for taking Q2 seriously is that
guaranteeing classical-only queries may be hard once quantum hardware is common, and that it covers scenarios
such as an encryption device handed to the adversary as an obfuscated program [L38], [L40]. NIST's post-quantum
process evaluates schemes against classical queries to private-key functionality, i.e. Q1 [L14].

For a file cipher the question is: can an attacker ever make Turing encrypt, decrypt or authenticate a
superposition of inputs under the victim's key? The key lives in software on a classical computer, and the
attacker sees files (classical bits). A Q2 oracle would need the victim's own implementation to run on quantum
hardware and accept quantum input. Q1 is therefore the model that matches Turing's use; Q2 matters only as a
robustness margin (section 6).

### 4.2 Simon's algorithm in one paragraph

Simon's problem: a function f on n-bit strings hides a secret s, with f(x) = f(x XOR s) for all x. Classically,
finding s means finding a collision, about 2^(n/2) queries. Simon's algorithm finds s with O(n) superposition
queries [L40]. One run: prepare the uniform superposition of all x, query f once, measure the output (which
collapses the input to the pair {x, x XOR s}), apply the Hadamard transform, measure a y. Every y satisfies
y . s = 0 (mod 2). After about n runs the y's span the space orthogonal to s, and linear algebra over GF(2) gives s
[L40]. KLLN also prove the algorithm still works when f has extra random collisions, as long as no other
"period" holds for more than half the inputs [L41].

The exponential gap (O(n) against 2^(n/2)) is why these attacks are dramatic, but it exists only when the
attacker can query f in superposition, and f is built from the secret-keyed oracle.

### 4.3 The published attacks

| attack | what breaks | model | cost | source |
|---|---|---|---|---|
| Kuwakado-Morii 2010 | 3-round Feistel (Luby-Rackoff PRP) distinguished from random: f(b, x) = y_R XOR alpha_b has period 1 \|\| R1(alpha_0) XOR R1(alpha_1) | Q2 | O(n) queries | [L42] |
| Kuwakado-Morii 2012 | Even-Mansour E(x) = P(x XOR k1) XOR k2: f(x) = E(x) XOR P(x) has period k1; then k2 = E(x) XOR P(x XOR k1) | Q2 | O(n) queries, key recovery | [L42], [L43] |
| KLLN 2016, modes | forgeries against CBC-MAC (and XCBC, OMAC, CMAC), PMAC, GMAC, GCM, OCB; also CLOC, AEZ, COPA, OTR, POET, OMD, Minalpher; LRW tweakable cipher broken | Q2 | O(n) queries | [L40], [L44] |
| KLLN 2016, slide | any cipher of r identical keyed rounds E = (P(x XOR k))^r, f(0, x) = P(E_k(x)) XOR x, f(1, x) = E_k(P(x)) XOR x has period 1 \|\| k | Q2 | O(n) instead of O(2^(n/2)); "the first known exponential quantum speed-up of a classical attack" | [L45] |

Two details matter for Turing:

1. **The modes result.** The attacks break MAC and AE modes built on a *secure* block cipher. They exploit the
   mode's linear structure (the XOR of E_k(alpha_0) and E_k(alpha_1) becomes a period), not the cipher. For
   encryption-only modes the picture is better: KLLN summarise Anand et al. as showing "OFB and CTR remain secure,
   while CBC and CFB are not secure in general ... but are secure if the underlying PRF is quantum secure" [L46]
   (section 5.4 checks this against Anand et al. directly).
2. **The slide attack needs identical rounds.** The slide property P(E_k(x)) XOR k = E_k(P(x XOR k)) holds only if
   every round is the same keyed function [L45]. Round constants that differ per round, or round keys that differ
   per round, destroy it. The toy in `qc_simon_grover_toy.py` shows this on an 8-bit, 12-round cipher: with
   identical round keys Simon's algorithm returns the period 0x113 = 1 || k exactly; with a distinct constant XORed
   into each round key the y's reach full rank 9 and no non-zero period exists [L47].

The Even-Mansour toy (n = 8) recovers k1 = 0x08 and k2 = 0xb0 from 24 simulated superposition queries; every
measured y is orthogonal to k1, and the rank reaches n - 1 = 7 as the theory predicts [L48]. The simulation is
exact: it measures the output register first (deferred measurement), so the input collapses to the preimage set,
and draws y from the Walsh-Hadamard transform of that state.

## 5. Offline Simon, quantum differential/linear and related-key attacks

### 5.1 Offline Simon: Simon's algorithm with classical queries only (Q1)

Bonnetain, Hosoyamada, Naya-Plasencia, Sasaki and Schrottenloher (ASIACRYPT 2019) found a way to use Simon's
algorithm in the Q1 model. The attacker guesses part of the key with Grover; for each guess it tests offline,
with Simon's algorithm, whether "offline function XOR online function" has a period. The online function is
queried classically once, and the resulting quantum state is reused across the Grover iterations [L49].

The problem they solve (their Problem 3): a family f_i computable offline and a keyed function g queried online,
such that exactly one f_i XOR g has a hidden period [L50]. Cryptographic instances:

- **Even-Mansour** P(x XOR k1) XOR k2 with public P: key recovery in quantum time about 2^(n/3) (O~), with
  O(2^(n/3)) classical queries and O(n^2) qubits [L49].
- **FX construction** E_k(x XOR k_in) XOR k_out, with an m-bit inner key k and n-bit whitening keys: Q1 attack
  with O(2^((m+n)/3)) classical queries and O(n^3 2^((m+n)/3)) time; in Q2, O(n) queries and O(n^3 2^(m/2)) time,
  so in Q2 the whitening keys add nothing beyond Grover on k [L51].

Bonnetain, Schrottenloher and Sibleyras (EUROCRYPT 2022) extended offline Simon to the 2XOR-Cascade key-length
extension of Gazi and Tessaro: a construction proven to give 5n/2 bits of classical security from an n-bit block
cipher with a 2n-bit key falls in quantum time O~(2^n) with classical queries only, "a 2.5 quantum speedup over
the best classical attack". Their conclusion: "the 2XOR-Cascade cannot be used to generically strengthen block
ciphers against quantum adversaries" [L52]. This is the first published Q1 key recovery on a block cipher design
with more than a quadratic speed-up [L52].

What the structure needs: an XOR-masked input and output around something the attacker can evaluate offline once
part of the key is guessed. Plain double encryption with independent keys behaves differently: Kaplan (2014, as
summarised by Kaplan et al. 2016) showed quantum meet-in-the-middle on double iteration only reduces the time
exponent by 3/2, not 2 [L53].

### 5.2 Quantum differential and linear cryptanalysis

Kaplan, Leurent, Leverrier and Naya-Plasencia (ToSC 2016) quantised differential, truncated differential and
linear attacks [L38]. The numbers that matter [L54]:

| attack | classical | Q2 | Q1 |
|---|---|---|---|
| differential distinguisher, probability 2^-h | 2^(h+1) | 2^(h/2+1) | (data is classical: 2^(h+1)) |
| differential last-rounds attack | 2^(h+1) + 2^(h+D-n) (C + 2^(k-h_out)) | 2^(h/2+1) + 2^((h+D-n)/2) (C* + 2^((k-h_out)/2)) | 2^(h+1) + 2^((h+D-n)/2) (C* + 2^((k-h_out)/2)) |
| linear distinguisher, correlation eps | 1/eps^2 | 1/eps | (data is classical) |

(D stands for the paper's Delta_fin, C for the partial-key cost C_kout.) A Q2 differential distinguisher still
needs h < n: for a random function the chance of finding a "right pair" after 2^(h/2) queries is at most
2^(h-n) [L55].

Their conclusions [L54]:

1. A quantum differential or linear attack costs at least the square root of the corresponding classical
   attack. A cipher resistant classically at cost 2^k is resistant to these quantum attacks at 2^(k/2).
2. Truncated differentials gain less than a square root; the best quantum attack is not always the quantised best
   classical attack.
3. Key size matters in Q1: "with k >= 2n, the data complexity is always smaller than 2^(k/2)". For ciphers with
   long keys, the authors conclude, classical breaks are likely to give quantum breaks even in the Q1 model [L56].

Point 3 describes Turing exactly: k = 256 = 2n. The script `qc_grover_costs.py` (section "Why k = 2n") shows the
arithmetic: any classical attack with data D below about 2^127 and key-guessing work W below 2^256 has a Q1
version costing about D + sqrt(W), which is below Grover's 2^128 [L57]. **For Turing the classical security margin
and the quantum (Q1) margin are the same question.** That is good news for the existing analysis: docs/09's rule
(usable trails need probability above 2^-128, extensions of 4 rounds, longest attack 8 of 24 rounds) was built on
exactly the constraints that carry over.

The one published full case study, AES, points the same way. Bonnetain, Naya-Plasencia and Schrottenloher quantised
the best classical attacks on AES in Q1: the best quantum attack reaches 8 rounds of AES-256 (a Demirci-Selcuk
meet-in-the-middle), against 9 rounds classically, and they conclude AES has "a bigger security margin with respect
to quantum generic attacks" [L58].

### 5.3 Quantum related-key attacks

Rotteler and Steinwandt (Inf. Process. Lett. 115(1), 2015) show that if the attacker can query encryptions under
a superposition of XOR-related keys K XOR L, then Simon's algorithm recovers K in polynomial time, provided the
cipher can be evaluated as a quantum circuit and a few known blocks determine the key [L59]. The function is
f_s(x) = {E_x(m), E_{s XOR x}(m)} (an unordered pair), which has period s = K; nothing about the key schedule
enters the argument [L59]. The toy confirms this: with the cipher using a random bijection W(K) of the key
(standing in for cSHAKE whitening), the attack still returns 1 || K [L60]. The authors themselves call the attack
"unlikely to pose a practical threat", since querying a superposition of secret keys may not be feasible [L59], and
Bonnetain et al. call the model "too powerful, as it would allow to break most block ciphers in polynomial time"
[L61].

### 5.4 Modes of operation and MACs under quantum queries

- **Encryption modes.** Anand, Targhi, Tabia and Unruh (PQCrypto 2016): OFB and CTR are IND-qCPA secure (secure
  under superposition encryption queries) if the block cipher is a standard secure PRF, i.e. secure against
  classical queries only. CBC, CFB and XTS are not, under that assumption; CBC and CFB are if the cipher is a
  quantum-secure PRF [L62].
- **MACs.** Boneh and Zhandry (EUROCRYPT 2013): a quantum-secure PRF gives a quantum-secure MAC; a variant of
  Carter-Wegman MACs can be proven quantum secure; pairwise-independent hashing is not enough for a one-time
  MAC under quantum queries, four-wise independence is [L63]. KLLN broke CBC-MAC, PMAC, GMAC, GCM and OCB with
  superposition queries (section 4.3). Song and Yun (CRYPTO 2017) proved NMAC, HMAC, AMAC and the cascade
  construction are quantum-secure PRFs against superposition queries [L64].

### 5.5 Multi-target key search

When many keys each encrypt the same known block, finding any one of t keys is easier than finding a given key.
Banegas and Bernstein (SAC 2017) give a quantum algorithm that, on p mesh-connected processors, finds one of t
targets in roughly sqrt(N / (p t^(1/2))) steps (sqrt(N / (p t)) if communication were free), and state that NIST's
AES-128/192/256 security claims "need to be revised" because they assume single-target Grover is optimal [L65].
For a 256-bit key and t = 2^64 targets on one processor this is about 2^112 steps (2^96 with free communication)
[L66]. The precondition is a shared known plaintext block under one function k -> E_k(m). Bellare and Tackmann
(CRYPTO 2016) analysed the classical version of this problem for TLS 1.3 and showed that randomising the nonce per
key improves multi-user security in the ideal-cipher model [L67].

A quantum counterpart now exists, as a preprint. Hosoyamada (ePrint 2026/1718, revised 2026-09-18) analyses GCM
under u independent keys in the quantum ideal cipher model. The trivial multi-key bound has a key-search term
u p^2 / 2^k (p = quantum queries to the cipher); he shows that, at the cost of extra loss terms, it can be replaced
by sqrt(d p^2 / 2^k), where d is the largest number of keys under which one nonce appears. With randomised nonces d
stays small even when u is large. He calls it the first non-trivial post-quantum multi-key bound for an AEAD mode
in this model, and says the bounds are not tight [L86]. At Turing's key size: with 2^64 keys the trivial term
reaches 1 at p = 2^96, the same exponent as the multi-target algorithm without communication cost [L66]; with d = 1
it reaches 1 at p = 2^128, the single-key Grover level [L88]. For structures with whitening, Shiba and Iwata
(ToSC 2026) prove that FX with 2^u keys needs Omega(2^((kappa + n - u)/3)) queries in the multi-key Q1 model, and the
tweakable Even-Mansour cipher Omega(2^(kappa/3)) whatever the number of keys [L87].

A worked example of why the nonce matters. Suppose every Turing file starts with the same 16-byte magic header,
encrypted in CTR mode with a counter that starts at 0. The first keystream block is E_K(0), and the attacker
learns it as (known header) XOR (first ciphertext block). So every file gives the attacker the output of the same
function k -> E_k(0) at a different key K, and one Grover search for "E_k(0) equals any of the collected values"
attacks all files at once [L65]. If instead the counter block contains a 96-bit random nonce
stored in the file, the value E_K(nonce || 0) differs from file to file, no single function k -> E_k(m) covers two
files, and the multi-target search has nothing to share.

### 5.6 Positive results: what has been proven against quantum attackers

The attacks above say what fails. A second group of papers proves lower bounds: how many queries any quantum
attacker needs, in an idealised model (random permutations or an ideal cipher). These bounds matter for any "twist"
the owner considers, because they say which wrappers and cascades add quantum security and which do not.
`qc_constructions.py` evaluates each published formula at Turing's sizes (n = 128, k = 256) [L81].

Why Q1 is the realistic model, in the words of a proof paper. Alagic, Bai, Katz and Majenz (EUROCRYPT 2022) note that
if f involves a private key, an attacker could obtain quantum access to f only if "there were an explicit interface
granting such access", and that in most real-world applications honest parties implement f on a classical computer.
They call the Q1 setting simply "the post-quantum setting" [L73]. Jaeger, Song and Tessaro (TCC 2021) add that Q1
is "arguably more realistic and less controversial than Q2" [L75].

| construction | result | model | at Turing's sizes | source |
|---|---|---|---|---|
| Even-Mansour P(x XOR k1) XOR k2 | any attack needs q_E q_P^2 + q_P q_E^2 of about 2^n (matches offline Simon, 2^(n/3) each) | Q1, random permutation | (not a Turing structure) | [L74] |
| FX: E_k(x XOR k1) XOR k2 with n-bit whitening (Jaeger-Song-Tessaro use k1 = k2) | non-adaptive bound O(sqrt(p^2 q / 2^(k+n))): about 2^((k+n)/3) queries needed, tight | Q1, ideal cipher | k = 256, n = 128: 2^128, exactly Grover on k: **whitening adds nothing** | [L75], [L81] |
| FX in Q2 | Leander-May: whitening keys do not increase security significantly; time about Grover on the inner key | Q2 | 2^128 | [L76] |
| double encryption E_k2(E_k1(x)), independent keys | Omega(2^(2k/3)) queries, even in Q2 (matches Kaplan's claw-finding attack) | Q2, ideal cipher | two 256-bit keys: 2^170.67 queries (single cipher: 2^128) | [L77], [L81] |
| t-round key-alternating cipher (independent random permutations and round keys) | non-adaptive: classical Omega(2^(tn/(t+1))), Q1 Omega(2^(tn/(2t+1))), Q2 Omega(2^((t-1)n/(2t))); "for t >= 2, the exponential Q1-Q2 gap collapses" | Q1, Q2, ideal | t = 24, n = 128: Q1 >= 2^62.69, Q2 >= 2^61.33 (generic block-size bounds, below 2^64) | [L78], [L81] |
| two-key iterated Even-Mansour (alternating two independent keys, like LED) | Q1 attacks beat exhaustive search: 4 rounds in 2^(7n/9), 6 rounds in 2^n / sqrt(log n), known plaintexts only | Q1 | n = 128: 2^99.56 and 2^126.60 against 2^128 | [L79], [L81] |

What these results say for a designer:

1. **Extra XOR whitening keys are not a quantum "twist".** For k = 2n the Q1 bound 2^((k+n)/3) equals 2^(k/2), and in
   Q2 the Leander-May attack removes the whitening entirely [L75], [L76], [L81]. Wrapping Turing in independent
   128-bit whitening keys would add key material and buy no quantum margin.
2. **Cascading with an independent key does help, generically.** Double encryption needs Omega(2^(2k/3)) queries even
   in Q2 [L77]. For two 256-bit keys that is 2^170.67 queries, above category 5's reference [L81]. This is an
   ideal-cipher statement: it says nothing about structural attacks on either cipher, and it holds only for plain
   composition with independent keys. The XOR-masked 2XOR-Cascade falls in Q1 in time O~(2^n) [L52].
3. **Multi-round key-alternating structure is what defeats the polynomial Simon attacks.** One round (Even-Mansour)
   breaks in Q2 with O(n) queries; from two rounds on, the ideal-model Q2 lower bound is exponential for non-adaptive
   attackers [L78]. Turing is a 24-round key-alternating cipher. The KAC bounds are generic (they stay below
   2^(n/2)), assume random round permutations, and cover only non-adaptive attackers, so they are structural
   reassurance, not a security level for Turing [L78], [L81].
4. **Simple alternating key schedules lose quantum security.** With two keys alternating, Q1 attacks improve on
   exhaustive search at 4 to 6 rounds [L79]. Turing's 25 round keys are distinct outputs of a nonlinear schedule
   [L69], [L72], so this model does not describe it; the result is a warning for any "twist" that uses a
   two-key alternating schedule.

### 5.7 Block size, modes and the MAC under quantum queries

Turing has a 128-bit block. Does a quantum attacker make that too small? The primary sources separate three cases.

- **Q1 (classical queries).** The data an attacker collects is classical, so birthday effects in the mode stay at the
  classical 2^(n/2) = 2^64 blocks per key [L80], [L81]. With a fresh key per file this limit is far away.
- **CTR encryption, even in Q2.** The Saturnin specification points out that in counter mode a superposition query
  "can be easily emulated using a classical one (by querying the all-zero sequence and XORing the inputs)", so the
  counter mode "remains quantumly secure up to the classical birthday bound" [L80]. This agrees with Anand et al.
  [L62].
- **A MAC built from the block cipher, in Q2.** Feed-forward and cascade MACs (NMAC-like, Davies-Meyer or MMO
  compression) need the block cipher to act as a random function. Quantumly, a random permutation can be told apart
  from a random function with about 2^(n/3) superposition queries (Zhandry 2015, as used by Saturnin, advantage
  C q^3 / 2^n) [L80]. For n = 256 that is the 2^85 in Saturnin's text; for n = 128 it is 2^42.67 [L81]. This is the
  reason Saturnin gives for its 256-bit block: "the security of most modes of operation is limited by the
  complexity of finding collisions, which may benefit of a quantum acceleration, depending only on the block size"
  [L80]. Two caveats: the 2^(n/3) collision algorithm (Brassard-Hoyer-Tapp) needs 2^(n/3) quantum RAM [L80], and
  Banegas-Bernstein record Bernstein's analysis that once communication costs are counted, no known quantum
  collision algorithm beats the classical parallel rho method [L82].

Constructions with Q2 proofs, for the AEAD decision (step 9):

- **Saturnin** (NIST lightweight round 2): a 256-bit-block, 256-bit-key cipher with CTR encryption plus a Cascade
  (NMAC-like) MAC, encrypt-then-MAC, all claims in the Q2 model. Its claims include: no quantum single-key attack with
  T^2/p < 2^224; Saturnin "does not provide security against related-key superposition attacks (as is the case of
  all known block ciphers)"; no quantum attack on CTR-Cascade with D^3 + T^2 + D^2 2^(256-t)/p < 2^224, so data
  D < 2^74.67 blocks [L80], [L81].
- **QCB** (Bhaumik et al., ASIACRYPT 2021): a rate-one, parallelisable AEAD with proofs of IND-qCPA and
  BZ-unforgeability, given a tweakable block cipher secure under classical tweaks [L83]. Its key-tweak insertion TBC
  E_(K XOR T) has advantage at most 8 sqrt(m q'^2 / 2^k) + sqrt(q2 s0 / (2 * 2^k)) in the ideal-cipher model: the
  bound depends on the key length, not the block size, but it needs a related-key-secure cipher, and tweaks queried
  in superposition give the Roetteler-Steinwandt attack [L83]. The paper instantiates QCB with 256-bit-block
  ciphers (Saturnin with 16 super-rounds, or TRAX-L-17) and says "Block ciphers of 256 bits seem more convenient for
  post-quantum security" [L83].
- **Keyed sponges (KMAC-type MACs).** Hosoyamada (ASIACRYPT 2025) proves keyed sponges secure in the quantum ideal
  permutation model with classical construction queries (Q1): about min(2^(c/3), 2^(kappa/3)) queries for inner- and
  full-keyed sponges, and about min(2^(c/3), 2^((kappa - r)/2), 2^(r/2)) for the outer-keyed sponge that KMAC is,
  **but only when the key is longer than the rate (kappa > r)** [L84]. KMAC256 has r = 1088, so a 256-bit KMAC key
  is outside that theorem [L81], [L84]. Alagic, Carolan, Majenz and Tokat (2025 preprint) prove the unkeyed sponge
  quantum-indifferentiable from a random oracle, with a loose bound O(l^3 (q^9 2^(-min(r,c)))^(1/4)); for c = 512
  the bound is non-trivial only below about 2^56.89 queries [L85], [L81].

## 6. Mapping onto Turing

Turing's relevant structure (docs/03, 07, 09; `crates/turing/src/keyschedule.rs`) [L69]: a 128-bit key-alternating SPN
with 24 rounds and 25 round keys XORed into the state; S-box layer in every round; MixState (16 x 16 Cauchy, branch
17) in odd rounds, ShiftRows + MixColumns (branch 5) in even rounds, no linear layer in round 24. The 256-bit key K
is whitened to K' = cSHAKE256(K, "Turing v2 key"); a Feistel with round function MixState(S(x XOR C_j)) and a fresh
cSHAKE constant C_j in every round expands K' (13 warm-up rounds, then a pair of round keys every 8 rounds), and
each round key is a Feistel half XOR the matching half of K'.

| attack (section) | model | what it needs | Turing | verdict |
|---|---|---|---|---|
| Grover key search (3) | Q1 (r = 3 known blocks) | nothing | 256-bit key; the attacker can search K' directly | applies to every cipher; cost comparable to AES-256 key search (category 5), not more than that on present evidence |
| quantum differential / linear (5.2) | Q1, Q2 | a usable differential or hull, then key guessing | k = 2n, so classical and Q1 margins coincide; Q2 lower bounds 2^52.0 (3-round MEDP), 2^49.8 (3-round hull), 2^56.4 / 2^52.95 (5-round bounds) [L70] | covered by the classical analysis in docs/09 and docs/12 with its factor-of-3 round margin; nothing extra is needed |
| Kuwakado-Morii 3-round Feistel (4.3) | Q2 | query access to a 3-round Feistel | data path is an SPN; the key-schedule Feistel is never queried and has 109 rounds | not applicable |
| Even-Mansour / FX, Q2 and offline Simon (4.3, 5.1) | Q2, Q1 | independent XOR whitening around a permutation the attacker can evaluate once part of the key is guessed | the first and last round keys come from the same K' as every inner round key; seen as FX with m = 256, the Q2 attack costs O(n^3 2^128) [L51] | no gain over Grover; applies only if a future design adds independent whitening or XOR-masked cascades |
| quantum slide attacks (4.3) | Q2 | 1 to 4 rounds of self-similarity (identical rounds, or round keys repeating with a short period, possibly up to a fixed XOR) [L68] | round keys distinct and pseudorandom; no linear relation among key and round-key bits (0 relations, docs/12); layers alternate and the last round differs | not applicable; the docs/11 "slide attacks: not applicable" argument covers the quantum variants too, for the same reason |
| quantum related-key (5.3) | Q2 related-key | superposition queries under related keys | the attack ignores the key schedule, so cSHAKE whitening does not help [L59], [L60] | no block cipher resists this model; Turing's use (fresh random file keys, no related-key interface) excludes it |
| Q2 attacks on MAC/AE modes (4.3, 5.4) | Q2 | a GHASH-, CBC-MAC-, PMAC- or OCB-style mode | AEAD not chosen yet (docs/03: "decided in step 9") | a design choice: CTR encryption is IND-qCPA secure from a classically secure PRF [L62]; for the MAC, constructions with Q2 proofs exist (HMAC/NMAC [L64], any quantum-secure PRF [L63]) |
| multi-target key search (5.5) | Q1 | many keys encrypting one shared known block | one fresh key per file, but docs/03 gives the chunk nonce only "the chunk counter and a 'last chunk' flag" [L90], so chunk 0 of every file uses the same nonce | applies as docs/03 stands, whenever a file's first block is known or guessable (file magic numbers): 2^112 steps for 2^64 files in the mesh model [L66]; avoidable by a per-file random value in the block-cipher input [L65], [L86] |
| beyond-quadratic Q1 (2XOR-Cascade) (5.1) | Q1 | XOR-whitened cascade of two keyed ciphers | not present | a warning for any "twist" that wraps Turing and another layer with XOR masks [L52] |
| generic multi-round key-alternating structure (5.6) | Q1, Q2 (ideal model, non-adaptive) | t rounds of public permutations and key XORs | Turing is a 24-round key-alternating SPN | from t = 2 on, the ideal-model Q2 lower bound is exponential, so the one-round Even-Mansour break does not generalise [L78]; generic bounds stay below 2^64 [L81], so this is structural reassurance, not a security level |
| extra independent whitening keys, as a "twist" (5.6) | Q1, Q2 | k1 XORed before and after Turing | not present | Q1 needs about 2^((256+128)/3) = 2^128, Q2 about 2^128: no gain over Grover on Turing's key [L75], [L76], [L81] |
| cascade with an independent cipher and key, as a "twist" (5.6) | Q2 (ideal cipher) | plain composition, independent keys | not present | Omega(2^(2k/3)) = 2^170.67 queries for two 256-bit keys [L77], [L81]; generic only |
| two-key alternating key schedule (5.6) | Q1 | round keys alternating between two keys | not present: 25 distinct round keys from a nonlinear schedule [L69], [L72] | 4 to 6 rounds attacked below exhaustive search [L79]; a warning for any simplified schedule |
| 128-bit block in Q2 MACs and PRFs (5.7) | Q2 | a MAC or PRF built from the block cipher with feed-forward | AEAD not chosen | PRP/PRF switching at about 2^42.67 superposition queries for n = 128 [L80], [L81]; CTR encryption is not affected [L80]; in Q1 the limit is the classical 2^64 blocks per key |

Which existing Bombe checks and document statements this supports:

- **docs/11, "Slide attacks: not applicable".** Justified for the quantum slide attacks as well: they need
  self-similarity over at most 4 rounds [L68], and Bombe's key checks find no repeated round key (docs/11) and no
  linear relation between key and round-key bits (docs/12). docs/12's text reports "0 relations among 2,432
  bits", and 2,432 = 256 + 17 x 128 is version 1's key plus 17 round keys [L71]; the check itself scales with
  `ROUND_KEYS` (`crates/bombe/src/keyrelations.rs`) and the version-2 campaign reports 0 relations among 3,456
  bits = 256 + 25 x 128 [L72]. The statement therefore holds for version 2; only docs/12's number needs updating.
- **docs/02 and docs/03, "a 256-bit key keeps ~128-bit security".** Correct as a Grover query count (2^127.65
  sequential calls). A more precise wording: generic quantum key search on Turing is key search on a 256-bit key,
  NIST's category 5 reference [L8]; for the reference cipher AES-256 that costs far more than 2^128 gates once a
  depth limit applies (2^192.4 to 2^246.9 G-cost at MAXDEPTH 2^96 to 2^40 [L11]).
- **docs/07, "the related-key bound holds even if cSHAKE256 were broken".** This is a classical related-key
  statement and stays valid in Q1. It says nothing about the quantum related-key model, where no design feature
  helps; a one-line note would prevent a reader from over-reading it.
- **A possible Bombe addition (not required).** The `rounds` report could print, next to each window's bound,
  the Q2 lower bound 2^(h/2+1) from Kaplan et al. eq. (4) and the Q1 reading for k = 2n. It is arithmetic on
  numbers Bombe already proves, as `qc_grover_costs.py` shows. It would add no new security evidence; it would
  document that the quantum reading was checked.

## What this means for Turing

Options and risks for the design phase, each with its evidence.

1. **Keep the 256-bit key; it is the whole of the generic quantum defence.** Grover's bound depends only on the
   key length [L1], [L2]; a 256-bit key is NIST's category 5 reference [L8], [L13]. A longer key (for example
   512 bits) would push generic search above category 5, but NIST defines nothing higher, it would need a new
   key-schedule analysis (docs/07), and no source read here suggests it is needed. Risk of doing it: new,
   unanalysed schedule structure for no measured gain.
2. **Treat the classical cryptanalysis programme as the quantum one.** Because k = 2n, any classical attack faster
   than 2^256 with fewer than about 2^127 blocks is likely to give a Q1 attack faster than Grover [L56], [L57]. The
   open items in docs/09 (linear hulls, meet-in-the-middle, bit-level models) are therefore also the open quantum
   items. The factor-of-3 round margin (8 of 24 rounds) is the quantum margin too; the AES case study suggests
   quantisation reaches fewer rounds, not more [L58], but that is one cipher, not a theorem.
3. **Do not claim Q2 security for the cipher; if the AEAD is to carry a Q2 claim, choose its parts for that.** No
   source read here proves Q2 security for any concrete block cipher; the literature analyses known attacks. Even
   Saturnin, designed for the Q2 model, states that it gives no security against related-key superposition attacks,
   "as is the case of all known block ciphers" [L80]. For the file format:
   - *Encryption.* CTR is IND-qCPA secure from a classically secure PRF [L62], because a superposition query can be
     emulated by a classical one [L80]. Turing in CTR mode keeps its classical limit of 2^64 blocks (2^68 bytes)
     per key in both models [L81].
   - *Authentication.* CBC-MAC, PMAC, GMAC/GCM and OCB have Q2 forgeries [L40]. A MAC built from Turing with
     feed-forward (Cascade, NMAC-like, Davies-Meyer or MMO) inherits the 128-bit block's quantum PRP/PRF limit of
     about 2^42.67 superposition queries [L80], [L81]. NMAC/HMAC over a quantum-secure PRF compression function have
     Q2 proofs [L64]. Keyed sponges have Q1 proofs, about min(2^(c/3), 2^(kappa/3)) queries for inner- and
     full-keyed sponges, but the KMAC theorem needs a key longer than the rate (1088 bits for KMAC256) [L84], [L81];
     for a 256-bit-key KMAC in Q2 only the loose unkeyed-sponge indifferentiability result exists [L85] (OQ3).
   - *A rate-one AEAD with Q2 proofs* exists (QCB), but its instances use 256-bit-block ciphers and need
     related-key security from the cipher [L83].
   This belongs with the sibling topics cca-transforms-and-binding and turing-integration-constraints when the AEAD
   is chosen.
4. **Put a per-file random value into the block-cipher input.** File keys are fresh, but docs/03 describes the
   chunk nonce as encoding only "the chunk counter and a 'last chunk' flag" [L90]. Chunk 0 of every file therefore
   uses the same nonce, and whenever the first 16 plaintext bytes are known or guessable (most file formats start
   with a fixed magic number), every file hands the attacker one value E_K(same input) under its own key. The files
   then form a multi-target instance: about 2^112 steps for 2^64 files in the mesh model [L66]. This is still far
   beyond reach, but it is a generic loss the design can avoid for free. Deriving the chunk key from the file key
   with a random salt does not help, because the attacker searches the key the block cipher actually uses; the
   random value must enter the block-cipher input itself. A random per-file nonce inside the block-cipher input
   removes the shared block, which is the precondition of the multi-target algorithm [L65]. The classical benefit is proven
   (Bellare-Tackmann, ideal-cipher model [L67]); a quantum ideal-cipher-model bound for GCM with randomised nonces
   now exists as a 2026 preprint, bringing the key-search term back to about single-key Grover when nonces rarely
   repeat across keys [L86], [L88]. It does not yet cover Turing's own AEAD layout (OQ5).
5. **What the literature says about each kind of "twist" (lattice layer, cascade, extra whitening).**
   - *Extra XOR whitening keys: no quantum gain.* In Q2 they add nothing beyond Grover on the inner key [L51],
     [L76]; in Q1 the tight bound is 2^((k+n)/3), which for Turing's k = 2n equals Grover's 2^128 [L75], [L81].
   - *XOR-masked cascades: a known loss.* The 2XOR-Cascade falls in Q1 in time O~(2^n), more than a square-root
     speed-up [L52].
   - *Plain cascade with an independent key: a proven generic gain.* Double encryption needs Omega(2^(2k/3))
     queries even in Q2 [L77] (2^170.67 for two 256-bit keys [L81]); Kaplan's attack reduces the time exponent by
     only 3/2 [L53]. This is the only "twist" in this topic with a published quantum benefit. It is generic
     (ideal-cipher model), costs a second full encryption, and says nothing about a lattice-based layer, whose own
     analysis is the sibling topic lattices-inside-symmetric-primitives.
   - *Simplified key schedules: a known loss.* Two alternating keys fall below exhaustive search at 4 to 6 rounds
     in Q1 [L79]; round keys that repeat within 4 rounds invite quantum slide attacks with O(n) superposition
     queries [L45], [L68].
   - *Tweaks through the key (E_(K XOR T)).* Provably fine in the ideal-cipher model while tweaks stay classical,
     but it needs a related-key-secure cipher, and superposition tweaks give the Roetteler-Steinwandt attack [L83],
     [L59].
   - *Any new structure needs its own Q1 analysis.* Quantising the best classical attack does not always give the
     best quantum attack [L54]; offline Simon brings period-finding into Q1 wherever XOR-masked structure appears
     [L49]-[L52]. No "harder to break" claim should be made before that analysis exists.
6. **No QKD, no QRNG.** Neither fits a software file cipher, no standard requires either, and every agency position
   read prefers post-quantum cryptography [L24]-[L26], [L32], [L35], [L36]. The public-key plan in docs/02 and 03
   (a vetted post-quantum hybrid KEM) is what those positions recommend.
7. **Documentation edits the evidence supports** (owner's decision, for the docs/ maintainer):
   - docs/02 and 03: "256-bit key keeps about 128-bit security" can say "generic quantum key search is key search on
     a 256-bit key, NIST's category 5 reference" [L8], [L11].
   - docs/07: add that the related-key bound is classical; in the quantum related-key model no schedule helps
     [L59].
   - docs/11: the slide-attack paragraph can mention that quantum slide attacks need the same self-similarity
     [L45], [L68]; the key-relation evidence it leans on holds for version 2 [L72].
   - docs/12: update "0 relations among 2,432 bits" to the version-2 figure, 3,456 bits [L71], [L72].
8. **Testing hooks** (for the sibling topic testing-ci-cd): `qc_grover_costs.py` and `qc_simon_grover_toy.py` are
   deterministic, need only numpy, and read Turing's round constants from the source tree, so a CI job can
   re-run them when ROUNDS, WARMUP_ROUNDS or ROUNDS_PER_PAIR change. `qc_constructions.py` is pure arithmetic.
   `qc_source_checks.py` and `qc_verify_ledger.py` need the gitignored PDFs (and, for the web rows, the saved page
   copies in the scratch directory) and stay local checks.
9. **Keep the 128-bit block for Q1; know what a 256-bit block would buy.** In Q1 (Turing's model, section 4.1) the
   block-size limit is the classical 2^64 blocks per key [L80], [L81], far beyond any file under a fresh key. The
   published designs that target Q2 claims for MACs and rate-one AEAD use 256-bit blocks (Saturnin [L80], QCB's
   instances [L83]), because quantum PRP/PRF switching costs only 2^(n/3) superposition queries [L80]; that attack
   also needs 2^(n/3) quantum RAM [L80], and once communication is costed no known quantum collision algorithm beats
   classical parallel rho [L82]. A 256-bit-block Turing would be a new cipher: every Bombe bound, the S-box layer
   count and MixState would have to be redesigned and re-proven. Evidence supports keeping 128 bits and not building
   the MAC from Turing by feed-forward if a Q2 claim is wanted.

## Sources

| file in research/papers/ | full reference | URL | used for |
|---|---|---|---|
| 1984-bennett-brassard-bb84-quantum-cryptography.pdf | C. H. Bennett, G. Brassard. Quantum cryptography: public key distribution and coin tossing. Proc. IEEE Int. Conf. Computers, Systems and Signal Processing, Bangalore, 10-12 Dec 1984, pp. 175-179 (scan; reprinted Theor. Comput. Sci. 560, 2014) | https://arxiv.org/abs/2003.06557 | BB84, eavesdropping trade-off, authentication |
| 1996-grover-fast-quantum-database-search.pdf | L. K. Grover. A fast quantum mechanical algorithm for database search. 1996 | https://arxiv.org/abs/quant-ph/9605043 | Grover's algorithm |
| 1999-zalka-grover-search-optimal.pdf | C. Zalka. Grover's quantum searching algorithm is optimal. Phys. Rev. A 60, 2746 (1999) | https://arxiv.org/abs/quant-ph/9711070 | optimality, parallelisation |
| 2010-lydersen-et-al-hacking-commercial-qkd-bright-illumination.pdf | L. Lydersen et al. Hacking commercial quantum cryptography systems by tailored bright illumination. Nature Photonics 4, 686-689 (2010) | https://arxiv.org/abs/1008.4593 | detector blinding |
| 2010-kuwakado-morii-quantum-distinguisher-3-round-feistel.pdf | H. Kuwakado, M. Morii. Quantum distinguisher between the 3-round Feistel cipher and the random permutation. ISIT 2010, Austin, pp. 2682-2685 (copy from NIST's FOIA release) | https://nist.pqcrypto.org/foia/20230315/quantum-feistel.pdf | first Simon attack, 3-round Feistel |
| 2013-boneh-zhandry-quantum-secure-macs.pdf | D. Boneh, M. Zhandry. Quantum-secure message authentication codes. EUROCRYPT 2013 | (local copy; venue per KLLN16 ref. [12]) | Q2 MACs |
| 2015-rotteler-steinwandt-quantum-related-key-attacks.pdf | M. Roetteler, R. Steinwandt. A note on quantum related-key attacks. Inf. Process. Lett. 115(1):40-44, 2015 | https://arxiv.org/abs/1306.2301 | quantum related-key attack |
| 2016-anand-et-al-post-quantum-security-modes-of-operation.pdf | M. V. Anand, E. E. Targhi, G. N. Tabia, D. Unruh. Post-quantum security of the CBC, CFB, OFB, CTR, and XTS modes of operation. PQCrypto 2016 | (local copy; venue per KLLN16 ref. [3]) | modes under Q2 |
| 2016-kaplan-et-al-breaking-symmetric-quantum-period-finding.pdf | M. Kaplan, G. Leurent, A. Leverrier, M. Naya-Plasencia. Breaking symmetric cryptosystems using quantum period finding. CRYPTO 2016 | https://arxiv.org/abs/1602.05973 | Simon attacks, Kuwakado-Morii, modes, slide |
| 2016-kaplan-et-al-quantum-differential-linear-cryptanalysis.pdf | M. Kaplan, G. Leurent, A. Leverrier, M. Naya-Plasencia. Quantum differential and linear cryptanalysis. ToSC 2016(1), 71-94 | https://arxiv.org/abs/1510.05836 | Q1/Q2 definitions, quantum differential/linear, k >= 2n |
| 2016-bellare-tackmann-multi-user-security-aes-gcm-tls13.pdf | M. Bellare, B. Tackmann. The multi-user security of authenticated encryption: AES-GCM in TLS 1.3. CRYPTO 2016 (full version 2017) | https://eprint.iacr.org/2016/564 | nonce randomisation, multi-user |
| 2017-herrero-collantes-garcia-escartin-quantum-random-number-generators.pdf | M. Herrero-Collantes, J. C. Garcia-Escartin. Quantum random number generators. Rev. Mod. Phys. 89, 015004 (2017) | https://arxiv.org/abs/1604.03304 | QRNG overview |
| 2017-banegas-bernstein-low-communication-parallel-quantum-multi-target-preimage-search.pdf | G. Banegas, D. J. Bernstein. Low-communication parallel quantum multi-target preimage search. SAC 2017 | https://eprint.iacr.org/2017/789 | multi-target key search |
| 2017-song-yun-quantum-security-nmac.pdf | F. Song, A. Yun. Quantum security of NMAC and related constructions. CRYPTO 2017 | https://eprint.iacr.org/2017/509 | HMAC/NMAC as quantum-secure PRFs |
| 2019-bonnetain-et-al-offline-simon-quantum-attacks.pdf | X. Bonnetain, A. Hosoyamada, M. Naya-Plasencia, Y. Sasaki, A. Schrottenloher. Quantum attacks without superposition queries: the offline Simon's algorithm. ASIACRYPT 2019 | https://eprint.iacr.org/2019/614 | offline Simon, FX, Even-Mansour in Q1 |
| 2019-bonnetain-naya-plasencia-schrottenloher-quantum-security-aes.pdf | X. Bonnetain, M. Naya-Plasencia, A. Schrottenloher. Quantum security analysis of AES. IACR publication presented at FSE 2020 (per ePrint metadata) | https://eprint.iacr.org/2019/272 | AES quantum margin; related-key model remark |
| 2019-bonnetain-naya-plasencia-schrottenloher-quantum-slide-attacks.pdf | X. Bonnetain, M. Naya-Plasencia, A. Schrottenloher. On quantum slide attacks. (ePrint listing: preprint) | https://eprint.iacr.org/2018/1067 | quantum slide variants |
| 2020-jaques-et-al-grover-oracles-aes-lowmc.pdf | S. Jaques, M. Naehrig, M. Roetteler, F. Virdia. Implementing Grover oracles for quantum key search on AES and LowMC. EUROCRYPT 2020 (ePrint revision) | https://eprint.iacr.org/2019/1146 | Grover costs, spurious keys, Table 13 |
| 2020-pirandola-et-al-advances-in-quantum-cryptography.pdf | S. Pirandola et al. Advances in quantum cryptography. Adv. Opt. Photon. 12, 1012-1236 (2020) | https://arxiv.org/abs/1906.01645 | E91, PLOB bound |
| 2022-bonnetain-schrottenloher-sibleyras-beyond-quadratic-speedups.pdf | X. Bonnetain, A. Schrottenloher, F. Sibleyras. Beyond quadratic speedups in quantum attacks on symmetric schemes. EUROCRYPT 2022 (file: arXiv v1, 2021) | https://arxiv.org/abs/2110.02836 ; https://eprint.iacr.org/2021/1348 | 2XOR-Cascade Q1 break |
| 2023-liu-et-al-twin-field-qkd-1000-km.pdf | Y. Liu et al. Experimental twin-field quantum key distribution over 1000 km fiber distance. Phys. Rev. Lett. 130, 210801 (2023) | https://arxiv.org/abs/2303.15795 | QKD distance record |
| 2024-anssi-bsi-nlncsa-sma-position-paper-qkd.pdf | ANSSI, BSI, NLNCSA, Swedish National Communications Security Authority / Swedish Armed Forces. Position paper on quantum key distribution. January 2024 | https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/Quantum_Positionspapier.html | joint agency position |
| nist-pqc-call-for-proposals-2016.pdf | NIST. Submission requirements and evaluation criteria for the post-quantum cryptography standardization process (2016 call; submission deadline November 30, 2017) | http://www.nist.gov/pqcrypto (address printed in the document) | categories, MAXDEPTH, Q1 statement |
| nist-pqc-call-additional-signatures-2022.pdf | NIST. Call for additional digital signature schemes for the PQC standardization process (2022; the file notes an update in October 2022) | https://csrc.nist.gov/projects/pqc-dig-sig | updated AES gate counts |
| nist-ir-8547-pqc-transition.pdf | D. Moody, R. Perlner, A. Regenscheid, A. Robinson, D. Cooper. NIST IR 8547 ipd, Transition to post-quantum cryptography standards. November 2024 | https://doi.org/10.6028/NIST.IR.8547.ipd | symmetric categories |
| nist-sp800-90b-entropy-sources.pdf | M. Sonmez Turan et al. NIST SP 800-90B, Recommendation for the entropy sources used for random bit generation. January 2018 | https://doi.org/10.6028/NIST.SP.800-90B | entropy sources |
| 2024-bsi-ais-31-functionality-classes-rng-v3.pdf | M. Peter, W. Schindler. A proposal for functionality classes for random number generators, version 3.0 (mathematical-technical reference of AIS 20 and AIS 31). BSI, 10 September 2024 | https://www.bsi.bund.de (AIS 20/31 page) | QRNGs as physical TRNGs, quantum computers and DRNGs |
| nist-sp800-90c-rbg-constructions.pdf | E. Barker et al. NIST SP 800-90C, Recommendation for random bit generator (RBG) constructions. September 2025 | https://doi.org/10.6028/NIST.SP.800-90C | RBG constructions |
| nist-fips-197-upd1-aes.pdf | NIST FIPS 197 (updated 2023), Advanced Encryption Standard | (local copy) | AES-256 key-expansion S-box count for the proxy |
| online | NSA. Quantum Key Distribution (QKD) and Quantum Cryptography (QC) | https://www.nsa.gov/Cybersecurity/Quantum-Key-Distribution-QKD-and-Quantum-Cryptography-QC/ (read via Wayback snapshot 20260918043425) | NSA position |
| online | UK NCSC. Quantum security technologies. 24 March 2020 | https://www.ncsc.gov.uk/paper/quantum-security-technologies | NCSC 2020 position, QRNG |
| online | UK NCSC. Quantum networking technologies. 5 August 2025 | https://www.ncsc.gov.uk/paper/quantum-networking-technologies | NCSC 2025 position |
| 2017-leander-may-grover-meets-simon-fx.pdf | G. Leander, A. May. Grover meets Simon - quantumly attacking the FX-construction. ASIACRYPT 2017 | https://eprint.iacr.org/2017/427 | whitening keys in Q2 |
| 2019-canteaut-et-al-saturnin-spec-round2.pdf | A. Canteaut, S. Duval, G. Leurent, M. Naya-Plasencia, L. Perrin, T. Pornin, A. Schrottenloher. Saturnin: a suite of lightweight symmetric algorithms for post-quantum security. NIST LWC round-2 specification (journal version ToSC 2020 Special Issue 1, 160-207) | https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/saturnin-spec-round2.pdf | 256-bit block rationale, Q2 claims, CTR argument |
| 2020-bhaumik-et-al-qcb-quantum-secure-authenticated-encryption.pdf | R. Bhaumik, X. Bonnetain, A. Chailloux, G. Leurent, M. Naya-Plasencia, A. Schrottenloher, Y. Seurin. QCB: efficient quantum-secure authenticated encryption. ASIACRYPT 2021 | https://eprint.iacr.org/2020/1304 | Q2-secure AEAD, key-tweak insertion bound |
| 2021-alagic-bai-katz-majenz-post-quantum-security-even-mansour.pdf | G. Alagic, C. Bai, J. Katz, C. Majenz. Post-quantum security of the Even-Mansour cipher. EUROCRYPT 2022 | https://eprint.iacr.org/2021/1601 | Q1 lower bound, why Q1 is realistic |
| 2021-jaeger-song-tessaro-quantum-key-length-extension.pdf | J. Jaeger, F. Song, S. Tessaro. Quantum key-length extension. TCC 2021 | https://eprint.iacr.org/2021/579 | FX in Q1, double encryption in Q2 |
| 2024-bai-esmaili-mantri-key-alternating-ciphers-quantum-lower-bounds.pdf | C. Bai, M. Esmaili, A. Mantri. Security of key-alternating ciphers: quantum lower bounds and quantum walk attacks. arXiv 2412.05026v3 (9 Oct 2025) | https://arxiv.org/abs/2412.05026 | multi-round KAC in Q1/Q2 |
| 2025-hosoyamada-post-quantum-keyed-sponge-kmac-ascon.pdf | A. Hosoyamada. Post-quantum security of keyed sponge-based constructions through a modular approach. ASIACRYPT 2025 (ePrint major revision) | https://eprint.iacr.org/2025/1059 | KMAC and keyed sponges in Q1 |
| 2025-alagic-carolan-majenz-tokat-sponge-quantum-indifferentiable.pdf | G. Alagic, J. Carolan, C. Majenz, S. Tokat. The sponge is quantum indifferentiable. ePrint 2025/731 (preprint) | https://eprint.iacr.org/2025/731 | sponge under quantum queries |
| 2026-degre-et-al-improved-quantum-attacks-iterated-even-mansour.pdf | M. Degre, A. Lafontaine, A. Pichollet--Mugnier, A. Schrottenloher. Improved quantum attacks on iterated Even-Mansour ciphers with classical queries. ePrint 2026/930 (preprint) | https://eprint.iacr.org/2026/930 | two-key IEM in Q1 |
| 2026-hosoyamada-post-quantum-multi-key-security-gcm.pdf | A. Hosoyamada. On post-quantum multi-key security of GCM. ePrint 2026/1718 (preprint, revised 2026-09-18) | https://eprint.iacr.org/2026/1718 | quantum multi-key bound with randomised nonces |
| 2026-shiba-iwata-multi-key-quantum-tem-fx.pdf | R. Shiba, T. Iwata. Multi-key security in the quantum world: revisiting tweakable Even-Mansour and FX. ToSC 2026 | https://eprint.iacr.org/2026/382 | multi-key Q1 bounds for TEM and FX |
| online | IACR ToSC article page for Saturnin (Volume 2020, Special Issue 1, pp. 160-207) | https://tosc.iacr.org/index.php/ToSC/article/view/8621 | Saturnin venue |
| online | ANSSI. Position paper on quantum key distribution (publication page, 25 January 2024) | https://cyber.sites.beta.gouv.fr/en/publications/jointly-led-international-publications/position-paper-on-quantum-key-distribution/ | date, authorship |

## Claim ledger

| # | claim | status | source |
|---|---|---|---|
| L1 | Grover search finds the marked element among N with about (pi/4) sqrt(N) oracle calls | VERIFIED | 1999-zalka-grover-search-optimal.pdf, abstract and p. 1 ("about pi/4 sqrt(N) steps"); original algorithm 1996-grover-fast-quantum-database-search.pdf, Summary (O(sqrt N) steps) |
| L2 | Grover's algorithm is exactly optimal for any number of oracle calls up to about (pi/4) sqrt(N); quantum search cannot be parallelised better than splitting the search space over independent machines | VERIFIED | 1999-zalka-grover-search-optimal.pdf, abstract; pp. 1-2 |
| L3 | (pi/4) 2^128 = 2^127.65; with S = 2^64 machines, 2^95.65 iterations each and 2^159.65 in total | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "Grover iterations") |
| L4 | Toy Grover, N = 2^10: 25 iterations give 0.9995 success; doubling the iterations gives 0.0002 | COMPUTED | `python research/scripts/pq/qc_simon_grover_toy.py` section 1 (seed 20260926) |
| L5 | MAXDEPTH plausible range 2^40 (one year, envisioned quantum architectures), 2^64 (a decade, classical architectures), no more than 2^96 (a millennium, atomic-scale qubits) | VERIFIED | nist-pqc-call-for-proposals-2016.pdf, Sec. 4.A.5, p. 17; same text in nist-pqc-call-additional-signatures-2022.pdf, Sec. 4.B.3, p. 16 |
| L6 | Under depth limit D_max, total gates G = c_p^2 2^k G_D G_G / D_max (eq. 9); minimising parallel machines minimises cost | VERIFIED | 2020-jaques-et-al-grover-oracles-aes-lowmc.pdf (ePrint 2019/1146 revision), Sec. 2.3, eqs. (6)-(9), p. 14 |
| L7 | NIST's formula is G * D / MAXDEPTH (x^2 machines each using G/x gates) | VERIFIED | 2020-jaques-et-al-grover-oracles-aes-lowmc.pdf, Sec. 6, p. 29 |
| L8 | Category 1/3/5 = key search on a block cipher with a 128/192/256-bit key (AES128/192/256); 2 and 4 = collision search on 256/384-bit hash; attacks must cost at least as much in all metrics NIST deems relevant | VERIFIED | nist-pqc-call-for-proposals-2016.pdf, Sec. 4.A.5, pp. 16-17 |
| L9 | 2016 call: AES-128 2^170/MAXDEPTH quantum or 2^143 classical gates; AES-192 2^233 or 2^207; AES-256 2^298 or 2^272; quantum sizes from Grassl et al. 2016 | VERIFIED | nist-pqc-call-for-proposals-2016.pdf, Sec. 4.A.5, p. 18 table and p. 17 footnote 4 |
| L10 | 2022 call: AES-128 2^157/MAXDEPTH, AES-192 2^221, AES-256 2^285 quantum gates (classical 2^143/2^207/2^272), quantum sizes from Jaques et al. 2020 | VERIFIED | nist-pqc-call-additional-signatures-2022.pdf, Sec. 4.B.3, pp. 16-17 and footnote 4 |
| L11 | Jaques et al. Table 13: AES-256 G-cost 246.9/224.4/192.4 (log2) at MAXDEPTH 2^40/2^64/2^96, approx. 2^288/MAXDEPTH; AES-128 approx. 2^159, AES-192 approx. 2^224; reduction 9-12 bits (11-13 in the original version); AES-128 at 2^96 needs no parallelisation | VERIFIED | 2020-jaques-et-al-grover-oracles-aes-lowmc.pdf, Table 13, p. 32; text p. 31 |
| L12 | Footnote 5 (both calls): estimates may understate the security of SHA for very small MAXDEPTH and the quantum security of AES for very large MAXDEPTH | VERIFIED | nist-pqc-call-for-proposals-2016.pdf p. 17 fn. 5; nist-pqc-call-additional-signatures-2022.pdf p. 17 fn. 5 |
| L13 | NIST IR 8547 ipd (Nov 2024): AES-128/192/256 = categories 1/3/5 (Table 6); approved symmetric primitives with at least 128-bit classical security believed to meet at least category 1; NIST does not expect to transition away from its symmetric standards | VERIFIED | nist-ir-8547-pqc-transition.pdf (ipd), Sec. 4.1.3 and Table 6, pp. 15-16; Sec. 2.1, p. 5 |
| L14 | NIST is "primarily concerned with attacks that use classical (rather than quantum) queries" to decryption/private-key functionality (KEMs) and to the signing oracle (signatures) | VERIFIED | nist-pqc-call-for-proposals-2016.pdf, Sec. 4.A.2 and Sec. 4.A.4, both p. 15; nist-pqc-call-additional-signatures-2022.pdf, Sec. 4.B.2, p. 14 |
| L15 | Expected spurious keys (2^k - 1) 2^(-rn); for k = b n, r = b + 1 gives a unique key with probability at least 1 - 2^-n; r must be at least ceil(k/n); rn = k gives Pr(unique) about 1/e | VERIFIED | 2020-jaques-et-al-grover-oracles-aes-lowmc.pdf, Sec. 2.2, p. 5 |
| L16 | Turing (k = 256, n = 128): r = 3 gives expected spurious keys 2^-128; r = 2 gives about 1 (Pr[unique] = 0.368) | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "Known blocks") |
| L17 | Toy k = 12, n = 8: 17, 1, 1 consistent keys for r = 1, 2, 3 | COMPUTED | `python research/scripts/pq/qc_simon_grover_toy.py` section 2 |
| L18 | S-box proxy: AES-256 oracle (r = 3) 724 S-boxes, about 14 layers; Turing (24 rounds, 13 warm-up + 8 per pair, 25 round keys, 109 Feistel rounds) 2896 S-boxes, about 110 layers; size x4.00, depth x7.86, product x31.4 (+5.0 bits). Proxy only. Keccak is not counted: round keys are functions of K' = cSHAKE256(K) alone (docs/07 steps 2-3; keyschedule.rs header), so Grover can search K' directly | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "S-box count"); constants read from crates/turing/src/structure.rs (ROUNDS = 24) and keyschedule.rs (WARMUP_ROUNDS = 13, ROUNDS_PER_PAIR = 8); AES key expansion rule FIPS 197 upd1 Algorithm 2 |
| L19 | BB84: no measurement by an eavesdropper who learns the basis afterwards yields more than 1/2 expected bit per photon; b bits cost disagreement probability at least b/2; measuring all photons rectilinearly learns half and disturbs 1/4 of re-measured bits | VERIFIED | 1984-bennett-brassard-bb84-quantum-cryptography.pdf, proceedings p. 177 (PDF p. 4) |
| L20 | BB84 toy: sifted 0.499 / QBER 0.000 (no Eve); 0.500 / 0.251 / Eve = Bob on 0.747 (intercept-resend); 0.250 / 0.000 / 1.000 (blinding model) | COMPUTED | `python research/scripts/pq/qc_qkd_toy.py` section 1-2 (seed 20260926, 200,000 photons) |
| L21 | BB84's public channel need not resist active eavesdropping if Alice and Bob pre-share a small secret key for Wegman-Carter authentication tags | VERIFIED | 1984-bennett-brassard-bb84-quantum-cryptography.pdf, p. 177 |
| L22 | E91: singlet state; Alice's angles 0, pi/4, pi/2; Bob's pi/4, pi/2, 3pi/4; CHSH E = <a1b1> - <a1b3> + <a3b1> + <a3b3>; -2 <= E <= 2 otherwise; ideal value -2 sqrt 2; isotropic state p \|Psi><Psi\| + (1-p) I/4 | VERIFIED | 2020-pirandola-et-al-advances-in-quantum-cryptography.pdf (Adv. Opt. Photon. 12, 1012 (2020)), Sec. D.1, eqs. (48)-(51), p. 14 |
| L23 | E = -2.828427 for the singlet; E = -2 sqrt(2) p for the isotropic state; \|E\| > 2 only for p > 1/sqrt 2 (p = 0.7071 gives -2.0000) | COMPUTED | `python research/scripts/pq/qc_qkd_toy.py` section 3 |
| L24 | Joint paper: QKD theoretically secure against unbounded attackers only with a one-time pad; keys fed to AES invalidate "absolute security"; implementations have been broken (cites Lydersen et al.); "absolute"/"unconditional" claims never apply to implementations; needs specialised hardware, high cost, not for mobile; eavesdropping = DoS; fibre demos at most a few hundred km, commercial about 100 km; trusted nodes; satellites mostly trusted nodes; authentication by pre-shared keys or PQ signatures; niche use only; not mature; PQC priority, in hybrid with symmetric keying or classical PKC | VERIFIED | 2024-anssi-bsi-nlncsa-sma-position-paper-qkd.pdf, Executive summary p. 1; Secs. 2-5, pp. 2-5 |
| L25 | NCSC 2025: QKD does not provide authentication "nor do any other quantum techniques"; "will not support the use of QKD for government or military applications. PQC is the best mitigation"; other sectors should not rely solely on QKD; QRNG possible advantages: rate, fast degradation detection; "we are keen that research on QRNGs continues to progress" | VERIFIED (saved copy; live page re-read 2026-09-27 with the same date, version and QKD sentences) | online: NCSC "Quantum networking technologies", https://www.ncsc.gov.uk/paper/quantum-networking-technologies, published 5 August 2025, version 1.0 (saved copy scratch pq/qc/ncsc-qnt.html) |
| L26 | NSA: does not recommend QKD/QC for NSS unless limitations are overcome; QKD does not authenticate the source; needs special equipment, "cannot be implemented in software or as a service on a network"; trusted relays; security "highly implementation-dependent"; DoS risk; PQC "more cost effective and easily maintained" | VERIFIED | online: https://www.nsa.gov/Cybersecurity/Quantum-Key-Distribution-QKD-and-Quantum-Cryptography-QC/ read through the Wayback Machine snapshot 20260918043425 (scratch pq/qc/nsa-qkd-archive.html); the live page returned HTTP 403 to curl on 2026-09-27 |
| L27 | PLOB bound K <= -log2(1 - eta) (eq. 134); secret-key capacity of the pure-loss channel = -log2(1 - eta), about 1.44 eta at high loss (eq. 135); standard fibre-loss rate 0.2 dB/km (Fig. 11 caption) | VERIFIED | 2020-pirandola-et-al-advances-in-quantum-cryptography.pdf, eqs. (134)-(135), p. 62; Fig. 11 caption, p. 63 |
| L28 | At 0.2 dB/km: PLOB 1.443e-4 bits/use at 200 km, 1.443e-20 at 1000 km; 256 bits at 0.0034 bit/s = 75294 s = 20.9 h. The 1e9 uses/s rate is an assumption for illustration | COMPUTED | `python research/scripts/pq/qc_qkd_toy.py` section 4 |
| L29 | Twin-field QKD over 1002 km: 9.53e-12 per pulse = 0.0034 bps, asymptotic regime only; finite-size up to 952 km at 0.0031 bps; ultra-low-loss fibre average attenuation < 0.157 dB/km; fibre spools | VERIFIED | 2023-liu-et-al-twin-field-qkd-1000-km.pdf (arXiv 2303.15795v1; PRL 130, 210801 (2023) per arXiv metadata), pp. 5, 9-10 |
| L30 | Lydersen et al.: detectors in id3110 Clavis2 (ID Quantique) and QPN 5505 (MagiQ) fully remote-controlled by tailored bright illumination; full secret key acquired tracelessly; off-the-shelf eavesdropper; loophole likely in most APD-based systems | VERIFIED | 2010-lydersen-et-al-hacking-commercial-qkd-bright-illumination.pdf (arXiv 1008.4593v2; Nature Photonics 4, 686-689 (2010) per arXiv metadata), abstract and p. 1 |
| L31 | Blinding: Bob detects only when his basis equals Eve's, losing half the bits, "not a problem" because transmittance to Bob's detectors is much lower than 1/2 | VERIFIED | 2010-lydersen-et-al-hacking-commercial-qkd-bright-illumination.pdf, p. 2 |
| L32 | NCSC 2020: does not endorse QKD for any government or military applications; cautions against sole reliance for business-critical networks; QKD may not count for CAF B3.b; QRNGs give no new mitigation against quantum computers; classical RNG noise is often quantum too; unpredictability hard to realise; classical RNGs will meet government and military needs for the foreseeable future | VERIFIED | online: NCSC "Quantum security technologies", https://www.ncsc.gov.uk/paper/quantum-security-technologies, published 24 March 2020, version 1.0 (saved copy scratch pq/qc/ncsc-qst.html) |
| L33 | Joint paper authorship: ANSSI, BSI, NLNCSA, Swedish National Communications Security Authority, Swedish Armed Forces; ANSSI page: published Thursday 25 January 2024; BSI page date 26.01.2024; the PDF itself has no date | VERIFIED | 2024-anssi-bsi-nlncsa-sma-position-paper-qkd.pdf, title page p. 1, PDF metadata empty; online: ANSSI page, canonical URL https://cyber.sites.beta.gouv.fr/en/publications/jointly-led-international-publications/position-paper-on-quantum-key-distribution/ (saved scratch pq/qc/anssi-qkd.html) and https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/Quantum_Positionspapier.html (scratch pq/qc/bsi-qkd.html) |
| L34 | QRNG review: "one of the most mature quantum technologies"; covers randomness extraction and device-independent generation with untrusted hardware | VERIFIED | 2017-herrero-collantes-garcia-escartin-quantum-random-number-generators.pdf (arXiv 1604.03304v2), abstract p. 1 |
| L35 | SP 800-90B (January 2018): physical noise sources use dedicated hardware; non-physical use system data or human input; min-entropy estimation, health tests | VERIFIED | nist-sp800-90b-entropy-sources.pdf, Sec. 2.2.1 (PDF p. 13) and contents |
| L36 | The word "quantum" does not occur in SP 800-90B | COMPUTED | `python research/scripts/pq/qc_source_checks.py` (counts occurrences in the PDF text) |
| L37 | SP 800-90C, September 2025 (not marked as a draft); RBG1/RBG2/RBG3/RBGC; security strength note: "a classical definition that does not consider quantum attacks ... will be revised" | VERIFIED | nist-sp800-90c-rbg-constructions.pdf, title page (September 2025), abstract, Appendix glossary "security strength" |
| L38 | Q1 = standard security, only classical queries; Q2 = quantum security, superposition queries; definitions follow Zhandry; ensuring classical-only queries "seems difficult" in a world with quantum resources | VERIFIED | 2016-kaplan-et-al-quantum-differential-linear-cryptanalysis.pdf (arXiv 1510.05836; ToSC 2016(1), 71-94, DOI 10.13154/tosc.v2016.i1.71-94), Sec. 1, p. 3 |
| L39 | Q2 "might appear rather extreme and perhaps even unrealistic"; a cipher secure in Q2 remains secure in any setting; Q1 "appears more realistic, but might be a little bit too simplistic" | VERIFIED | same file, Sec. 9, pp. 21-22 |
| L40 | Simon's algorithm finds hidden-period collisions with O(n) queries against Omega(2^(n/2)) classically; CBC-MAC, PMAC, GMAC, GCM, OCB "completely broken" with superposition queries, also CLOC, AEZ, COPA, OTR, POET, OMD, Minalpher; Q2 also covers obfuscated-device scenarios; measuring incoming queries is one countermeasure | VERIFIED | 2016-kaplan-et-al-breaking-symmetric-quantum-period-finding.pdf (arXiv 1602.05973v3; CRYPTO 2016, DOI 10.1007/978-3-662-53008-5_8), abstract p. 1; Sec. 1, p. 4; Simon's algorithm steps 1-5, Sec. 2 |
| L41 | Simon's algorithm still recovers s when f has extra collisions, provided no other (tau, t) has Pr[f(x) = f(x XOR t)] > 1/2 (Theorems 1-2 as applied in Sec. 3) | VERIFIED | 2016-kaplan-et-al-breaking-symmetric-quantum-period-finding.pdf, Sec. 3.1-3.2, pp. 10-12 |
| L42 | Kuwakado-Morii: 3-round Feistel distinguisher (ISIT 2010, pp. 2682-2685) and Even-Mansour key recovery (ISITA 2012, pp. 312-316), both with superposition queries; KM assumed an oracle returning only one half; KLLN extend to random round functions. The 2010 original (read in the second pass): internal permutations P1, P2, P3 independent and random; W = the first n bits of the 2n-bit output; f(b \|\| a) = W(a \|\| alpha) XOR beta (b = 0) or W(a \|\| beta) XOR alpha (b = 1) collides exactly under XOR with 1 \|\| z, z = P1(alpha) XOR P1(beta); "the first application of Simon's algorithm to cryptographic analysis" | VERIFIED (2010 paper read directly; the 2012 Even-Mansour paper only as described by KLLN16) | 2010-kuwakado-morii-quantum-distinguisher-3-round-feistel.pdf (copy from NIST's FOIA release hosted at nist.pqcrypto.org; footer "ISIT 2010, Austin, Texas, U.S.A., June 13 - 18, 2010", pp. 2682-2683), abstract and Sec. III.A; 2016-kaplan-et-al-breaking-symmetric-quantum-period-finding.pdf, Sec. 3.1-3.2, pp. 9-12, refs. [30], [31] p. 27 |
| L43 | Even-Mansour is secure classically up to 2^(n/2) queries; with superposition queries f(x) = E(x) XOR P(x) has period k1 and k2 follows from one classical query | VERIFIED | same file, Sec. 3.2, pp. 11-12 |
| L44 | Forgery attacks on the MAC/AE modes cost O(n) superposition queries | VERIFIED | same file, Sec. 5 introduction, p. 14 |
| L45 | Quantum slide attack: cipher of r applications of an identical round function with the same key; f(0, x) = P(E_k(x)) XOR x, f(1, x) = E_k(P(x)) XOR x, period 1 \|\| k; O(2^(n/2)) drops to O(n); "first known exponential quantum speed-up of a classical attack" | VERIFIED | same file, Sec. 6, pp. 23-24; Sec. 7, p. 25 |
| L46 | KLLN summary of Anand et al.: OFB and CTR remain secure; CBC and CFB not secure in general, secure if the PRF is quantum secure | VERIFIED (as KLLN's summary; see L62 for the primary) | same file, Sec. 1, pp. 4-5 |
| L47 | Toy slide attack (n = 8, 12 rounds): identical keys give period candidates [0x113] = 1 \|\| k; distinct per-round constants give rank 9 of 9 and no non-zero period | COMPUTED | `python research/scripts/pq/qc_simon_grover_toy.py` section 4 (seed 20260926) |
| L48 | Toy Even-Mansour (n = 8): 24 queries, rank 7 = n - 1, k1 = 0x08 and k2 = 0xb0 recovered, every y orthogonal to k1 | COMPUTED | `python research/scripts/pq/qc_simon_grover_toy.py` section 3 |
| L49 | Offline Simon: Grover over a partial key guess, Simon's test reusing one set of classical queries; Even-Mansour broken in quantum time O~(2^(n/3)) with O(2^(n/3)) classical queries and O(n^2) qubits | VERIFIED | 2019-bonnetain-et-al-offline-simon-quantum-attacks.pdf (ePrint 2019/614, ASIACRYPT 2019 per ePrint metadata), abstract p. 1 |
| L50 | Problem 3 (asymmetric search of a period): f_i offline, g online, exactly one f_i XOR g periodic, other candidates satisfy Condition (2); FX key recovery is an instance | VERIFIED | same file, Sec. 3, pp. 10-11 |
| L51 | FX (m-bit inner key, n-bit whitening): Q1 O(2^((m+n)/3)) queries, O(n^3 2^((m+n)/3)) time, O(n^2) qubits (Sec. 5); Q2 O(n) queries, O(n^3 2^(m/2)) time (Sec. 4); earlier Q1 MITM O(2^(3(m+n)/7)) | VERIFIED | same file, Table 1, pp. 3-4 |
| L52 | 2XOR-Cascade (Gazi-Tessaro, 5n/2-bit classical security from an n-bit cipher with 2n-bit key) attacked in quantum time O~(2^n) with classical queries: 2.5 speedup; first Q1 key recovery on a block cipher design with more than quadratic speedup; "cannot be used to generically strengthen block ciphers against quantum adversaries" | VERIFIED | 2022-bonnetain-schrottenloher-sibleyras-beyond-quadratic-speedups.pdf (arXiv 2110.02836v1; ePrint 2021/1348, "A minor revision of an IACR publication in EUROCRYPT 2022" per ePrint metadata), abstract p. 1 |
| L53 | Kaplan 2014: quantum attacks on double iteration reduce time only by exponent 3/2, so double iteration "can restore the security against quantum adversaries" | VERIFIED (as summarised by Kaplan et al. 2016; Kap14 itself not read) | 2016-kaplan-et-al-quantum-differential-linear-cryptanalysis.pdf, Sec. 1, p. 2 |
| L54 | Time formulas for classical, Q1 and Q2 differential, truncated differential and linear attacks; quantum cost at least the square root of classical; truncated gains less; best attack may change | VERIFIED | same file, Sec. 7.2-8, PDF pp. 19-20 (every formula in the section 5.2 table compared with the rendered pages, second pass) |
| L55 | Q2 differential distinguisher: 2^(h/2+1) queries (eq. 4); for a random function the success probability is at most 2^(h-n) | VERIFIED | same file, Sec. 4.2.1, p. 9 |
| L56 | "with k >= 2n, the data complexity is always smaller than 2^(k/2)"; with longer keys classical breaks likely lead to Q1 breaks | VERIFIED | same file, Sec. 8, p. 20; phrase located by `python research/scripts/pq/qc_source_checks.py` |
| L57 | Turing (n = 128, k = 256): D = 2^100, W = 2^220 gives Q1 about 2^110; D = 2^127, W = 2^255 gives about 2^127.5, both below 2^128 | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "Why k = 2n") |
| L58 | Quantum (Q1) attacks on AES: square attacks on 6-round AES-128, 7-round AES-192 and AES-256; DS-MITM on 8 rounds of AES-256 (classical DS-MITM: 9 rounds); AES has a bigger security margin w.r.t. quantum generic attacks | VERIFIED | 2019-bonnetain-naya-plasencia-schrottenloher-quantum-security-aes.pdf (ePrint 2019/272; "Published by the IACR in FSE 2020" per ePrint metadata), abstract p. 1, Sec. 1.2 p. 3 |
| L59 | Quantum related-key attack: conditions (efficient cipher circuit, key determined by r > ceil(k/n) pairs, superposition of related keys); f_s(x) = {E_x(m), E_{s XOR x}(m)}; polynomial time; "unlikely to pose a practical threat" | VERIFIED | 2015-rotteler-steinwandt-quantum-related-key-attacks.pdf (arXiv 1306.2301v2; Inf. Process. Lett. 115(1):40-44, 2015, DOI 10.1016/j.ipl.2014.08.009 as cited in offline-Simon ref. 37), abstract p. 1, pp. 2-3 |
| L60 | Toy quantum related-key attack (k = 10, n = 8, r = 3, key whitened by a random bijection): candidates [0x6a3] = 1 \|\| K | COMPUTED | `python research/scripts/pq/qc_simon_grover_toy.py` section 5 |
| L61 | Quantum related-key model "seems too powerful, as it would allow to break most block ciphers in polynomial time" | VERIFIED | 2019-bonnetain-naya-plasencia-schrottenloher-quantum-security-aes.pdf, Sec. 2, p. 6 |
| L62 | OFB and CTR IND-qCPA secure if the block cipher is a standard-secure PRF; CBC, CFB, XTS not under that assumption; CBC and CFB secure with a quantum-secure PRF | VERIFIED | 2016-anand-et-al-post-quantum-security-modes-of-operation.pdf (PQCrypto 2016 per KLLN16 ref. [3]), abstract p. 1 |
| L63 | Quantum-secure PRF implies quantum-secure MAC; a Carter-Wegman variant is quantum secure; pairwise independence insufficient for one-time MAC, four-wise sufficient | VERIFIED | 2013-boneh-zhandry-quantum-secure-macs.pdf (EUROCRYPT 2013 per KLLN16 ref. [12]), abstract p. 1 |
| L64 | NMAC, HMAC, AMAC and the fixed-input-length cascade are quantum-secure PRFs against superposition queries | VERIFIED | 2017-song-yun-quantum-security-nmac.pdf (ePrint 2017/509, major revision of CRYPTO 2017 paper per ePrint metadata), abstract p. 1 |
| L65 | t-target preimage search on p mesh processors: roughly sqrt(N / (p t^(1/2))) steps (t instead of t^(1/2) without communication cost); NIST's AES claims "need to be revised" | VERIFIED | 2017-banegas-bernstein-low-communication-parallel-quantum-multi-target-preimage-search.pdf (ePrint 2017/789, SAC 2017 per ePrint metadata), abstract p. 1; Sec. 1.4-1.5, p. 4 (both the formula and "need to be revised") |
| L66 | k = 256, t = 2^64, p = 1: about 2^112 steps (mesh model), 2^96 (communication ignored); t = 2^32: 2^120 / 2^112 | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "multi-target") |
| L67 | Bellare-Tackmann: multi-user security of AE; nonce randomisation (RGCM) gives better mu security than GCM in the ideal-cipher model; classical analysis | VERIFIED | 2016-bellare-tackmann-multi-user-security-aes-gcm-tls13.pdf (full version, Nov 2017; CRYPTO 2016 stated on p. 1), abstract p. 1 |
| L68 | Quantum slide attacks extend KLLN: advanced slide attacks on Feistel networks reach up to two-round self-similarity with modular additions and up to four rounds with XOR only, at most quadratic cost in the block size; some combine with FX whitening; sliding with a twist, complementation slide and mirror slidex are quantised; conclusion: protect "using e.g a good key schedule" | VERIFIED | 2019-bonnetain-naya-plasencia-schrottenloher-quantum-slide-attacks.pdf (ePrint 2018/1067; the ePrint listing says "Preprint", so the venue is not confirmed), abstract p. 1; Sec. 7, pp. 23-24 |
| L69 | Turing facts used in Section 6: 24 rounds, 25 round keys, MixState in odd rounds, ShiftRows+MixColumns in even rounds, none in round 24; K' = cSHAKE256(K, "Turing v2 key"); Feistel with fresh constant per round, 13 warm-up rounds, 8 per pair, feed-forward; no repeated round key among 266 suspicious keys and 65,536 neighbours; 0 linear relations | VERIFIED (project documents and source, not external) | docs/09 "The round"; docs/07 steps 1-3; crates/turing/src/keyschedule.rs header and constants; docs/11 "Slide attacks"; docs/12 "Linear relations in the key schedule" |
| L70 | Lower bounds on distinguisher cost from Turing's bounds: 3-round trail 2^-108 gives Q2 >= 2^55, classical >= 2^109; 3-round MEDP 2^-102.0 gives Q2 >= 2^52.0; 3-round MELP 2^-99.6 gives Q2 >= 2^49.80; 5-round MEDP 2^-110.8 gives Q2 >= 2^56.4; 5-round MELP 2^-105.9 gives Q2 >= 2^52.95; 4- and 5-round trails below 2^-128 | COMPUTED | `python research/scripts/pq/qc_grover_costs.py` (section "Q2 differential/linear"); inputs from docs/09 table and docs/12 provable bounds; formula from L55 |
| L71 | 2,432 = 256 + 17 x 128 (version 1 key plus 17 round keys); version 2: 256 + 25 x 128 = 3,456 | COMPUTED | arithmetic; version 2 round-key count from crates/turing/src/structure.rs (ROUND_KEYS = ROUNDS + 1 = 25) |
| L72 | Version-2 Bombe campaign, section 17: "0 relations among 3456 bits (3585 random keys)" for the key and all round keys, and the same for the Feistel stage alone; AES-128 control 1088 relations among 1536 bits; the run reports "24 rounds in the cipher". The test sizes itself from `ROUND_KEYS` and draws 8 x bytes + 1 + 128 rows (3,456 + 1 + 128 = 3,585) | VERIFIED (project output, not external) | target/reports/attack-report.md (full run, 135 findings, written 2026-09-26 21:42), lines 181-187 and 40; target/reports/quick-linux.txt lines 131-134 (WSL Linux run); crates/bombe/src/keyrelations.rs `turing()` and `turing_feistel()` |
| L73 | Quantum access to a keyed f needs "an explicit interface granting such access"; honest parties "would implement f using a classical computer"; the Q1 setting is called "the post-quantum setting" | VERIFIED | 2021-alagic-bai-katz-majenz-post-quantum-security-even-mansour.pdf (ePrint 2021/1601, "Published by the IACR in EUROCRYPT 2022" per ePrint metadata), PDF p. 2 |
| L74 | Even-Mansour in Q1 (classical access to E, quantum access to P): any attack needs q_E q_P^2 + q_P q_E^2 of about 2^n; applies to two-key and single-key variants; in Q2 attacks with O(n) queries exist | VERIFIED | same file, abstract, PDF p. 1 |
| L75 | FX in the partially-quantum (Q1) model: non-adaptive bound O(sqrt(p^2 q / 2^(k+n))); breaking needs about 2^((k+n)/3) queries, matching the offline-Simon attack (tight); non-adaptive security suffices for CTR/OFB-type uses; Q1 "arguably more realistic and less controversial than Q2" | VERIFIED | 2021-jaeger-song-tessaro-quantum-key-length-extension.pdf (ePrint 2021/579, "A minor revision of an IACR publication in TCC 2021"), abstract p. 1; PDF p. 2; Sec. 1.1, PDF p. 3 |
| L76 | Leander-May: whitening keys do "not increase the security in the quantum-CPA setting significantly"; the Grover-meets-Simon attack runs in essentially Grover's time on the inner cipher | VERIFIED | 2017-leander-may-grover-meets-simon-fx.pdf (ePrint 2017/427, "Published by the IACR in ASIACRYPT 2017"), abstract, PDF p. 1 |
| L77 | Double encryption with independent keys: SPRP security in the fully-quantum (Q2) model; a highly successful attacker needs Omega(2^(2k/3)) queries (ignoring log factors), matching Kaplan's Theta(N^(2/3)) claw-finding attack; restricting to Q1 would not improve the bound | VERIFIED | 2021-jaeger-song-tessaro-quantum-key-length-extension.pdf, Sec. 1.2, PDF pp. 4-5 |
| L78 | t-round key-alternating cipher (random permutations, independent permutations and round keys), non-adaptive adversaries: Q1 Omega(2^(tn/(2t+1))), classical Omega(2^(tn/(t+1))), Q2 Omega(2^((t-1)n/(2t))); "for t >= 2, the exponential Q1-Q2 gap collapses in the non-adaptive setting"; Q1 key recovery O(2^(alpha n)), alpha = t(t+1)/((t+1)^2+1) | VERIFIED | 2024-bai-esmaili-mantri-key-alternating-ciphers-quantum-lower-bounds.pdf (arXiv 2412.05026v3, 9 Oct 2025; no venue in the arXiv record), abstract PDF p. 1 (exponents read from the rendered page), Sec. 1.1 PDF p. 3 |
| L79 | Two-key iterated Even-Mansour (key schedule alternating two independent keys, like LED): first quantum attacks beating exhaustive search for 4 to 6 rounds; 4 rounds up to quantum time 2^(7n/9), 6 rounds 2^n/sqrt(log n), against 2^n; classical known-plaintext queries only | VERIFIED | 2026-degre-et-al-improved-quantum-attacks-iterated-even-mansour.pdf (ePrint 2026/930, "Preprint", received 2026-05-11), abstract PDF p. 1 (exponents read from the rendered page) |
| L80 | Saturnin spec (round 2): 256-bit block and key; 128-bit quantum security "does not seem enough" with a 256-bit key because mode security depends on collisions "depending only on the block size" (p. 4); no quantum single-key attack with T^2/p < 2^224; no security against related-key superposition attacks "(as is the case of all known block ciphers)" (p. 7); quantum CTR-Cascade claim D^3 + T^2 + D^2 2^(256-t)/p < 2^224 (p. 8); CTR superposition queries emulated classically, so CTR is quantum-secure up to the classical birthday bound; random functions vs permutations quantumly distinguishable at 2^(n/3), 2^85 for n = 256, advantage C q^3/2^n [Zha15] (pp. 30-31); all claims in Q2 (p. 6); BHT collision search needs 2^(n/3) quantum RAM (p. 41) | VERIFIED | 2019-canteaut-et-al-saturnin-spec-round2.pdf (NIST LWC round-2 specification; journal version ToSC 2020 Special Issue 1, pp. 160-207, DOI 10.13154/tosc.v2020.iS1.160-207, per the ToSC article page https://tosc.iacr.org/index.php/ToSC/article/view/8621 read 2026-09-27), PDF pp. 4, 6-8, 30-31, 41 |
| L81 | At Turing's sizes: FX Q1 2^((256+128)/3) = 2^128 = Grover on k (gain 0 bits); double encryption with two 256-bit keys 2^170.67; t = 24 KAC n = 128: Q1 >= 2^62.69, Q2 >= 2^61.33; two-key IEM n = 128: 2^99.56 (4 rounds), 2^126.60 (6 rounds); quantum PRP/PRF switching 2^42.67 (n = 128), 2^85.33 (n = 256); Saturnin data limit 2^74.67; Turing CTR 2^64 blocks x 16 bytes = 2^68 bytes per key; key-tweak insertion first term 2^-13 for m = 2^32, q' = 2^96, k = 256; keyed sponges: inner/full-keyed 2^85.33 for a 256-bit key; KMAC with a 256-bit key not covered by Hosoyamada's Theorem 7; sponge indifferentiability non-trivial below q = 2^56.89 (c = 512) | COMPUTED | `python research/scripts/pq/qc_constructions.py` |
| L82 | Bernstein's cost analysis concluded that no known quantum collision-finding algorithm was faster than the non-quantum parallel rho method (as recorded by Banegas-Bernstein) | VERIFIED (as summarised in Banegas-Bernstein; Bernstein 2009 itself not read) | 2017-banegas-bernstein-low-communication-parallel-quantum-multi-target-preimage-search.pdf, Sec. 1.4, PDF p. 4 |
| L83 | QCB: rate-one parallelisable AEAD with Q2 proofs (IND-qCPA, BZ-unforgeability) given a TBC secure under classical tweaks; LRW is not quantum-secure even with classical tweaks; key-tweak insertion E_(K XOR T) is broken with superposition tweaks (RS attack) and has STPRP advantage <= 8 sqrt(m q'^2/2^k) + sqrt(q2 s0/(2 * 2^k)) in the ideal-cipher model (Proposition 1); Saturnin-QCB needs Saturnin16 related-key secure; "Block ciphers of 256 bits seem more convenient for post-quantum security" | VERIFIED | 2020-bhaumik-et-al-qcb-quantum-secure-authenticated-encryption.pdf (ePrint 2020/1304, "Published by the IACR in ASIACRYPT 2021"), abstract PDF p. 1; Sec. 4.2 PDF p. 14; Proposition 1 PDF p. 15; Sec. 5 PDF p. 17 |
| L84 | Keyed sponges in the quantum ideal permutation model with classical construction queries: inner-/full-keyed secure up to about min(2^(c/3), 2^(kappa/3)) queries; outer-keyed (KMAC) about min(2^(c/3), 2^((kappa-r)/2), 2^(r/2)); Theorem 7 assumes kappa > r; "if the key is sufficiently long", KMAC128 and KMAC256 have more than 80-bit and 160-bit security | VERIFIED | 2025-hosoyamada-post-quantum-keyed-sponge-kmac-ascon.pdf (ePrint 2025/1059, "A major revision of an IACR publication in ASIACRYPT 2025"), abstract PDF p. 1; PDF p. 5; Theorem 7 PDF p. 29 |
| L85 | The sponge is quantum-indifferentiable from a random oracle (adversary with quantum access to the permutation, its inverse and the sponge); bound O(l^3 (q^9 2^(-min(r,c)))^(1/4)), described by the authors as loose | VERIFIED | 2025-alagic-carolan-majenz-tokat-sponge-quantum-indifferentiable.pdf (ePrint 2025/731, "Preprint"), abstract PDF p. 1; Theorem 1.2 PDF p. 6 (formula read from the rendered page) |
| L86 | GCM with u keys in the quantum ideal cipher model: trivial key-search term u p^2/2^k (u = 2^32: constant at p = 2^48 for k = 128, p = 2^80 for k = 192); can be replaced, at the cost of additional loss terms, by a term of order sqrt(d p^2/2^k), d = maximum number of keys under which the same nonce appears; d small for randomised nonces; bounds not tight; "the first non-trivial post-quantum multi-key security bound for an AEAD mode in the QICM" | VERIFIED | 2026-hosoyamada-post-quantum-multi-key-security-gcm.pdf (ePrint 2026/1718, "Preprint", received 2026-08-18, revised 2026-09-18), abstract PDF p. 1 (formula read from the rendered page) |
| L87 | Q1MK model: TEM needs Omega(2^(kappa/3)) classical and quantum queries whatever the number of kappa-bit keys; FX with a (kappa + n)-bit key needs Omega(2^((kappa+n)/3)) in Q1 (tightened proof) and Omega(2^((kappa+n-u)/3)) with 2^u independent keys | VERIFIED | 2026-shiba-iwata-multi-key-quantum-tem-fx.pdf (ePrint 2026/382, "Published by the IACR in TOSC 2026"), abstract PDF p. 1 |
| L88 | k = 256: trivial multi-key term reaches 1 at p = 2^112 (u = 2^32) and 2^96 (u = 2^64); with nonce randomisation at p = 2^128, 2^124, 2^120 for d = 1, 2^8, 2^16; FX Q1MK (kappa = 256, n = 128): 2^128, 2^117.33, 2^106.67 for 1, 2^32, 2^64 keys; the script reproduces the abstract's examples (2^48, 2^80) as a check | COMPUTED | `python research/scripts/pq/qc_constructions.py` (section 10) |
| L89 | AIS 31 v3.0 (M. Peter, W. Schindler, BSI, 10 September 2024): seven functionality classes DRG.2, DRG.3, DRG.4, DRT.1, PTG.2, PTG.3, NTG.1, technology-agnostic; par. 1124: QRNGs exploit quantum mechanics, the document "does not distinguish between quantum entropy and entropy from physical phenomena based on other physical models", QRNGs are PTRNGs, most physical noise sources exploit quantum effects; DRNGs based on factoring/DL "will likely become insecure" with quantum computers; DRG.3: Grover may reduce the effort "but a successful attack shall still be infeasible" | VERIFIED | 2024-bsi-ais-31-functionality-classes-rng-v3.pdf, title page PDF p. 1; class list PDF p. 9; PDF pp. 29, 49, 64; par. 1124 PDF p. 234 |
| L90 | Turing's planned file layer (docs/03, "Layer 2: file encryption"): a fresh random 256-bit file key per file; chunks (e.g. 64 KiB) encrypted with a Turing-based AEAD "using a nonce that encodes the chunk counter and a 'last chunk' flag (STREAM construction)"; the AEAD construction "(e.g. CTR + MAC) is decided in step 9" | VERIFIED (project document, not external) | docs/03-design-spec.md, section "Layer 2: file encryption" (read 2026-09-27) |
| L91 | KMAC256 keyed with a 256-bit key is a quantum-secure PRF against superposition queries, by composing the sponge's quantum indifferentiability [L85] with the fact that a random oracle on K \|\| m is a quantum-secure PRF | UNVERIFIED | an inference, not a source statement: the composition theorem for quantum indifferentiability and its conditions were not read; settle by reading the composition result used in [L85] or a direct keyed-sponge Q2 proof (OQ3) |
| L92 | Post-2020 quantum circuits for AES lower the absolute gate counts behind NIST categories 1, 3 and 5 below Jaques et al.'s [L11] | UNVERIFIED | seen only as search-result titles on 2026-09-27; settle by reading the most recent AES Grover-oracle estimate (OQ10) |

## Open questions

- **OQ1. No quantum resource estimate for Turing.** Only an S-box proxy exists [L18]. A real estimate (a reversible
  circuit for Turing's S-box, MixState and the Feistel schedule, costed as in Jaques et al.) would be needed to
  claim that Turing's key search costs more than AES-256's. Not needed for a category 5 claim.
- **OQ2 (closed 2026-09-27).** The key-relation check was re-run on version 2 (0 of 3,456 bits) [L72]. What
  remains is a documentation edit: docs/12 still prints version 1's 2,432 [L71].
- **OQ3 (partly answered). Quantum security of a KMAC-based MAC with a 256-bit key.** Read in this pass: Q1 proofs
  for keyed sponges (inner/full-keyed about min(2^(c/3), 2^(kappa/3)); KMAC only for kappa > r) [L84], and quantum
  indifferentiability of the unkeyed sponge with a loose bound [L85]. Still open: (a) a Q2 PRF proof for KMAC256
  with a 256-bit key; one could argue it from indifferentiability (KMAC as a sponge on a key-prefixed input, and a
  random oracle on K || m is a quantum-secure PRF), but that composition argument was not checked against a source
  and is UNVERIFIED [L91]; (b) whether a full-keyed Keccak-p MAC (covered up to about 2^85.33 queries in Q1 with a 256-bit
  key [L81]) is preferable to KMAC for Turing. Settle with the sibling topic lattices-inside-symmetric-primitives
  or at the AEAD decision.
- **OQ4 (mostly answered). Quantum attacks on multi-round key-alternating ciphers.** In the ideal model with
  independent round keys, t >= 2 rounds already give an exponential Q2 lower bound against non-adaptive attackers
  [L78]; the Q1 attacks found (Degre et al. 2026) need a two-key alternating schedule [L79]. Open: adaptive Q2
  attackers on multi-round key-alternating ciphers (the lower bound is non-adaptive only [L78]), and any analysis of
  key-alternating ciphers whose round keys come from a nonlinear schedule, as Turing's do. The generic bounds stay
  below 2^64 [L81] and so cannot certify Turing's 2^128 target on their own.
- **OQ5 (partly answered). Quantum multi-target security with randomised nonces.** Bellare-Tackmann is classical
  [L67]. A quantum ideal-cipher-model bound for GCM with randomised nonces now exists as a preprint (ePrint
  2026/1718): the key-search term becomes sqrt(d p^2 / 2^k) [L86], [L88]. Open: it is a preprint with loose bounds,
  it covers GCM (whose GHASH is itself broken in Q2 [L40]), not the CTR-plus-MAC or STREAM layout Turing's file
  format will use, and it is an ideal-cipher statement. A proof for Turing's chosen AEAD would need the same
  analysis, or an argument that it reduces to the CTR part.
- **OQ6. Quantum meet-in-the-middle, impossible-differential and integral attacks on Turing-like SPNs.** Only AES
  has a published quantum case study [L58]. Kaplan et al. show truncated differentials gain less than a square
  root [L54]; the other families are covered here only by the k = 2n argument.
- **OQ7 (half closed). Kuwakado-Morii originals.** The ISIT 2010 Feistel paper was read in the second pass (a copy
  in NIST's FOIA release) and matches KLLN's description [L42]. The ISITA 2012 Even-Mansour paper is still read only
  through KLLN [L42], [L43]; the Even-Mansour Q2 break is also stated independently by Alagic et al. [L74].
- **OQ8 (closed 2026-09-27, by the sibling topic).** NIST IR 8547 is still the initial public draft of 12 November
  2024; there is no final version (research/notes/pq/nist-pqc-standards.md, Section 5 and its ledger row 47, checked
  against the CSRC page on 2026-09-27). The category text used here (L13) is therefore draft text.
- **OQ10. Newer quantum circuits for AES.** Papers after Jaques et al. (2020) publish other AES quantum circuits
  (seen only as search-result titles here) [L92]. They could lower the gate counts that define categories 1, 3 and 5 in
  absolute terms. They do not change the statement used for Turing, "key search on a 256-bit key is the category 5
  reference", because the category is defined by AES-256 key search whatever its cost. Settle by reading the most
  recent estimate if an absolute gate count is ever quoted.
- **OQ11. Q2 for adaptive attackers on multi-round key-alternating ciphers, and for ciphers with nonlinear key
  schedules.** See OQ4; the only multi-round lower bounds read are non-adaptive and assume independent round keys
  [L78].
- **OQ9. Owner decision: claim anything about Q2?** The evidence supports "no known Q2 structural attack applies to
  Turing's cipher" (section 6) but not "Turing is Q2-secure". Whether the documents should say the first is a
  design-phase choice.
