# Derivations behind Bombe's predictions

Short proofs for the claims the attack bench relies on, so they can be
re-checked without the conversation that produced them.

## 1. Sub-window bound (docs/12)

With independent round keys, EDP composes like a Markov chain:
EDP_T(a, b) = Σ_{c,d} EDP_pre(a, c) · EDP_win(c, d) · EDP_post(d, b).
Bound the middle factor by its maximum. What is left is
Σ_c EDP_pre(a, c) · Σ_d EDP_post(d, b), and both sums are 1: for a
permutation, each row and each column of the difference table sums to 1. So
MEDP_T ≤ MEDP of any window. Linear hulls work the same way, with Nyberg's
ELP composition and Parseval (Σ_c ELP(a, c) = 1).

## 2. Word branch number of MixState between super-box layers

Group MixState's input into 4 words (the columns coming out of one
super-box layer) and its output into 4 words (the diagonals going into the
next). If k words are active in, at most 4k bytes are active, so at least
17 − 4k output bytes are active, which is at least ⌈(17 − 4k)/4⌉ = 5 − k
words. So k + (5 − k) ≥ 5: branch number 5 over words, for any grouping into
4-byte words. The same holds for the linear branch number (MDS is preserved
by the inverse transpose). Park et al.'s Theorem 1 over the super-boxes
then gives max Σ_v EDP_SB(u, v)^5 ≤ μ^4 · Σ_v EDP_SB(u, v) = μ^4.

## 3. Bytewise symmetries must be field scalings (docs/12, `symmetry.rs`)

Suppose L · diag(B_j) = diag(A′_i) · L, where every non-zero entry of L is a
block "multiply by m_ij". Then m_ij B_j = A′_i m_ij for all non-zero m_ij.

Take rows i, i′ and columns j, k, all four entries non-zero. Row i gives
B_k = ρ_i B_j ρ_i⁻¹ with ρ_i = m_ij / m_ik, and row i′ gives the same with
ρ_i′. Equating the two, B_j commutes with c = ρ_i / ρ_i′, the cross-ratio
(m_ij m_i′k)/(m_ik m_i′j).

If c ∉ GF(16), then GF(2)[c] = GF(2^8). The centraliser of multiplication by
c in M_8(GF(2)) is GF(2)[c] (its minimal polynomial is irreducible of
degree 8), so B_j is a field multiplication β_j.

Then S(A x ⊕ a) = β S(x) ⊕ b means x ↦ S⁻¹(β S(x) ⊕ b) is affine.

## 4. Reflection form of an inversion S-box

With S = A_out ∘ inv ∘ A_in, we have S⁻¹ = A_in⁻¹ ∘ inv ∘ A_out⁻¹
= T ∘ S ∘ T, where T = A_in⁻¹ ∘ A_out⁻¹. Substituting into decryption, each
S⁻¹ becomes T S T. Between S-boxes the maps become T ∘ L⁻¹ ∘ T. Keys pass
through T as T_lin(k), a related key. Decryption is encryption under other
keys iff T_lin L⁻¹ T_lin equals the encryption layer at the mirrored
position. Turing's layer pattern MS, SM, …, MS is a palindrome, so the
condition is per layer type.

## 5. Exact 2-round boomerang rate (docs/11)

The pairs differ by M·(γ, 0, …, 0) after MixState. The last S-box inputs u
and u ⊕ β₀ must shift alike, where T(u) = S⁻¹(S(u) ⊕ δ) ⊕ u, so
T(u) = T(u ⊕ β₀).

Then the returning pair is shifted by c = (M⁻¹)₀₀ · T(u) at the first S-box.
It returns iff S⁻¹(S(x) ⊕ c) ⊕ S⁻¹(S(x ⊕ α) ⊕ c) = α.

Count over (x, u) ∈ 256²: 8/65536. Treating the switches as independent
gives 2^-15.2 instead.

## 6. Exact 2-round differential-linear correlation (docs/12)

corr(j, λ) = Σ_γ DDT[α][γ]/256 · AC_λ(m_j γ)/256, where
AC_λ(d) = Σ_y (−1)^{λ·(S(y) ⊕ S(y ⊕ d))}. The last S-box input in byte j is
uniform and independent of γ, because it mixes all 16 plaintext bytes.

## 7. Cube sums vanish at 2 rounds (docs/11)

An output bit after 2 rounds is a component of S (degree 7) applied to
MixState outputs, and each of those is a sum of functions of single bytes.
Every monomial is a product of at most 7 such functions, so it involves at
most 7 first-round bytes. Its degree in the cube variables is at most the
number of cube bits in those bytes. Sixteen random distinct bits among 128
fall into at most 7 bytes with probability 0.35% (inclusion-exclusion over
byte sets), 10.7 bytes on average.

## 8. Key-schedule linear relations

Relations holding for every key = linear dependencies among the columns
(key bits, round-key bits, constant) of a samples × columns matrix. With
N = columns + 128 random keys, a genuinely independent set of columns is
rank-deficient with probability below 2^-100. AES-128: rank 449 =
1 + 128 + 320, since the only non-linear words are the 10 SubWord outputs,
so there are 1536 + 1 − 449 = 1088 relations.

## 9. Equivalent keys through cSHAKE (docs/11)

A random function from 256 to 256 bits hits about 1 − 1/e of its range, so
about 2^255.34 distinct K′. Collisions exist but take a cSHAKE256 collision
(about 2^128) to find.

## Masking and leakage (docs/13)

**Why the centred product predicts HW(v).** With v = m ⊕ (v ⊕ m) and m
uniform on 8 bits, write HW(m) − 4 = Σ_i (m_i − 1/2) and likewise for
v ⊕ m. For one bit, (m_i − 1/2)((v_i ⊕ m_i) − 1/2) is +1/4 when v_i = 0
and −1/4 when v_i = 1; bits at different positions are independent with
zero mean. So E[(HW(m) − 4)(HW(v ⊕ m) − 4)] = Σ_i (1 − 2v_i)/4 =
−(HW(v) − 4)/2. Prouff, Rivain and Bévan's Proposition 10 gives the same,
−H(z)/2 plus a constant. With independent noise of variance σ² on each leak,
the correlation with HW(v) is −1/(√2 (2 + σ²)): −0.354 without noise, −0.177
at SNR 1 (σ² = 2), which a few thousand traces resolve among 256 guesses.

**ISW at d = 1.** c0 = a0 b0 ⊕ r and c1 = a1 b1 ⊕ ((r ⊕ a0 b1) ⊕ a1 b0), so
c0 ⊕ c1 = (a0 ⊕ a1)(b0 ⊕ b1). Share c0 is uniform because r is fresh, and
c1 = ab ⊕ c0. Each intermediate involves at most one share of each input,
or is masked by r. If the cross terms were summed before r is added, the
intermediate (a0 ⊕ a1)(b0 ⊕ b1) = ab would be the secret itself: the planted
bug the operation-level TVLA catches.

**A mutant that is too weak to see.** Leaving c0 = a0 b0 unmasked keeps the
output correct and gives c1 = v ⊕ a0 b0. A product of two uniform bytes is
0 with probability 511/65,536 and each non-zero value with probability
255/65,536, so E[HW(c1)] = (255 · 1024 + 256 · HW(v))/65,536, which moves by
only 0.0039 per unit of HW(v). Fixed-versus-random classes differ by under
0.01 against a standard deviation of 1.4: t ≈ 0.3 at 20,000 traces. It is a
real first-order leak, but it would need millions of traces, so the planted
recombination bug was used instead.

**TVLA false alarms.** For a normal statistic, P(|t| > 4.5) = 6.8 × 10^-6. One
group over 768 independent points raises a false alarm with probability
about 0.5% (1.2% over 1,728 points). Goodwill et al.'s rule needs both
groups past 4.5 in the same direction: 2 × (3.4 × 10^-6)^2 per point, under
10^-7 over all points.

## Integrity checksum (keyschedule.rs)

The checksum C = Σ_{i=0}^{24} H^(i+1) · RK_i over GF(2^128), modulo the
irreducible x^128 + x^7 + x^2 + x + 1, is taken at a secret point H: for a
plain cipher cSHAKE256 of K' under "Turing v2 key check", for the masked one
a value drawn from its mask stream, made odd in both cases. Errors E_i in
the round keys and e in the stored checksum go unseen only if
f(H) = Σ_i E_i · H^(i+1) + e = 0. Unless every E_i and e are zero, f is a
non-zero polynomial of degree at most 25, so it has at most 25 roots in the
field. H is uniform over 2^127 odd values and unknown to whoever arranges
the fault, so the fault escapes with probability at most
25/2^127 ≈ 2^-122.4, whatever its weight. Each failed attempt rules out at
most 25 values of H, so repeated attempts learn next to nothing.

That argument holds H fixed, so it covers faults in the round keys and the
stored checksum only. A fault can also move H itself, to H + d with d ≠ 0;
the check then recomputes the checksum at H + d from the faulted keys and
compares it with the faulted stored value. The fault goes unseen exactly
when

    P = Σ_i ((H + d)^(i+1) + H^(i+1)) · RK_i + Σ_i (H + d)^(i+1) · E_i + e = 0.

For i = 0 the first sum's term is ((H + d) + H) · RK_0 = d · RK_0, with no
H in it, and no other term contains RK_0. So P = d · RK_0 + Q, where Q
depends on H, RK_1 … RK_24 and the fault but not on RK_0, and P = 0 exactly
when RK_0 = d^-1 · Q: one value of RK_0 for each H and each choice of the
other round keys. With round key 0 unknown (uniform, independent of the
rest, the model docs/12's bounds also use), the fault escapes with
probability 2^-128, even for someone who knows H. Nothing weaker suffices:
whoever knows every round key can compute Q and match any moved point with
a new stored checksum (the control test does), but has nothing left to
attack. Together: every fault arranged without knowledge of the key escapes
with probability at most 25/2^127.

The weights start at H^1 for a reason. With Σ H^i · RK_i, round key 0
would carry weight 1, and flipping bit j of RK_0 together with bit j of the
stored checksum would cancel for every H.

Checked by brute force in the same algebra at a size where everything can be
enumerated, GF(2^8) with 4 round keys and weights H^1 … H^4. Over 300 random
faults: with d = 0, for each of the 256 values of RK_0 (the other keys
fixed), no fault passed at more than 3 of the 128 odd points (the bound is
4); with d ≠ 0, at every one of the 256 points exactly one of the 256 values
of RK_0 let the fault through.

Linearity (for a fixed H) is why the masked cipher can keep the checksum as
shares: C(k0) ⊕ C(k1) = C(k0 ⊕ k1), and re-randomising both key shares with
the same masks moves both sides of the comparison by the same amount.

Why H must be secret: version 2 first used the public point x,
C = Σ x^i · RK_i. Bit b of RK_i then contributes x^(i+b), so any two bits
with the same i + b cancel. For round keys i < j = i + d, the pairs are
bit c + d of RK_i with bit c of RK_j, c < 128 − d, which gives
Σ_{d=1}^{24} (25 − d)(128 − d) = 35,800 pairs of round-key bits. Bit b of
RK_i and bit i + b of the stored checksum also cancel when i + b < 128:
Σ_{i=0}^{24} (128 − i) = 2,900 more. Together that is 38,700 of the
C(3328, 2) = 5,536,128 two-bit faults, 0.70%. Enumerating all two-bit faults
through `encrypt_block_checked` reproduces 35,800 exactly for the round
keys, and finds 0 with the keyed checksum.


## Fifth campaign: attacks from the AES-256 literature (docs/14)

### The keyed square structure

Round 1 is S-box layer, MixState, RK1. For a guess g of RK0, the plaintext
P = S^-1(MixState^-1(z)) ⊕ g gives MixState(S(P ⊕ RK0)) ⊕ RK1 = z ⊕ RK1 at
round 2's S-box input exactly when g = RK0. RK1 only adds a constant, so a
set of z with the diagonal (bytes 0, 5, 10, 15) taking all 2^32 values and
the other bytes fixed lands on the same kind of set.

Division property by hand (word level, Todo 2015). Input vector: 8 on the
diagonal. S-box layer 2 keeps it; ShiftRows moves the diagonal into column
0; MixColumns spreads the total 32 over the column, and S-box layer 3 can
only return (8, 8, 8, 8), since a column total of 32 has no other split.
MixState spreads 32 over all 16 bytes. A byte below 8 holds at most 7, so
after S-box layer 4 the smallest vectors are five 1s, four 1s and an 8,
three 1s and two 8s, two 1s and three 8s, or four 8s. ShiftRows +
MixColumns cannot put five nonzero bytes in one column, and a column
holding an 8 keeps an 8 or two nonzero bytes through S-box layer 5, so at
least two bytes stay nonzero there; MixState keeps that total of 2 at the
input of S-box layer 6: balanced there. S-box layer 6 can turn a 2 into a
1: balance ends. `bombe::division` gives the
same (window starting at round 2, `balanced_until` 5 = layer 6), and the
run confirms it: two 2^32 structures balanced at the inputs of S-box layers
2 to 6 in all 16 bytes, not at layer 7 (0 of 16 bytes).

With 1 to 3 diagonal bytes the column total is at most 24 and S-box layer
3 can leave a single 1: balanced to layer 4 only (measured: 2^8, 2^16 and
2^24 texts balanced at layers 2-4, not 5).

### Costs

- 6 rounds: per guess g, one structure of 2^32 codebook lookups, then 16
  bytes × 2^8 guesses of RK6. A byte of a wrong g keeps at least one of 256
  guesses with probability 1 − (1 − 2^-8)^256 ≈ 0.632, all 16 with 2^-10.6,
  so almost every wrong g dies on its first structure: 2^128 · 2^32 = 2^160
  lookups.
- 7 rounds: a byte of the S-box layer 6 input is
  S^-1(Σ_i M^-1[r][i] · S^-1(C[4c + i] ⊕ RK7[4c + i]) ⊕ e) with
  e = ShiftRows^-1(MixColumns^-1(RK6)): 5 key bytes, 2^40 guesses. Ferguson
  et al.'s partial sums (FSE 2000, section 2.3) cost 2^48 steps, about 2^50
  S-box lookups, per structure for all 2^40. A wrong g keeps 2^(40 − 8s)
  guesses after s structures, so it dies after about 6: 2^128 · 6 · 2^50 =
  2^180.6 S-box lookups, 2^173.8 seven-round encryptions (112 S-boxes each).
  About 5 + 16 = 21 structures single out g, as for Ferguson et al.'s
  7-round AES-256 attack (21 · 2^32 texts, 2^172), whose cost ours matches
  but with the full codebook, since every g needs its own plaintexts.
- 6 rounds from plaintexts: the 2^120 structure of docs/11 keeps the S-box
  layer 5 input balanced; one byte of it needs all of RK6 and a byte of
  MixState^-1(RK5), 17 bytes. Partial sums over 16 ciphertext bytes cost
  2^(8(m+1)) · 2^(8(17 − m)) = 2^144 at each of about 15 stages, 2^148 per
  structure; 17 structures single out 136 bits: 2^152 S-box lookups with
  about 2^124 chosen plaintexts.
- 8 rounds: one byte of the S-box layer 6 input through rounds 6-8 needs
  all of RK8 (round 7 has MixState): 2^128 more on top of RK0, 2^256.

### Yoyo words

For E = S2 ∘ L ∘ S1, swapping words of the S2 layer between two ciphertexts
keeps the XOR of the pair before S2, L^-1 keeps it, and S1^-1 keeps which of
its words are zero. So the swap is in S2's words and the pattern is in S1's:
they need not match. Rounds 1-3 of Turing are S (bytes) ∘ MixState ∘ S ∘
ShiftRows ∘ MixColumns ∘ S; ShiftRows commutes with the S-box layer before
it, so the last two S-box layers and MixColumns form super-boxes on columns.
Rounds 2-5 are ShiftRows, then super-boxes, ShiftRows ∘ MixState, super-boxes:
the first ShiftRows makes the words at round 2's S-box input its diagonals.

### Meet-in-the-middle counts

Parameters of a δ-set sequence: the bytes of each S-box layer between the
δ-set and the output byte that are both active and needed (Derbez-Fouque
FSE 2013, Property 5: 4 + 16 + 4 = 24 for AES, 25 with the output value).
After round 2's S-boxes, Turing: 4 (a column), 16 (after MixState),
16 (all of them are needed, because the output byte comes out of
MixState) = 36. Differential enumeration counted as for AES's 10 bytes
(δ-set 1 + S-box outputs before the meeting layer + S-box inputs after it +
output 1): AES 1 + 4 + 4 + 1 = 10; Turing 1 + 4 + 16 + 1 = 22, because
MixState^-1 of a one-byte difference has all 16 bytes active. The pair must
end 16 -> 1 through MixState: 15 bytes forced to zero, 2^-120.
