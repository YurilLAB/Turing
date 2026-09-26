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
