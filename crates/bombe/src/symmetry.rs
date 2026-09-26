//! Symmetries an attacker who knows every constant would look for.
//!
//! A symmetry is a map phi with Round(phi(x)) = phi'(Round(x)) for the
//! keyless round. With round keys it becomes a related-key or equivalent-key
//! property; with a key schedule that repeats itself, a weak-key class or a
//! slide. Two families cover the maps that can pass an S-box layer: byte
//! permutations (one S-box is used everywhere, so the S-box layer commutes
//! with every permutation) and bytewise affine maps built from the S-box's
//! own self-equivalences S(A x) = B S(x).
//!
//! 1. Permutations: pi with L[pi(i)][pi(j)] = L[i][j]. AES's
//!    ShiftRows+MixColumns commutes with rotating the columns (the control);
//!    MixState commutes with no permutation but the identity.
//!
//! 2. Bytewise maps: if L carries B (on every byte) to A' (on every byte),
//!    each non-zero block m_ij of L gives m_ij B_j = A'_i m_ij. Two rows and
//!    two columns then give B_j commuting with the cross-ratio
//!    (m_ij m_i'k) / (m_ik m_i'j); when that is outside GF(16) it generates
//!    GF(2^8), whose centraliser among 8x8 bit matrices is GF(2^8) itself, so
//!    B_j is a field multiplication: B_j = beta. A symmetry therefore needs
//!    x -> S^-1(beta S(x) ^ b) to be affine for some (beta, b) other than
//!    (1, 0). The bare inverse function passes for every beta (the control:
//!    x^-1 has the scaling symmetry that the affine layers exist to break).
//!
//! 3. Reflection: an S-box A_out(A_in(x)^-1) satisfies S^-1 = T S T with
//!    T = A_in^-1 A_out^-1. Decryption is then an SPN with the same S-box and
//!    linear layers T L^-1 T. If those equal the encryption layers,
//!    decryption is encryption under other keys (how the involutional
//!    ciphers Khazad and Anubis are built, and what reflection attacks use).

use crate::gf256;
use crate::invariant::{self, LinearMap};

pub type ByteMatrix = [[u8; 16]; 16];

/// The matrix of a GF(2^8)-linear map on the 16-byte state: L[i][j] is
/// output byte i for the input with byte j equal to 1.
pub fn byte_matrix(f: impl Fn(&[u8; 16]) -> [u8; 16]) -> ByteMatrix {
    let mut m = [[0u8; 16]; 16];
    for j in 0..16 {
        let mut e = [0u8; 16];
        e[j] = 1;
        let column = f(&e);
        for (i, row) in m.iter_mut().enumerate() {
            row[j] = column[i];
        }
    }
    m
}

/// Every byte permutation pi with L[pi(i)][pi(j)] = L[i][j].
pub fn permutation_symmetries(m: &ByteMatrix) -> Vec<[usize; 16]> {
    fn extend(m: &ByteMatrix, depth: usize, perm: &mut [usize; 16], used: &mut [bool; 16], found: &mut Vec<[usize; 16]>) {
        if depth == 16 {
            found.push(*perm);
            return;
        }
        for c in 0..16 {
            if used[c] || m[c][c] != m[depth][depth] {
                continue;
            }
            if (0..depth).all(|i| m[perm[i]][c] == m[i][depth] && m[c][perm[i]] == m[depth][i]) {
                perm[depth] = c;
                used[c] = true;
                extend(m, depth + 1, perm, used, found);
                used[c] = false;
            }
        }
    }
    let mut found = Vec::new();
    extend(m, 0, &mut [0; 16], &mut [false; 16], &mut found);
    found
}

/// Every pair of byte permutations with L[pi_out(i)][pi_in(j)] = L[i][j]:
/// shuffling the input by pi_in shuffles the output by pi_out. A symmetry
/// that changes from round to round needs such pairs to chain through every
/// layer, so a layer that admits only (identity, identity) stops them all.
/// Needs distinct entries within each row and each column (true for
/// MixState, whose entries are 1 / (x_i + y_j) with distinct x's and y's):
/// then pi_out(0) fixes pi_in through row 0 and pi_in(0) fixes pi_out.
pub fn permutation_pairs(m: &ByteMatrix) -> Vec<([usize; 16], [usize; 16])> {
    let distinct = |v: [u8; 16]| (0..16).all(|a| (a + 1..16).all(|b| v[a] != v[b]));
    assert!((0..16).all(|i| distinct(m[i]) && distinct(std::array::from_fn(|r| m[r][i]))), "rows and columns need distinct entries");
    let mut found = Vec::new();
    for b in 0..16 {
        let pi_in: Option<Vec<usize>> = (0..16).map(|j| (0..16).find(|&c| m[b][c] == m[0][j])).collect();
        let Some(pi_in) = pi_in else { continue };
        let pi_out: Option<Vec<usize>> = (0..16).map(|i| (0..16).find(|&r| m[r][pi_in[0]] == m[i][0])).collect();
        let Some(pi_out) = pi_out else { continue };
        let permutation = |p: &[usize]| (0..16).all(|x| p.contains(&x));
        if permutation(&pi_in) && permutation(&pi_out) && (0..16).all(|i| (0..16).all(|j| m[pi_out[i]][pi_in[j]] == m[i][j])) {
            found.push((std::array::from_fn(|i| pi_out[i]), std::array::from_fn(|j| pi_in[j])));
        }
    }
    found
}

/// A Cauchy matrix on structured points, the control for `permutation_pairs`:
/// x runs over GF(16) and y over the coset 2 + GF(16), listed in the order
/// j -> 7j + 3 mod 16 so rows and columns are numbered differently (not by a
/// reversal: for a sorted subgroup that is itself a shift). Adding any c in GF(16) to
/// both permutes rows and columns and leaves 1 / (x + y) unchanged.
pub fn structured_cauchy() -> ByteMatrix {
    let gf16: Vec<u8> = (0..=255u8).filter(|&x| in_gf16(x)).collect();
    assert_eq!(gf16.len(), 16);
    std::array::from_fn(|i| std::array::from_fn(|j| gf256::inv(gf16[i] ^ gf16[(7 * j + 3) % 16] ^ 2)))
}

pub fn is_symmetry(m: &ByteMatrix, perm: &[usize; 16]) -> bool {
    (0..16).all(|i| (0..16).all(|j| m[perm[i]][perm[j]] == m[i][j]))
}

fn pow(x: u8, e: u32) -> u8 {
    (0..e).fold(1, |acc, _| gf256::fast_mul(acc, x))
}

fn in_gf16(x: u8) -> bool {
    pow(x, 16) == x
}

/// For every column j, some cross-ratio (m_ij m_i'k) / (m_ik m_i'j) over
/// non-zero entries lies outside GF(16): the condition that forces every
/// bytewise symmetry to be a field multiplication.
pub fn cross_ratios_generate(m: &ByteMatrix) -> bool {
    (0..16).all(|j| {
        (0..16).any(|k| {
            k != j
                && (0..16).any(|i| {
                    (0..16).any(|i2| {
                        let (a, b, c, d) = (m[i][j], m[i2][k], m[i][k], m[i2][j]);
                        i2 != i && a != 0 && b != 0 && c != 0 && d != 0 && {
                            let ratio = gf256::fast_mul(gf256::fast_mul(a, b), gf256::inv(gf256::fast_mul(c, d)));
                            !in_gf16(ratio)
                        }
                    })
                })
        })
    })
}

fn inverse_table(t: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (x, &y) in t.iter().enumerate() {
        inv[y as usize] = x as u8;
    }
    inv
}

/// Every (beta, b) for which x -> S^-1(beta S(x) ^ b) is affine.
pub fn scalar_symmetries(table: &[u8; 256]) -> Vec<(u8, u8)> {
    let inv = inverse_table(table);
    let mut out = Vec::new();
    for beta in 1..=255u8 {
        for b in 0..=255u8 {
            let g = |x: u8| inv[(gf256::fast_mul(beta, table[x as usize]) ^ b) as usize];
            let g0 = g(0);
            let basis: [u8; 8] = std::array::from_fn(|i| g(1 << i) ^ g0);
            let affine = (0..=255u8).all(|x| (0..8).filter(|&i| x >> i & 1 == 1).fold(0u8, |acc, i| acc ^ basis[i]) == g(x) ^ g0);
            if affine {
                out.push((beta, b));
            }
        }
    }
    out
}

/// T = A_in^-1 A_out^-1 for Turing's S-box, as a table.
pub fn turing_reflection_map() -> [u8; 256] {
    let a_in: [u8; 256] = std::array::from_fn(|x| turing::sbox::A_IN.apply(x as u8));
    let a_out: [u8; 256] = std::array::from_fn(|x| turing::sbox::A_OUT.apply(x as u8));
    let (a_in_inv, a_out_inv) = (inverse_table(&a_in), inverse_table(&a_out));
    std::array::from_fn(|x| a_in_inv[a_out_inv[x] as usize])
}

/// Rank over GF(2) of (T L^-1 T) + L', with the linear part of `t` applied to
/// every byte: 0 means decryption through this layer is encryption through
/// L' (a reflection); 128 means nothing in common.
pub fn reflection_distance(t: &[u8; 256], l_inv: &LinearMap, target: &LinearMap) -> usize {
    let t0 = t[0];
    let bytewise = |v: u128| u128::from_le_bytes(v.to_le_bytes().map(|b| t[b as usize] ^ t0));
    let diff: Vec<u128> = (0..128).map(|i| bytewise(l_inv.apply(bytewise(1u128 << i))) ^ target.columns()[i]).collect();
    invariant::rank(&diff)
}

/// The Hadamard matrix with first row (1, 2, 4, 6) on every column: an
/// involution (1 ^ 2 ^ 4 ^ 6 = 1), as in Anubis. The reflection control.
pub fn hadamard_columns(s: &[u8; 16]) -> [u8; 16] {
    const H: [[u8; 4]; 4] = [[1, 2, 4, 6], [2, 1, 6, 4], [4, 6, 1, 2], [6, 4, 2, 1]];
    std::array::from_fn(|k| {
        let (c, r) = (k / 4, k % 4);
        (0..4).fold(0, |acc, j| acc ^ gf256::fast_mul(H[r][j], s[4 * c + j]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use turing::linear;
    use turing::structure::Layer;

    fn aes_round() -> ByteMatrix {
        const MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        byte_matrix(|s| linear::mix_columns_with(&MIX, &linear::shift_rows(s)))
    }

    #[test]
    fn aes_round_commutes_with_column_rotation() {
        let rotate: [usize; 16] = std::array::from_fn(|k| (k + 4) % 16);
        let found = permutation_symmetries(&aes_round());
        assert!(found.contains(&rotate), "the known AES symmetry");
        assert!(found.iter().all(|p| is_symmetry(&aes_round(), p)));
    }

    #[test]
    fn inverse_function_has_every_scaling_symmetry() {
        let inv: [u8; 256] = std::array::from_fn(|x| gf256::inv(x as u8));
        let found = scalar_symmetries(&inv);
        assert_eq!(found.len(), 255);
        assert!(found.iter().all(|&(_, b)| b == 0));
    }

    #[test]
    fn affine_layers_remove_the_scaling_symmetries() {
        assert_eq!(scalar_symmetries(&gf256::aes_sbox()), [(1, 0)]);
        assert_eq!(scalar_symmetries(&turing::sbox::TABLE), [(1, 0)]);
    }

    #[test]
    fn reflection_map_inverts_the_sbox() {
        let t = turing_reflection_map();
        let s = turing::sbox::TABLE;
        let s_inv = inverse_table(&s);
        for x in 0..256 {
            assert_eq!(s_inv[x], t[s[t[x] as usize] as usize], "S^-1 = T S T at {x}");
        }
    }

    #[test]
    fn involutional_control_is_a_reflection() {
        let identity: [u8; 256] = std::array::from_fn(|x| x as u8);
        let h = LinearMap::from_fn(128, |v| u128::from_le_bytes(hadamard_columns(&v.to_le_bytes())));
        assert_eq!(reflection_distance(&identity, &h, &h), 0, "H is its own inverse");
        let mix = LinearMap::turing(Layer::MixState);
        assert!(reflection_distance(&identity, &h, &mix) > 0);
    }

    #[test]
    fn structured_points_give_permutation_pairs() {
        let pairs = permutation_pairs(&structured_cauchy());
        assert_eq!(pairs.len(), 16, "one pair per shift c in GF(16)");
        assert!(pairs.iter().any(|(out, inp)| out != inp), "the two sides are shuffled differently");
    }

    #[test]
    fn byte_matrix_matches_the_layer() {
        let m = byte_matrix(|s| linear::apply_layer(Layer::MixState, s));
        assert_eq!(m, linear::MIX_STATE);
    }
}
