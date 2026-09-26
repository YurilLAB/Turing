//! Validates the MDS checker against AES and broken matrices, then checks
//! Turing's mixing matrices and that the committed constants are reproducible.

use bombe::gen;
use bombe::gf256::{fast_inv, fast_mul};
use bombe::matrix::{self, check_submatrices, min_branch_at_weight, Matrix, MdsReport};

const AES_MIX: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

fn report(m: &Matrix) -> Option<MdsReport> {
    matrix::invert(m).map(|inv| MdsReport::new(m, &inv))
}

// Published: AES MixColumns is MDS with branch number 5.
#[test]
fn aes_mix_columns_is_mds() {
    let r = report(&matrix::from_array(&AES_MIX)).unwrap();
    assert!(r.passed());
    assert!(r.branch.iter().all(|&(_, b, _, _)| b == 5));
}

// Negative control: one changed entry makes the 2x2 block at rows {0,1},
// columns {2,3} equal [[3,1],[3,1]], which is singular. Both detectors must
// catch it on their own: the submatrix scan and the direct branch measurement.
#[test]
fn broken_aes_matrix_is_caught_twice() {
    let mut m = matrix::from_array(&AES_MIX);
    m[0][2] = 3;
    assert!(matrix::invert(&m).is_some(), "still invertible, so only MDS is broken");
    let sub = check_submatrices(&m, 2, u64::MAX, 1);
    assert!(sub.exhaustive && sub.singular.is_some());
    let (branch, _, exhaustive) = min_branch_at_weight(&m, 2, u64::MAX, 1);
    assert!(exhaustive);
    assert!(branch < 5, "measured branch {branch}");
    assert!(!report(&m).unwrap().passed());
}

// Negative control: the all-ones matrix is not even invertible.
#[test]
fn all_ones_is_rejected() {
    assert!(matrix::invert(&vec![vec![1u8; 4]; 4]).is_none());
}

// Negative control on the 16x16 path: force the 2x2 block at rows {5,6},
// columns {9,12} singular by setting b = a·d/c in [[a, b], [c, d]]. The
// changed entry sits in 225 blocks and the scan reports the first singular
// one, so require a singular block through that entry, not this exact one.
#[test]
fn broken_state_matrix_is_caught() {
    let mut m = matrix::from_array(&turing::linear::MIX_STATE);
    let (a, c, d) = (m[5][9], m[6][9], m[6][12]);
    m[5][12] = fast_mul(fast_mul(a, d), fast_inv(c));
    let planted: Matrix = vec![vec![m[5][9], m[5][12]], vec![m[6][9], m[6][12]]];
    assert!(!matrix::nonsingular(planted));
    let (rows, cols) = check_submatrices(&m, 2, u64::MAX, 1).singular.expect("must be caught");
    assert!(rows.contains(&5) && cols.contains(&12), "found {rows:?} x {cols:?}");
}

#[test]
fn turing_matrices_are_cauchy_on_their_published_points() {
    use turing::linear::*;
    assert!(matrix::is_cauchy(&matrix::from_array(&MIX_COLUMNS), &COLUMNS_X, &COLUMNS_Y));
    assert!(matrix::is_cauchy(&matrix::from_array(&MIX_STATE), &STATE_X, &STATE_Y));
    // A repeated point breaks the construction and must be refused.
    let mut ys = COLUMNS_Y;
    ys[0] = COLUMNS_X[0];
    assert!(!matrix::is_cauchy(&matrix::from_array(&MIX_COLUMNS), &COLUMNS_X, &ys));
}

// Regenerates both matrices (running the full MDS report on each) and
// requires the committed file to match byte for byte.
#[test]
fn committed_linear_constants_are_reproducible() {
    let l = gen::linear();
    assert!(l.columns.report.passed() && l.state.report.passed());
    let committed = include_str!("../../turing/src/linear_constants.rs").replace("\r\n", "\n");
    assert_eq!(gen::render_linear_rust(&l), committed);
}

// The cipher's constant-time multiply agrees with Bombe's table-based one.
#[test]
fn cipher_mixing_agrees_with_reference_arithmetic() {
    let m = matrix::from_array(&turing::linear::MIX_STATE);
    let mut x = [0u8; 16];
    for trial in 0..200u32 {
        for (i, b) in x.iter_mut().enumerate() {
            *b = (trial.wrapping_mul(2654435761) >> (i % 24)) as u8 ^ i as u8;
        }
        assert_eq!(turing::linear::mix_state(&x).to_vec(), matrix::mat_vec(&m, &x));
    }
}

#[test]
fn diffusion_rounds() {
    let aes_round = |p| matrix::mix_columns_pattern(matrix::shift_rows_pattern(p));
    assert_eq!(matrix::rounds_to_full_diffusion(aes_round), 2);
    assert_eq!(matrix::rounds_to_full_diffusion(matrix::mix_state_pattern), 1);
    // Negative control: MixColumns without ShiftRows never leaves its column.
    assert_eq!(matrix::rounds_to_full_diffusion(matrix::mix_columns_pattern), 64);
}
