//! Why Turing keeps its S-box (docs/13). The published way to make an
//! inversion S-box "less algebraic" while staying differentially 4-uniform
//! is to swap two points of the inverse (Li, Wang and Yu, ePrint 2013/731,
//! Theorem 1): F(x) = (pi(x))^-1 with pi = (1 alpha) is 4-uniform exactly
//! when Tr(alpha) = Tr(1/alpha) = 1. Measured here on GF(2^8): it removes
//! only 2 of the 39 quadratic equations, and costs nonlinearity, boomerang
//! uniformity and the provable linear bound.

use bombe::analysis::{boomerang_uniformity, ddt, implicit_equations, lat};
use bombe::sbox::Sbox;
use bombe::{gf256, provable};

fn trace(x: u8) -> u8 {
    let (mut t, mut acc) = (x, x);
    for _ in 1..8 {
        t = gf256::mul(t, t);
        acc ^= t;
    }
    acc
}

fn inverse() -> [u8; 256] {
    std::array::from_fn(|x| gf256::inv(x as u8))
}

/// x -> (pi(x))^-1 with pi = (1 alpha): the inverse with F(1) and F(alpha) swapped.
fn switched(alpha: u8) -> [u8; 256] {
    let mut f = inverse();
    f.swap(1, alpha as usize);
    f
}

#[test]
fn li_wang_yu_theorem_holds_on_gf256() {
    let mut four_uniform = 0;
    for alpha in 2..=255u8 {
        let uniform4 = ddt(&Sbox::new(switched(alpha))).uniformity() == 4;
        assert_eq!(uniform4, trace(alpha) == 1 && trace(gf256::inv(alpha)) == 1, "alpha {alpha:#04x}");
        four_uniform += usize::from(uniform4);
    }
    assert_eq!(four_uniform, 72);
}

#[test]
fn every_good_swap_is_weaker_than_the_inverse() {
    let inv = Sbox::new(inverse());
    let base = implicit_equations(&inv);
    assert_eq!((base.quadratic, base.bi_affine, lat(&inv).nonlinearity()), (39, 23, 112));
    for alpha in (2..=255u8).filter(|&a| trace(a) == 1 && trace(gf256::inv(a)) == 1) {
        let s = Sbox::new(switched(alpha));
        let eq = implicit_equations(&s);
        assert_eq!((eq.quadratic, eq.bi_affine), (37, 21), "only 2 relations removed, alpha {alpha:#04x}");
        assert_eq!(lat(&s).nonlinearity(), 110, "alpha {alpha:#04x}");
    }
}

#[test]
fn the_best_swap_costs_boomerang_and_linear_strength() {
    let s = switched(0x20);
    assert_eq!(boomerang_uniformity(&Sbox::new(inverse())), Some(6));
    assert_eq!(boomerang_uniformity(&Sbox::new(s)), Some(10));
    assert!(provable::lp_bound(&s, 17).log2 > provable::lp_bound(&inverse(), 17).log2 + 5.0, "the MixState window loses over 2^5");
}
