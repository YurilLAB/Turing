//! Bombe: the cryptanalysis workbench for the Turing cipher.
//!
//! Every measurement here is one attack's view of a component. The tools are
//! validated against AES, whose values are published, before they are trusted
//! on anything of ours.

pub mod analysis;
pub mod avalanche;
pub mod battery;
pub mod campaign;
pub mod differential;
pub mod gen;
pub mod gf256;
pub mod html;
pub mod impossible;
pub mod integral;
pub mod keycheck;
pub mod keyschedule;
pub mod matrix;
pub mod nist;
pub mod refcipher;
pub mod report;
pub mod rng;
pub mod sbox;
pub mod structure;
pub mod timing;
pub mod trace;
pub mod trail;
