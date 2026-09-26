//! Bombe: the cryptanalysis workbench for the Turing cipher.
//!
//! Every measurement here is one attack's view of a component. The tools are
//! validated against AES, whose values are published, before they are trusted
//! on anything of ours.

pub mod analysis;
pub mod gen;
pub mod gf256;
pub mod html;
pub mod impossible;
pub mod keyschedule;
pub mod matrix;
pub mod report;
pub mod sbox;
pub mod structure;
pub mod trail;
