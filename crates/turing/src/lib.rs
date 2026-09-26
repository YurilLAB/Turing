//! Turing: an experimental 128-bit block cipher with a 256-bit key.
//!
//! EXPERIMENTAL. A new cipher is only trusted after years of public
//! cryptanalysis. Do not use this to protect real data.

pub mod cipher;
pub mod gf;
pub mod keyschedule;
pub mod linear;
pub mod sbox;
pub mod selftest;
pub mod structure;
pub mod xof;

pub use cipher::{Block, FaultDetected, Turing};
pub use selftest::{self_test, SelfTestError};
