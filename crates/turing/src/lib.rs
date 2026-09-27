//! Turing: an experimental 128-bit block cipher with a 256-bit key, and
//! Turing-256, the same design on a 256-bit block (docs/15).
//!
//! EXPERIMENTAL. A new cipher is only trusted after years of public
//! cryptanalysis. Do not use this to protect real data.

pub mod cipher;
pub mod gf;
pub mod keyschedule;
pub mod keyschedule256;
pub mod linear;
pub mod linear256;
pub mod masked;
pub mod memory;
pub mod random;
pub mod sbox;
pub mod selftest;
pub mod shield;
pub mod structure;
pub mod turing256;
pub mod xof;

pub use cipher::{Block, FaultDetected, Turing};
pub use masked::MaskedTuring;
pub use random::RandomnessError;
pub use shield::ShieldedKey;
pub use turing256::{Block256, Turing256};
pub use selftest::{self_test, SelfTestError};

// Every type that holds a key can move to another thread and be shared:
// the ones used through `&self` are safe to call concurrently, and
// MaskedTuring needs `&mut` for every call (docs/13).
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Turing>();
    send_sync::<Turing256>();
    send_sync::<MaskedTuring>();
    send_sync::<ShieldedKey>();
};
