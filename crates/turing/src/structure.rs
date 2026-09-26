//! Round structure: how many rounds Turing has and which mixing layer each
//! round uses (docs/09-round-structure.md).
//!
//! Encryption: add round key 0, then for each round r = 1..=ROUNDS apply the
//! S-box layer, the linear layer `layer(r)` (none in the last round), and
//! round key r.
//!
//! The layers alternate, MixState in odd rounds (1, 3, ..., 23) and
//! ShiftRows + MixColumns in even rounds. Among the mixes Bombe compared
//! (`bombe rounds`), strict alternation gives the best trail bounds for its
//! cost: any 3 rounds have at least 18 active S-boxes, any 7 at least 52.
//! Starting and ending on MixState means an attack extended by a round at
//! either end must guess a whole 16-byte round key, not one 4-byte column.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Layer {
    /// ShiftRows, then the 4x4 MixColumns on every column (branch 5).
    ShiftMixColumns,
    /// The 16x16 MixState over the whole state (branch 17).
    MixState,
}

/// Version 2: 24 rounds (version 1 had 16). The best attack found reaches 4
/// (docs/11), and the round-count rule of docs/09 allows 8; 24 is the ceiling
/// chosen for Turing, so more rounds are never added.
pub const ROUNDS: usize = 24;
pub const MAX_ROUNDS: usize = 24;
pub const ROUND_KEYS: usize = ROUNDS + 1;
const _: () = assert!(ROUNDS <= MAX_ROUNDS, "24 rounds is Turing's ceiling");
// An odd number of layered rounds keeps MixState at both ends (docs/09).
const _: () = assert!(ROUNDS.is_multiple_of(2), "rounds 1 and ROUNDS - 1 must both use MixState");

/// The linear layer after the S-box layer of `round` (1-based), or `None`
/// for the last round.
pub const fn layer(round: usize) -> Option<Layer> {
    if round == 0 || round >= ROUNDS {
        None
    } else if round % 2 == 1 {
        Some(Layer::MixState)
    } else {
        Some(Layer::ShiftMixColumns)
    }
}

/// The linear layers of rounds 1..ROUNDS-1 in order.
pub const fn schedule() -> [Layer; ROUNDS - 1] {
    let mut out = [Layer::ShiftMixColumns; ROUNDS - 1];
    let mut r = 1;
    while r < ROUNDS {
        out[r - 1] = match layer(r) {
            Some(l) => l,
            None => Layer::ShiftMixColumns,
        };
        r += 1;
    }
    out
}
