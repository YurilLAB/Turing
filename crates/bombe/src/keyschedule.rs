//! Related-key analysis of the Turing key schedule.
//!
//! The schedule's core is a Feistel network on two 16-byte halves:
//!     (L, R) -> (R XOR F(L), L),   F(x) = MixState(S(x XOR C_j)).
//! A related-key attack needs a key difference to reach the round keys in a
//! controlled way. Every byte difference entering F crosses one S-box, and
//! each active S-box passes a chosen difference with probability at most
//! 4/256 = 2^-6. So a lower bound on active S-boxes is an upper bound on the
//! probability of any key-schedule trail.
//!
//! Because MixState is a 16x16 MDS matrix, only the *number* of active bytes
//! in each half matters, not their positions:
//! - F with a active input bytes (a > 0) outputs b active bytes, a + b >= 17.
//! - XOR of halves with b and r active bytes has between |b - r| and
//!   min(16, b + r) active bytes (bytes can cancel only where both are active).
//!
//! These rules allow every real transition (and possibly some impossible
//! ones), so the minimum they give is a valid lower bound.

/// For r = 1..=rounds, the minimum number of active S-boxes over r rounds of
/// a Feistel network with n-byte halves whose round function's linear layer
/// has byte branch number `branch`, over every non-zero input difference.
pub fn feistel_min_active_general(n: usize, branch: usize, rounds: usize) -> Vec<u32> {
    const INF: u32 = u32::MAX;
    // cost[wl][wr]: cheapest way to be in a state with these half weights.
    let mut cost = vec![vec![INF; n + 1]; n + 1];
    for (wl, row) in cost.iter_mut().enumerate() {
        for (wr, c) in row.iter_mut().enumerate() {
            if (wl, wr) != (0, 0) {
                *c = 0;
            }
        }
    }
    let mut bounds = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut next = vec![vec![INF; n + 1]; n + 1];
        for wl in 0..=n {
            for wr in 0..=n {
                let c = cost[wl][wr];
                if c == INF {
                    continue;
                }
                let paid = c + wl as u32;
                if wl == 0 {
                    // F sees no difference: new L = R, new R = 0.
                    next[wr][0] = next[wr][0].min(paid);
                    continue;
                }
                for b in branch.saturating_sub(wl).max(1)..=n {
                    for row in &mut next[b.abs_diff(wr)..=(b + wr).min(n)] {
                        row[wl] = row[wl].min(paid);
                    }
                }
            }
        }
        cost = next;
        // The bound counts S-boxes already crossed; states still carrying a
        // difference may cost more later, so the minimum over all is correct.
        bounds.push(cost.iter().flatten().copied().min().unwrap());
    }
    bounds
}

/// The Turing key schedule's Feistel: 16-byte halves, MixState (branch 17).
pub fn feistel_min_active(rounds: usize) -> Vec<u32> {
    feistel_min_active_general(16, 17, rounds)
}

/// Security target. Each active S-box passes a chosen difference with
/// probability at most 2^-6. Every single round key must sit behind at least
/// 43 active S-boxes, so predicting the difference of even one round key
/// from a key difference has probability <= 2^-258, below 2^-256 (the key
/// size).
pub const ROUND_KEY_TARGET: u32 = 43;

/// Smallest number of Feistel rounds whose bound reaches `target`.
pub fn rounds_for(target: u32, max_rounds: usize) -> Option<usize> {
    feistel_min_active(max_rounds).iter().position(|&b| b >= target).map(|i| i + 1)
}

/// The bound protecting round key `index`: the minimum active S-boxes over
/// the Feistel rounds that determine it (`turing::keyschedule::round_key_depth`).
pub fn round_key_bound(index: usize) -> u32 {
    let depth = turing::keyschedule::round_key_depth(index);
    feistel_min_active(depth)[depth - 1]
}
