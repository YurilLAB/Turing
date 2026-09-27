//! A fault map of Turing-1026 decapsulation (docs/16): every transient fault
//! the model lists, injected into the real decapsulation code through the
//! hooks `turing::turing1026` leaves inert in production, classified by what
//! it does to a chosen ciphertext.
//!
//! The dangerous outcome is a *bypass*: an invalid ciphertext decapsulating
//! to the key it would give if the re-encryption check had accepted it. That
//! turns the KEM back into the bare lattice decryption oracle the transform
//! removes, and the key-mismatch attack (see `tests/turing1026_adversarial`)
//! then recovers the secret. A *validity oracle* is nearly as bad: the
//! returned key becomes computable by the attacker (the rejection key without
//! the secret z), so accept and reject are distinguishable. Everything else
//! is denial of service (a wrong key, or a rejection), which costs the honest
//! party a session but leaks nothing.
//!
//! With the single-comparison design decapsulation once used, forcing the one
//! accept mask was a single-fault bypass. Decapsulation now computes the
//! re-encryption twice and compares it three ways (the first run as packed
//! bytes, the second as coefficients and as packed bytes); two chained
//! selections install the accepted key only if the first two verdicts
//! accept, and the third verdict binds the accepted key itself to the
//! comparison (cSHAKE256(c || k' xor K-bar) unless it accepts). No single
//! fault on the check bypasses it, and forcing both selection verdicts no
//! longer does either: the map finds a bypass only from both runs' data
//! (two correlated faults) or all three verdicts (three).
//!
//! Two single faults used to leak without any bypass, and are closed now:
//! - skipping the secret z in the rejection hash (an XOF-state fault) made
//!   the returned key computable, a validity oracle. The rejection key is now
//!   computed twice and a disagreement infected with a fresh random value, so
//!   it takes two faults (z skipped in both computations, or one skip and the
//!   infection suppressed);
//! - skipping the rounding (`+ q/4`) of one coefficient in the decoder made a
//!   valid ciphertext's decapsulation succeed exactly when that coefficient's
//!   noise was non-negative (Pessl and Prokop, TCHES 2021(2)): a key-dependent
//!   effective/ineffective oracle. Decryption now runs three times, each pass
//!   computing C - B'S afresh and decoding it in its own random order, and
//!   every bit is voted, so one skipped rounding, or one fault in a pass's
//!   arithmetic, changes nothing (`decoder_sweep` tries every step and every
//!   coefficient of every pass).
//!
//! Both have negative controls here, the decapsulation as it was (one pass
//! in order; one rejection hash), so the map shows each hole was real and is
//! closed. The decoder's layers are also shown one at a time: with the vote
//! skipped (a fault), the random order alone still hides which coefficient a
//! skipped rounding hit. Its boundary is measured, not assumed: the
//! arithmetic runs in a fixed order, so two faults aimed at one coefficient
//! in two passes do outvote the third and leak its noise sign, the decoder's
//! cheapest attack, as the check's cheapest bypass also takes two faults.
//!
//! This map runs the `Faults` compilation of decapsulation. The production
//! one (`NoFault`) is compiled separately, and its release build once fused
//! the two selection verdicts into one mask, a single-fault bypass this map
//! could not see (research/reviews/2026-09-28 R2): `tools/ct_check.py` checks
//! the production machine code for that.
//!
//! The two comparisons read two *independent* re-encryptions, not one shared
//! intermediate: an earlier version packed one re-encryption and compared it
//! both ways, so a single fault on its coefficients (before packing) fooled
//! both checks -- a hole this map now injects (`Intermediate1`/`2`) and the
//! two-re-encryption design closes.

use turing::lwe;
use turing::turing1026::{DecapsulationKey, Fault, FaultPoint, Matrix, PARAMS};

use crate::refkem1026::ReferenceKem;

const BP_BYTES: usize = 15_390;
const PKE_BYTES: usize = 15_870;
const Q_MASK: u16 = (1 << 15) - 1;

/// What a fault does to one ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The result is unchanged (a valid ciphertext still gives its key, an
    /// invalid one still the rejection key).
    NoEffect,
    /// An invalid ciphertext gives the key it would have if accepted: the
    /// check is defeated and the bare decryption exposed.
    Bypass,
    /// The returned key is the rejection key without z, computable by the
    /// attacker: accept and reject become distinguishable.
    ValidityOracle,
    /// Some other change (a rejection of a valid ciphertext, or a corrupted
    /// key): the session is lost but nothing leaks.
    DenialOfService,
}

/// The reference values a fault outcome is judged against, all computed by
/// the independent reference so the verdict does not trust the code under
/// test.
struct Oracle {
    accepted: [u8; 32],
    rejection_without_z: [u8; 32],
}

impl Oracle {
    fn new(reference: &ReferenceKem, ct: &[u8]) -> Oracle {
        Oracle {
            accepted: reference.accepted_key(ct),
            rejection_without_z: reference.rejection_key_without_z(ct),
        }
    }

    fn classify(&self, honest: &[u8; 32], got: &[u8; 32]) -> Outcome {
        if got == honest {
            Outcome::NoEffect
        } else if got == &self.accepted {
            Outcome::Bypass
        } else if got == &self.rejection_without_z {
            Outcome::ValidityOracle
        } else {
            Outcome::DenialOfService
        }
    }
}

/// The worst outcome over a set of injected faults, on a valid and on an
/// invalid ciphertext.
#[derive(Clone, Debug)]
pub struct MapEntry {
    pub name: String,
    /// The fault or faults injected.
    pub faults: Vec<Fault>,
    /// On a valid ciphertext (baseline: its real shared key).
    pub on_valid: Outcome,
    /// On an invalid ciphertext (baseline: the rejection key).
    pub on_invalid: Outcome,
}

impl MapEntry {
    /// The security-relevant verdict: a bypass or validity oracle on the
    /// invalid ciphertext is a break; anything else is at worst DoS.
    pub fn breaks(&self) -> bool {
        matches!(self.on_invalid, Outcome::Bypass | Outcome::ValidityOracle)
    }
}

/// A key, a valid ciphertext and an invalid one, with the reference oracle
/// for each.
struct Setup {
    dk: DecapsulationKey,
    valid: Vec<u8>,
    invalid: Vec<u8>,
    valid_key: [u8; 32],
    invalid_oracle: Oracle,
    valid_oracle: Oracle,
    reject_invalid: [u8; 32],
    /// The coefficient of C the invalid ciphertext raised by `fault_delta`,
    /// so an intermediate fault that adds the same delta forces a match.
    fault_index: usize,
    fault_delta: u16,
}

/// Whether two ciphertexts decrypt to the same message under `s`.
fn decodes_same(s: &[u16], a: &[u8], b: &[u8]) -> bool {
    let decode = |ct: &[u8]| {
        let (mut bp, mut c) = (vec![0u16; PARAMS.mbar * PARAMS.n], vec![0u16; PARAMS.mbar * PARAMS.nbar]);
        lwe::unpack(15, &ct[..BP_BYTES], &mut bp);
        lwe::unpack(15, &ct[BP_BYTES..PKE_BYTES], &mut c);
        let mut msg = vec![0u8; PARAMS.message_bytes()];
        lwe::decrypt(&PARAMS, s, &bp, &c, &mut msg);
        msg
    };
    decode(a) == decode(b)
}

fn setup(seed: u8) -> Setup {
    let dk = DecapsulationKey::from_seed(&[seed; 32]).expect("consistent");
    let reference = ReferenceKem::from_seed(&[seed; 32]);
    let (valid, key) = dk.encapsulation_key().encapsulate_with(&[0x5c; 32], &[0x3a; 64]);
    let valid_key: [u8; 32] = key[..].try_into().expect("32");
    // An invalid ciphertext the attacker knows the decryption of: a valid one
    // with coefficient 0 of C raised by 1. That is far inside the q/4 decoding
    // window, so the decoded message is unchanged and the honest re-encryption
    // recreates the original coefficient -- the ciphertext is rejected. The
    // small, known delta is what an intermediate fault adds back to force a
    // re-encryption to match (the user-found single-fault bypass).
    let (fault_index, fault_delta) = (0usize, 1u16);
    let mut c = vec![0u16; PARAMS.mbar * PARAMS.nbar];
    lwe::unpack(15, &valid[BP_BYTES..PKE_BYTES], &mut c);
    c[fault_index] = c[fault_index].wrapping_add(fault_delta) & Q_MASK;
    let mut invalid = valid.clone();
    lwe::pack(15, &c, &mut invalid[BP_BYTES..PKE_BYTES]);
    // The modification must preserve the decoded message, or the honest
    // re-encryption would change and the intermediate fault would not
    // reproduce the received coefficient.
    assert!(decodes_same(dk.secret_matrix(), &valid, &invalid), "the invalid ciphertext must decode to the same message");
    Setup {
        valid_oracle: Oracle::new(&reference, &valid),
        invalid_oracle: Oracle::new(&reference, &invalid),
        reject_invalid: reference.rejection_key(&invalid),
        valid_key,
        valid,
        invalid,
        dk,
        fault_index,
        fault_delta,
    }
}

impl Setup {
    /// Inject `faults` and classify the outcome on each ciphertext. The
    /// baselines (honest results) are the real shared key for the valid
    /// ciphertext and the rejection key for the invalid one; the reference
    /// supplies both, so the classification never trusts the faulted code.
    fn run(&self, name: &str, faults: Vec<Fault>) -> MapEntry {
        let v = self.dk.decapsulate_with_faults(&self.valid, &faults).expect("length");
        let i = self.dk.decapsulate_with_faults(&self.invalid, &faults).expect("length");
        let v: [u8; 32] = v[..].try_into().expect("32");
        let i: [u8; 32] = i[..].try_into().expect("32");
        MapEntry {
            name: name.to_string(),
            faults,
            on_valid: self.valid_oracle.classify(&self.valid_key, &v),
            on_invalid: self.invalid_oracle.classify(&self.reject_invalid, &i),
        }
    }
}

/// Byte-buffer fault points and a representative byte to hit in each.
const FLIP_POINTS: [(FaultPoint, &str, usize); 5] = [
    (FaultPoint::Message, "decoded message mu'", 0),
    (FaultPoint::Coins, "coins (rho' || k')", 0),
    (FaultPoint::Reencryption, "packed re-encryption", 0),
    (FaultPoint::RejectionKey, "rejection key K-bar", 0),
    (FaultPoint::AcceptedKey, "accepted key K'", 0),
];

/// The full single-fault map, plus the correlated pair that does bypass.
pub fn map(seed: u8) -> Vec<MapEntry> {
    let s = setup(seed);
    let mut out = Vec::new();
    // Bit flips at each byte-buffer point (every bit of the chosen byte).
    for (point, name, byte) in FLIP_POINTS {
        // The worst outcome over the eight single-bit flips of the byte.
        let mut entry: Option<MapEntry> = None;
        for bit in 0..8 {
            let e = s.run(&format!("flip a bit of the {name}"), vec![Fault::FlipBit(point, byte, bit)]);
            entry = Some(match entry {
                None => e,
                Some(prev) if severity(&e) > severity(&prev) => e,
                Some(prev) => prev,
            });
        }
        out.push(entry.expect("eight bits"));
    }
    // Forcing each verdict to accept (the accept-mask fault).
    out.push(s.run("force the packed-byte verdict to accept", vec![Fault::Verdict(FaultPoint::AcceptBytes, 0xff)]));
    out.push(s.run("force the coefficient verdict to accept", vec![Fault::Verdict(FaultPoint::AcceptCoeffs, 0xff)]));
    out.push(s.run("force the binding verdict to accept", vec![Fault::Verdict(FaultPoint::AcceptBinding, 0xff)]));
    // Faulting one re-encryption's coefficients to match the received one (the
    // user-found bypass of the shared-intermediate design): each is caught by
    // the other, independent re-encryption.
    let force1 = Fault::AddCoeff(FaultPoint::Intermediate1, Matrix::C, s.fault_index, s.fault_delta);
    let force2 = Fault::AddCoeff(FaultPoint::Intermediate2, Matrix::C, s.fault_index, s.fault_delta);
    out.push(s.run("force the first re-encryption to match (coefficients)", vec![force1]));
    out.push(s.run("force the second re-encryption to match (coefficients)", vec![force2]));
    // Skipping the secret z in either rejection hash (an XOF-state fault):
    // the two computations disagree and the key is infected (no oracle).
    out.push(s.run("skip absorbing z into the rejection key", vec![Fault::Skip(FaultPoint::RejectionZ)]));
    out.push(s.run("skip absorbing z into the second rejection key", vec![Fault::Skip(FaultPoint::RejectionZ2)]));
    out.push(s.run("force the rejection keys' agreement verdict", vec![Fault::Verdict(FaultPoint::Infection, 0xff)]));
    // Skipping the final selection (pqm4's skipped copy).
    out.push(s.run("skip the final masked selection", vec![Fault::Skip(FaultPoint::Selection)]));
    // Both selection verdicts forced: the accepted key is still bound to the
    // comparison, so what comes out needs z to compute (no bypass).
    out.push(s.run(
        "force BOTH selection verdicts to accept (two faults)",
        vec![Fault::Verdict(FaultPoint::AcceptBytes, 0xff), Fault::Verdict(FaultPoint::AcceptCoeffs, 0xff)],
    ));
    // Data and verdict mixed. The third verdict reads the second run, packed:
    // forcing the first run and the coefficient verdict still leaves it
    // rejecting (no bypass); forcing the second run fools both verdicts that
    // read it, so the byte verdict is the one fault left to force (bypass).
    out.push(s.run(
        "force the first re-encryption AND the coefficient verdict (two faults)",
        vec![force1, Fault::Verdict(FaultPoint::AcceptCoeffs, 0xff)],
    ));
    out.push(s.run(
        "force the second re-encryption AND the byte verdict (two correlated faults)",
        vec![force2, Fault::Verdict(FaultPoint::AcceptBytes, 0xff)],
    ));
    // The rejection key's cheapest oracle: two faults.
    out.push(s.run(
        "skip z in BOTH rejection keys (two faults)",
        vec![Fault::Skip(FaultPoint::RejectionZ), Fault::Skip(FaultPoint::RejectionZ2)],
    ));
    out.push(s.run(
        "skip z AND force the agreement verdict (two faults)",
        vec![Fault::Skip(FaultPoint::RejectionZ), Fault::Verdict(FaultPoint::Infection, 0xff)],
    ));
    // Negative control: one rejection hash, as before, and z skipped in it.
    out.push(s.run(
        "control: one rejection hash, z skipped (as before the fix)",
        vec![Fault::SingleRejectionHash, Fault::Skip(FaultPoint::RejectionZ)],
    ));
    // The cheapest bypasses: both re-encryptions' data (two correlated
    // faults), or all three verdicts (three).
    out.push(s.run("force BOTH re-encryptions to match (two correlated faults)", vec![force1, force2]));
    out.push(s.run(
        "force ALL THREE verdicts to accept (three faults)",
        vec![
            Fault::Verdict(FaultPoint::AcceptBytes, 0xff),
            Fault::Verdict(FaultPoint::AcceptCoeffs, 0xff),
            Fault::Verdict(FaultPoint::AcceptBinding, 0xff),
        ],
    ));
    out
}

/// `bombe fault-map`: the table, and whether no single fault bypasses the
/// re-encryption check.
pub fn report(seed: u8) -> (String, bool) {
    use std::fmt::Write;
    let mut out = String::new();
    let name = |o: Outcome| match o {
        Outcome::NoEffect => "no effect",
        Outcome::Bypass => "BYPASS",
        Outcome::ValidityOracle => "validity oracle",
        Outcome::DenialOfService => "denial of service",
    };
    let _ = writeln!(out, "Turing-1026 decapsulation fault map (docs/16): every fault of the model, on a");
    let _ = writeln!(out, "valid and an invalid ciphertext. BYPASS or validity oracle on the invalid one is a");
    let _ = writeln!(out, "break; the rest cost only a session.\n");
    let _ = writeln!(out, "  {:<48} {:<18} on invalid ct", "fault", "on valid ct");
    let m = map(seed);
    for e in &m {
        let _ = writeln!(out, "  {:<48} {:<18} {}", e.name, name(e.on_valid), name(e.on_invalid));
    }
    let s = single_fault_summary(seed);
    let _ = writeln!(
        out,
        "\n{} single faults bypass the check; {} give a validity oracle. Forcing both selection verdicts {};\nthe cheapest bypass takes {} faults (both re-encryptions' data), forcing verdicts alone {}; the\ncheapest validity oracle takes {} faults (z skipped in both rejection hashes).",
        s.bypasses,
        s.validity_oracles,
        if s.verdict_pair_bypasses { "BYPASSES" } else { "does not bypass (the key is bound to the comparison)" },
        s.cheapest_bypass,
        if s.all_verdicts_bypass { "three" } else { "more than three" },
        s.cheapest_validity_oracle
    );
    let d = decoder_sweep(seed);
    let _ = writeln!(
        out,
        "\nDecoder (Pessl-Prokop): skipping the rounding of one coefficient changes {} of {} decapsulations\nof a valid ciphertext (every step of every pass). Control, one pass in order: {} of 256 steps\nchange it, exactly the {} coefficients whose noise is negative ({}). The same step in two passes:\n{} of 256 change it (the random orders meet by chance).",
        d.protected_effective,
        d.protected_tried,
        d.unprotected_effective,
        d.negative_noise,
        if d.unprotected_matches_noise_sign { "a key-dependent oracle" } else { "NOT the noise signs" },
        d.two_pass_effective
    );
    let _ = writeln!(
        out,
        "A fault in one pass's arithmetic (C - B'S shifted by -q/4 at one coefficient): {} of 768 change it\n(control: {}). With the vote skipped, one skipped rounding changes {} of 256, and {} of 256 outcomes\nfollow the noise signs by index (the random order alone hides the coefficient). The boundary: the\nsame coefficient's arithmetic faulted in two passes changes {} of 256, {}.",
        d.arithmetic_effective,
        if d.arithmetic_unprotected_matches_noise_sign { "exactly the negative-noise coefficients" } else { "NOT the noise signs" },
        d.vote_skipped_effective,
        d.vote_skipped_agreement,
        d.arithmetic_two_pass_effective,
        if d.arithmetic_two_pass_matches_noise_sign { "exactly the negative-noise ones: two aimed faults leak" } else { "not the noise signs" }
    );
    (out, s.bypasses == 0 && s.validity_oracles == 0 && !s.verdict_pair_bypasses && d.protected_effective == 0 && d.arithmetic_effective == 0)
}

fn severity(e: &MapEntry) -> u8 {
    match e.on_invalid {
        Outcome::Bypass => 4,
        Outcome::ValidityOracle => 3,
        Outcome::DenialOfService => 2,
        Outcome::NoEffect => match e.on_valid {
            Outcome::NoEffect => 0,
            _ => 1,
        },
    }
}

/// The fault picture: how many single faults give a full bypass, how many a
/// validity oracle, whether forcing both selection verdicts bypasses, the
/// fewest faults of any bypass, and whether forcing all three verdicts does.
pub struct SingleFaultSummary {
    pub bypasses: usize,
    pub validity_oracles: usize,
    pub verdict_pair_bypasses: bool,
    pub cheapest_bypass: usize,
    pub all_verdicts_bypass: bool,
    /// Fewest faults of any validity oracle, the negative control excluded.
    pub cheapest_validity_oracle: usize,
}

pub fn single_fault_summary(seed: u8) -> SingleFaultSummary {
    let m = map(seed);
    let singles = m.iter().filter(|e| e.faults.len() == 1);
    let named = |part: &str| m.iter().find(|e| e.name.contains(part)).expect("entry");
    SingleFaultSummary {
        bypasses: singles.clone().filter(|e| e.on_invalid == Outcome::Bypass).count(),
        validity_oracles: singles.filter(|e| e.on_invalid == Outcome::ValidityOracle).count(),
        verdict_pair_bypasses: named("BOTH selection verdicts").on_invalid == Outcome::Bypass,
        cheapest_bypass: m.iter().filter(|e| e.on_invalid == Outcome::Bypass).map(|e| e.faults.len()).min().unwrap_or(usize::MAX),
        all_verdicts_bypass: named("ALL THREE verdicts").on_invalid == Outcome::Bypass,
        cheapest_validity_oracle: m
            .iter()
            .filter(|e| e.on_invalid == Outcome::ValidityOracle && !e.name.starts_with("control"))
            .map(|e| e.faults.len())
            .min()
            .unwrap_or(usize::MAX),
    }
}

/// The decoder faults across every step and coefficient: what one skipped
/// rounding, or one fault in a pass's arithmetic, does to a valid
/// ciphertext's decapsulation, in the real code and in the negative control
/// (one pass, in order, as before the review of 2026-09-28); the random
/// order's contribution alone (the vote skipped); and the two-fault
/// boundary.
pub struct DecoderSweep {
    /// Single skipped roundings tried (3 passes x 256 steps) and how many
    /// changed the result.
    pub protected_tried: usize,
    pub protected_effective: usize,
    /// The control: how many of the 256 steps changed the result, how many
    /// coefficients have negative noise, and whether the changed steps are
    /// exactly those (the key-dependent oracle Pessl and Prokop exploit).
    pub unprotected_effective: usize,
    pub negative_noise: usize,
    pub unprotected_matches_noise_sign: bool,
    /// The same step skipped in passes 0 and 1, for every step: how many of
    /// the 256 changed the result (only when both orders put one coefficient
    /// there, and its noise is negative).
    pub two_pass_effective: usize,
    /// One pass's arithmetic faulted (its C - B'S shifted by -q/4 at one
    /// coefficient, the effect of a skipped rounding), for every coefficient
    /// of every pass: how many changed the result; and in the control (one
    /// pass, as before), whether the changed coefficients are exactly those
    /// with negative noise.
    pub arithmetic_effective: usize,
    pub arithmetic_unprotected_matches_noise_sign: bool,
    /// The same coefficient's arithmetic faulted in passes 0 and 1, for every
    /// coefficient: the arithmetic runs in a fixed order, so both faults can
    /// be aimed, and they outvote the third pass. How many changed the
    /// result, and whether exactly the negative-noise ones (the decoder's
    /// two-fault boundary).
    pub arithmetic_two_pass_effective: usize,
    pub arithmetic_two_pass_matches_noise_sign: bool,
    /// The vote skipped and one rounding skipped in the first pass, for every
    /// step: how many changed the result, and at how many steps the outcome
    /// agrees with the sign of the coefficient of the same index (all 256 in
    /// order, as in the control; about half, chance, in random orders).
    pub vote_skipped_effective: usize,
    pub vote_skipped_agreement: usize,
}

/// The noise e_j of each coefficient of a valid ciphertext: C - B'S minus
/// the encoded message bit, centred, computed from the secret and the known
/// message (what the attacker's inequalities are about).
fn noise_of(dk: &DecapsulationKey, ct: &[u8], message: &[u8; 32]) -> Vec<i32> {
    let (mut bp, mut c) = (vec![0u16; PARAMS.mbar * PARAMS.n], vec![0u16; PARAMS.mbar * PARAMS.nbar]);
    lwe::unpack(15, &ct[..BP_BYTES], &mut bp);
    lwe::unpack(15, &ct[BP_BYTES..PKE_BYTES], &mut c);
    let mut values = vec![0u16; c.len()];
    lwe::decrypt_values(&PARAMS, dk.secret_matrix(), &bp, &c, &mut values);
    values
        .iter()
        .enumerate()
        .map(|(j, &v)| {
            let bit = u16::from((message[j / 8] >> (j % 8)) & 1);
            let e = i32::from(v.wrapping_sub(bit << 14) & Q_MASK);
            if e >= 1 << 14 { e - (1 << 15) } else { e }
        })
        .collect()
}

pub fn decoder_sweep(seed: u8) -> DecoderSweep {
    let dk = DecapsulationKey::from_seed(&[seed; 32]).expect("consistent");
    let message = [0x5c; 32];
    let (ct, key) = dk.encapsulation_key().encapsulate_with(&message, &[0x3a; 64]);
    let changed = |faults: &[Fault]| dk.decapsulate_with_faults(&ct, faults).expect("length")[..] != key[..];
    let negative: Vec<bool> = noise_of(&dk, &ct, &message).iter().map(|&e| e < 0).collect();
    // Which of the 256 indices (steps or coefficients) change the result.
    let by_index = |faults: &dyn Fn(usize) -> Vec<Fault>| -> Vec<bool> { (0..256).map(|i| changed(&faults(i))).collect() };
    let count = |v: &[bool]| v.iter().filter(|&&x| x).count();
    // -q/4 mod q: shifting a value by it has the effect of skipping its rounding.
    let down = (1u16 << 15) - (1 << 13);
    let every_pass = |fault: &dyn Fn(u8, usize) -> Fault| (0..3u8).map(|pass| count(&by_index(&|i| vec![fault(pass, i)]))).sum::<usize>();
    let effective = by_index(&|step| vec![Fault::UnprotectedDecoder, Fault::SkipRounding(0, step)]);
    let arithmetic_unprotected = by_index(&|j| vec![Fault::UnprotectedDecoder, Fault::ShiftValue(0, j, down)]);
    let arithmetic_two_pass = by_index(&|j| vec![Fault::ShiftValue(0, j, down), Fault::ShiftValue(1, j, down)]);
    let vote_skipped = by_index(&|step| vec![Fault::SkipVote, Fault::SkipRounding(0, step)]);
    DecoderSweep {
        protected_tried: 3 * 256,
        protected_effective: every_pass(&|pass, step| Fault::SkipRounding(pass, step)),
        unprotected_effective: count(&effective),
        negative_noise: count(&negative),
        unprotected_matches_noise_sign: effective == negative,
        two_pass_effective: count(&by_index(&|step| vec![Fault::SkipRounding(0, step), Fault::SkipRounding(1, step)])),
        arithmetic_effective: every_pass(&|pass, j| Fault::ShiftValue(pass, j, down)),
        arithmetic_unprotected_matches_noise_sign: arithmetic_unprotected == negative,
        arithmetic_two_pass_effective: count(&arithmetic_two_pass),
        arithmetic_two_pass_matches_noise_sign: arithmetic_two_pass == negative,
        vote_skipped_effective: count(&vote_skipped),
        vote_skipped_agreement: vote_skipped.iter().zip(&negative).filter(|(a, b)| a == b).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No single fault on the check turns a rejected ciphertext into an
    // accepted one: the only single-fault break is the validity oracle from
    // skipping z, and the accept-mask faults do nothing. Forcing both
    // selection verdicts gives a key bound to the comparison (denial of
    // service); a bypass takes both re-encryptions' data, or all three
    // verdicts.
    #[test]
    fn no_single_fault_bypass() {
        for seed in [1u8, 2, 7, 200] {
            let m = map(seed);
            for e in &m {
                if e.faults.len() == 1 {
                    assert_ne!(e.on_invalid, Outcome::Bypass, "single fault bypassed: {}", e.name);
                }
            }
            // Forcing one verdict is caught by the other check.
            let force_bytes = m.iter().find(|e| e.name.contains("packed-byte verdict")).expect("entry");
            assert_eq!(force_bytes.on_invalid, Outcome::NoEffect);
            let force_coeffs = m.iter().find(|e| e.name.contains("coefficient verdict")).expect("entry");
            assert_eq!(force_coeffs.on_invalid, Outcome::NoEffect);
            let force_binding = m.iter().find(|e| e.name.contains("binding verdict")).expect("entry");
            assert_eq!(force_binding.on_invalid, Outcome::NoEffect);
            assert_eq!(force_binding.on_valid, Outcome::NoEffect, "forcing an accepting verdict changes nothing on a valid ciphertext");
            // Forcing one re-encryption's coefficients to match is caught by
            // the other, independent re-encryption.
            let force1 = m.iter().find(|e| e.name.contains("first re-encryption to match")).expect("entry");
            assert_eq!(force1.on_invalid, Outcome::NoEffect, "one re-encryption fault bypassed");
            let force2 = m.iter().find(|e| e.name.contains("second re-encryption to match")).expect("entry");
            assert_eq!(force2.on_invalid, Outcome::NoEffect, "one re-encryption fault bypassed");
            // Skipping the final selection leaves the rejection key (default-fail).
            let skip = m.iter().find(|e| e.name.contains("final masked selection")).expect("entry");
            assert_eq!(skip.on_invalid, Outcome::NoEffect);
            assert_eq!(skip.on_valid, Outcome::DenialOfService);
            // Both selection verdicts forced: the released key is bound to
            // the comparison (it needs z), so no bypass. research/reviews/
            // 2026-09-28 R2: this pair was a bypass, and the release build
            // had fused it into one fault.
            let verdicts = m.iter().find(|e| e.name.contains("BOTH selection verdicts")).expect("entry");
            assert_eq!(verdicts.on_invalid, Outcome::DenialOfService, "forcing both selection verdicts bypassed");
            // The cheapest bypasses remain: both runs' data, or three verdicts.
            let data = m.iter().find(|e| e.name.contains("BOTH re-encryptions")).expect("entry");
            assert_eq!(data.on_invalid, Outcome::Bypass, "both re-encryptions forced should bypass");
            // The third verdict reads the second run: forcing the first run
            // and a verdict does not bypass; the second run and the byte
            // verdict does (two faults, as cheap as both runs' data).
            let first_and_coeffs = m.iter().find(|e| e.name.contains("first re-encryption AND")).expect("entry");
            assert_eq!(first_and_coeffs.on_invalid, Outcome::DenialOfService, "first run + coefficient verdict bypassed");
            let second_and_bytes = m.iter().find(|e| e.name.contains("second re-encryption AND")).expect("entry");
            assert_eq!(second_and_bytes.on_invalid, Outcome::Bypass);
            let three = m.iter().find(|e| e.name.contains("ALL THREE verdicts")).expect("entry");
            assert_eq!(three.on_invalid, Outcome::Bypass, "all three verdicts forced should bypass");
        }
    }

    // Skipping z in one rejection hash no longer gives a validity oracle: the
    // two computations disagree and the key is infected (denial of service).
    // The control, one rejection hash as before the fix, still shows the
    // oracle, so the test can tell. Two faults are needed now.
    #[test]
    fn skipping_z_is_no_longer_a_validity_oracle() {
        let m = map(3);
        let entry = |part: &str| m.iter().find(|e| e.name.contains(part)).expect("entry").on_invalid;
        assert_eq!(entry("skip absorbing z into the rejection key"), Outcome::DenialOfService);
        assert_eq!(entry("skip absorbing z into the second rejection key"), Outcome::DenialOfService);
        assert_eq!(entry("force the rejection keys' agreement verdict"), Outcome::NoEffect);
        assert_eq!(entry("control: one rejection hash, z skipped"), Outcome::ValidityOracle, "the control must show the oracle");
        assert_eq!(entry("skip z in BOTH rejection keys"), Outcome::ValidityOracle);
        assert_eq!(entry("skip z AND force the agreement verdict"), Outcome::ValidityOracle);
    }

    // The decoder fault (Pessl and Prokop): in the control (one pass, in
    // order, as before the fix) skipping the rounding of coefficient j, or
    // shifting its value by -q/4 in the arithmetic, changes a valid
    // ciphertext's result exactly when e_j < 0, a key-dependent oracle. In
    // the real code no single fault of either kind, at any step or
    // coefficient of any pass, changes anything; the same step skipped in two
    // passes rarely lands on one coefficient; and with the vote skipped, the
    // random order alone still hides which coefficient a skipped rounding
    // hit. The boundary: two faults aimed at one coefficient's arithmetic in
    // two passes leak its noise sign (docs/16 states it).
    #[test]
    fn a_skipped_rounding_leaks_nothing() {
        let d = decoder_sweep(5);
        assert!(d.unprotected_matches_noise_sign, "control: the unprotected decoder must leak the noise signs");
        assert!(d.arithmetic_unprotected_matches_noise_sign, "control: an arithmetic fault in the unprotected decoder must leak them too");
        assert!(d.negative_noise > 0 && d.negative_noise < 256, "the control needs both signs");
        assert_eq!(d.protected_effective, 0, "{} of {} single skipped roundings changed the result", d.protected_effective, d.protected_tried);
        assert_eq!(d.arithmetic_effective, 0, "{} of 768 single arithmetic faults changed the result", d.arithmetic_effective);
        assert!(d.two_pass_effective <= 8, "{} of 256 two-pass skips changed the result", d.two_pass_effective);
        assert!(d.vote_skipped_effective >= 64, "the vote-skip fault must take effect ({} of 256)", d.vote_skipped_effective);
        assert!(d.vote_skipped_agreement < 200, "with the vote skipped, {} of 256 outcomes follow the noise signs by index", d.vote_skipped_agreement);
        assert!(d.arithmetic_two_pass_matches_noise_sign, "the two-fault boundary moved: docs/16 says two aimed arithmetic faults leak");
    }

    #[test]
    fn single_fault_count_is_reported() {
        let s = single_fault_summary(11);
        assert_eq!(s.bypasses, 0, "no single fault gives a full bypass");
        assert_eq!(s.validity_oracles, 0, "no single fault gives a validity oracle");
        assert_eq!(s.cheapest_validity_oracle, 2, "a validity oracle takes two faults");
        assert!(!s.verdict_pair_bypasses, "forcing both selection verdicts must not bypass");
        assert_eq!(s.cheapest_bypass, 2, "the cheapest bypass is both re-encryptions' data");
        assert!(s.all_verdicts_bypass, "three verdict faults do bypass");
    }
}
