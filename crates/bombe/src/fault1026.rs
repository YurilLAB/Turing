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
//! (two correlated faults) or all three verdicts (three). The one
//! single-fault hole on the check left is skipping the secret z in the
//! rejection hash (an XOF-state fault), which no amount of comparison
//! redundancy can close; it needs redundant or masked hashing, noted as not
//! done. The decoder is outside this map: a skipped `+ q/4` makes the
//! decapsulation's success depend on the sign of one noise coefficient
//! (Pessl and Prokop, TCHES 2021(2)), docs/16's fault model.
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
    // Skipping the secret z in the rejection hash (an XOF-state fault).
    out.push(s.run("skip absorbing z into the rejection key", vec![Fault::Skip(FaultPoint::RejectionZ)]));
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
        "\n{} single faults bypass the check; {} give a validity oracle (skipping z in the rejection hash,\nwhich comparison redundancy cannot close). Forcing both selection verdicts {}; the cheapest\nbypass takes {} faults (both re-encryptions' data), forcing verdicts alone {}.",
        s.bypasses,
        s.validity_oracles,
        if s.verdict_pair_bypasses { "BYPASSES" } else { "does not bypass (the key is bound to the comparison)" },
        s.cheapest_bypass,
        if s.all_verdicts_bypass { "three" } else { "more than three" }
    );
    (out, s.bypasses == 0 && !s.verdict_pair_bypasses)
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

    // Skipping z in the rejection hash is a validity oracle: the returned key
    // is the rejection key anyone can compute from the public key.
    #[test]
    fn skipping_z_is_a_validity_oracle() {
        let m = map(3);
        let z = m.iter().find(|e| e.name.contains("skip absorbing z")).expect("entry");
        assert_eq!(z.on_invalid, Outcome::ValidityOracle);
    }

    #[test]
    fn single_fault_count_is_reported() {
        let s = single_fault_summary(11);
        assert_eq!(s.bypasses, 0, "no single fault gives a full bypass");
        assert_eq!(s.validity_oracles, 1, "only skipping z is a single-fault validity oracle");
        assert!(!s.verdict_pair_bypasses, "forcing both selection verdicts must not bypass");
        assert_eq!(s.cheapest_bypass, 2, "the cheapest bypass is both re-encryptions' data");
        assert!(s.all_verdicts_bypass, "three verdict faults do bypass");
    }
}
