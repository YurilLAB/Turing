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
//! accept mask was a single-fault bypass. Decapsulation now checks the
//! re-encryption twice (packed bytes and coefficients, independent memory and
//! code) and installs the accepted key only through two chained selections,
//! so no single fault on the check bypasses it: the map below finds a bypass
//! only from the correlated pair that forces *both* verdicts. The one
//! single-fault hole left is skipping the secret z in the rejection hash (an
//! XOF-state fault), which no amount of comparison redundancy can close; it
//! needs redundant or masked hashing, noted as not done.

use turing::turing1026::{DecapsulationKey, Fault, FaultPoint};

use crate::refkem1026::ReferenceKem;

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
}

fn setup(seed: u8) -> Setup {
    let dk = DecapsulationKey::from_seed(&[seed; 32]).expect("consistent");
    let reference = ReferenceKem::from_seed(&[seed; 32]);
    let (valid, key) = dk.encapsulation_key().encapsulate_with(&[0x5c; 32], &[0x3a; 64]);
    let valid_key: [u8; 32] = key[..].try_into().expect("32");
    // An invalid ciphertext the attacker knows the decryption of: a valid one
    // with a coefficient of C shifted by q/2, so one message bit flips and the
    // re-encryption no longer matches.
    let mut invalid = valid.clone();
    let bp_bytes = 15_390;
    invalid[bp_bytes] ^= 0x40; // a bit inside the first coefficient of C
    Setup {
        valid_oracle: Oracle::new(&reference, &valid),
        invalid_oracle: Oracle::new(&reference, &invalid),
        reject_invalid: reference.rejection_key(&invalid),
        valid_key,
        valid,
        invalid,
        dk,
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
    // Skipping the secret z in the rejection hash (an XOF-state fault).
    out.push(s.run("skip absorbing z into the rejection key", vec![Fault::Skip(FaultPoint::RejectionZ)]));
    // Skipping the final selection (pqm4's skipped copy).
    out.push(s.run("skip the final masked selection", vec![Fault::Skip(FaultPoint::Selection)]));
    // The correlated pair that forces both verdicts: two faults, a bypass.
    out.push(s.run(
        "force BOTH verdicts to accept (two correlated faults)",
        vec![Fault::Verdict(FaultPoint::AcceptBytes, 0xff), Fault::Verdict(FaultPoint::AcceptCoeffs, 0xff)],
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
        "\n{} single faults bypass the check; {} give a validity oracle (skipping z in the rejection hash,\nwhich comparison redundancy cannot close). The correlated pair forcing both verdicts {}.",
        s.bypasses,
        s.validity_oracles,
        if s.pair_bypasses { "does bypass (two faults)" } else { "does not bypass" }
    );
    (out, s.bypasses == 0)
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

/// The single-fault picture: how many single faults give a full bypass, how
/// many give a validity oracle, and whether the correlated two-fault pair
/// bypasses.
pub struct SingleFaultSummary {
    pub bypasses: usize,
    pub validity_oracles: usize,
    pub pair_bypasses: bool,
}

pub fn single_fault_summary(seed: u8) -> SingleFaultSummary {
    let m = map(seed);
    let (pair, singles) = m.split_last().expect("entries");
    let singles = singles.iter().filter(|e| e.faults.len() == 1);
    SingleFaultSummary {
        bypasses: singles.clone().filter(|e| e.on_invalid == Outcome::Bypass).count(),
        validity_oracles: singles.filter(|e| e.on_invalid == Outcome::ValidityOracle).count(),
        pair_bypasses: pair.on_invalid == Outcome::Bypass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No single fault on the check turns a rejected ciphertext into an
    // accepted one: the only single-fault break is the validity oracle from
    // skipping z, and the accept-mask faults do nothing. The correlated pair
    // that forces both verdicts does bypass, so two faults are needed.
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
            // Skipping the final selection leaves the rejection key (default-fail).
            let skip = m.iter().find(|e| e.name.contains("final masked selection")).expect("entry");
            assert_eq!(skip.on_invalid, Outcome::NoEffect);
            assert_eq!(skip.on_valid, Outcome::DenialOfService);
            // The correlated pair bypasses.
            let pair = m.last().expect("pair");
            assert_eq!(pair.on_invalid, Outcome::Bypass);
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
        assert!(s.pair_bypasses, "two correlated faults do bypass");
    }
}
