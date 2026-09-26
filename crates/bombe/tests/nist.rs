//! Validates Bombe's NIST SP 800-22 implementation against the document
//! itself: every worked example, and the reference results NIST published
//! for 1,000,000 bits of e (Appendix B). A test only counts as working if it
//! reproduces NIST's numbers to the six decimals NIST prints.

use bombe::nist::*;

const EPS: f64 = 1e-6;

fn close(got: f64, want: f64, what: &str) {
    assert!((got - want).abs() < EPS, "{what}: got {got:.7}, NIST says {want}");
}

// The 100-bit sequence used by most of NIST's worked examples.
const E100: &str = "11001001000011111101101010100010001000010110100011\
                    00001000110100110001001100011001100010100010111000";

// The 128-bit sequence of the longest-run example (2.4.8).
const E128: &str = "11001100000101010110110001001100111000000000001001\
                    00110101010001000100111101011010000000110101111100\
                    1100111001101101100010110010";

#[test]
fn special_functions() {
    close(erfc(0.0), 1.0, "erfc(0)");
    close(erfc(1.0), 0.157_299_207_050_285_1, "erfc(1)");
    close(erfc(2.0), 0.004_677_734_981_047_266, "erfc(2)");
    close(erfc(-1.0), 1.842_700_792_949_715, "erfc(-1)");
    close(igamc(1.0, 0.7), (-0.7f64).exp(), "igamc(1, x) = e^-x");
    close(igamc(2.0, 0.8), (-0.8f64).exp() * 1.8, "igamc(2, x) = e^-x (1 + x)");
    close(normal_cdf(1.96), 0.975_002_104_851_780, "Phi(1.96)");
    close(ln_gamma(10.0), 362_880f64.ln(), "ln Gamma(10) = ln 9!");
    close(ln_gamma(0.5), std::f64::consts::PI.sqrt().ln(), "ln Gamma(1/2)");
}

// Every worked example in sections 2.1 - 2.13 of SP 800-22 rev. 1a.
#[test]
fn worked_examples() {
    let e100 = Bits::parse(E100);
    assert_eq!(e100.len(), 100);
    close(frequency(&Bits::parse("1011010101")), 0.527089, "2.1.4 frequency");
    close(frequency(&e100), 0.109599, "2.1.8 frequency");
    close(block_frequency(&Bits::parse("0110011010"), 3), 0.801252, "2.2.4 block frequency");
    close(block_frequency(&e100, 10), 0.706438, "2.2.8 block frequency");
    close(runs(&Bits::parse("1001101011")), 0.147232, "2.3.4 runs");
    close(runs(&e100), 0.500798, "2.3.8 runs");
    let e128 = Bits::parse(E128);
    assert_eq!(e128.len(), 128);
    close(longest_run(&e128), 0.180609, "2.4.8 longest run");
    // The spectral test's two small worked examples are inconsistent with the
    // document's own definition (the test was corrected after they were
    // written; Kim, Umeno, Hasegawa, ePrint 2004/018). Computing the
    // transforms directly:
    //  - 2.6.4, 1001010011: all ten magnitudes are below T = 5.4733 (the
    //    largest is 4.4721), so N1 = 5, not the printed 4, and P = 0.468160,
    //    not 0.029523.
    //  - 2.6.8, the 100-bit sequence: 48 of |S_0| .. |S_49| are below
    //    T = 17.3082, not the printed 46 (no counting convention and neither
    //    published threshold gives 46), so P = 0.646355, not 0.168669.
    // NIST's million-bit reference result, produced by its corrected code,
    // matches this implementation to six decimals (e_reference_results).
    let spectral_p = |below: f64, n: f64| {
        erfc(((below - 0.95 * n / 2.0) / (n * 0.95 * 0.05 / 4.0).sqrt()).abs() / std::f64::consts::SQRT_2)
    };
    close(spectral(&Bits::parse("1001010011")), spectral_p(5.0, 10.0), "2.6.4 spectral, N1 = 5");
    close(spectral(&Bits::parse("1001010011")), 0.468160, "2.6.4 spectral, N1 = 5");
    close(spectral(&e100), spectral_p(48.0, 100.0), "2.6.8 spectral, N1 = 48");
    close(spectral(&e100), 0.646355, "2.6.8 spectral, N1 = 48");
    let (p1, p2) = serial(&Bits::parse("0011011101"), 3);
    close(p1, 0.808792, "2.11.6 serial 1");
    close(p2, 0.670320, "2.11.6 serial 2");
    close(approximate_entropy(&Bits::parse("0100110101"), 3), 0.261961, "2.12.4 approximate entropy");
    close(approximate_entropy(&e100, 2), 0.235301, "2.12.8 approximate entropy");
    close(cumulative_sums(&Bits::parse("1011010111"), true), 0.4116588, "2.13.4 cusum");
    close(cumulative_sums(&e100, true), 0.219194, "2.13.8 cusum forward");
    close(cumulative_sums(&e100, false), 0.114866, "2.13.8 cusum backward");
}

fn e_bits() -> Bits {
    Bits::from_bytes(include_bytes!("data/e-1000000.bin"))
}

// The first 1,000,000 bits of e, checked against the counts NIST gives in
// the serial-test example (2.11.8) and its rank example on the first
// 100,000 bits (2.5.8). This confirms the data file is NIST's "data.e".
#[test]
fn e_sequence_matches_nist_counts() {
    let e = e_bits();
    assert_eq!(e.len(), 1_000_000);
    assert_eq!(e.0.iter().filter(|&&b| b == 1).count(), 500_029);
    let (p1, p2) = serial(&e, 2);
    close(p1, 0.843764, "2.11.8 serial 1");
    close(p2, 0.561915, "2.11.8 serial 2");
    close(rank(&Bits(e.0[..100_000].to_vec())), 0.532069, "2.5.8 rank");
}

// Appendix B, "The binary expansion of e": NIST's reference P-values for the
// whole sequence.
#[test]
fn e_reference_results() {
    let e = e_bits();
    close(frequency(&e), 0.953749, "frequency");
    close(block_frequency(&e, 128), 0.211072, "block frequency (m = 128)");
    close(cumulative_sums(&e, true), 0.669887, "cusum forward");
    close(cumulative_sums(&e, false), 0.724266, "cusum reverse");
    close(runs(&e), 0.561917, "runs");
    close(longest_run(&e), 0.718945, "longest run of ones");
    close(rank(&e), 0.306156, "rank");
    close(spectral(&e), 0.847187, "spectral DFT");
    close(approximate_entropy(&e, 10), 0.700073, "approximate entropy (m = 10)");
    close(serial(&e, 16).0, 0.766182, "serial (m = 16)");
}

// The general-length transform agrees with the direct definition, for
// lengths that are and are not powers of two.
#[test]
fn fft_matches_direct_dft() {
    for n in [8usize, 64, 97, 100, 250, 1000] {
        let x: Vec<f64> = (0..n).map(|i| ((i * 7919 + 13) % 17) as f64 - 8.0).collect();
        let (fast, slow) = (dft(&x), dft_naive(&x));
        for (a, b) in fast.iter().zip(&slow) {
            assert!((a.0 - b.0).abs() < 1e-7 && (a.1 - b.1).abs() < 1e-7, "n = {n}");
        }
    }
}

// Negative controls: sequences that are obviously not random must be
// rejected (P < 0.01) by the tests aimed at their flaw.
#[test]
fn obviously_non_random_sequences_fail() {
    let n = 1 << 20;
    let alternating = Bits((0..n).map(|i| (i % 2) as u8).collect());
    let biased = Bits((0..n).map(|i| u8::from((i * 2_654_435_761usize) % 100 < 53)).collect());
    let repeating = Bits((0..n).map(|i| ((0x9d_u32 >> (i % 8)) & 1) as u8).collect());
    assert!(runs(&alternating) < 0.01, "alternating 0101... has far too many runs");
    assert!(frequency(&biased) < 0.01, "53% ones");
    assert!(serial(&repeating, 16).0 < 0.01, "a period-8 pattern");
    assert!(spectral(&repeating) < 0.01, "a period-8 pattern has a strong spectral peak");
    assert!(approximate_entropy(&repeating, 10) < 0.01, "period-8 pattern is predictable");
}
