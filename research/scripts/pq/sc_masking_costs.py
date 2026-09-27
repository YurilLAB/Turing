"""Masking cost factors for Kyber768 decapsulation, from published cycle counts.

Reproduces the slowdown factors quoted in
research/notes/pq/side-channels-faults-and-ct-verification.md, Section 3.
Inputs are copied from the sources (not measured here):

  Bos, Gourjon, Renes, Schneider, van Vredendaal, "Masking Kyber: First- and
  Higher-Order Implementations", TCHES 2021(4):173-214, Table 2 (PDF p. 21):
  Kyber768 crypto_kem_dec, thousands of cycles.
    STM32F407G (Cortex-M4F): pqm4 unmasked 882; masked 1st 3 116; 2nd 44 347;
                             3rd 115 481
    FRDM-KL82Z (Cortex-M0+): PQClean unmasked 5 530; masked 1st 12 208;
                             2nd 107 352; 3rd 231 632
  Heinz, Kannwischer, Land, Pöppelmann, Schwabe, Sprenkels, "First-Order
  Masked Kyber on ARM Cortex-M4", ePrint 2022/058 (abstract): masked
  Kyber768 decapsulation 2 978 441 cycles, including randomness generation.

The paper prints the first-order factors (3.5x, 2.2x); the higher-order
factors are not printed in the paper and are derived here. The Heinz et al.
factor uses the Bos et al. pqm4 baseline, which is an assumption: the two
papers measured on different boards (STM32F407G vs STM32F407VG) and code
versions, so it is only indicative.
Usage: python sc_masking_costs.py
"""

BOS_M4 = {"unmasked": 882, "1st": 3116, "2nd": 44347, "3rd": 115481}
BOS_M0 = {"unmasked": 5530, "1st": 12208, "2nd": 107352, "3rd": 231632}
HEINZ_M4_FIRST = 2978441 / 1000  # thousands of cycles


def show(name, d):
    base = d["unmasked"]
    print(f"{name}: unmasked {base} kcycles")
    for k in ("1st", "2nd", "3rd"):
        print(f"   {k}-order masked: {d[k]:>7} kcycles  = {d[k] / base:6.1f} x unmasked")


def main():
    show("Bos et al. Kyber768 decaps, Cortex-M4F (STM32F407G)", BOS_M4)
    show("Bos et al. Kyber768 decaps, Cortex-M0+ (FRDM-KL82Z)", BOS_M0)
    print(f"Heinz et al. first-order Kyber768 decaps: {HEINZ_M4_FIRST:.0f} kcycles "
          f"= {HEINZ_M4_FIRST / BOS_M4['unmasked']:.1f} x the Bos et al. pqm4 baseline (indicative)")
    # Check against the factors the paper itself prints (negative control on transcription).
    assert round(BOS_M4["1st"] / BOS_M4["unmasked"], 1) == 3.5, "paper prints 3.5x"
    assert round(BOS_M0["1st"] / BOS_M0["unmasked"], 1) == 2.2, "paper prints 2.2x"
    print("check: first-order factors match the 3.5x and 2.2x printed in Table 2")


if __name__ == "__main__":
    main()
