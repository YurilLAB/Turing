"""dfr_verify_sources.py - re-check the VERIFIED claims of research/notes/pq/decryption-failures.md
against the primary-source PDFs in research/papers/.

What it reproduces, and from where
----------------------------------
Nothing numeric is recomputed here (dfr.py does that). For each claim-ledger row marked VERIFIED
this script opens the cited PDF with pymupdf, normalises the page text (whitespace collapsed,
Unicode minus and ligatures replaced, exponents flattened as the text layer gives them, e.g.
"2^184" reads "2184"), and searches for a short quotation or number group. A check PASSES only if
the pattern is found on the cited physical PDF page (1-based). Negative controls (patterns that
must NOT be on the cited page, e.g. a wrong digit) show that a PASS is not automatic.

Usage: python dfr_verify_sources.py [PAPERS_DIR]      (default: research/papers next to this repo)
Deterministic; no network; about 10-30 s.
"""
import os
import re
import sys

import pymupdf

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
PAPERS = sys.argv[1] if len(sys.argv) > 1 else os.path.normpath(os.path.join(HERE, "..", "..", "papers"))

FIPS203 = "nist-fips-203-ml-kem.pdf"
KYB3 = "2021-avanzi-et-al-kyber-round3-specification.pdf"
FRO3 = "2021-alkim-et-al-frodokem-round3-specification-20210604.pdf"
FRO25 = "2025-alkim-et-al-frodokem-standard-proposal-20250929.pdf"
PKC19 = "2019-danvers-et-al-decryption-failure-attacks-ind-cca-lattice.pdf"
ARV = "2020-danvers-rossi-virdia-one-failure-is-not-an-option.pdf"
DB22 = "2022-danvers-batsleer-multitarget-decryption-failure-attacks.pdf"
BS20 = "2020-bindel-schanck-decryption-failure-more-likely-after-success.pdf"
GJN = "2020-guo-johansson-nilsson-key-recovery-timing-attack-fo-frodokem.pdf"
FAHR = "2022-fahr-et-al-when-frodo-flips-rowhammer.pdf"
SP227 = "nist-sp800-227-kem-recommendations.pdf"
IR8413 = "nist-ir-8413-pqc-round3-report.pdf"
IR8545 = "nist-ir-8545-pqc-round4-report.pdf"
CFP = "nist-pqc-call-for-proposals-2016.pdf"
LAC = "2018-lu-et-al-lac-ring-lwe-byte-level-modulus.pdf"
DVV = "2019-danvers-vercauteren-verbauwhede-impact-of-error-dependencies.pdf"
DTVV = "2019-danvers-tiepelt-vercauteren-verbauwhede-timing-attacks-on-ecc-pq.pdf"
R5 = "2019-baan-et-al-round5-kem-pke-based-on-glwr.pdf"
FWZ = "2022-fang-wang-zhao-tight-analysis-kyber-dfr-in-reality.pdf"
DT26 = "2026-duriez-tommasini-dependency-aware-correctness-bounds-ml-kem-768.pdf"
ZHOU = "2026-zhou-et-al-refined-evaluation-dfr-message-encoding.pdf"
MS24 = "2024-majenz-sisinni-provable-security-against-decryption-failure-attacks-lwe.pdf"
GJY = "2019-guo-johansson-yang-cca-attack-decryption-errors-lac.pdf"
HHK = "2017-hofheinz-hovelmanns-kiltz-modular-analysis-fo-transformation.pdf"
FLU = "2016-fluhrer-cryptanalysis-rlwe-key-exchange-key-reuse.pdf"
GJS = "2016-guo-johansson-stankovski-key-recovery-qc-mdpc-decoding-errors.pdf"
NH2 = "2019-alkim-et-al-newhope-round2-specification.pdf"
BAR25 = "2025-barbosa-et-al-formally-verified-correctness-bounds-lattice.pdf"
SHAO = "2024-shao-et-al-lwe-kems-under-various-distributions-kyber.pdf"
DAS = "2026-das-incomplete-ciphertext-comparison-ml-kem.pdf"
FLZ = "2026-fang-li-zhao-dfr-multidimensional-lattice-decoders.pdf"

# (claim id, file, cited PDF page, regex, must_match)
CHECKS = [
    ("1", FIPS203, 24, r"ML-KEM-512 2-138\.8 ML-KEM-768 2-164\.8 ML-KEM-1024 2-174\.8", True),
    ("1-neg", FIPS203, 24, r"ML-KEM-768 2-164\.9", False),
    ("2", FIPS203, 24, r"Theorem 1 in \[8\] and the scripts in \[15\]", True),
    ("3", FIPS203, 24, r"taken over uniformly random seeds", True),
    ("6", KYB3, 11, r"Kyber512 256 2 3329 3 2 \(10, 4\) 2-139 Kyber768 256 3 3329 2 2 \(10, 4\) 2-164", True),
    ("20", KYB3, 13, r"Allowing decapsulation failures", True),
    ("29", KYB3, 33, r"hard to trigger even one failure", True),
    ("44a", KYB3, 21, r"we do not see a need for it to decrease with the security parameter", True),
    ("44b", KYB3, 21, r"exclude these attacks from our claims", True),
    ("45", KYB3, 2, r"736 bytes to 768 bytes, for a 2-139 decryption error", True),
    ("5-nontight", KYB3, 19, r"\(quadratic\) non-tightness in the decryption-failure probability", True),
    ("14a", FRO3, 24, r"Frodo-640 1 2-138\.7", True),
    ("14b", FRO3, 24, r"Frodo-976 3 2-199\.6", True),
    ("14c", FRO3, 24, r"Frodo-1344 5 2-252\.5", True),
    ("14d", FRO25, 19, r"Frodo-640 2-138\.7", True),
    ("14-neg", FRO3, 24, r"2-199\.5 ", False),
    ("15a", FRO3, 25, r"9288 8720 7216 5264 3384 1918 958 422 164 56 17 4 1", True),
    ("15b", FRO3, 25, r"11278 10277 7774 4882 2545 1101 396 118 29 6 1", True),
    ("15c", FRO3, 25, r"18286 14320 6876 2023 364 40 2", True),
    ("15d", FRO25, 15, r"9288 8720 7216 5264 3384 1918 958 422 164 56 17 4 1", True),
    ("16", FRO3, 18, r"Lemma 2\.18\. Let q = 2D, B ?≤ ?D", True),
    ("48a", FRO3, 45, r"exceeds 3\.5 bits", True),
    ("48b", FRO25, 12, r"exceeds 3\.5 bits", True),
    ("25a", PKC19, 21, r"Saber 2184 2139 245 77 2131", True),
    ("25b", PKC19, 21, r"FireSaber 2257 2170 287 233 2161", True),
    ("25c", PKC19, 21, r"Kyber768 2175 2142 233 42 2131", True),
    ("25d", PKC19, 21, r"Kyber1024 2239 2169 270 159 2158", True),
    ("25e", PKC19, 21, r"LAC256 2293 297. 2196 106 · 56 280", True),
    ("25f", PKC19, 21, r"FrodoKEM976 2188 2188 20 0 0", True),
    ("25-neg", PKC19, 21, r"Kyber768 2175 2141", False),
    ("26", PKC19, 20, r"rules out a decryption failure attack on schemes with a low enough failure rate such as Saber and Kyber", True),
    ("4.1", PKC19, 17, r"variance of the secret drastically reduces upon knowing only a few failing ciphertexts", True),
    ("27a", ARV, 21, r"112\.45 112\.77 112\.78 112\.78 112\.78 112\.78 112\.78", True),
    ("27b", ARV, 21, r"the following ones are essentially for free", True),
    ("27c", ARV, 1, r"hard to even obtain one decryption failure", True),
    ("28", ARV, 24, r"ss-ntru-pke 2198 2139\.5 2139\.6 296\.6", True),
    ("30a", DB22, 26, r"Saber \[6\] 172 2-136", True),
    ("30b", DB22, 26, r"Kyber768 \[27\] 165 2-164 - 208 / 102 208 / 102 187 / 112 175 / 126 - 186/126", True),
    ("30c", DB22, 26, r"Kyber1024 232 2-174 - - - - 228 / 126", True),
    ("30d", DB22, 26, r"Kyber512 107 2-139 - 138 / 102 138 / 102 131 / 118 131 / 118 131/118 131/118", True),
    ("31a", DB22, 27, r"2145W and 2126Q", True),
    ("31b", DB22, 27, r"not vulnerable to the decryption failure attack we developed, in case of Kyber1024 and FireSaber this is due to the constraints on the number of ciphertexts due to \|M\|", True),
    ("31c", DB22, 27, r"practical execution of the attack would not be straightforward", True),
    ("31d", DB22, 27, r"generally has no impact on the security of the scheme under non-decryption failure attacks", True),
    ("34a", BS20, 12, r"264/284\.7 = 2-20\.7", True),
    ("34b", BS20, 7, r"not justified", True),
    ("35a", GJN, 1, r"about 230 decapsulation calls", True),
    ("35b", GJN, 13, r"memcmp\(Bp , BBp , 2\* PARAMS_N\*PARAMS_NBAR\) == 0 &&", True),
    ("36a", SP227, 22, r"leaking information about failures and aborts outside of the perimeter", True),
    ("36b", SP227, 14, r"with all but negligible probability", True),
    ("37a", FAHR, 1, r"on the order of only 200,000 core-hours", True),
    ("37b", FAHR, 13, r"regenerate A, S, and E from randomness and compute B again", True),
    ("37c", FAHR, 13, r"from 8ms to 1300ms", True),
    ("46a", IR8413, 38, r"without raising the decryption failure rate above the requisite threshold", True),
    ("46b", IR8413, 43, r"HQC-256-1 was broken during the second round \[208\]", True),
    ("46c", IR8413, 78, r"\[208\] Guo Q, Johansson T \(2020\) A new decryption failure attack against HQC", True),
    ("55", IR8413, 43, r"removal of the BCH-repetition decoder", True),
    ("56", IR8413, 47, r"perfectly correct", True),
    ("47a", IR8545, 18, r"decisive factor in favor of HQC relative to BIKE is HQC.s stable DFR analysis", True),
    ("47b", IR8545, 19, r"inaccurate DFR estimates have resulted in BIKE being attacked as late as the fourth round", True),
    ("47c", IR8545, 19, r"discarded parameter sets target- ?ing a higher DFR than 2-λ for λ bits of security", True),
    ("47d", IR8545, 19, r"must be δ-correct3? for δ ?≤ ?2-λ", True),
    ("47e", IR8545, 2, r"March 2025", True),
    ("47f", IR8545, 18, r"simplifying assumption that the coordinates", True),
    ("47g", IR8545, 18, r"added a salt to mitigate multi-ciphertext attacks", True),
    ("36c", SP227, 2, r"September 2025", True),
    ("52", DVV, 1, r"LAC-128, the failure rate is 248 times big- ?ger than estimated", True),
    ("53a", DTVV, 1, r"in under 2 minutes using less than 216 decryption queries", True),
    ("53b", DTVV, 1, r"approximately 2400 decryption queries", True),
    ("40", DT26, 1, r"164\.810716", True),
    ("59", ZHOU, 1, r"at least 84 bits", True),
    ("60", MS24, 1, r"FFP-NG", True),
    ("61a", FLU, 1, r"drop in replacement", True),
    ("65a", BAR25, 13, r"ML-KEM 768 2-80 2-164 2-158 ML-KEM 1024 2-95 2-174 2-169", True),
    ("65b", BAR25, 13, r"FrodoKEM 640 2-138 - - FrodoKEM 976 2-199 - - FrodoKEM 1344 2-252", True),
    ("65-neg", BAR25, 13, r"ML-KEM 768 2-81 ", False),
    ("66a", BAR25, 12, r"optimal value for \S{2,6}is 296 in ML-KEM-768", True),
    ("66b", BAR25, 12, r"partial error probabilities of 2-81 and 2-82", True),
    ("66c", BAR25, 12, r"partial error probabilities of 2-96 and 2-97", True),
    ("67a", BAR25, 3, r"applies to ML-KEM is an open problem", True),
    ("67b", BAR25, 8, r"doesn.t require any heuristic approximations \(except for the ROM\)", True),
    ("72a", FWZ, 10, r"usually less than 40", True),
    ("72b", FWZ, 11, r"we only testes 300 samples for each parameter set", True),
    ("38", FWZ, 13, r"KYBER768 2-164 2-233 2-222 2-166 2-366", True),
    ("38b", FWZ, 1, r"for Kyber-1024, the failure probability of some public keys is worse than claimed", True),
    ("74a", DT26, 1, r"164\.82 is not certified", True),
    ("74b", DT26, 32, r"Generative AI disclosure", True),
    ("49", CFP, 15, r"no more than 264 chosen ciphertexts", True),
    ("41a", HHK, 10, r"δ1\(qG\) = qG · δ", True),
    ("41b", HHK, 1, r"\(qG \+ qP\) · δ instead of qG · δ", True),
    ("42a", KYB3, 20, r"4qROδ", True),
    ("42b", KYB3, 31, r"chance of 2-100 of a decapsulation failure in Kyber768", True),
    ("46d", IR8413, 39, r"on average over all keys and messages", True),
    ("56b", IR8413, 49, r"eliminating the possibility of random decryption failures", True),
    ("50a", LAC, 16, r"BCH\[511,256,41\]\+D2 256 1056 1024 1464 2-20\.01 2-302", True),
    ("51", LAC, 6, r"constant time BCH code for LAC-v3", True),
    ("54a", R5, 11, r"cannot be directly employed", True),
    ("54b", R5, 39, r"around 25% lower bandwidth", True),
    ("54c", R5, 5, r"avoid table look-ups and conditions", True),
    ("33", GJY, 1, r"one key among approximately 264 public keys with complexity 279, if the precomputation cost of 2162 is excluded", True),
    ("79a", NH2, 21, r"Dimension n 512 1024 Modulus q 12289 12289 Noise parameter k 8 8", True),
    ("79b", NH2, 21, r"Decryption error probability 2-213 2-216", True),
    ("79c", NH2, 20, r"encode one key bit into 4 coefficients", True),
    ("79d", NH2, 36, r"failure rate of less than 2-216 for NewHope1024", True),
    ("79e", NH2, 36, r"required generating about 4000 decryption requests", True),
    ("80a", ZHOU, 1, r"rely on oversimpli.{0,2}ed assumptions, rough approximations", True),
    ("80b", ZHOU, 1, r"approximate 15 bits decreasing for CNTR, 1 bit decreasing for Scloud\+", True),
    ("77a", DB22, 27, r"modest cost in ciphertext size", True),
    ("77b", DB22, 27, r"too low value for \|M\| could impact the security under traditional attacks", True),
    ("82", HHK, 7, r"PKE δ-correct if E\[ ?max m∈M Pr \[Dec\(sk, c\) ?̸? ?= m \| c ←Enc\(pk, m\)\]\] ≤ ?δ", True),
    ("84a", IR8413, 39, r"for δ ≤ ?2-, to apply this trans", True),
    ("84b", IR8413, 39, r"maximum decryption failure rate over all messages is difficult to compute", True),
    ("84c", IR8413, 2, r"July 2022 Includes updates as of 09-26-2022", True),
    ("89a", SHAO, 7, r"decryption failure probability δ 2-139\.1 2-25\.4 2-165\.2 2-50\.3 2-175\.2 2-47\.5", True),
    ("89b", SHAO, 1, r"practical decryption failure attack on Kyber512 in this scenario with a complexity of 237", True),
    ("89c", SHAO, 1, r"enhances the LWE hardness", True),
    ("89d", SHAO, 10, r"3000 × 225\.4 ≈ ?237", True),
    ("89-neg", SHAO, 7, r"2-25\.5", False),
    ("91a", DAS, 1, r"compared 1536 of 1568 bytes; the ARM64 NEON path compared roughly half", True),
    ("91b", DAS, 1, r"98\.0 % of the 2048 secret coefficients at 400 ciphertexts on AVX2, and 98\.5 % at 600 on NEON", True),
    ("91c", DAS, 7, r"a comparison routine should be tested on differences confined to its last bytes", True),
    ("91d", DAS, 2, r"CVE- ?2026-10097", True),
    ("92a", FLZ, 1, r"6\.537- ?7\.621 bits lower", True),
    ("92b", FLZ, 1, r"2,396 packing exits contain 26 message failures", True),
    ("92c", FLZ, 1, r"polynomial multiplication can create nontrivial dependence", True),
    ("50b", LAC, 16, r"128-v3a 512 251 Ψ 256 512 BCH\[255,128,17\]\+D2 128 544 512 704 2-22\.26 2-151", True),
    ("54d", R5, 1, r"Draft Friday 25th January, 2019", True),
    ("27d", ARV, 6, r"Chosen parameters 3 256 8192 2\.00 2\.00 2-119", True),
    ("45b", IR8413, 38, r"increased the binomial noise parameter η from 2 to 3", True),
    ("61b", GJS, 1, r"typically does not include the decoding error possibility", True),
    ("63", IR8413, 77, r"ASIACRYPT 2016, eds Cheon JH, Takagi T .{0,80}pp 789- ?815", True),
    ("32", FWZ, 13, r"Decryption failure attacks on IND-CCA secure lattice-based schemes\. IACR International Workshop on Public Key Cryptog- ?raphy\. pages 565-598", True),
    ("4-FIPS-T2", FIPS203, 48, r"ML-KEM-512 256 3329 2 3 2 10 4 128 ML-KEM-768 256 3329 3 2 2 10 4 192 ML-KEM-1024 256 3329 4 2 2 11 5 256", True),
]


def norm(t: str) -> str:
    t = t.replace("−", "-").replace("–", "-").replace("—", "-")
    for a, b in (("ﬁ", "fi"), ("ﬂ", "fl"), ("ﬀ", "ff"), ("ﬃ", "ffi"),
                 ("ﬄ", "ffl"), ("­", ""), ("’", "'")):
        t = t.replace(a, b)
    return re.sub(r"\s+", " ", t)


cache: dict = {}


def pages(fname: str):
    if fname not in cache:
        doc = pymupdf.open(os.path.join(PAPERS, fname))
        cache[fname] = [norm(doc[i].get_text()) for i in range(doc.page_count)]
    return cache[fname]


ok_all = True
n_pass = 0
for cid, fname, page, pat, must in CHECKS:
    try:
        pg = pages(fname)
    except Exception as exc:  # missing file
        print(f"[FAIL] claim {cid}: cannot open {fname}: {exc}")
        ok_all = False
        continue
    rx = re.compile(pat, re.I)
    hits = [i + 1 for i, t in enumerate(pg) if rx.search(t)]
    on_page = page in hits
    good = on_page if must else not on_page
    ok_all &= good
    n_pass += good
    kind = "found on" if must else "absent from"
    extra = "" if (must and on_page) or not must else f" (found on pages {hits[:6]})"
    print(f"[{'PASS' if good else 'FAIL'}] claim {cid}: /{pat[:70]}/ {kind} {fname} p.{page}{extra}")
print(f"\n{n_pass}/{len(CHECKS)} checks pass")
print("RESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
