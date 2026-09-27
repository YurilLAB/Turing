# Fact-check audit trail: hybrid-combiners.md (lens: mathematics and reasoning)

Independent check of D:/Dev/Turing/research/notes/pq/hybrid-combiners.md,
2026-09-27. Lens: derivations, formulas, worked examples, the author's scripts,
security arguments and conclusions. Own script:
research/scripts/pq/check_hybrid-combiners_reasoning.py.
Logs of script runs: scratch pq/hyb-reason/*.log.

Status codes: OK | WRONG (with correction) | UNVERIFIABLE (with reason).
Severity for WRONG rows: critical / major / minor.

## Progress log

- Created skeleton. Read the whole notes file (1318 lines).
- Re-ran the author's four scripts with timeouts (all exit 0, ALL CHECKS PASSED):
  hybrid_combiner_checks.py (57 PASS, 0 FAIL), hyb_worked_examples.py,
  hyb_factcheck_math.py, hyb_x25519_torsion.py. Logs in scratch pq/hyb-reason/.
- Read GHP18 pp. 6-10, 21-23; ABK25 pp. 1-5, 7-8, 14-16; X-Wing paper pp. 4, 9, 13, 16-18;
  Bindel et al. 2019 pp. 5, 11, 16.

## Claim check table

| # | claim (quote or paraphrase) | status | evidence |
|---|---|---|---|
| 1 | GHP18 Theorem 1: Adv ≤ 2·(Adv_IND-CCA(K_i)(B) + Adv_skPRF(W,i)(C)), C makes ≤ q_d+1 Eval queries (p. 10) | OK | 2018-giacon-heuer-poettering-kem-combiners.pdf PDF p. 10 |
| 2 | GHP18 proof assumes perfectly correct KEMs (p. 10) | OK | same, p. 10 "Noting that the KEMs we consider are perfectly correct" |
| 3 | GHP18 Lemma 1 XOR keeps CPA; Lemma 2 one query breaks CCA with one bad ingredient (p. 7) | OK | PDF p. 7; Lemma 2 advantage 1 − 1/|K| |
| 4 | GHP18 Remark (strip FO, XOR, one FO) and reasons not pursued (p. 7) | OK | PDF p. 7 |
| 5 | GHP18 Lemma 6: Adv ≤ q_H·ε (p. 22); Example 3 concatenation almost uniform | OK (note) | PDF pp. 21-22. The paper prints "1/|K|-almost uniform" for Example 3; per-slot ε is 1/|K_i|, which is what the notes use (2^-256 for a 256-bit k_i). Math OK. |
| 6 | GHP18 Fig. 4 line 15 "If k_i = ⊥: Return ⊥" | OK | PDF p. 6 |
| 7 | Bindel et al. Theorem 2 bound 2·(min{Adv K1, Adv K2} + Adv_dPRF + Adv_PRF) (p. 16) | OK | 2019-bindel-et-al-...pdf PDF p. 16 |
| 8 | Bindel et al. mix-and-match on XOR even with both KEMs IND-CCA (p. 11) | OK | PDF p. 11 |
| 9 | X-Wing Theorem 1: Adv ≤ 2Δ_N + Adv_SDH + Adv_C2PRI, classical ROM (p. 9) | OK | 2024-barbosa-et-al-x-wing-hybrid-kem.pdf PDF p. 9 |
| 10 | X-Wing Theorem 2: 2 IND-CCA + 2 PRF terms + 2δ, standard model, "follows closely ... [GHP18, Theorem 1]" (p. 13) | OK | PDF p. 13; H a PRF when keyed on k1 |
| 11 | X-Wing Theorem 3: ML-KEM-768 C2PRI ≤ (q_g + q_j + 2)/2^256, G and J classical ROs (pp. 16-17) | OK | PDF pp. 16-17 |
| 12 | X-Wing p. 4 quotes (pk_X for multi-target; X25519 not C2PRI) | OK | PDF p. 4 |
| 13 | ABK25 Theorem 1 informal: two bounds (C2PRI(KEM1)+IND-CCA(KEM2)+skPRF+δ; IND-CCA(KEM1)+skPRF+δ), ×2 (p. 3) | OK | 2025-alagic-bajaj-kocoglu-...pdf PDF p. 3 |
| 14 | ABK25 Theorem 2 informal: secrets-only with dual PRF is IND-CCA if KEM1 IND-CCA and KEM2 C2PRI or vice versa (p. 3) | OK (note) | PDF p. 3 says this; p. 2 and p. 8 say "provided both KEMs satisfy C2PRI" (Theorem 6 "by symmetry"). The notes follow p. 3; the formal route (Theorem 6) is the "both C2PRI" reading. Not an error in the notes' use. |
| 15 | ABK25 Theorem 3/8 (n KEMs, omitted ciphertexts need C2PRI, ×2 bound, δ) and "Proof sketch" only (p. 15) | OK | PDF pp. 3, 15 |
| 16 | ABK25 submitted to TCC 2025 except Secs 3.3 and 4 (p. 5) | OK | PDF p. 5 |
| 17 | ABK25 Theorem 4/9: 4·sqrt((q²+q)/|K_i|) (pp. 4, 15) | OK | PDF pp. 4, 15 |
| 18 | ABK25 Theorem 5: (q+1)/|K| ROM; 4·sqrt((q²+q)/|K|) QROM; BIKE directly; adapted to McEliece, HQC, ML-KEM (p. 4) | OK | PDF p. 4 |
| 19 | Theorem 9 bound reaches 1 at q = 2^126 / 2^94 / 2^62 for 256/192/128-bit secrets | OK (COMPUTED) | hyb_factcheck_math.py part 4 re-run; 4q/2^(b/2) = 1 ⇒ q = 2^(b/2−2) |
| 20 | 3 × 2^256 = 2^257.6 ("only log2(3) = 1.6 bits more") | OK (COMPUTED) | hyb_factcheck_math.py part 7: 2^257.585 |
| 21 | Author script hybrid_combiner_checks.py: 57 PASS, 0 FAIL | OK | re-run, scratch pq/hyb-reason/checks.log |
| 22 | Worked XOR example 0x3a XOR 0xc5 = 0xff; answers 0xd4, 0x4d | OK | hyb_worked_examples.py part 1 re-run |
| 23 | Cost table rows (pk, ct, KDF input, Keccak-f) | OK except note | recomputed in check script; UG row KDF input 2416 has no 4-byte counter although the table note says the counter is counted (2420 with it; Keccak-f 18 either way) |

## Issues (to be returned)

(being collected; see rows marked WRONG)
