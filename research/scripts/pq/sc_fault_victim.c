/*
 * sc_fault_victim.c: the last step of a lattice-KEM decapsulation (compare
 * the received ciphertext with the re-encryption, then choose the real key
 * K' or the implicit-rejection key K-bar), in three orders, as a target for
 * fault simulation (driven by sc_fault_sim.py and sc_fault_sim.c).
 *
 * Variants (argv[1]):
 *   literal   FIPS 203 Algorithm 18 order (Sec. 6.3): the output first holds
 *             K', and is overwritten by K-bar "if c != c'". This is also the
 *             pqm4 round-3 pattern that Xagawa et al. (ASIACRYPT 2021,
 *             Sec. 5.3) defeated by skipping the cmov call.
 *   ref       pq-crystals/kyber ref/kem.c crypto_kem_dec on main (copy fetched
 *             2026-09-26): fail = verify(ct, cmp); ss = K-bar (rkprf);
 *             cmov(ss, kr, 32, !fail). This is the "default fail" order
 *             Xagawa et al. Sec. 7 recommend.
 *   hardened  written here (a design proposal, not from a paper): default
 *             fail; no 0/1 flag: the select mask is derived straight from the
 *             OR of all byte differences; then the difference is recomputed
 *             independently (after a compiler memory barrier, reverse order)
 *             and a second mask reverts the output to K-bar unless it is also
 *             zero. Getting K' out on an invalid ciphertext needs both checks
 *             to be defeated.
 * argv[2]: "invalid" (c != c', the case an attacker wants to turn into a
 *          real key) or "valid" (c == c').
 * argv[3] (only in the FLIPHOOK build): "none" or TARGET:BIT, where TARGET is
 *          fail | d1 | m1 | d2 | m2. The named variable gets bit BIT flipped
 *          right after it is computed (a single stored-bit fault such as the
 *          Rowhammer flip of the "fail" variable in Mondal et al., ACNS 2024).
 * Output: "SS <hex>" and, in mode "info", also "KR <hex>" and "RK <hex>".
 *
 * All victim code sits in the section "victim_text", so the fault simulator
 * can count and skip exactly these instructions.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VICTIM __attribute__((noinline, section("victim_text")))
#define CTLEN 64
#define KLEN 32

uint8_t ct[CTLEN], cmpbuf[CTLEN], kr[KLEN], rk[KLEN];

#ifdef FLIPHOOK
enum { T_NONE, T_FAIL, T_D1, T_M1, T_D2, T_M2 };
volatile int fault_target = T_NONE;
volatile int fault_bit = 0;
#define HOOK(tag, var)                                        \
  do {                                                        \
    if (fault_target == (tag)) (var) ^= (1u << fault_bit);    \
  } while (0)
#else
#define HOOK(tag, var) do { } while (0)
#endif

/* ref/verify.c verify(): returns 0 if equal, 1 otherwise. */
VICTIM int verify(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;
  uint8_t r = 0;
  for (i = 0; i < len; i++) r |= a[i] ^ b[i];
  return (-(uint64_t)r) >> 63;
}

/* ref/verify.c cmov() with the 7dff53d barrier: r = x if b == 1. */
VICTIM void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
  size_t i;
  __asm__("" : "+r"(b) : /* no inputs */);
  b = -b;
  for (i = 0; i < len; i++) r[i] ^= b & (r[i] ^ x[i]);
}

VICTIM void copy(uint8_t *dst, const uint8_t *src, size_t len) {
  for (size_t i = 0; i < len; i++) dst[i] = src[i];
}

VICTIM void tail_literal(uint8_t *ss) {
  int fail;
  copy(ss, kr, KLEN);                 /* K' already in the output */
  fail = verify(ct, cmpbuf, CTLEN);
  HOOK(T_FAIL, fail);
  cmov(ss, rk, KLEN, (uint8_t)fail);  /* overwrite with K-bar if c != c' */
}

VICTIM void tail_ref(uint8_t *ss) {
  int fail;
  fail = verify(ct, cmpbuf, CTLEN);
  HOOK(T_FAIL, fail);
  copy(ss, rk, KLEN);                 /* K-bar first */
  cmov(ss, kr, KLEN, (uint8_t)!fail); /* K' only if c == c' */
}

VICTIM void tail_hardened(uint8_t *ss) {
  size_t i;
  uint32_t d1 = 0, d2 = 0, m1, m2;
  copy(ss, rk, KLEN);                 /* default fail */
  for (i = 0; i < CTLEN; i++) d1 |= ct[i] ^ cmpbuf[i];
  HOOK(T_D1, d1);
  __asm__("" : "+r"(d1));
  m1 = ((uint32_t)(-d1) >> 31) - 1;   /* all ones iff d1 == 0 */
  HOOK(T_M1, m1);
  for (i = 0; i < KLEN; i++) ss[i] ^= (uint8_t)m1 & (ss[i] ^ kr[i]);
  __asm__ volatile("" ::: "memory");  /* forces the second pass to re-read */
  for (i = CTLEN; i-- > 0;) d2 |= cmpbuf[i] ^ ct[i];
  HOOK(T_D2, d2);
  __asm__("" : "+r"(d2));
  m2 = ((uint32_t)(-d2) >> 31) - 1;
  HOOK(T_M2, m2);
  for (i = 0; i < KLEN; i++) ss[i] ^= (uint8_t)~m2 & (ss[i] ^ rk[i]);
}

static void hex(const char *tag, const uint8_t *x) {
  printf("%s ", tag);
  for (int i = 0; i < KLEN; i++) printf("%02x", x[i]);
  printf("\n");
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s literal|ref|hardened invalid|valid|info [TARGET:BIT]\n", argv[0]);
    return 2;
  }
  uint64_t s = 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < CTLEN; i++) { s = s * 6364136223846793005ULL + 1; ct[i] = (uint8_t)(s >> 56); }
  for (int i = 0; i < KLEN; i++) { s = s * 6364136223846793005ULL + 1; kr[i] = (uint8_t)(s >> 56); }
  for (int i = 0; i < KLEN; i++) { s = s * 6364136223846793005ULL + 1; rk[i] = (uint8_t)(s >> 56); }
  memcpy(cmpbuf, ct, CTLEN);
  if (strcmp(argv[2], "valid") != 0)       /* invalid: re-encryption differs everywhere */
    for (int i = 0; i < CTLEN; i++) { s = s * 6364136223846793005ULL + 1; cmpbuf[i] = (uint8_t)(s >> 56); }
#ifdef FLIPHOOK
  if (argc > 3 && strcmp(argv[3], "none") != 0) {
    char t[8] = {0};
    int bit = 0;
    if (sscanf(argv[3], "%7[a-z0-9]:%d", t, &bit) != 2) return 2;
    fault_bit = bit;
    fault_target = !strcmp(t, "fail") ? T_FAIL : !strcmp(t, "d1") ? T_D1 : !strcmp(t, "m1") ? T_M1
                 : !strcmp(t, "d2") ? T_D2 : !strcmp(t, "m2") ? T_M2 : T_NONE;
  }
#endif
  uint8_t ss[KLEN];
  memset(ss, 0, KLEN);
  if (!strcmp(argv[1], "literal")) tail_literal(ss);
  else if (!strcmp(argv[1], "ref")) tail_ref(ss);
  else if (!strcmp(argv[1], "hardened")) tail_hardened(ss);
  else return 2;
  hex("SS", ss);
  if (!strcmp(argv[2], "info")) { hex("KR", kr); hex("RK", rk); }
  return 0;
}
