/*
 * ct_bugclasses.c: small, self-contained reproductions of the timing bug
 * classes found in lattice-KEM code, for the constant-time notes in
 * research/notes/pq/side-channels-faults-and-ct-verification.md.
 * Driven by ct_bugclasses.py (compiles with gcc/clang at several -O levels,
 * disassembles, and runs each case under Valgrind memcheck with the secret
 * input marked undefined, the ctgrind/TIMECOP method).
 *
 * Sources of the code (all pq-crystals/kyber, ref/):
 *   tomsg_div      poly_tomsg before commit dda29cc (2023-12-01), KyberSlash1;
 *                  same text as Figure 2 of Bernstein et al., TCHES 2025(2).
 *   tomsg_mul      poly_tomsg after dda29cc (current main).
 *   compress4_div  poly_compress (d=4) before commit 272125f (2023-12-29),
 *                  KyberSlash2; Figure 4 of the KyberSlash paper.
 *   compress4_mul  poly_compress (d=4) on current main.
 *   frommsg_mask   poly_frommsg before commit 0264efa (2024-06-03), the
 *                  code Clangover (Purnal 2024) attacked.
 *   frommsg_cmov   poly_frommsg + cmov_int16 with the asm value barrier
 *                  (commits 0264efa and 7dff53d).
 *   frommsg_cmov_nobar  the same without the barrier (0264efa alone),
 *                  compiled in one translation unit with its caller.
 *   verify_ct      verify() from ref/verify.c.
 * Written here for the demonstration (not copied):
 *   cmp_early      byte compare that returns at the first difference (the
 *                  bug class of the FrodoKEM timing attack, Guo-Johansson-
 *                  Nilsson CRYPTO 2020, which used memcmp).
 *   table_lookup   secret-indexed table read (cache-timing class).
 *   rej_uniform    ref/indcpa.c rej_uniform; run once with the input buffer
 *                  marked secret (as TIMECOP 2 marks all RNG output) and
 *                  once declassified (the seed rho is public in ML-KEM).
 *
 * Usage: ct_bugclasses CASE      (runs one case on poisoned secret data)
 *        ct_bugclasses selftest  (exhaustive equality of the fixed code
 *                                 against the division code, no Valgrind)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <valgrind/memcheck.h>

#define N 256
#define Q 3329
#define NOINLINE __attribute__((noinline))

typedef struct { int16_t coeffs[N]; } poly;

NOINLINE void tomsg_div(uint8_t msg[32], const poly *a) {
  unsigned int i, j;
  uint16_t t;
  for (i = 0; i < N / 8; i++) {
    msg[i] = 0;
    for (j = 0; j < 8; j++) {
      t = a->coeffs[8 * i + j];
      t += ((int16_t)t >> 15) & Q;
      t = (((t << 1) + Q / 2) / Q) & 1;
      msg[i] |= t << j;
    }
  }
}

NOINLINE void tomsg_mul(uint8_t msg[32], const poly *a) {
  unsigned int i, j;
  uint32_t t;
  for (i = 0; i < N / 8; i++) {
    msg[i] = 0;
    for (j = 0; j < 8; j++) {
      t = a->coeffs[8 * i + j];
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] |= t << j;
    }
  }
}

NOINLINE void compress4_div(uint8_t r[128], const poly *a) {
  unsigned int i, j;
  int16_t u;
  uint8_t t[8];
  for (i = 0; i < N / 8; i++) {
    for (j = 0; j < 8; j++) {
      u = a->coeffs[8 * i + j];
      u += (u >> 15) & Q;
      t[j] = ((((uint16_t)u << 4) + Q / 2) / Q) & 15;
    }
    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
}

NOINLINE void compress4_mul(uint8_t r[128], const poly *a) {
  unsigned int i, j;
  int16_t u;
  uint32_t d0;
  uint8_t t[8];
  for (i = 0; i < N / 8; i++) {
    for (j = 0; j < 8; j++) {
      u = a->coeffs[8 * i + j];
      u += (u >> 15) & Q;
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }
    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
}

NOINLINE void frommsg_mask(poly *r, const uint8_t msg[32]) {
  unsigned int i, j;
  int16_t mask;
  for (i = 0; i < N / 8; i++) {
    for (j = 0; j < 8; j++) {
      mask = -(int16_t)((msg[i] >> j) & 1);
      r->coeffs[8 * i + j] = mask & ((Q + 1) / 2);
    }
  }
}

static inline void cmov_int16(int16_t *r, int16_t v, uint16_t b) {
  __asm__("" : "+r"(b) : /* no inputs */);
  b = -b;
  *r ^= b & ((*r) ^ v);
}

NOINLINE void frommsg_cmov(poly *r, const uint8_t msg[32]) {
  unsigned int i, j;
  for (i = 0; i < N / 8; i++) {
    for (j = 0; j < 8; j++) {
      r->coeffs[8 * i + j] = 0;
      cmov_int16(r->coeffs + 8 * i + j, ((Q + 1) / 2), (msg[i] >> j) & 1);
    }
  }
}

/* cmov_int16 as committed in 0264efa (2024-06-03), without the asm value
   barrier that 7dff53d (2026-07-28) added. The commit message of 7dff53d says
   the barrier stops the compiler "inferring that b is 0/1-valued" and
   "handling the two cases with a branch", which matters when cmov_int16 and
   its caller end up in one translation unit, as here. */
static inline void cmov_int16_nobar(int16_t *r, int16_t v, uint16_t b) {
  b = -b;
  *r ^= b & ((*r) ^ v);
}

NOINLINE void frommsg_cmov_nobar(poly *r, const uint8_t msg[32]) {
  unsigned int i, j;
  for (i = 0; i < N / 8; i++) {
    for (j = 0; j < 8; j++) {
      r->coeffs[8 * i + j] = 0;
      cmov_int16_nobar(r->coeffs + 8 * i + j, ((Q + 1) / 2), (msg[i] >> j) & 1);
    }
  }
}

NOINLINE int verify_ct(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;
  uint8_t r = 0;
  for (i = 0; i < len; i++) r |= a[i] ^ b[i];
  return (-(uint64_t)r) >> 63;
}

NOINLINE int cmp_early(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    if (a[i] != b[i]) return 1;
  return 0;
}

static const uint8_t TABLE[256] = {
#define R8(x) x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7
    R8(0), R8(8), R8(16), R8(24), R8(32), R8(40), R8(48), R8(56),
    R8(64), R8(72), R8(80), R8(88), R8(96), R8(104), R8(112), R8(120),
    R8(128), R8(136), R8(144), R8(152), R8(160), R8(168), R8(176), R8(184),
    R8(192), R8(200), R8(208), R8(216), R8(224), R8(232), R8(240), R8(248)};

NOINLINE void table_lookup(uint8_t *out, const uint8_t *in, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) out[i] = TABLE[(uint8_t)(in[i] * 167 + 13)];
}

NOINLINE unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf,
                                  unsigned int buflen) {
  unsigned int ctr, pos;
  uint16_t val0, val1;
  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
    val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
    pos += 3;
    if (val0 < Q) r[ctr++] = val0;
    if (ctr < len && val1 < Q) r[ctr++] = val1;
  }
  return ctr;
}

/* Deterministic filler (xorshift32), so every run sees the same data. */
static uint32_t rng_state = 0x12345678u;
static uint32_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

static uint32_t checksum(const void *p, size_t n) {
  const uint8_t *b = p;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
  return h;
}

#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))

static int selftest(void) {
  /* Exhaustive: the division code and the multiply-shift code must agree on
     every coefficient value the callers can pass. poly_reduce in the current
     reference code returns centred values in [-(q-1)/2, (q-1)/2]; older code
     and other callers use [0, q). Both ranges are checked, plus the whole
     int16 range to show where the shortcut stops being valid. */
  poly a, b;
  uint8_t m1[32], m2[32], c1[128], c2[128];
  long bad_center = 0, bad_canon = 0, bad_all = 0, bad_c4 = 0, n_c4 = 0;
  for (int x = -32768; x <= 32767; x++) {
    for (int k = 0; k < N; k++) a.coeffs[k] = (int16_t)x;
    tomsg_div(m1, &a);
    tomsg_mul(m2, &a);
    int differ = memcmp(m1, m2, 32) != 0;
    if (differ) bad_all++;
    if (differ && x >= -(Q - 1) / 2 && x <= (Q - 1) / 2) bad_center++;
    if (differ && x >= 0 && x < Q) bad_canon++;
    if (x > -Q && x < Q) {
      compress4_div(c1, &a);
      compress4_mul(c2, &a);
      n_c4++;
      if (memcmp(c1, c2, 128) != 0) bad_c4++;
    }
  }
  printf("tomsg: mismatches centred [-(q-1)/2,(q-1)/2]: %ld of %d\n", bad_center, Q);
  printf("tomsg: mismatches canonical [0,q): %ld of %d\n", bad_canon, Q);
  printf("tomsg: mismatches over all int16: %ld of 65536\n", bad_all);
  printf("compress d=4: mismatches over (-q,q): %ld of %ld\n", bad_c4, n_c4);
  /* Negative control: a deliberately wrong constant must be caught. */
  {
    long caught = 0;
    for (int x = 0; x < Q; x++) {
      uint32_t t = (uint32_t)x;
      uint32_t good = ((((uint16_t)x << 1) + Q / 2) / Q) & 1;
      uint32_t bad = (((t << 1) + 1665) * 80636 >> 28) & 1; /* 80636, not 80635 */
      if (good != bad) caught++;
    }
    printf("negative control (constant 80636): %ld mismatches found in [0,q)\n", caught);
  }
  return (bad_center || bad_c4) ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s CASE|selftest\n", argv[0]);
    return 2;
  }
  const char *c = argv[1];
  if (!strcmp(c, "selftest")) return selftest();

  poly a, r;
  uint8_t msg[32], out[128], x[64], y[64];
  int16_t coeffs[N];
  uint8_t buf[504];
  uint32_t h = 0;
  for (int k = 0; k < N; k++) a.coeffs[k] = (int16_t)(rnd() % Q) - (Q - 1) / 2;
  for (int k = 0; k < 32; k++) msg[k] = (uint8_t)rnd();
  for (int k = 0; k < 64; k++) x[k] = y[k] = (uint8_t)rnd();
  x[40] ^= 1; /* x and y differ at byte 40 */
  for (size_t k = 0; k < sizeof buf; k++) buf[k] = (uint8_t)rnd();

  if (!strcmp(c, "tomsg_div")) {
    SECRET(&a, sizeof a); tomsg_div(msg, &a); DECLASSIFY(msg, 32); h = checksum(msg, 32);
  } else if (!strcmp(c, "tomsg_mul")) {
    SECRET(&a, sizeof a); tomsg_mul(msg, &a); DECLASSIFY(msg, 32); h = checksum(msg, 32);
  } else if (!strcmp(c, "compress4_div")) {
    SECRET(&a, sizeof a); compress4_div(out, &a); DECLASSIFY(out, 128); h = checksum(out, 128);
  } else if (!strcmp(c, "compress4_mul")) {
    SECRET(&a, sizeof a); compress4_mul(out, &a); DECLASSIFY(out, 128); h = checksum(out, 128);
  } else if (!strcmp(c, "frommsg_mask")) {
    SECRET(msg, 32); frommsg_mask(&r, msg); DECLASSIFY(&r, sizeof r); h = checksum(&r, sizeof r);
  } else if (!strcmp(c, "frommsg_cmov")) {
    SECRET(msg, 32); frommsg_cmov(&r, msg); DECLASSIFY(&r, sizeof r); h = checksum(&r, sizeof r);
  } else if (!strcmp(c, "frommsg_cmov_nobar")) {
    SECRET(msg, 32); frommsg_cmov_nobar(&r, msg); DECLASSIFY(&r, sizeof r); h = checksum(&r, sizeof r);
  } else if (!strcmp(c, "verify_ct")) {
    SECRET(x, 64); int v = verify_ct(x, y, 64); DECLASSIFY(&v, sizeof v); h = (uint32_t)v;
  } else if (!strcmp(c, "cmp_early")) {
    SECRET(x, 64); int v = cmp_early(x, y, 64); DECLASSIFY(&v, sizeof v); h = (uint32_t)v;
  } else if (!strcmp(c, "table_lookup")) {
    SECRET(x, 64); table_lookup(out, x, 64); DECLASSIFY(out, 64); h = checksum(out, 64);
  } else if (!strcmp(c, "rej_secret")) {
    SECRET(buf, sizeof buf);
    unsigned n = rej_uniform(coeffs, N, buf, sizeof buf);
    DECLASSIFY(&n, sizeof n); DECLASSIFY(coeffs, sizeof coeffs); h = n ^ checksum(coeffs, sizeof coeffs);
  } else if (!strcmp(c, "rej_public")) {
    unsigned n = rej_uniform(coeffs, N, buf, sizeof buf);
    h = n ^ checksum(coeffs, sizeof coeffs);
  } else {
    fprintf(stderr, "unknown case %s\n", c);
    return 2;
  }
  printf("%s %08x\n", c, h);
  return 0;
}
