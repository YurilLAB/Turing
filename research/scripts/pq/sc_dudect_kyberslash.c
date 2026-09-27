/*
 * sc_dudect_kyberslash.c: would a dudect-style timing test have flagged
 * KyberSlash on this CPU?
 *
 * Reproduces the dudect method of Reparaz, Balasch, Verbauwhede, "Dude, is
 * my code constant time?", DATE 2017 (ePrint 2016/1123): measure the cycle
 * count of the function under test for two input classes, interleaved in a
 * random order; crop the measurements at a series of upper percentiles; run
 * Welch's t-test on every cropped set and on the raw set; report the largest
 * |t|. The paper treats |t| > 4.5 as strong evidence of a timing difference
 * (Sec. III). The percentile series follows the dudect reference code:
 * p_i = 1 - 0.5^(10 (i+1) / 100), i = 0..99. (Here the thresholds come from
 * all measurements rather than from a first batch; this only changes which
 * crops are tried.)
 *
 * Functions under test (copied from research/scripts/pq/ct_bugclasses.c,
 * which documents their pq-crystals/kyber origin):
 *   tomsg_div      pre-dda29cc poly_tomsg (KyberSlash1): (2t + 1664) / 3329
 *   compress4_div  pre-272125f poly_compress d=4 (KyberSlash2): (16u + 1664) / 3329
 *   tomsg_mul, compress4_mul   the multiply-shift fixes (negative controls)
 *   cmp_early      early-exit byte compare (positive control; the bug class
 *                  of Guo-Johansson-Nilsson CRYPTO 2020)
 * Compiled at gcc -Os the *_div functions contain a hardware divide on
 * x86-64 (KyberSlash Sec. 1.1; ct_bugclasses.py shows it on this machine);
 * at gcc -O2 they do not, which gives a second control.
 *
 * Usage: sc_dudect_kyberslash TEST NMEAS SEED
 *   TEST: tomsg_div_zero tomsg_div_high compress_div_zero compress_div_high
 *         tomsg_mul_zero compress_mul_zero cmp_early div64_calib
 * Prints: test name, measurements per class, mean cycles per class, raw t,
 * max |t| over crops, and the crop index where it occurred.
 * Deterministic inputs (xorshift64* PRNG seeded by SEED); timings are not.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

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

NOINLINE int cmp_early(const uint8_t *a, const uint8_t *b, size_t len) {
  for (size_t i = 0; i < len; i++)
    if (a[i] != b[i]) return 1;
  return 0;
}

/* Calibration (not from Kyber): 256 64-bit divisions by 3329 with a small or
 * a full-width dividend. If this is flagged, the harness can see division
 * timing on this CPU when it exists. */
NOINLINE uint64_t div64_calib(const uint64_t *x) {
  uint64_t acc = 0;
  for (int i = 0; i < N; i++) {
    uint64_t d = x[i];
    __asm__("" : "+r"(d));   /* keep a real div: no constant-divisor rewrite */
    uint64_t q = 3329;
    __asm__("" : "+r"(q));
    acc += d / q;
  }
  return acc;
}

static uint64_t rng_state;
static uint64_t rng(void) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  return rng_state * 0x2545F4914F6CDD1DULL;
}

static inline uint64_t cycles(void) {
  _mm_lfence();
  uint64_t t = __rdtsc();
  _mm_lfence();
  return t;
}

typedef struct { double n, mean, m2; } welford;
static void wpush(welford *w, double x) {
  w->n += 1;
  double d = x - w->mean;
  w->mean += d / w->n;
  w->m2 += d * (x - w->mean);
}
static double welch_t(const welford *a, const welford *b) {
  double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
  return (a->mean - b->mean) / sqrt(va / a->n + vb / b->n);
}
static int cmp_u64(const void *x, const void *y) {
  uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
  return (a > b) - (a < b);
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s TEST NMEAS SEED\n", argv[0]);
    return 2;
  }
  const char *test = argv[1];
  long nmeas = atol(argv[2]);
  rng_state = strtoull(argv[3], NULL, 10) | 1;

  enum { T_TOMSG_DIV, T_TOMSG_MUL, T_COMP_DIV, T_COMP_MUL, T_CMP, T_DIV64 } kind;
  int fixed_value = 0;
  if (!strcmp(test, "tomsg_div_zero")) { kind = T_TOMSG_DIV; fixed_value = 0; }
  else if (!strcmp(test, "tomsg_div_high")) { kind = T_TOMSG_DIV; fixed_value = 3300; }
  else if (!strcmp(test, "compress_div_zero")) { kind = T_COMP_DIV; fixed_value = 0; }
  else if (!strcmp(test, "compress_div_high")) { kind = T_COMP_DIV; fixed_value = 3300; }
  else if (!strcmp(test, "tomsg_mul_zero")) { kind = T_TOMSG_MUL; fixed_value = 0; }
  else if (!strcmp(test, "compress_mul_zero")) { kind = T_COMP_MUL; fixed_value = 0; }
  else if (!strcmp(test, "cmp_early")) { kind = T_CMP; }
  else if (!strcmp(test, "div64_calib")) { kind = T_DIV64; }
  else { fprintf(stderr, "unknown test %s\n", test); return 2; }

  /* Pre-generate inputs so that input generation is outside the timed region. */
  enum { BATCH = 4096 };
  static poly in[BATCH];
  static uint8_t cls[BATCH];
  static uint8_t ref[768], buf[BATCH][768];
  static uint64_t big[BATCH][N];
  for (int i = 0; i < 768; i++) ref[i] = (uint8_t)rng();

  uint64_t *meas = malloc(sizeof(uint64_t) * nmeas);
  uint8_t *mcls = malloc(nmeas);
  uint8_t out[128];
  volatile uint8_t sink = 0;

  for (long done = 0; done < nmeas; done += BATCH) {
    for (int b = 0; b < BATCH; b++) {
      cls[b] = rng() & 1;
      if (kind == T_DIV64) {
        for (int i = 0; i < N; i++)
          big[b][i] = cls[b] == 0 ? (rng() & 0xff) : (rng() | (1ULL << 63));
      } else if (kind == T_CMP) {
        if (cls[b] == 0) memcpy(buf[b], ref, 768);          /* equal: full scan */
        else for (int i = 0; i < 768; i++) buf[b][i] = (uint8_t)rng();
      } else {
        for (int i = 0; i < N; i++)
          in[b].coeffs[i] = cls[b] == 0 ? (int16_t)fixed_value
                                        : (int16_t)(rng() % Q);
      }
    }
    for (int b = 0; b < BATCH && done + b < nmeas; b++) {
      uint64_t t0 = cycles();
      switch (kind) {
        case T_TOMSG_DIV: tomsg_div(out, &in[b]); break;
        case T_TOMSG_MUL: tomsg_mul(out, &in[b]); break;
        case T_COMP_DIV: compress4_div(out, &in[b]); break;
        case T_COMP_MUL: compress4_mul(out, &in[b]); break;
        case T_CMP: out[0] = (uint8_t)cmp_early(buf[b], ref, 768); break;
        case T_DIV64: out[0] = (uint8_t)div64_calib(big[b]); break;
      }
      uint64_t t1 = cycles();
      sink ^= out[0];
      meas[done + b] = t1 - t0;
      mcls[done + b] = cls[b];
    }
  }

  /* Discard the first 1% as warm-up (dudect also drops early measurements). */
  long start = nmeas / 100;
  long m = nmeas - start;
  uint64_t *sorted = malloc(sizeof(uint64_t) * m);
  memcpy(sorted, meas + start, sizeof(uint64_t) * m);
  qsort(sorted, m, sizeof(uint64_t), cmp_u64);

  welford raw[2] = {{0}}, crop[100][2];
  memset(crop, 0, sizeof crop);
  uint64_t thr[100];
  for (int i = 0; i < 100; i++) {
    double p = 1.0 - pow(0.5, 10.0 * (i + 1) / 100.0);
    long idx = (long)(p * (double)m);
    if (idx >= m) idx = m - 1;
    thr[i] = sorted[idx];
  }
  for (long k = start; k < nmeas; k++) {
    double x = (double)meas[k];
    int c = mcls[k];
    wpush(&raw[c], x);
    for (int i = 0; i < 100; i++)
      if (meas[k] < thr[i]) wpush(&crop[i][c], x);
  }
  double traw = welch_t(&raw[0], &raw[1]);
  double tmax = fabs(traw);
  int imax = -1;
  for (int i = 0; i < 100; i++) {
    if (crop[i][0].n < 1000 || crop[i][1].n < 1000) continue;
    double t = fabs(welch_t(&crop[i][0], &crop[i][1]));
    if (t > tmax) { tmax = t; imax = i; }
  }
  printf("%-18s n0=%.0f n1=%.0f mean0=%.1f mean1=%.1f median=%llu raw_t=%.2f max_abs_t=%.2f at_crop=%d verdict=%s\n",
         test, raw[0].n, raw[1].n, raw[0].mean, raw[1].mean,
         (unsigned long long)sorted[m / 2], traw, tmax, imax,
         tmax > 4.5 ? "LEAK(|t|>4.5)" : "no-evidence");
  free(meas); free(mcls); free(sorted);
  return (int)(sink & 0);
}
