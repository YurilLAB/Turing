/*
 * sc_fault_victim_rs_main.c: data set-up and printing for the Rust fault
 * victim (sc_fault_victim.rs). Same data, arguments and output format as
 * sc_fault_victim.c without the FLIPHOOK option:
 *   victim literal|ref|hardened invalid|valid|info
 * Output: "SS <hex>", and in mode "info" also "KR <hex>" and "RK <hex>".
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CTLEN 64
#define KLEN 32

void rs_tail_literal(uint8_t *ss, const uint8_t *ct, const uint8_t *cmp, const uint8_t *kr, const uint8_t *rk);
void rs_tail_ref(uint8_t *ss, const uint8_t *ct, const uint8_t *cmp, const uint8_t *kr, const uint8_t *rk);
void rs_tail_hardened(uint8_t *ss, const uint8_t *ct, const uint8_t *cmp, const uint8_t *kr, const uint8_t *rk);

uint8_t ct[CTLEN], cmpbuf[CTLEN], kr[KLEN], rk[KLEN];

static void hex(const char *tag, const uint8_t *x) {
  printf("%s ", tag);
  for (int i = 0; i < KLEN; i++) printf("%02x", x[i]);
  printf("\n");
}

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  uint64_t s = 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < CTLEN; i++) { s = s * 6364136223846793005ULL + 1; ct[i] = (uint8_t)(s >> 56); }
  for (int i = 0; i < KLEN; i++) { s = s * 6364136223846793005ULL + 1; kr[i] = (uint8_t)(s >> 56); }
  for (int i = 0; i < KLEN; i++) { s = s * 6364136223846793005ULL + 1; rk[i] = (uint8_t)(s >> 56); }
  memcpy(cmpbuf, ct, CTLEN);
  if (strcmp(argv[2], "valid") != 0)
    for (int i = 0; i < CTLEN; i++) { s = s * 6364136223846793005ULL + 1; cmpbuf[i] = (uint8_t)(s >> 56); }
  uint8_t ss[KLEN];
  memset(ss, 0, KLEN);
  if (!strcmp(argv[1], "literal")) rs_tail_literal(ss, ct, cmpbuf, kr, rk);
  else if (!strcmp(argv[1], "ref")) rs_tail_ref(ss, ct, cmpbuf, kr, rk);
  else if (!strcmp(argv[1], "hardened")) rs_tail_hardened(ss, ct, cmpbuf, kr, rk);
  else return 2;
  hex("SS", ss);
  if (!strcmp(argv[2], "info")) { hex("KR", kr); hex("RK", rk); }
  return 0;
}
