/*
 * sc_fault_sim.c: exhaustive single-instruction-skip fault simulation on a
 * real x86-64 Linux binary, using ptrace (no emulator needed).
 *
 * Fault model: the "instruction skip" of Xagawa et al. (ASIACRYPT 2021) and
 * Pessl-Prokop (TCHES 2021(2)): one dynamic instruction is not executed,
 * everything else runs normally. For every dynamic instruction k executed in
 * the victim's code range [START, END) during one call of the function at
 * ENTRY, the victim is run once with instruction k skipped.
 *
 * Method: fork + PTRACE_TRACEME + execv; a breakpoint (int3) at ENTRY; from
 * there single-step, counting instructions whose address lies in
 * [START, END); at count k set RIP to the next instruction (lengths from
 * LENFILE, produced from objdump by sc_fault_sim.py) instead of executing
 * it; then let the victim run to completion (2 s alarm) and capture stdout.
 *
 * Usage: sc_fault_sim VICTIM ENTRY START END LENFILE K ARGS...
 *   ENTRY/START/END in hex; K = -1 for a fault-free run that prints the
 *   number of in-range dynamic instructions ("DYN n").
 * Output: the victim's stdout, then "EXIT <status>" or "SIGNAL <n>".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXI 65536
static uint64_t iaddr[MAXI];
static int ilen[MAXI];
static int ni;

static int len_at(uint64_t a) {
  int lo = 0, hi = ni - 1;
  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    if (iaddr[mid] == a) return ilen[mid];
    if (iaddr[mid] < a) lo = mid + 1; else hi = mid - 1;
  }
  return -1;
}

int main(int argc, char **argv) {
  if (argc < 7) {
    fprintf(stderr, "usage: %s VICTIM ENTRY START END LENFILE K ARGS...\n", argv[0]);
    return 2;
  }
  uint64_t entry = strtoull(argv[2], NULL, 16);
  uint64_t start = strtoull(argv[3], NULL, 16);
  uint64_t end = strtoull(argv[4], NULL, 16);
  long k = atol(argv[6]);
  FILE *lf = fopen(argv[5], "r");
  if (!lf) { perror("lenfile"); return 2; }
  unsigned long long a;
  int l;
  while (ni < MAXI && fscanf(lf, "%llx %d", &a, &l) == 2) { iaddr[ni] = a; ilen[ni] = l; ni++; }
  fclose(lf);

  int pfd[2];
  if (pipe(pfd)) { perror("pipe"); return 2; }
  pid_t pid = fork();
  if (pid == 0) {
    dup2(pfd[1], 1);
    close(pfd[0]);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    alarm(2);                      /* survives execve: bounds a looping victim */
    char **vargv = calloc(argc, sizeof(char *));
    vargv[0] = argv[1];
    for (int i = 7; i < argc; i++) vargv[i - 6] = argv[i];
    execv(argv[1], vargv);
    _exit(127);
  }
  close(pfd[1]);
  int st;
  waitpid(pid, &st, 0);            /* stopped at exec */

  errno = 0;
  long orig = ptrace(PTRACE_PEEKTEXT, pid, (void *)entry, 0);
  if (errno) { perror("peek"); return 2; }
  ptrace(PTRACE_POKETEXT, pid, (void *)entry, (void *)((orig & ~0xffL) | 0xcc));
  ptrace(PTRACE_CONT, pid, 0, 0);
  waitpid(pid, &st, 0);
  if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) { fprintf(stderr, "no breakpoint hit\n"); return 2; }
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, 0, &regs);
  ptrace(PTRACE_POKETEXT, pid, (void *)entry, (void *)orig);
  regs.rip = entry;
  ptrace(PTRACE_SETREGS, pid, 0, &regs);
  uint64_t retaddr = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rsp, 0);
  uint64_t entry_rsp = regs.rsp;

  long count = 0;
  int skipped = 0, delivered = 0;
  uint64_t skipped_at = 0;
  for (;;) {
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (regs.rip == retaddr && regs.rsp > entry_rsp) break;   /* returned from ENTRY */
    if (regs.rip >= start && regs.rip < end) {
      if (count == k) {
        int len = len_at(regs.rip);
        if (len <= 0) { fprintf(stderr, "no length for %llx\n", (unsigned long long)regs.rip); kill(pid, SIGKILL); return 2; }
        skipped_at = regs.rip;
        regs.rip += len;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        skipped = 1;
        count++;
        break;
      }
      count++;
    }
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) || WIFSIGNALED(st)) { delivered = 1; break; }
    if (WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP) {         /* crash or alarm while stepping */
      ptrace(PTRACE_CONT, pid, 0, (void *)(long)WSTOPSIG(st));
      waitpid(pid, &st, 0);
      delivered = 1;
      break;
    }
    if (count > 1000000) { kill(pid, SIGKILL); waitpid(pid, &st, 0); delivered = 1; break; }
  }
  if (!delivered) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    for (;;) {
      waitpid(pid, &st, 0);
      if (WIFEXITED(st) || WIFSIGNALED(st)) break;
      if (WIFSTOPPED(st)) ptrace(PTRACE_CONT, pid, 0, (void *)(long)(WSTOPSIG(st) == SIGTRAP ? 0 : WSTOPSIG(st)));
    }
  }
  char buf[8192];
  ssize_t n, tot = 0;
  while ((n = read(pfd[0], buf + tot, sizeof buf - 1 - tot)) > 0) tot += n;
  buf[tot] = 0;
  fputs(buf, stdout);
  if (k < 0) printf("DYN %ld\n", count);
  if (skipped) printf("SKIPPED %llx\n", (unsigned long long)skipped_at);
  if (WIFEXITED(st)) printf("EXIT %d\n", WEXITSTATUS(st));
  else if (WIFSIGNALED(st)) printf("SIGNAL %d\n", WTERMSIG(st));
  else printf("SIGNAL ?\n");
  return 0;
}
