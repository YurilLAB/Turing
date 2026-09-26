"""List the conditional jumps in selected functions of an x86-64 assembly file.

For the constant-time review (docs/11): source code without branches can
still compile to machine code with branches, so the release build is read
directly. Every conditional jump is printed with the instructions before it,
so each one can be traced to a public loop counter, length or bounds check,
or flagged as depending on data. The script only lists; a person judges.

    cargo rustc -p turing --release --lib -- --emit asm
    python tools/asm_branches.py target/release/deps/turing-<hash>.s \
        encrypt_block decrypt_block Turing3new feistel_round inv8 sub8 \
        apply16 apply_columns cshake256_secret

Negative control: an analysis build of the reference `linear::mix_columns_with`
shows 21 jumps that test single bits of state bytes.
"""
import re
import sys


def main():
    path, *wanted = sys.argv[1:]
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    # Function labels are mangled Rust symbols at column 0 ending with ':'.
    starts = [i for i, line in enumerate(lines) if re.match(r"^_ZN\S+:$", line)]
    starts.append(len(lines))
    for a, b in zip(starts, starts[1:]):
        name = lines[a][:-1]
        if not any(w in name for w in wanted):
            continue
        body = lines[a + 1 : b]
        code = [l.strip() for l in body if l.strip() and not l.strip().startswith((".", "#"))]
        jumps = [i for i, l in enumerate(code) if re.match(r"^j(?!mp\b)[a-z]+\s", l)]
        calls = sorted({l.split(None, 1)[1] for l in code if l.startswith("call")})
        print(f"=== {name}: {len(code)} instructions, {len(jumps)} conditional jumps")
        for c in calls:
            print(f"    calls {c}")
        for i in jumps:
            print("    " + " | ".join(code[max(0, i - 3) : i + 1]))


if __name__ == "__main__":
    main()
