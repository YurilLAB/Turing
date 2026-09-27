"""sc_varlat_patch_ops.py - list the VEX IR operations that the KyberSlash
Valgrind patch checks for secret ("undefined") operands.

Source reproduced: valgrind-varlat-patch-20250805.txt from
https://kyberslash.cr.yp.to/ (KyberSlash paper, TCHES 2025(2), Sec. 7.1.1
says the patch covers "sdiv or udiv on AArch64, or idiv or div on x86-64",
with "preliminary support for catching other variable-latency instructions").
This script answers: which operations exactly?

Method: in the patch's memcheck/mc_translate.c hunks, collect the `case Iop_*:`
labels that fall through to an added (`+`) line calling
complainIfVariableLatency(mce, ...). Also reports whether any multiply
operation or scalar floating-point division is named anywhere in the patch.

Usage: python sc_varlat_patch_ops.py PATH/valgrind-varlat-patch-20250805.txt
Deterministic: pure text processing.
"""
import hashlib
import re
import sys


def main(path):
    raw = open(path, "rb").read()
    print("patch sha256:", hashlib.sha256(raw).hexdigest())
    lines = raw.decode("utf-8", errors="replace").splitlines()
    ops, pending, calls = set(), [], 0
    for line in lines:
        m = re.match(r"^[+ ]\s*case (Iop_\w+):", line)
        if m:
            pending.append(m.group(1))
            continue
        if line.startswith("+") and "complainIfVariableLatency(mce" in line:
            calls += 1
            ops.update(pending)
        if re.match(r"^[+ -]\s*(return|break)\b", line) or line.startswith("@@"):
            pending = []
    print("added complainIfVariableLatency call sites:", calls)
    print("IR ops checked for secret operands:", len(ops))
    groups = {
        "integer divide / modulo": [o for o in ops if re.match(r"Iop_(Div(S|U|Mod)|Mod)", o)],
        "floating-point divide (vector/lane forms)": [o for o in ops if re.match(r"Iop_Div\d+F", o)],
        "x87 floating-point remainder": [o for o in ops if o.startswith("Iop_PRem")],
        "square root": [o for o in ops if o.startswith("Iop_Sqrt")],
    }
    covered = set()
    for name, members in groups.items():
        covered.update(members)
        print(f"  {name} ({len(members)}): {', '.join(sorted(members))}")
    other = ops - covered
    print("  other:", sorted(other) if other else "none")
    text = "\n".join(lines)
    mul_named = sorted(set(re.findall(r"Iop_Mul\w*|Iop_Mull\w*", text)))
    print("multiply ops named anywhere in the patch (context lines included):", mul_named)
    mul_checked = [o for o in ops if "Mul" in o]
    print("multiply ops that get a variable-latency check:", mul_checked if mul_checked else "none")
    scalar_fdiv = sorted(set(re.findall(r"Iop_DivF(?:16|32|64|128)\b", text)))
    print("scalar Iop_DivF32/F64 named in the patch:", scalar_fdiv if scalar_fdiv else "none")
    ok = calls > 0 and any(o.startswith("Iop_DivU32") for o in ops) and not mul_checked
    print("CHECK integer division covered, multiplication not covered:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
