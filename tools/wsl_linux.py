"""Build Turing for Linux on Windows and run it in WSL.

The Linux code paths (mmap, mlock, MADV_DONTDUMP, MADV_WIPEONFORK, fork
detection, /proc/self/maps) never run in a Windows build. This makes
`cargo test --target x86_64-unknown-linux-gnu` work from Windows: rustc
compiles for Linux, this script links with the gcc inside WSL, and the test
binaries run inside WSL.

    rustup target add x86_64-unknown-linux-gnu
    python tools/wsl_linux.py test -p turing --lib

Everything after the script name is passed to cargo. The script sets
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER and _RUNNER to itself (through
tools/wsl_linux.cmd, since cargo needs an executable) and then acts as the
linker or the runner when cargo calls it back: the .cmd sets TURING_WSL_MODE,
and the runner's first argument is the word "run".
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "wsl_linux.cmd")
DRIVE = re.compile(r"([A-Za-z]):[\\/]")


def to_wsl(arg):
    """Rewrites every Windows path inside one argument as a /mnt path."""
    if not DRIVE.search(arg):
        return arg
    return DRIVE.sub(lambda m: f"/mnt/{m.group(1).lower()}/", arg).replace("\\", "/")


def expand(args):
    """Inlines rustc's GNU-style @response files (one argument per line,
    backslash escapes)."""
    out = []
    for a in args:
        if a.startswith("@") and os.path.isfile(a[1:]):
            text = open(a[1:], encoding="utf-8").read()
            for line in text.splitlines():
                out.append(re.sub(r"\\(.)", r"\1", line))
        else:
            out.append(a)
    return out


def link(args):
    args = [to_wsl(a) for a in expand(args)]
    out = next((args[i + 1] for i, a in enumerate(args) if a == "-o"), None)
    rsp_dir = os.path.join(HERE, "..", "target", "wsl-link")
    os.makedirs(rsp_dir, exist_ok=True)
    rsp = os.path.join(rsp_dir, f"{os.getpid()}.rsp")
    quote = lambda a: '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'
    with open(rsp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(quote(a) for a in args) + "\n")
    try:
        code = subprocess.call(["wsl.exe", "-e", "gcc", "@" + to_wsl(os.path.abspath(rsp))])
    finally:
        os.remove(rsp)
    if code != 0:
        print(f"wsl gcc failed for {out}", file=sys.stderr)
    return code


def run(args):
    binary, *rest = args
    return subprocess.call(["wsl.exe", "-e", to_wsl(os.path.abspath(binary)), *rest])


def main():
    mode = os.environ.get("TURING_WSL_MODE")
    if mode == "link":
        sys.exit(link(sys.argv[1:]))
    if mode == "run":
        sys.exit(run(sys.argv[2:]))
    env = dict(os.environ)
    env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"] = WRAPPER
    env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER"] = WRAPPER + " run"
    cargo = sys.argv[1:]
    if "--target" not in cargo:
        cargo[1:1] = ["--target", "x86_64-unknown-linux-gnu"]
    sys.exit(subprocess.call(["cargo", *cargo], env=env))


if __name__ == "__main__":
    main()
