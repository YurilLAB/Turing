"""Run a Linux tool (gcc as C compiler or linker, ar) inside WSL on behalf of a Windows cargo build.

Topic rust-pqc-implementations (research/notes/pq/rust-pqc-implementations.md, Sec. 5): used to
build the scratch probe research/scripts/pq/rpi_oracle_probe.rs for x86_64-unknown-linux-gnu from the
Windows Rust toolchain (rustup target x86_64-unknown-linux-gnu is installed on the Windows host; WSL has
gcc but no Rust). The same idea as the repository's tools/wsl_linux.py, re-implemented here because
research scripts may not write into the repository (that tool writes response files under target/).

What it does: expands GNU-style @response files, rewrites every Windows path (C:\\... or C:/...) as
/mnt/c/..., turns remaining backslashes in path-like arguments into slashes, and runs
`wsl.exe -e TOOL ARGS...`. Nothing else. The exit code of the tool is returned.

Cargo needs executables, so small .cmd wrappers call this script, e.g. rpi-wsl-gcc.cmd:
    @python "D:\\Dev\\Turing\\research\\scripts\\pq\\rpi_wsl_tool.py" gcc %*
and the build is run with
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=...\\rpi-wsl-gcc.cmd
    CC_x86_64_unknown_linux_gnu=...\\rpi-wsl-gcc.cmd  AR_x86_64_unknown_linux_gnu=...\\rpi-wsl-ar.cmd
    cargo build --release --target x86_64-unknown-linux-gnu
Response files are written to the system temp directory (outside the repository) and deleted after use.
"""
import os
import re
import subprocess
import sys
import tempfile

DRIVE = re.compile(r"([A-Za-z]):[\\/]")
TOOLS = {"gcc", "ar", "g++"}


def to_wsl(arg):
    if DRIVE.search(arg):
        arg = DRIVE.sub(lambda m: f"/mnt/{m.group(1).lower()}/", arg)
        return arg.replace("\\", "/")
    # relative paths from the cc crate, e.g. pqclean\crypto_kem\ml-kem-512\clean\verify.c
    if "\\" in arg and not arg.startswith("-D"):
        return arg.replace("\\", "/")
    if arg.startswith("-I") and "\\" in arg:
        return arg.replace("\\", "/")
    return arg


def expand(args):
    out = []
    for a in args:
        if a.startswith("@") and os.path.isfile(a[1:]):
            text = open(a[1:], encoding="utf-8").read()
            for line in text.splitlines():
                line = line.strip()
                if len(line) >= 2 and line[0] == '"' and line[-1] == '"':
                    line = line[1:-1]
                out.append(re.sub(r"\\(.)", r"\1", line))
        else:
            out.append(a)
    return out


def main():
    tool = sys.argv[1]
    if tool not in TOOLS:
        print(f"rpi_wsl_tool: unsupported tool {tool}", file=sys.stderr)
        return 2
    args = [to_wsl(a) for a in expand(sys.argv[2:])]
    if tool == "gcc" and len(" ".join(args)) > 6000:
        # long link lines: pass them through a response file that WSL gcc reads
        fd, rsp = tempfile.mkstemp(suffix=".rsp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join('"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"' for a in args) + "\n")
        try:
            return subprocess.call(["wsl.exe", "-e", "gcc", "@" + to_wsl(rsp)])
        finally:
            os.remove(rsp)
    return subprocess.call(["wsl.exe", "-e", tool, *args])


if __name__ == "__main__":
    sys.exit(main())
