"""Fetch primary-source tool documentation (READMEs, book pages, docs pages)
into the scratch directory, read-only, so the notes can quote them.

What it reproduces, and from which source: nothing is computed; it saves the
current text of each project's own documentation (GitHub raw files via the
`gh` CLI, docs.github.com through its markdown article API, other pages with
curl) and records the fetch date, byte count and SHA-256 of each file in
SCRATCH/web/index.tsv, so a later reader can see exactly which version was
quoted.

Usage:
    python research/scripts/pq/tcc_fetch_docs.py SCRATCH_PQ_DIR [NAME ...]

Each fetch has a 90 s timeout. Existing files are kept unless --refresh.
"""
import datetime as dt
import hashlib
import os
import subprocess
import sys

GH = {
    # name: (repo, path)
    "cargo-fuzz-README.md": ("rust-fuzz/cargo-fuzz", "README.md"),
    "rust-fuzz-book-setup.md": ("rust-fuzz/book", "src/cargo-fuzz/setup.md"),
    "rust-fuzz-book-afl-setup.md": ("rust-fuzz/book", "src/afl/setup.md"),
    "afl.rs-README.md": ("rust-fuzz/afl.rs", "README.md"),
    "honggfuzz-rs-README.md": ("rust-fuzz/honggfuzz-rs", "README.md"),
    "miri-README.md": ("rust-lang/miri", "README.md"),
    "unstable-book-sanitizer.md": ("rust-lang/rust", "src/doc/unstable-book/src/compiler-flags/sanitizer.md"),
    "cargo-mutants-README.md": ("sourcefrog/cargo-mutants", "README.md"),
    "cargo-llvm-cov-README.md": ("taiki-e/cargo-llvm-cov", "README.md"),
    "cross-README.md": ("cross-rs/cross", "README.md"),
    "proptest-README.md": ("proptest-rs/proptest", "README.md"),
    "cargo-audit-README.md": ("rustsec/rustsec", "cargo-audit/README.md"),
    "cargo-deny-README.md": ("EmbarkStudios/cargo-deny", "README.md"),
    "cargo-vet-README.md": ("mozilla/cargo-vet", "README.md"),
    "cargo-cyclonedx-README.md": ("CycloneDX/cyclonedx-rust-cargo", "README.md"),
    "cargo-auditable-README.md": ("rust-secure-code/cargo-auditable", "README.md"),
    "zizmor-README.md": ("zizmorcore/zizmor", "README.md"),
    "scorecard-README.md": ("ossf/scorecard", "README.md"),
    "scorecard-checks.md": ("ossf/scorecard", "docs/checks.md"),
    "harden-runner-README.md": ("step-security/harden-runner", "README.md"),
    "cosign-README.md": ("sigstore/cosign", "README.md"),
    "minisign-README.md": ("jedisct1/minisign", "README.md"),
    "attest-build-provenance-README.md": ("actions/attest-build-provenance", "README.md"),
    "cargo-msrv-README.md": ("foresterre/cargo-msrv", "README.md"),
    "cargo-geiger-README.md": ("geiger-rs/cargo-geiger", "README.md"),
    "cargo-careful-README.md": ("RalfJung/cargo-careful", "README.md"),
    "rust-platform-support.md": ("rust-lang/rust", "src/doc/rustc/src/platform-support.md"),
    "openssl-NEWS.md": ("openssl/openssl", "NEWS.md"),
    "cargo-reference-rust-version.md": ("rust-lang/cargo", "doc/book/src/reference/rust-version.md"),
    "cargo-reference-resolver.md": ("rust-lang/cargo", "doc/book/src/reference/resolver.md"),
}

GHDOCS = [
    "actions/reference/security/secure-use",
    "actions/concepts/security/github_token",
    "actions/reference/security/oidc",
    "actions/concepts/security/artifact-attestations",
    "actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations",
    "actions/concepts/runners/self-hosted-runners",
    "actions/reference/workflows-and-actions/events-that-trigger-workflows",
    "repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
    "code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security",
    "actions/concepts/security/compromised-runners",
]

CURL = {
    # sourceware's gitweb is behind a bot challenge; valgrind NEWS is not fetched here
    "slsa-v1.1-levels.html": "https://slsa.dev/spec/v1.1/levels",
    "reproducible-builds-definition.html": "https://reproducible-builds.org/docs/definition/",
}


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    root = os.path.join(sys.argv[1], "web")
    names = [a for a in sys.argv[2:] if not a.startswith("--")]
    refresh = "--refresh" in sys.argv
    os.makedirs(root, exist_ok=True)
    index = os.path.join(root, "index.tsv")
    today = dt.date.today().isoformat()
    jobs = []
    for name, (repo, path) in GH.items():
        if repo:
            jobs.append((name, ["gh", "api", f"repos/{repo}/contents/{path}",
                                "-H", "Accept: application/vnd.github.raw"], f"github.com/{repo}/{path}"))
    for p in GHDOCS:
        name = "gh-docs-" + p.replace("/", "_") + ".md"
        url = f"https://docs.github.com/api/article/body?pathname=/en/{p}"
        jobs.append((name, ["curl", "-sL", "--fail", "--max-time", "80", url], url))
    for name, url in CURL.items():
        jobs.append((name, ["curl", "-sL", "--fail", "--max-time", "80", "-A", "Mozilla/5.0", url], url))
    for name, cmd, src in jobs:
        if names and name not in names:
            continue
        out = os.path.join(root, name)
        if os.path.exists(out) and os.path.getsize(out) > 0 and not refresh:
            print(f"[KEEP] {name}")
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=90)
        except subprocess.TimeoutExpired:
            print(f"[FAIL] {name}: timeout")
            continue
        if r.returncode != 0 or not r.stdout:
            print(f"[FAIL] {name}: exit {r.returncode} {r.stderr[:200]!r}")
            continue
        open(out, "wb").write(r.stdout)
        with open(index, "a", encoding="utf-8") as f:
            f.write(f"{today}\t{name}\t{len(r.stdout)}\t{sha(out)}\t{src}\n")
        print(f"[OK]   {name} {len(r.stdout)} B")


if __name__ == "__main__":
    main()
