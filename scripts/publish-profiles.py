"""Publish the profile bundle between releases: build, sign, upload.

    python scripts/publish-profiles.py [--key PATH] [--dry-run]

Builds profiles.json.gz and its Ed25519 signature from profiles/ with
`curlpro bundle`, stamped with the package version of python/pyproject.toml,
the native library version of lib/curlpro.go as the oldest library that reads
it, and the commit; then replaces the assets of the GitHub release tagged
`profiles` (created on the first run, never marked latest) with `gh`.
curlpro.update_profiles() fetches from there.

The private key is the maintainer's and never enters the repository: --key, or
CURLPRO_SIGNING_KEY, or the default %APPDATA%/curlpro/profile-signing.key
(~/.config/curlpro/profile-signing.key elsewhere). profiles/ must be committed:
a bundle names the commit it was built from.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = "profiles"


def default_key() -> Path:
    if os.environ.get("CURLPRO_SIGNING_KEY"):
        return Path(os.environ["CURLPRO_SIGNING_KEY"])
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "curlpro" / "profile-signing.key"
    return Path.home() / ".config" / "curlpro" / "profile-signing.key"


def run(*args: str, **kw) -> str:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--key", type=Path, default=default_key())
    ap.add_argument("--dry-run", action="store_true", help="build and sign, do not upload")
    a = ap.parse_args()

    if run("git", "status", "--porcelain", "--", "profiles"):
        sys.exit("profiles/ has uncommitted changes: a bundle names the commit it comes from")
    commit = run("git", "rev-parse", "HEAD")
    package = re.search(r'^version = "([^"]+)"', (ROOT / "python" / "pyproject.toml").read_text(encoding="utf-8"),
                        re.M).group(1)
    abi = re.search(r'^const Version = "([^"]+)"', (ROOT / "lib" / "curlpro.go").read_text(encoding="utf-8"),
                    re.M).group(1)
    out = ROOT / "dist" / "bundle"
    print(run("go", "run", "./cmd/curlpro", "bundle", "-key", str(a.key), "-package", package,
              "-min-abi", abi, "-commit", commit, "-out", str(out)))
    files = [str(out / "profiles.json.gz"), str(out / "profiles.json.gz.sig")]
    if a.dry_run:
        print("dry run:", *files)
        return 0
    if subprocess.run(["gh", "release", "view", TAG], cwd=ROOT, capture_output=True).returncode != 0:
        run("gh", "release", "create", TAG, "--title", "Profiles between releases", "--latest=false",
            "--notes", "The signed profile bundle curlpro.update_profiles() fetches. Its assets are "
                       "replaced as profiles are captured; each names the commit it was built from.")
    run("gh", "release", "upload", TAG, *files, "--clobber")
    print(f"published: package {package}, ABI {abi}, commit {commit[:7]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
