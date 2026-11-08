#!/usr/bin/env python3
"""One version number for the package, the native library and the bindings.

    python scripts/version.py              # every place that declares it; fails if they differ
    python scripts/version.py check v0.34.0  # the same, and all of them equal to the tag
    python scripts/version.py set 0.35.0   # write it everywhere
    python scripts/version.py min-abi      # the oldest library a profile bundle asks for

Until 0.22.1 the package and the C ABI were numbered apart — package 0.22.x
carried ABI 0.33 — and two numbers for one release only confused. Since 0.34.0
there is one: the wheel, libcurlpro, the header and the bindings' packages all
say the same. The rule that makes it hold is in docs/VERSIONING.md: a patch
adds nothing to the ABI, so `major.minor` is enough to check against.

A profile bundle asks for the profile format's version (FormatVersion in
internal/profile/format.go), not for the release it is published from: the
format moves seldom, and asking for the release would cut every older minor
off the profile updates it could read.

The bindings' and Python's *floors* (REQUIRED, REQUIRED_VERSION) are not the
version: they are the oldest library a binding works with and are raised by
hand when it starts depending on something new. They may not exceed it.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (file, pattern): group 1 is the version. The first match in the file counts.
PLACES = [
    ("python/pyproject.toml", r'^version = "([^"]+)"'),
    ("python/curlpro/__init__.py", r'^__version__ = "([^"]+)"'),
    ("lib/curlpro.go", r'^const Version = "([^"]+)"'),
    ("curlpro.go", r'^const Version = "([^"]+)"'),
    ("include/curlpro.h", r'^#define CURLPRO_ABI_VERSION_STRING "([^"]+)"'),
    ("bindings/node/package.json", r'^  "version": "([^"]+)"'),
    ("bindings/rust/Cargo.toml", r'^version = "([^"]+)"'),
    ("bindings/java/pom.xml", r"<artifactId>curlpro</artifactId>\s*<version>([^<]+)</version>"),
    ("bindings/dotnet/Curlpro/Curlpro.csproj", r"<Version>([^<]+)</Version>"),
]

# The header spells the number out once more, part by part.
MACROS = r"^#define CURLPRO_ABI_VERSION_(MAJOR|MINOR|PATCH) (\d+)"

# Floors: (file, pattern) with major and minor in groups 1 and 2.
FLOORS = [
    ("python/curlpro/_ffi.py", r"^REQUIRED_VERSION = \((\d+), (\d+)\)"),
    ("bindings/node/index.js", r"^const REQUIRED = \[(\d+), (\d+)\];"),
    ("bindings/php/src/curlpro.php", r"public const REQUIRED = \[(\d+), (\d+)\];"),
    ("bindings/rust/src/lib.rs", r"pub const REQUIRED: \(u32, u32\) = \((\d+), (\d+)\);"),
    ("bindings/dotnet/Curlpro/Interop.cs", r"Required = new\((\d+), (\d+)\);"),
    ("bindings/java/src/main/java/io/curlpro/Curlpro.java", r"REQUIRED_MAJOR = (\d+), REQUIRED_MINOR = (\d+);"),
]

SEMVER = re.compile(r"\d+\.\d+\.\d+")


def _read(rel: str) -> str:
    return (ROOT / rel).read_bytes().decode("utf-8")


def _find(rel: str, pattern: str) -> re.Match:
    m = re.search(pattern, _read(rel), re.M)
    if not m:
        sys.exit(f"{rel}: {pattern} not found")
    return m


def declared() -> dict[str, str]:
    """Every place and the version it declares."""
    found = {rel: _find(rel, pattern).group(1) for rel, pattern in PLACES}
    parts = dict(re.findall(MACROS, _read("include/curlpro.h"), re.M))
    found["include/curlpro.h (MAJOR.MINOR.PATCH)"] = ".".join(parts.get(k, "?") for k in ("MAJOR", "MINOR", "PATCH"))
    return found


def floors() -> dict[str, tuple[int, int]]:
    out = {}
    for rel, pattern in FLOORS:
        m = _find(rel, pattern)
        out[rel] = (int(m.group(1)), int(m.group(2)))
    return out


def problems(want: str | None = None) -> list[str]:
    """What disagrees; empty when every place says the same (and `want`, if given)."""
    found = declared()
    values = set(found.values())
    out = []
    if want is not None and values != {want}:
        out += [f"{rel}: {v}, the tag says {want}" for rel, v in found.items() if v != want]
    elif len(values) != 1:
        common = max(values, key=lambda v: sum(x == v for x in found.values()))
        out += [f"{rel}: {v}, the rest say {common}" for rel, v in found.items() if v != common]
    version = want or found["lib/curlpro.go"]
    if SEMVER.fullmatch(version):
        top = tuple(int(p) for p in version.split(".")[:2])
        out += [f"{rel}: floor {a}.{b} is above the version {version}: its own library would be refused"
                for rel, (a, b) in floors().items() if (a, b) > top]
        fmt = min_abi()
        if not SEMVER.fullmatch(fmt) or tuple(int(p) for p in fmt.split(".")) > tuple(int(p) for p in version.split(".")):
            out.append(f"{FORMAT[0]}: FormatVersion {fmt} is not X.Y.Z at most {version}: a bundle from this "
                       f"release would ask for a library that does not exist")
    else:
        out.append(f"{version!r} is not X.Y.Z")
    return out


FORMAT = ("internal/profile/format.go", r'^const FormatVersion = "([^"]+)"')


def min_abi() -> str:
    """The oldest library a profile bundle asks for: the profile format's version."""
    return _find(*FORMAT).group(1)


def set_version(version: str) -> None:
    if not SEMVER.fullmatch(version):
        sys.exit(f"{version!r} is not X.Y.Z")
    for rel, pattern in PLACES:
        p = ROOT / rel
        raw = p.read_bytes()
        crlf = b"\r\n" in raw
        t = raw.decode("utf-8").replace("\r\n", "\n")
        m = re.search(pattern, t, re.M)
        if not m:
            sys.exit(f"{rel}: {pattern} not found")
        t = t[: m.start(1)] + version + t[m.end(1):]
        if rel == "include/curlpro.h":
            for name, value in zip(("MAJOR", "MINOR", "PATCH"), version.split(".")):
                t = re.sub(rf"^(#define CURLPRO_ABI_VERSION_{name}) \d+", rf"\g<1> {value}", t, count=1, flags=re.M)
        if crlf:
            t = t.replace("\n", "\r\n")
        p.write_bytes(t.encode("utf-8"))
        print(f"{rel}: {m.group(1)} -> {version}")


def main(argv: list[str]) -> int:
    if argv[:1] == ["set"] and len(argv) == 2:
        set_version(argv[1])
        argv = ["check", argv[1]]
    if argv[:1] == ["min-abi"] and len(argv) == 1:
        print(min_abi())
        return 0
    if (argv and argv[0] != "check") or len(argv) > 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    want = argv[1].removeprefix("v") if len(argv) == 2 else None
    for rel, v in declared().items():
        print(f"{v:10} {rel}")
    bad = problems(want)
    for line in bad:
        print(f"::error::{line}" if "GITHUB_ACTIONS" in os.environ else f"error: {line}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
