#!/usr/bin/env python3
"""Packages the bindings with the native library inside, one package per ecosystem.

    python scripts/package-bindings.py --natives natives --version 0.34.0 --out dist/bindings

`natives` holds one directory per platform, named as Node names platforms —
the release workflow downloads one artifact per runner into it:

    natives/win32-x64/curlpro.dll       natives/linux-x64/libcurlpro.so
    natives/win32-arm64/curlpro.dll     natives/linux-arm64/libcurlpro.so
    natives/darwin-x64/libcurlpro.dylib natives/darwin-arm64/libcurlpro.dylib

A platform that is missing is left out of every package (and said so), so a
local run with one library builds packages for that one machine.

What comes out, under --out:

    npm/      curlpro-<v>.tgz and @curlpro/<platform> packages (one library each;
              the main package depends on them optionally, npm installs the one
              that matches the machine)
    nuget/    Curlpro.<v>.nupkg — runtimes/<rid>/native/ + profiles as content
    maven/    curlpro-<v>.jar + pom — the libraries and the signed profile bundle
              as resources, extracted at run time
    php/      curlpro-php-<v>.zip — src/, lib/<platform>/, profiles/
    native/   curlpro-<v>-<platform>.zip — the library, include/curlpro.h and the
              licence: for C, C++, Rust and anything else that loads it itself

The Rust crate carries no binaries (crates.io is source); it finds the library
through CURLPRO_LIBRARY or next to the executable — the native archive.
A step whose tool is not installed (npm, dotnet, jar) is skipped with a note.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# platform: (library file, .NET runtime id, npm os, npm cpu)
PLATFORMS = {
    "win32-x64": ("curlpro.dll", "win-x64", "win32", "x64"),
    "win32-arm64": ("curlpro.dll", "win-arm64", "win32", "arm64"),
    "linux-x64": ("libcurlpro.so", "linux-x64", "linux", "x64"),
    "linux-arm64": ("libcurlpro.so", "linux-arm64", "linux", "arm64"),
    "darwin-x64": ("libcurlpro.dylib", "osx-x64", "darwin", "x64"),
    "darwin-arm64": ("libcurlpro.dylib", "osx-arm64", "darwin", "arm64"),
}


def tool(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("  $", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def present(natives: Path) -> dict[str, Path]:
    found = {}
    for plat, (lib, *_rest) in PLATFORMS.items():
        f = natives / plat / lib
        if f.is_file():
            found[plat] = f
        else:
            print(f"  (no {plat}: {f} is missing)")
    if not found:
        sys.exit(f"no native library under {natives}")
    return found


def npm(libs: dict[str, Path], version: str, out: Path) -> None:
    print("npm")
    stage = out / "npm" / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    main = stage / "curlpro"
    main.mkdir(parents=True)
    for f in ("index.js", "index.d.ts", "README.md"):
        shutil.copy2(ROOT / "bindings" / "node" / f, main / f)
    shutil.copy2(ROOT / "LICENSE", main / "LICENSE")
    shutil.copytree(ROOT / "profiles", main / "profiles")
    pkg = json.loads((ROOT / "bindings" / "node" / "package.json").read_text(encoding="utf-8"))
    pkg["version"] = version
    pkg["files"] = ["index.js", "index.d.ts", "profiles/"]
    pkg.pop("scripts", None)
    pkg["optionalDependencies"] = {f"@curlpro/{p}": version for p in libs}
    (main / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")

    for plat, lib in libs.items():
        _, _, os_, cpu = PLATFORMS[plat]
        d = stage / f"curlpro-{plat}"
        (d / "lib").mkdir(parents=True)
        shutil.copy2(lib, d / "lib" / lib.name)
        shutil.copy2(ROOT / "LICENSE", d / "LICENSE")
        (d / "package.json").write_text(json.dumps({
            "name": f"@curlpro/{plat}",
            "version": version,
            "description": f"libcurlpro for {plat} — installed by the curlpro package",
            "os": [os_],
            "cpu": [cpu],
            "files": ["lib/"],
            "license": "Apache-2.0",
            "repository": pkg.get("repository"),
        }, indent=2) + "\n", encoding="utf-8")

    if not tool("npm"):
        print("  npm is not installed: the packages are staged, not packed")
        return
    for d in sorted(stage.iterdir()):
        run([tool("npm"), "pack", "--silent", "--pack-destination", str(out / "npm")], cwd=d)


def nuget(natives: Path, version: str, out: Path, tfm: str | None) -> None:
    print("nuget")
    if not tool("dotnet"):
        print("  dotnet is not installed: skipped")
        return
    cmd = [tool("dotnet"), "pack", str(ROOT / "bindings" / "dotnet" / "Curlpro"), "-c", "Release", "-nologo", "-v", "q",
           "-o", str(out / "nuget"), f"-p:Version={version}",
           f"-p:CurlproNatives={natives.resolve()}", f"-p:CurlproProfiles={(ROOT / 'profiles').resolve()}"]
    if tfm:
        cmd.append(f"-p:CurlproTfm={tfm}")
    run(cmd)


def maven(libs: dict[str, Path], version: str, out: Path, bundle: Path) -> None:
    print("maven")
    if not (tool("javac") and tool("jar")):
        print("  javac/jar are not installed: skipped")
        return
    with tempfile.TemporaryDirectory() as tmp:
        classes = Path(tmp) / "classes"
        sources = [str(p) for p in (ROOT / "bindings" / "java" / "src" / "main" / "java").rglob("*.java")]
        run([tool("javac"), "--release", "22", "-d", str(classes), *sources])
        res = classes / "io" / "curlpro"
        for plat, lib in libs.items():
            (res / "native" / plat).mkdir(parents=True)
            shutil.copy2(lib, res / "native" / plat / lib.name)
        # The profiles always travel, listed in an index (a jar cannot be listed);
        # the signed bundle comes on top when the release could sign it.
        (res / "profiles").mkdir()
        names = sorted(p.name for p in (ROOT / "profiles").glob("*.json"))
        for n in names:
            shutil.copy2(ROOT / "profiles" / n, res / "profiles" / n)
        (res / "profiles" / "index.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
        gz, sig = bundle / "profiles.json.gz", bundle / "profiles.json.gz.sig"
        if gz.is_file() and sig.is_file():
            shutil.copy2(gz, res / gz.name)
            shutil.copy2(sig, res / sig.name)
        else:
            print(f"  (no signed bundle in {bundle}: the jar carries the plain profiles only)")
        (out / "maven").mkdir(parents=True, exist_ok=True)
        run([tool("jar"), "--create", "--file", str(out / "maven" / f"curlpro-{version}.jar"), "-C", str(classes), "."])
    pom = (ROOT / "bindings" / "java" / "pom.xml").read_text(encoding="utf-8")
    pom = re.sub(r"(<artifactId>curlpro</artifactId>\s*<version>)[^<]+", rf"\g<1>{version}", pom, count=1)
    (out / "maven" / f"curlpro-{version}.pom").write_text(pom, encoding="utf-8")


def php(libs: dict[str, Path], version: str, out: Path) -> None:
    print("php")
    (out / "php").mkdir(parents=True, exist_ok=True)
    target = out / "php" / f"curlpro-php-{version}.zip"
    src = ROOT / "bindings" / "php"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for f in ("composer.json", "README.md", "example.php", "src/curlpro.php"):
            z.write(src / f, f)
        z.write(ROOT / "LICENSE", "LICENSE")
        for plat, lib in libs.items():
            z.write(lib, f"lib/{plat}/{lib.name}")
        for p in sorted((ROOT / "profiles").glob("*.json")):
            z.write(p, f"profiles/{p.name}")
    print("  ", target.name)


def native(libs: dict[str, Path], version: str, out: Path) -> None:
    print("native")
    (out / "native").mkdir(parents=True, exist_ok=True)
    for plat, lib in libs.items():
        target = out / "native" / f"curlpro-{version}-{plat}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(lib, lib.name)
            z.write(ROOT / "include" / "curlpro.h", "include/curlpro.h")
            z.write(ROOT / "LICENSE", "LICENSE")
            z.write(ROOT / "NOTICE", "NOTICE")
        print("  ", target.name)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--natives", type=Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / "bindings")
    ap.add_argument("--bundle", type=Path, default=ROOT / "dist" / "bundle", help="the signed profiles.json.gz (+ .sig) for the jar")
    ap.add_argument("--dotnet-tfm", help="build the NuGet package for another framework (the SDK's own, offline)")
    ap.add_argument("--only", nargs="*", choices=["npm", "nuget", "maven", "php", "native"])
    a = ap.parse_args()
    # Absolute: npm pack runs in each package's own directory, where a
    # relative --pack-destination named nothing (npm exited 254).
    a.natives, a.out, a.bundle = a.natives.resolve(), a.out.resolve(), a.bundle.resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    libs = present(a.natives)
    steps = a.only or ["npm", "nuget", "maven", "php", "native"]
    if "npm" in steps:
        npm(libs, a.version, a.out)
    if "nuget" in steps:
        nuget(a.natives, a.version, a.out, a.dotnet_tfm)
    if "maven" in steps:
        maven(libs, a.version, a.out, a.bundle)
    if "php" in steps:
        php(libs, a.version, a.out)
    if "native" in steps:
        native(libs, a.version, a.out)


if __name__ == "__main__":
    main()
