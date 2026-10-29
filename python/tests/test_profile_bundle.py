"""The signed profile bundle published between releases (curlpro.update_profiles).

A bundle is built here with the real tool (``curlpro bundle``) and a key made
for the test; the library trusts it only through CURLPRO_BUNDLE_KEYS, as a
channel of one's own would be trusted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import curlpro
import curlpro.profiles as profiles

REPO = Path(__file__).resolve().parents[2]
GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="the bundle is built with the Go tool")


@pytest.fixture(scope="module")
def tool(tmp_path_factory) -> tuple[Path, Path, str]:
    """The curlpro CLI, a test key and its public half."""
    d = tmp_path_factory.mktemp("bundletool")
    exe = d / ("curlpro.exe" if os.name == "nt" else "curlpro")
    subprocess.run([GO, "build", "-o", str(exe), "./cmd/curlpro"], cwd=REPO, check=True)
    key = d / "test.key"
    pub = subprocess.run([str(exe), "bundle", "-genkey", str(key)], check=True,
                         capture_output=True, text=True).stdout.strip()
    return exe, key, pub


def build(tool, tmp_path: Path, *, package: str = "99.0.0", min_abi: str = "0.28.0") -> Path:
    exe, key, _ = tool
    src = tmp_path / "profiles"
    src.mkdir()
    # One self-standing profile under a name no wheel carries.
    p = json.loads((REPO / "profiles" / "okhttp-5.5-jvm.json").read_text(encoding="utf-8"))
    p["name"] = "bundletest-okhttp"
    (src / "bundletest-okhttp.json").write_text(json.dumps(p), encoding="utf-8")
    out = tmp_path / "out"
    subprocess.run([str(exe), "bundle", "-profiles", str(src), "-key", str(key), "-package", package,
                    "-min-abi", min_abi, "-out", str(out)], check=True, capture_output=True)
    return out / "profiles.json.gz"


def test_a_bundle_signed_with_an_unknown_key_is_refused(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path)
    monkeypatch.delenv("CURLPRO_BUNDLE_KEYS", raising=False)
    with pytest.raises(curlpro.CurlProError, match="signature"):
        curlpro.load_profile_bundle(path)
    assert "bundletest-okhttp" not in curlpro.list_profiles()


def test_a_trusted_bundle_loads(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path)
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    info = curlpro.load_profile_bundle(path)
    assert info["loaded"] == 1 and info["package"] == "99.0.0" and info["min_abi"] == "0.28.0"
    assert "bundletest-okhttp" in curlpro.list_profiles()
    with curlpro.Session("bundletest-okhttp") as s:
        assert "okhttp" in s.fingerprint().user_agent


def test_a_tampered_bundle_is_refused(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    with pytest.raises(curlpro.CurlProError, match="signature"):
        curlpro.load_profile_bundle(path)


def test_a_bundle_for_a_newer_library_is_refused(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path, min_abi="9.0.0")
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    with pytest.raises(curlpro.CurlProError, match="9.0.0"):
        curlpro.load_profile_bundle(path)


def _serve(monkeypatch, path: Path) -> None:
    files = {"https://example.test/profiles.json.gz": path.read_bytes(),
             "https://example.test/profiles.json.gz.sig": Path(str(path) + ".sig").read_bytes()}
    monkeypatch.setattr(profiles, "_fetch", lambda url, timeout: files[url])


def test_update_profiles_keeps_what_verified(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path)
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    cache = tmp_path / "cache"
    monkeypatch.setenv("CURLPRO_CACHE_DIR", str(cache))
    _serve(monkeypatch, path)
    info = curlpro.update_profiles("https://example.test/profiles.json.gz")
    assert info["package"] == "99.0.0"
    assert (cache / "profiles.json.gz").is_file() and (cache / "profiles.json.gz.sig").is_file()
    assert "bundletest-okhttp" in curlpro.list_profiles()
    assert not [p for p in cache.iterdir() if p.name.startswith("bundle-")], "the staging directory stayed"


def test_update_profiles_refuses_a_bundle_older_than_the_package(tool, tmp_path, monkeypatch):
    path = build(tool, tmp_path, package="0.1.0")
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    cache = tmp_path / "cache"
    monkeypatch.setenv("CURLPRO_CACHE_DIR", str(cache))
    _serve(monkeypatch, path)
    with pytest.raises(ValueError, match="older than the installed"):
        curlpro.update_profiles("https://example.test/profiles.json.gz")
    assert not (cache / "profiles.json.gz").exists()


def test_update_profiles_wants_https():
    with pytest.raises(ValueError, match="https"):
        curlpro.update_profiles("http://example.test/profiles.json.gz")


def test_the_cached_bundle_loads_at_import_unless_it_is_older(tool, tmp_path, monkeypatch):
    """What ensure_loaded does after the wheel's profiles, called directly: the
    test process imported curlpro long before. The registry is the process's,
    so what is checked is whether the bundle is offered to the library."""
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    monkeypatch.delenv("CURLPRO_PROFILE_UPDATES", raising=False)
    offered = []
    monkeypatch.setattr(profiles, "load_profile_bundle", lambda path: offered.append(Path(path)))
    for package, loads in (("0.1.0", False), ("99.0.0", True)):
        d = tmp_path / package
        d.mkdir()
        path = build(tool, d, package=package)
        cache = d / "cache"
        cache.mkdir()
        shutil.copy(path, cache / "profiles.json.gz")
        shutil.copy(str(path) + ".sig", cache / "profiles.json.gz.sig")
        monkeypatch.setenv("CURLPRO_CACHE_DIR", str(cache))
        offered.clear()
        profiles._load_cached_bundle()
        assert offered == ([cache / "profiles.json.gz"] if loads else []), package


def test_profile_updates_can_be_switched_off(tool, tmp_path, monkeypatch):
    monkeypatch.setenv("CURLPRO_BUNDLE_KEYS", tool[2])
    monkeypatch.setenv("CURLPRO_PROFILE_UPDATES", "0")
    monkeypatch.setenv("CURLPRO_CACHE_DIR", str(tmp_path / "nothing-here"))
    called = []
    monkeypatch.setattr(profiles, "load_profile_bundle", lambda path: called.append(path))
    profiles._load_cached_bundle()
    assert called == []
