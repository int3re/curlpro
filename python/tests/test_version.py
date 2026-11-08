"""The version must be the same in every place that declares it.

`__version__` said 0.1.0 across three published releases: nothing read it, so
nothing caught it. An installed wheel now reports the distribution's version,
and this test keeps the literal fallback — the one a source checkout sees —
equal to pyproject.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[1]


def _literal(path: Path, pattern: str) -> str:
    m = re.search(pattern, path.read_text(encoding="utf-8"), re.M)
    assert m, f"{path.name}: {pattern} not found"
    return m.group(1)


def test_fallback_matches_pyproject():
    pyproject = _literal(REPO / "pyproject.toml", r'^version = "([^"]+)"')
    fallback = _literal(
        REPO / "curlpro" / "__init__.py", r'^__version__ = "([^"]+)"'
    )
    assert fallback == pyproject


def test_one_number_for_the_package_the_library_and_the_bindings():
    # Since 0.34.0 the wheel, libcurlpro, the header and the bindings' packages
    # say the same version; scripts/version.py lists where it is written.
    script = REPO.parent / "scripts" / "version.py"
    if not script.is_file():
        pytest.skip("not a checkout of the whole repository")
    spec = importlib.util.spec_from_file_location("_versions", script)
    versions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(versions)
    assert versions.problems() == []
    # A profile bundle asks for the profile format's version, not the release's.
    assert re.fullmatch(r"\d+\.\d+\.\d+", versions.min_abi())


def test_exported_version_is_readable():
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", curlpro.__version__)


def test_every_package_goes_into_the_wheel():
    # setuptools takes the packages named and no others: curlpro.browser,
    # left out, would install as nothing, and the solver would fail with
    # ModuleNotFoundError on every machine but the developer's.
    listed = set(re.findall(r'"([\w.]+)"', _literal(REPO / "pyproject.toml", r"^packages = \[(.*)\]")))
    on_disk = {".".join(p.parent.relative_to(REPO).parts) for p in (REPO / "curlpro").rglob("__init__.py")}
    assert listed == on_disk, f"pyproject packages {sorted(listed)}, on disk {sorted(on_disk)}"
