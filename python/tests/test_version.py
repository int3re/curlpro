"""The version must be the same in every place that declares it.

`__version__` said 0.1.0 across three published releases: nothing read it, so
nothing caught it. An installed wheel now reports the distribution's version,
and this test keeps the literal fallback — the one a source checkout sees —
equal to pyproject.
"""

from __future__ import annotations

import re
from pathlib import Path

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


def test_exported_version_is_readable():
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", curlpro.__version__)
