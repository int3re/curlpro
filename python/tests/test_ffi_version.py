"""Сверка версии нативной части.

Рассинхрон Python и библиотеки нем: обе стороны переживают незнакомые поля
JSON, поэтому старая DLL молча игнорирует новые опции — запрос уходит без них.
Отладка выглядит как ошибка логики, а не как устаревшая сборка; на этом уже
терялось время.
"""

from __future__ import annotations

from unittest import mock

import pytest

from curlpro import _ffi


def _with_version(value: str):
    return mock.patch.object(_ffi, "_call", lambda name, *a: {"version": value})


def test_current_library_satisfies_requirement():
    raw = _ffi._call("curlpro_version")["version"]
    got = tuple(int(p) for p in raw.split(".")[:2])
    assert got >= _ffi.REQUIRED_VERSION, (
        f"собранная библиотека {raw} старее требуемой — пересоберите build.ps1"
    )


def test_old_library_rejected():
    older = f"{_ffi.REQUIRED_VERSION[0]}.{_ffi.REQUIRED_VERSION[1] - 1}.0"
    with _with_version(older):
        with pytest.raises(_ffi.CurlProError, match="older than the required"):
            _ffi._check_version()


def test_newer_library_accepted():
    """Библиотека новее требуемой — не повод отказываться работать."""
    newer = f"{_ffi.REQUIRED_VERSION[0]}.{_ffi.REQUIRED_VERSION[1] + 5}.0"
    with _with_version(newer):
        _ffi._check_version()


def test_unreadable_version_reported():
    with _with_version("не-версия"):
        with pytest.raises(_ffi.CurlProError, match="unreadable version"):
            _ffi._check_version()
