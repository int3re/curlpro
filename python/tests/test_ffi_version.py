"""Checking the version of the native part.

A mismatch between Python and the library is silent: both sides tolerate
unknown JSON fields, so an old DLL quietly ignores new options and the request
goes out without them. Debugging that looks like a logic error rather than a
stale build; time has already been lost that way.
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
        f"the built library {raw} is older than required — rebuild with build.ps1"
    )


def test_old_library_rejected():
    older = f"{_ffi.REQUIRED_VERSION[0]}.{_ffi.REQUIRED_VERSION[1] - 1}.0"
    with _with_version(older):
        with pytest.raises(_ffi.CurlProError, match="older than the required"):
            _ffi._check_version()


def test_newer_library_accepted():
    """A library newer than required is no reason to refuse to work."""
    newer = f"{_ffi.REQUIRED_VERSION[0]}.{_ffi.REQUIRED_VERSION[1] + 5}.0"
    with _with_version(newer):
        _ffi._check_version()


def test_unreadable_version_reported():
    with _with_version("not-a-version"):
        with pytest.raises(_ffi.CurlProError, match="unreadable version"):
            _ffi._check_version()
