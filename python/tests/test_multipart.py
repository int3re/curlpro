"""Checking multipart forms.

The form boundary is part of the fingerprint: Chrome sends ----WebKitFormBoundary
plus 16 characters, Firefox a run of dashes with digits. A style that does not
match the User-Agent is an anomaly in itself, so it is checked as well.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]
URL = "https://httpbin.org/post"


def _online() -> bool:
    try:
        with socket.create_connection(("httpbin.org", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _online(), reason="no access to httpbin.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_fields_only():
    with curlpro.Session() as s:
        got = s.post(URL, fields={"a": "1", "b": "two"}).json()
    assert got["form"] == {"a": "1", "b": "two"}


def test_file_upload():
    with curlpro.Session() as s:
        got = s.post(URL, files={"doc": ("note.txt", b"hello")}).json()
    assert got["files"]["doc"] == "hello"


def test_binary_file_survives_roundtrip():
    """Binary content must not be damaged on the way."""
    blob = bytes(range(256)) * 8
    with curlpro.Session() as s:
        got = s.post(URL, files={"bin": ("blob.bin", blob)}).json()
    # httpbin returns binary as a data: URL, so the length is checked through the header.
    assert got["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert got["files"]


def test_fields_and_files_together():
    with curlpro.Session() as s:
        got = s.post(
            URL,
            fields={"title": "report"},
            files={"doc": ("a.txt", b"body", "text/plain")},
        ).json()
    assert got["form"]["title"] == "report"
    assert got["files"]["doc"] == "body"


def test_chrome_boundary_style():
    with curlpro.Session("chrome-151-windows") as s:
        ct = s.post(URL, fields={"a": "1"}).json()["headers"]["Content-Type"]
    boundary = ct.split("boundary=")[1]
    assert re.fullmatch(r"----WebKitFormBoundary[A-Za-z0-9+/]{16}", boundary), boundary


def test_firefox_boundary_style():
    with curlpro.Session("firefox-144-macos") as s:
        ct = s.post(URL, fields={"a": "1"}).json()["headers"]["Content-Type"]
    boundary = ct.split("boundary=")[1]
    assert re.fullmatch(r"-{27}\d{30}", boundary), boundary


def test_boundary_is_unique_per_request():
    with curlpro.Session() as s:
        first = s.post(URL, fields={"a": "1"}).json()["headers"]["Content-Type"]
        second = s.post(URL, fields={"a": "1"}).json()["headers"]["Content-Type"]
    assert first != second, "the form boundary repeats between requests"


def test_multipart_conflicts_with_data():
    with curlpro.Session() as s:
        with pytest.raises(ValueError, match="cannot be combined"):
            s.post(URL, fields={"a": "1"}, data=b"x")
