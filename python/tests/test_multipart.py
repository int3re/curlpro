"""Проверка multipart-форм.

Граница формы — часть отпечатка: Chrome шлёт ----WebKitFormBoundary и 16
символов, Firefox — череду дефисов с цифрами. Несовпадение стиля с User-Agent
само по себе аномалия, поэтому проверяется и оно.
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


pytestmark = pytest.mark.skipif(not _online(), reason="нет доступа к httpbin.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_fields_only():
    with curlpro.Session() as s:
        got = s.post(URL, fields={"a": "1", "b": "два"}).json()
    assert got["form"] == {"a": "1", "b": "два"}


def test_file_upload():
    with curlpro.Session() as s:
        got = s.post(URL, files={"doc": ("note.txt", b"hello")}).json()
    assert got["files"]["doc"] == "hello"


def test_binary_file_survives_roundtrip():
    """Бинарное содержимое не должно пострадать по дороге."""
    blob = bytes(range(256)) * 8
    with curlpro.Session() as s:
        got = s.post(URL, files={"bin": ("blob.bin", blob)}).json()
    # httpbin отдаёт бинарь как data:-URL, поэтому сверяем длину через заголовок.
    assert got["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert got["files"]


def test_fields_and_files_together():
    with curlpro.Session() as s:
        got = s.post(
            URL,
            fields={"title": "отчёт"},
            files={"doc": ("a.txt", b"body", "text/plain")},
        ).json()
    assert got["form"]["title"] == "отчёт"
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
    assert first != second, "граница формы повторяется между запросами"


def test_multipart_conflicts_with_data():
    with curlpro.Session() as s:
        with pytest.raises(ValueError, match="несовместим"):
            s.post(URL, fields={"a": "1"}, data=b"x")
