"""Проверка потоковой отправки тела."""

from __future__ import annotations

import hashlib
import os
import socket
import tempfile
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]


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


@pytest.fixture
def big_file():
    """Файл заметно больше, чем стоило бы держать в памяти без нужды."""
    path = Path(tempfile.mkdtemp()) / "upload.bin"
    path.write_bytes(os.urandom(4 * 1024 * 1024))
    yield path
    path.unlink(missing_ok=True)


def test_file_upload_sets_content_length(big_file):
    """Без явной длины транспорт перешёл бы на chunked, чего браузер
    при отправке файла не делает — и это было бы видно на проводе."""
    with curlpro.Session() as s:
        h = s.post("https://httpbin.org/post", body_file=big_file).json()["headers"]
    assert h.get("Content-Length") == str(big_file.stat().st_size)
    assert "Transfer-Encoding" not in h


def test_file_content_arrives_intact():
    path = Path(tempfile.mkdtemp()) / "small.bin"
    payload = bytes(range(256)) * 4
    path.write_bytes(payload)
    try:
        with curlpro.Session() as s:
            got = s.post("https://httpbin.org/post", body_file=path).json()
        # httpbin отдаёт двоичное тело как data:-URL с base64.
        assert got["data"].startswith("data:application/octet-stream;base64,")
        import base64
        decoded = base64.b64decode(got["data"].split(",", 1)[1])
        assert hashlib.sha256(decoded).hexdigest() == hashlib.sha256(payload).hexdigest()
    finally:
        path.unlink(missing_ok=True)


def test_missing_file_reports_clearly():
    with curlpro.Session() as s:
        with pytest.raises(curlpro.CurlProError, match="request body"):
            s.post("https://httpbin.org/post", body_file="нет-такого-файла.bin")


def test_body_file_conflicts_with_data(big_file):
    with curlpro.Session() as s:
        with pytest.raises(ValueError, match="cannot be combined"):
            s.post("https://httpbin.org/post", body_file=big_file, data=b"x")
