"""Streaming reads of the body."""

from __future__ import annotations

import socket
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


pytestmark = pytest.mark.skipif(not _online(), reason="no access to httpbin.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_stream_reads_full_body():
    size = 50_000
    with curlpro.Session() as s:
        with s.stream("GET", f"https://httpbin.org/bytes/{size}") as r:
            assert r.status == 200
            data = b"".join(r.iter_content(8192))
    assert len(data) == size


def test_stream_matches_buffered_read():
    """A stream and an ordinary request must return the same bytes."""
    url = "https://httpbin.org/base64/Y3VybFBybyBzdHJlYW1pbmc="
    with curlpro.Session() as s:
        buffered = s.get(url).content
        with s.stream("GET", url) as r:
            streamed = r.read()
    assert buffered == streamed


def test_stream_yields_multiple_chunks():
    with curlpro.Session() as s:
        with s.stream("GET", "https://httpbin.org/bytes/40000") as r:
            chunks = list(r.iter_content(4096))
    assert len(chunks) > 1, "the body arrived in one piece — no streaming"
    assert sum(len(c) for c in chunks) == 40_000


def test_stream_headers_available_before_body():
    with curlpro.Session() as s:
        with s.stream("GET", "https://httpbin.org/bytes/10000") as r:
            # The headers are available before the body is read — that is the point of a stream.
            assert r.header("content-type")
            assert r.ok
            r.read()


def test_stream_follows_redirects():
    with curlpro.Session() as s:
        with s.stream("GET", "https://httpbin.org/redirect/2") as r:
            assert r.status == 200
            assert r.url.endswith("/get")
            r.read()


def test_connection_usable_after_stream_closed():
    """A closed stream must free the connection for the next request."""
    with curlpro.Session() as s:
        with s.stream("GET", "https://httpbin.org/bytes/10000") as r:
            r.read()
        assert s.get("https://httpbin.org/get").status == 200


def test_stream_close_is_idempotent():
    with curlpro.Session() as s:
        r = s.stream("GET", "https://httpbin.org/bytes/1000")
        r.read()
        r.close()
        r.close()
