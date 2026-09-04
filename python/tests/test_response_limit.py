"""``max_response_size`` on every path that collects a body.

The limit exists so that a server with an endless response cannot eat the
process memory. It used to bind the ordinary request only, while
``stream(...).read()`` — which collects the body just as thoroughly — read
whatever arrived. The audit measured 100002 bytes returned under a limit of
1000.

Reading in chunks stays unbounded on purpose: that is the way to handle a body
larger than memory, and a limit there would take the way out along with the
danger.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import curlpro
import pytest

from flakyserver import FlakyServer

REPO = Path(__file__).resolve().parents[2]
BODY = "x" * 100_000


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def _big(srv: FlakyServer, path: str, times: int = 8) -> str:
    return srv.scenario(path, [{"status": 200, "body": BODY}] * times)


def _length(url: str) -> int:
    """The body as the stand actually serves it — the limit is compared to this."""
    with curlpro.Session(verify=False, force_http1=True) as s:
        return len(s.get(url).content)


def test_plain_request_stops_at_the_limit():
    with FlakyServer() as srv:
        url = _big(srv, "/plain")
        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=1000) as s:
            with pytest.raises(curlpro.CurlProError) as caught:
                s.get(url)
    assert caught.value.code == "too_large"


def test_stream_read_stops_at_the_limit():
    """The finding itself: read() collects the body, so the limit binds it."""
    with FlakyServer() as srv:
        url = _big(srv, "/stream")
        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=1000) as s:
            with pytest.raises(curlpro.CurlProError) as caught:
                with s.stream("GET", url) as r:
                    r.read()
    assert caught.value.code == "too_large"
    # The message has to name the way out, or the limit reads as "no large
    # downloads" rather than "not into memory".
    assert "iter_content" in str(caught.value)


def test_iter_content_is_deliberately_unbounded():
    with FlakyServer() as srv:
        url = _big(srv, "/chunks")
        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=1000) as s:
            with s.stream("GET", url) as r:
                got = sum(len(chunk) for chunk in r.iter_content(8192))
    assert got > 1000


def test_the_boundary_is_the_same_on_both_paths():
    """A body exactly the size of the limit passes; one byte more does not."""
    with FlakyServer() as srv:
        url = _big(srv, "/edge")
        size = _length(url)

        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=size) as s:
            assert len(s.get(url).content) == size
            with s.stream("GET", url) as r:
                assert len(r.read()) == size

        with curlpro.Session(verify=False, force_http1=True,
                             max_response_size=size - 1) as s:
            with pytest.raises(curlpro.CurlProError):
                s.get(url)
            with pytest.raises(curlpro.CurlProError):
                with s.stream("GET", url) as r:
                    r.read()


def test_async_stream_read_stops_at_the_limit():
    async def run(url: str) -> str:
        async with curlpro.AsyncSession(verify=False, force_http1=True,
                                        max_response_size=1000) as s:
            r = await s.stream("GET", url)
            try:
                with pytest.raises(curlpro.CurlProError) as caught:
                    await r.read()
                return caught.value.code
            finally:
                await r.close()

    with FlakyServer() as srv:
        assert asyncio.run(run(_big(srv, "/async"))) == "too_large"


def test_no_limit_reads_everything():
    with FlakyServer() as srv:
        url = _big(srv, "/nolimit")
        size = _length(url)
        with curlpro.Session(verify=False, force_http1=True) as s:
            with s.stream("GET", url) as r:
                assert len(r.read()) == size
