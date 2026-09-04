"""Protocol and profile headers — per individual request."""

from __future__ import annotations

import asyncio
from pathlib import Path

import curlpro
import pytest
from curlpro.session import _protocol

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def server():
    # The stand server advertises http/1.1 only: it shows both the forcing to 1.1
    # and the refusal when a request demands h2.
    with RawHeaderServer(persistent=True) as srv:
        yield srv


def test_names_are_forgiving():
    assert _protocol(None) == ""
    assert _protocol("http/1.1") == _protocol(1.1) == _protocol("h1") == "http1"
    assert _protocol("h2") == _protocol(2) == _protocol("HTTP/2") == "h2"
    assert _protocol("h3") == _protocol(3) == _protocol("http3") == "h3"
    with pytest.raises(ValueError, match="protocol"):
        _protocol("spdy")


def test_http1_forced_per_request(server):
    with curlpro.Session(verify=False) as s:
        r = s.get(server.url, protocol="1.1")
    assert r.status == 200 and r.proto == "HTTP/1.1"


def test_h2_on_http1_server_fails_clearly(server):
    """Travelling over HTTP/1.1 in silence is not allowed: the request asked for h2."""
    with curlpro.Session(verify=False) as s:
        with pytest.raises(curlpro.CurlProError, match="http/1.1"):
            s.get(server.url, protocol=2)


def test_h3_needs_the_profile_section(server):
    with curlpro.Session("chrome-150-macos", verify=False) as s:
        with pytest.raises(curlpro.CurlProError, match="http3"):
            s.get(server.url, protocol="h3")


def test_h3_through_proxy_is_refused(server):
    """QUIC does not pass through CONNECT; going direct in silence would reveal the address."""
    with curlpro.Session(verify=False, proxy="http://127.0.0.1:9") as s:
        with pytest.raises(curlpro.CurlProError, match="proxy"):
            s.get(server.url, protocol="h3")


def test_stream_takes_the_protocol_too(server):
    with curlpro.Session(verify=False) as s:
        with s.stream("GET", server.url, protocol="http1") as r:
            assert r.status == 200 and r.proto == "HTTP/1.1"
            assert r.read()


def test_async_session_takes_the_protocol_too(server):
    async def run():
        async with curlpro.AsyncSession(verify=False) as s:
            with pytest.raises(curlpro.CurlProError, match="http/1.1"):
                await s.get(server.url, protocol="h2")
            assert (await s.get(server.url, protocol="http1")).status == 200

    asyncio.run(run())


def sent(response) -> list[str]:
    """The header names that reached the wire."""
    return [line.split(":", 1)[0].lower() for line in response.json()["raw"] if ":" in line]


def test_default_headers_switch_both_ways(server):
    """The session sets the default, a request overrides it either way."""
    with curlpro.Session(verify=False, force_http1=True, default_headers=False) as s:
        assert "sec-fetch-site" not in sent(s.get(server.url))
        assert "sec-fetch-site" in sent(s.get(server.url, default_headers=True))

    with curlpro.Session(verify=False, force_http1=True) as s:
        assert "sec-fetch-site" in sent(s.get(server.url))
        bare = sent(s.get(server.url, headers={"x-only": "1"}, default_headers=False))
    assert "x-only" in bare
    assert "sec-fetch-site" not in bare


def test_disabled_headers_do_not_leak_into_the_next_request(server):
    """Switching off applies to one request, not to the session."""
    with curlpro.Session(verify=False, force_http1=True) as s:
        s.get(server.url, default_headers=False)
        assert "sec-fetch-site" in sent(s.get(server.url))


# --- against a live server ----------------------------------------------------
#
# The local stand can do neither h2 nor QUIC at the same time, so the Alt-Svc
# upgrade and the forcing to h3 are checked against cloudflare-quic.com.

def _h3_reachable() -> bool:
    import socket
    try:
        with socket.create_connection(("cloudflare-quic.com", 443), timeout=5):
            return True
    except OSError:
        return False


LIVE = "https://cloudflare-quic.com/"
online = pytest.mark.skipif(not _h3_reachable(), reason="no access to cloudflare-quic.com")


@online
def test_forced_protocol_beats_alt_svc():
    """The site advertised h3 and the client upgraded — but a request may stay on h2."""
    with curlpro.Session("chrome-151-windows") as s:
        assert s.get(LIVE).proto == "HTTP/2.0"
        assert s.get(LIVE).proto == "HTTP/3.0", "the second request must go over QUIC"
        assert s.get(LIVE, protocol="h2").proto == "HTTP/2.0"
        assert s.get(LIVE, protocol=1.1).proto == "HTTP/1.1"
        assert s.get(LIVE, protocol=3).proto == "HTTP/3.0"


@online
def test_h3_without_waiting_for_alt_svc():
    """The instruction works on the very first request, before any Alt-Svc."""
    with curlpro.Session("chrome-151-windows") as s:
        assert s.get(LIVE, protocol="h3").proto == "HTTP/3.0"


@online
def test_request_can_step_back_from_session_http3():
    with curlpro.Session("chrome-151-windows", http3=True) as s:
        assert s.get(LIVE, protocol="http1").proto == "HTTP/1.1"
        assert s.get(LIVE).proto == "HTTP/3.0"
