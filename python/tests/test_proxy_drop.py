"""A proxy that hangs up on CONNECT instead of answering 407 — end to end.

Chrome sends the first CONNECT without credentials and adds them after the
407; so does this client. A user's provider closed the socket instead, and
every request died with "reading proxy response: unexpected EOF", while
socks5h:// on the same port worked because SOCKS negotiates authentication up
front. The Go tests prove the retry; this one proves the whole path from
Python: the retry with credentials, and the error code when there are none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import curlpro
from proxyserver import DroppingHTTPProxy
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_credentials_are_retried_when_the_proxy_drops_instead_of_challenging():
    with DroppingHTTPProxy(("user", "pw")) as proxy, RawHeaderServer() as srv:
        with curlpro.Session("chrome-151-windows", verify=False, force_http1=True,
                             proxy=f"http://user:pw@{proxy.url_host}", timeout=10) as s:
            r = s.get(srv.url)
    assert r.status == 200
    # The first CONNECT went without credentials, as a browser's does, and was
    # hung up on; the second carried them and was tunnelled.
    assert proxy.rejected == 1
    assert len(proxy.tunnels) == 1


def test_without_credentials_the_error_names_the_proxy_and_the_407_rule():
    with DroppingHTTPProxy(("user", "pw")) as proxy:
        with curlpro.Session("chrome-151-windows", verify=False, force_http1=True,
                             proxy=f"http://{proxy.url_host}", timeout=5) as s:
            with pytest.raises(curlpro.CurlProError) as info:
                s.get("https://example.com/")
    err = info.value
    assert err.code == "proxy_closed"
    assert "407" in str(err)
    assert "unexpected EOF" not in str(err)
    assert proxy.rejected == 1
