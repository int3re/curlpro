"""Checking proxies against local servers.

Every proxy counts its tunnels, so the test confirms not only that the request
succeeded but that it really went through the proxy rather than past it.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro
from proxyserver import HTTPProxy, Socks5Proxy

REPO = Path(__file__).resolve().parents[2]
TARGET = "https://httpbin.org/get"


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


def test_http_connect_proxy():
    with HTTPProxy() as proxy:
        with curlpro.Session(proxy=f"http://{proxy.url_host}") as s:
            r = s.get(TARGET)
        assert r.status == 200
        assert proxy.tunnels == ["httpbin.org:443"], "the request did not go through the proxy"


def test_http_proxy_with_auth():
    with HTTPProxy(auth=("user", "s3cret")) as proxy:
        with curlpro.Session(proxy=f"http://user:s3cret@{proxy.url_host}") as s:
            assert s.get(TARGET).status == 200
        assert proxy.tunnels == ["httpbin.org:443"]
        # One refusal is mandatory: the first CONNECT goes without credentials,
        # as in a browser, and they are added only in response to a 407.
        assert proxy.rejected == 1


def test_http_proxy_rejects_wrong_password():
    with HTTPProxy(auth=("user", "s3cret")) as proxy:
        with curlpro.Session(proxy=f"http://user:wrong@{proxy.url_host}") as s:
            with pytest.raises(curlpro.CurlProError, match="407"):
                s.get(TARGET)
        # Two refusals: the probing CONNECT without credentials and a retry with wrong ones.
        assert proxy.rejected == 2
        assert proxy.tunnels == []


def test_socks5_proxy():
    with Socks5Proxy() as proxy:
        with curlpro.Session(proxy=f"socks5://{proxy.url_host}") as s:
            assert s.get(TARGET).status == 200
        assert proxy.tunnels == ["httpbin.org:443"]


def test_socks5_proxy_with_auth():
    with Socks5Proxy(auth=("user", "s3cret")) as proxy:
        with curlpro.Session(proxy=f"socks5://user:s3cret@{proxy.url_host}") as s:
            assert s.get(TARGET).status == 200
        assert proxy.tunnels == ["httpbin.org:443"]


def test_socks5_proxy_rejects_wrong_password():
    with Socks5Proxy(auth=("user", "s3cret")) as proxy:
        with curlpro.Session(proxy=f"socks5://user:wrong@{proxy.url_host}") as s:
            with pytest.raises(curlpro.CurlProError):
                s.get(TARGET)
        assert proxy.tunnels == []


def _stand_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _stand_up(), reason="no echo-server on :8443")
def test_fingerprint_survives_proxy():
    """A proxy must not affect the TLS fingerprint: it tunnels bytes.

    Checked on a local stand rather than an external service: a test about
    tunnelling must not fail because of somebody else's network.
    """
    stand = "https://localhost:8443/json"
    with curlpro.Session(verify=False) as s:
        direct = s.get(stand).json()["ja4"]

    with Socks5Proxy() as proxy:
        with curlpro.Session(proxy=f"socks5://{proxy.url_host}", verify=False) as s:
            through_socks = s.get(stand).json()["ja4"]
        assert proxy.tunnels == ["localhost:443"] or proxy.tunnels == ["localhost:8443"]

    with HTTPProxy() as proxy:
        with curlpro.Session(proxy=f"http://{proxy.url_host}", verify=False) as s:
            through_http = s.get(stand).json()["ja4"]

    assert direct == through_socks == through_http


def test_unknown_proxy_scheme_is_rejected():
    with pytest.raises(curlpro.CurlProError, match="unsupported proxy scheme"):
        with curlpro.Session(proxy="ftp://127.0.0.1:21") as s:
            s.get(TARGET)
