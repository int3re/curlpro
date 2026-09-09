"""Which proxy the environment names, and for which scheme.

No network here: these read environment variables and nothing else. They live
apart from test_proxy.py because that file is marked network as a whole.
"""

from __future__ import annotations

import pytest  # noqa: F401  (kept for symmetry with the rest of the suite)


# --- the environment variable follows the scheme ---------------------------
#
# Only the HTTPS variables used to be read, which was consistent while the
# library refused http:// altogether. Once cleartext was supported a plain
# request went out direct while HTTP_PROXY sat in the environment saying
# otherwise, and said nothing about it.

def test_env_proxy_follows_the_scheme(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://plain:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://secure:2")
    monkeypatch.delenv("NO_PROXY", raising=False)
    from curlpro.proxies import proxy_for
    assert proxy_for("http://example.com/") == "http://plain:1"
    assert proxy_for("https://example.com/") == "http://secure:2"


def test_env_proxy_falls_back_to_all_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ALL_PROXY", "socks5://everything:1080")
    monkeypatch.delenv("NO_PROXY", raising=False)
    from curlpro.proxies import proxy_for
    for url in ("http://example.com/", "https://example.com/"):
        assert proxy_for(url) == "socks5://everything:1080"


def test_http_proxy_is_ignored_under_cgi(monkeypatch):
    """httpoxy, CVE-2016-5385: under CGI a client's "Proxy:" header arrives as
    HTTP_PROXY, so an attacker could choose where the process connects."""
    monkeypatch.setenv("HTTP_PROXY", "http://attacker:1")
    for name in ("HTTPS_PROXY", "ALL_PROXY", "all_proxy", "https_proxy", "http_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("REQUEST_METHOD", "GET")
    from curlpro.proxies import proxy_for
    assert proxy_for("http://example.com/") is None
