"""Name resolution override and IP version selection."""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_name_is_kept_while_address_is_substituted():
    """The key property: the socket goes to the overridden address while the name
    in Host stays the original — otherwise it would break fingerprint and vhost."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True,
                             resolve={f"example.com:{srv.port}": "127.0.0.1"}) as s:
            raw = s.get(f"https://example.com:{srv.port}/").json()["raw"]
    host = [ln for ln in raw if ln.lower().startswith("host:")][0]
    assert host == f"Host: example.com:{srv.port}", host


def test_rule_without_port_covers_any_port():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True,
                             resolve={"example.com": "127.0.0.1"}) as s:
            r = s.get(f"https://example.com:{srv.port}/")
    assert r.status == 200


def test_rule_may_change_the_port_too():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True,
                             resolve={"example.com:443": f"127.0.0.1:{srv.port}"}) as s:
            r = s.get("https://example.com/")
    assert r.status == 200


def test_without_a_rule_nothing_changes():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True,
                             resolve={"other.example": "127.0.0.1"}) as s:
            r = s.get(srv.url)
    assert r.status == 200


def test_two_rules_do_not_share_a_connection():
    """Different overrides of one name lead to different machines: a shared
    connection would send the request to the wrong one."""
    with RawHeaderServer(persistent=True) as first, RawHeaderServer(persistent=True) as second:
        with curlpro.Session(verify=False, force_http1=True,
                             resolve={f"example.com:{first.port}": "127.0.0.1",
                                      f"example.com:{second.port}": "127.0.0.1"}) as s:
            s.get(f"https://example.com:{first.port}/")
            s.get(f"https://example.com:{second.port}/")
    assert first.accepted == 1 and second.accepted == 1


def test_ip_version_four_still_works():
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True, ip_version="4") as s:
            r = s.get(f"https://127.0.0.1:{srv.port}/")
    assert r.status == 200


def test_ip_version_six_cannot_reach_an_ipv4_only_host():
    """The restriction really restricts rather than being ignored."""
    with RawHeaderServer(persistent=True) as srv:
        with curlpro.Session(verify=False, force_http1=True, ip_version="6", timeout=5) as s:
            with pytest.raises(curlpro.CurlProError):
                s.get(f"https://127.0.0.1:{srv.port}/")
