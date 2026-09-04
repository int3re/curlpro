"""The order of ordinary headers in HTTP/2 — on the wire, not in the assembly.

Between the header assembly and the wire lies HPACK, and until now the HTTP/2
order was checked by nothing: the Python header tests run with force_http1=True
while the Go tests only see the assembly result. That let a bug live unnoticed
where the custom header anchor worked over HTTP/1.1 only.

The `echo-server` stand from fingerproxy returns the HEADERS frame in wire order
(`/json/detail` -> detail.metadata.HTTP2Frames.Headers), which is what is used here.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

STAND = "https://localhost:8443/json/detail"
REPO = Path(__file__).resolve().parents[2]


def _stand_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _stand_up(), reason="no stand on :8443")


@pytest.fixture(scope="module", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def sess():
    with curlpro.Session("chrome-151-windows", verify=False) as s:
        yield s


def wire_order(s: curlpro.Session) -> list[str]:
    """The HEADERS field names in send order, pseudo-headers included."""
    detail = s.get(STAND).json()["detail"]
    return [h["Name"] for h in detail["metadata"]["HTTP2Frames"]["Headers"]]


def test_pseudo_headers_come_first_in_chrome_order(sess):
    assert wire_order(sess)[:4] == [":method", ":authority", ":scheme", ":path"]


def test_profile_order_reaches_the_wire(sess):
    names = [n for n in wire_order(sess) if not n.startswith(":")]
    assert names[0] == "sec-ch-ua", f"the profile order did not arrive: {names}"
    # Chrome appends its service tail last.
    assert names[-1] == "priority"
    assert names.index("accept-encoding") < names.index("accept-language")


def test_custom_header_lands_before_anchor():
    """The anchor must work in HTTP/2 as well, not only in HTTP/1.1.

    This is exactly the case that was broken: reorder ran only with an explicit
    order, which only http1.order has. The mode is set explicitly: without it a
    custom name switches the set to fetch.
    """
    with curlpro.Session("chrome-151-windows", verify=False, mode="navigate") as sess:
        before = wire_order(sess)
        sess.headers["X-Api-Key"] = "secret"
        after = wire_order(sess)

    assert "x-api-key" in after, "the session header never reached the wire"
    assert after.index("x-api-key") < after.index("accept-encoding"), (
        f"a custom header after the service tail: {after}"
    )
    # The order of the profile headers did not change.
    assert [n for n in after if n != "x-api-key"] == before


def test_custom_header_switches_to_fetch_set(sess):
    """Without an explicit mode a custom header means fetch: it has a different
    set and a different cluster (measured on Chrome 152)."""
    navigation = wire_order(sess)
    sess.headers["X-Api-Key"] = "secret"
    after = wire_order(sess)

    assert "x-api-key" in after
    assert "upgrade-insecure-requests" not in after, "fetch does not carry this header"
    assert "sec-fetch-user" not in after
    assert after.index("x-api-key") < after.index("sec-ch-ua-mobile")
    assert after != navigation


def test_profile_header_override_keeps_position(sess):
    """Overriding a profile name changes neither the set nor the position:
    user-agent is in the navigation set too, so it is not a sign of fetch."""
    before = wire_order(sess)
    position = before.index("user-agent")
    sess.headers["User-Agent"] = "custom/1.0"

    after = wire_order(sess)
    assert after.index("user-agent") == position, f"the position moved: {after}"
    assert after == before, "overriding the value changed the order"
