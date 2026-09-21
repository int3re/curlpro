"""Which cookies a request carries: fetch's credentials mode and SameSite.

Measured on Chrome 153 and Firefox 156 (cmd/hcapture -origins, 2026-09-21).
The stand is cleartext, so a Secure cookie never enters the picture; the four
here are enough to show every rule.
"""
import time

import pytest

import curlpro
from echo_stand import EchoStand

COOKIES = [("Set-Cookie", "strict=1; Path=/; SameSite=Strict"),
           ("Set-Cookie", "lax=1; Path=/; SameSite=Lax"),
           ("Set-Cookie", "nonens=1; Path=/; SameSite=None"),
           ("Set-Cookie", "plain=1; Path=/")]

CROSS = "http://www.example.test/app"


def primed(profile, **kw):
    st = EchoStand()
    st.__enter__()
    st.routes["/prime"] = (200, COOKIES, b"{}")
    s = curlpro.Session(profile, **kw)
    s.get(st.url + "/prime")
    return st, s


def cookie(st):
    return st.last().get("cookie", "")


def test_chromium_rules():
    st, s = primed("chrome-151-windows")
    with st, s:
        same_origin = st.url + "/app"
        same_site = "http://127.0.0.1:1/app"
        # No page: a navigation typed into the bar carries everything; the
        # SameSite=None cookie without Secure was never stored.
        s.get(st.url + "/x")
        assert cookie(st) == "strict=1; lax=1; plain=1"
        # fetch's default credentials: cookies only to the page's own origin.
        s.get(st.url + "/x", mode="fetch", page=same_origin)
        assert cookie(st) == "strict=1; lax=1; plain=1"
        s.get(st.url + "/x", mode="fetch", page=same_site)
        assert cookie(st) == ""
        s.get(st.url + "/x", mode="fetch", page=same_site, credentials="include")
        assert cookie(st) == "strict=1; lax=1; plain=1"
        # Cross-site fetch with include: only SameSite=None, and there is none.
        s.get(st.url + "/x", mode="fetch", page=CROSS, credentials="include")
        assert cookie(st) == ""
        s.get(st.url + "/x", mode="fetch", page=same_origin, credentials="omit")
        assert cookie(st) == ""
        # Cross-site navigation: lax and the unattributed one (Lax by default).
        s.get(st.url + "/x", mode="navigate", page=CROSS)
        assert cookie(st) == "lax=1; plain=1"
        # Cross-site POST navigation, cookies younger than two minutes: the
        # unattributed one still goes (Lax+POST), lax never.
        s.post(st.url + "/x", data="a=1", mode="navigate", page=CROSS,
               headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert cookie(st) == "plain=1"


def test_lax_post_window_closes_after_two_minutes():
    st, s = primed("chrome-151-windows")
    with st, s:
        s.cookies.set("plain", "1", domain="127.0.0.1", path="/")
        old = [c for c in s.cookies.export() if c["name"] == "plain"][0]
        old["created"] = int(time.time()) - 180
        s.cookies.load([old])
        s.post(st.url + "/x", data="a=1", mode="navigate", page=CROSS,
               headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert cookie(st) == ""


def test_firefox_rules():
    st, s = primed("firefox-155-windows")
    with st, s:
        # Total Cookie Protection: a cross-site fetch carries nothing, include or not.
        s.get(st.url + "/x", mode="fetch", page=CROSS, credentials="include")
        assert cookie(st) == ""
        s.get(st.url + "/x", mode="navigate", page=CROSS)
        assert cookie(st) == "lax=1; plain=1"
        # No Lax by default: the unattributed cookie goes on a POST regardless of age.
        s.post(st.url + "/x", data="a=1", mode="navigate", page=CROSS,
               headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert cookie(st) == "plain=1"
        # And SameSite=None without Secure was refused here too.
        s.get(st.url + "/x")
        assert "nonens" not in cookie(st)


def test_samesite_can_be_switched_off():
    st, s = primed("chrome-151-windows", samesite=False, credentials="include")
    with st, s:
        s.get(st.url + "/x", mode="fetch", page=CROSS)
        assert cookie(st) == "strict=1; lax=1; nonens=1; plain=1"


def test_credentials_is_validated():
    with pytest.raises(curlpro.ConfigurationError):
        curlpro.Session("chrome-151-windows", credentials="always")
    with curlpro.Session("chrome-151-windows") as s, pytest.raises(curlpro.ConfigurationError):
        s.get("http://127.0.0.1:1/", credentials="sometimes")


def test_headers_for_applies_the_same_rules():
    st, s = primed("chrome-151-windows")
    with st, s:
        h = s.headers_for("GET", st.url + "/x", mode="fetch", page=CROSS, credentials="include")
        assert "cookie" not in {k.lower() for k in h}
        h = s.headers_for("GET", st.url + "/x", mode="navigate", page=CROSS)
        assert h.get("Cookie") == "lax=1; plain=1"


def test_capabilities_carry_the_cookie_policy():
    chrome = curlpro.capabilities("chrome-151-windows")["cookies"]
    assert chrome["lax_by_default"] and chrome["third_party"] and chrome["none_requires_secure"]
    firefox = curlpro.capabilities("firefox-155-windows")["cookies"]
    assert not firefox["lax_by_default"] and not firefox["third_party"]
    assert "cookies" not in curlpro.capabilities("okhttp-5.5-jvm")


def test_a_response_to_an_uncredentialed_request_sets_no_cookie():
    # The third field report: an API answered a credentials="omit" fetch with
    # its own session cookie, the jar kept it beside the caller's, and the
    # next credentialed request carried a pair no browser sends.
    with EchoStand() as st, curlpro.Session("chrome-151-windows") as s:
        st.routes["/assort"] = (200, [("Set-Cookie", "spid=FROM_API"), ("Set-Cookie", "spsc=FROM_API")], b"{}")
        s.cookies.set("spid", "FROM_BOOTSTRAP", domain="127.0.0.1", path="/")
        same_site = "http://127.0.0.1:1/app"
        s.get(st.url + "/assort", page=same_site, mode="fetch", credentials="omit")
        assert "spsc" not in s.cookies and s.cookies["spid"] == "FROM_BOOTSTRAP"
        s.get(st.url + "/assort", page=CROSS, mode="fetch")            # default same-origin, another origin
        assert "spsc" not in s.cookies
        s.get(st.url + "/x", page=same_site, mode="fetch", credentials="include")
        assert cookie(st) == "spid=FROM_BOOTSTRAP"
        s.get(st.url + "/assort", page=same_site, mode="fetch", credentials="include")
        assert "spsc" in s.cookies                                    # with credentials it is stored
