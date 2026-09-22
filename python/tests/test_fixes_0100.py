"""The smaller fixes of 0.10 from the second field report."""
import curlpro
from echo_stand import EchoStand

PAGE = "http://www.example.test/app"


def test_audit_judges_the_modes_actually_used():
    # The report's client set the mode on every request, never on the
    # session, and the derived-set warning for Safari never fired for it.
    with EchoStand() as st, curlpro.Session("safari-26.0-macos") as s:
        assert [f.code for f in s.audit()] == []
        assert "derived_fetch_set" in [f.code for f in s.audit(mode="fetch")]
        s.get(st.url + "/x", mode="fetch", page=PAGE)
        assert "derived_fetch_set" in [f.code for f in s.audit()]
        assert "fetch" in s.fingerprint().to_dict()["modes_used"]


def test_headers_for_keeps_the_wire_case_on_http1():
    with EchoStand() as st, curlpro.Session("chrome-151-windows") as s:
        preview = s.headers_for("GET", st.url + "/x", mode="fetch", page=PAGE)
        s.get(st.url + "/x", mode="fetch", page=PAGE)
        wire = st.last()["_order"]
        # An http:// URL is HTTP/1.1 for certain: the preview takes that form
        # by itself — Host first, the profile's case, no priority.
        assert list(preview) == wire
        assert "Host" in preview and "Origin" in preview and "priority" not in {k.lower() for k in preview}
        # Over https:// the default preview stays the HTTP/2 form.
        h2 = s.headers_for("GET", "https://api.example.org/x", mode="fetch", page=PAGE)
        assert "host" not in {k.lower() for k in h2} and "priority" in h2


def test_capabilities_say_whether_fetch_metadata_is_sent():
    assert curlpro.capabilities("safari-15.5-macos")["fetch_metadata"] is False
    assert "fetch" in curlpro.capabilities("safari-15.5-macos")["modes"]
    assert curlpro.capabilities("safari-26.0-macos")["fetch_metadata"] is True
    assert curlpro.capabilities("chrome-151-windows")["fetch_metadata"] is True


def test_origin_is_null_after_a_cross_origin_redirect():
    with EchoStand() as a, EchoStand() as b, curlpro.Session("chrome-151-windows") as s:
        a.routes["/r"] = (302, [("Location", b.url + "/landed")], b"")
        # From a page elsewhere: the first hop already differs from the
        # request's origin, so the second makes it opaque.
        s.get(a.url + "/r", mode="fetch", page=PAGE)
        assert b.last()["origin"] == "null"
        # From a page on A itself: not tainted, the page's origin stands.
        s.get(a.url + "/r", mode="fetch", page=a.url + "/app")
        assert b.last()["origin"] == a.url


def test_the_fingerprint_names_the_device_actually_chosen():
    # A field report: with device="random" the fingerprint said "random",
    # and a parser recording which phones get banned had nothing to record.
    with curlpro.Session("chrome-152-android", device="random") as s:
        fp = s.fingerprint()
        assert fp.device in fp.devices and fp.device != "random"
        assert fp.to_dict()["device"] == fp.device
    with curlpro.Session("chrome-152-android", device="SM-S928B") as s:
        assert s.fingerprint().device == "Galaxy S24 Ultra"
    # A desktop without an identity pool (the 151-153 desktops carry one since 0.11).
    with curlpro.Session("chrome-150-macos") as s:
        assert s.fingerprint().device == "" and s.fingerprint().devices == []


def test_the_stream_response_carries_history_and_preflights():
    with EchoStand() as st, curlpro.Session("chrome-151-windows") as s:
        st.routes["/r"] = (302, [("Location", st.url + "/x")], b"")
        with s.stream("GET", st.url + "/r") as r:
            assert [h.status for h in r.history] == [302] and r.preflights == []
