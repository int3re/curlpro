"""The top-level site and partitioned cookies (0.14).

A frame's requests are made from the frame and under the page that embeds
it; ``top_level`` names that page. Measured with cmd/hcapture -chips on
Chrome 154 and Firefox 156: a frame of b under a set a plain and a
Partitioned cookie; Chrome sent the plain one wherever b was asked for and
the Partitioned one under a alone, Firefox kept both for b under a and sent
neither anywhere else. The Go side replays that capture; these check the
Python faces — the arguments, the property, the jar's records and files.

The stand speaks TLS on localhost: a Partitioned cookie is Secure, and a
Secure cookie goes back over https only.
"""
from __future__ import annotations

import asyncio
import json
import ssl
from pathlib import Path

import curlpro
import pytest
from curlpro.cookies import format_netscape
from echo_stand import EchoStand

CERT_DIR = Path(__file__).resolve().parents[2] / "capture" / "certs"

TOP_A = "https://www.a.test/checkout"
TOP_C = "https://c.test/"
SITE_A = "https://a.test"

FRAME_COOKIES = [("Set-Cookie", "u=1; Path=/; SameSite=None; Secure"),
                 ("Set-Cookie", "p=1; Path=/; SameSite=None; Secure; Partitioned")]


class TLSStand(EchoStand):
    """The echo stand over TLS, one thread per connection: the pool keys its
    connections by the top-level site, so one frame under two sites is two
    connections, and a server serving one at a time would stall the second."""

    def __init__(self) -> None:
        super().__init__()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        ctx.set_alpn_protocols(["http/1.1"])
        # The handshake happens on the connection's own thread, at its
        # first read, rather than in the accept loop.
        self._srv.socket = ctx.wrap_socket(self._srv.socket, server_side=True,
                                           do_handshake_on_connect=False)
        self.url = f"https://localhost:{self.port}"


@pytest.fixture
def stand():
    with TLSStand() as st:
        # The frame's first load sets the cookies; the later ones, under
        # other sites, must not set their own, or each would be checking
        # what it has just received.
        st.routes["/set"] = (200, FRAME_COOKIES, b"<!doctype html><p>frame")
        st.routes["/frame"] = (200, [], b"<!doctype html><p>frame")
        yield st


def session(profile: str, **kw) -> curlpro.Session:
    return curlpro.Session(profile, verify=False, force_http1=True, **kw)


def cookie(st: EchoStand) -> str:
    return st.last().get("cookie", "")


# --- top_level, the argument and the property ------------------------------

def test_top_level_is_an_absolute_url():
    with pytest.raises(curlpro.ConfigurationError, match="top_level"):
        curlpro.Session("chrome-154-windows", top_level="www.a.test/checkout")
    with curlpro.Session("chrome-154-windows") as s:
        with pytest.raises(curlpro.ConfigurationError, match="top_level"):
            s.top_level = "/relative"
        assert s.top_level is None, "a refused value leaves the old one"
        with pytest.raises(curlpro.ConfigurationError, match="top_level"):
            s.get("http://127.0.0.1:1/", top_level="ftp://a.test/")
        with pytest.raises(curlpro.ConfigurationError, match="top_level"):
            s.headers_for("GET", "https://b.test/", top_level="a.test")
        with pytest.raises(curlpro.ConfigurationError, match="top_level"):
            s.preflight_for("GET", "https://b.test/", top_level="a.test")
        with pytest.raises(ValueError, match="top_level=True"):
            s.get("http://127.0.0.1:1/", top_level=True)
        with pytest.raises(TypeError, match="top_level"):
            s.get("http://127.0.0.1:1/", top_level=5)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="top_level"):
            s.top_level = 5  # type: ignore[assignment]


def test_the_top_level_property_moves_and_clears():
    with curlpro.Session("chrome-154-windows", top_level=TOP_A) as s:
        assert s.top_level == TOP_A
        s.top_level = TOP_C
        assert s.top_level == TOP_C
        s.top_level = None
        assert s.top_level is None

    async def run() -> list:
        async with curlpro.AsyncSession("chrome-154-windows", top_level=TOP_A) as a:
            seen = [a.top_level]
            a.top_level = TOP_C
            seen.append(a._session.top_level)
            a.top_level = None
            seen.append(a.top_level)
            return seen

    assert asyncio.run(run()) == [TOP_A, TOP_C, None]


# --- cookies a frame sets, over the wire -----------------------------------

def test_chromium_keeps_a_partitioned_cookie_under_its_top_level(stand):
    frame = stand.url + "/frame"
    with session("chrome-154-windows") as s:
        s.get(stand.url + "/set", resource="iframe", page=TOP_A)
        records = {c.name: c for c in s.cookies.all()}
        # The plain cookie in the ordinary jar, the Partitioned one under a.
        assert records["u"].partition is None and "partition" not in records["u"]
        assert records["p"].partition == SITE_A and SITE_A in repr(records["p"])

        s.get(frame, resource="iframe", page=TOP_A)
        assert sorted(cookie(stand).split("; ")) == ["p=1", "u=1"]
        s.get(frame, resource="iframe", page=TOP_C)
        assert cookie(stand) == "u=1"
        s.get(frame)                                  # b at the top level
        assert cookie(stand) == "u=1"

        # The frame's own fetch: made from the frame, under whatever the
        # address bar holds — which only top_level can say.
        api = stand.url + "/api"
        s.get(api, mode="fetch", page=frame, top_level=TOP_A)
        assert sorted(cookie(stand).split("; ")) == ["p=1", "u=1"]
        s.get(api, mode="fetch", page=frame, top_level=TOP_C)
        assert cookie(stand) == "u=1"
        s.page, s.top_level = frame, TOP_A
        s.get(api, mode="fetch")
        assert sorted(cookie(stand).split("; ")) == ["p=1", "u=1"]
        # False takes the page for the top level: the frame's own site.
        s.get(api, mode="fetch", top_level=False)
        assert cookie(stand) == "u=1"


def test_firefox_partitions_everything_a_third_party_sets(stand):
    frame = stand.url + "/frame"
    with session("firefox-156-windows") as s:
        s.get(stand.url + "/set", resource="iframe", page=TOP_A)
        # Total Cookie Protection: both, plain and Partitioned, under a.
        assert {(c.name, c.partition) for c in s.cookies.all()} == {("u", SITE_A), ("p", SITE_A)}
        s.get(frame, resource="iframe", page=TOP_A)
        assert sorted(cookie(stand).split("; ")) == ["p=1", "u=1"]
        s.get(frame, resource="iframe", page=TOP_C)
        assert cookie(stand) == ""
        s.get(frame)
        assert cookie(stand) == ""


def test_a_rollback_undoes_a_partitioned_cookie(stand):
    with session("chrome-154-windows") as s:
        with pytest.raises(curlpro.ExpectationFailed):
            s.get(stand.url + "/set", resource="iframe", page=TOP_A,
                  expect=curlpro.Expect(status=404), rollback_cookies=True)
        assert s.cookies.export() == []
        s.get(stand.url + "/frame", resource="iframe", page=TOP_A)
        assert cookie(stand) == "", "the undone cookies went out"


# --- the jar's records and files ---------------------------------------------

WIDGET = "https://widget.b.example"


def primed(profile: str = "chrome-154-windows") -> curlpro.Session:
    s = curlpro.Session(profile)
    # Any URL on the site will do; it is kept as the site itself.
    s.cookies.set("p", "1", domain="widget.b.example", secure=True, same_site="None",
                  partition=TOP_A)
    s.cookies.set("u", "1", domain="widget.b.example", secure=True, same_site="None")
    return s


def under(s: curlpro.Session, **kw) -> list[str]:
    """The cookies the frame's fetch would carry, sorted."""
    h = s.headers_for("GET", WIDGET + "/api", mode="fetch", page=WIDGET + "/frame", **kw)
    value = {k.lower(): v for k, v in h.items()}.get("cookie", "")
    return sorted(value.split("; ")) if value else []


def test_headers_for_shows_a_partitioned_cookie_under_its_site_alone():
    with primed() as s:
        assert [c.partition for c in s.cookies.all()] == [None, SITE_A]
        assert under(s, top_level=TOP_A) == ["p=1", "u=1"]
        assert under(s, top_level="https://shop.a.test/") == ["p=1", "u=1"], "keyed by the site"
        assert under(s, top_level=TOP_C) == ["u=1"]
        assert under(s, top_level=False) == ["u=1"]
        assert under(s) == ["u=1"], "no top level: the page is its own"
        s.top_level = TOP_A
        assert under(s) == ["p=1", "u=1"]
        assert under(s, top_level=False) == ["u=1"], "a request's own wins"
        # A frame's document under a carries it too.
        h = s.headers_for("GET", WIDGET + "/frame", resource="iframe", page=TOP_A)
        assert "p=1" in {k.lower(): v for k, v in h.items()}["cookie"]


def test_partitioned_cookies_survive_a_json_round_trip(tmp_path):
    state = tmp_path / "cookies.json"
    with primed() as first:
        first.cookies.save(state)
        saved = first.cookies.export()
    assert json.loads(state.read_text(encoding="utf-8")) == saved
    assert [c.get("partition") for c in saved] == [None, SITE_A]
    with curlpro.Session("chrome-154-windows") as second:
        second.cookies.load_file(state)
        assert second.cookies.export() == saved
        assert under(second, top_level=TOP_A) == ["p=1", "u=1"]
        assert under(second, top_level=TOP_C) == ["u=1"]
        # A transaction's snapshot carries the partition as well.
        with pytest.raises(RuntimeError):
            with second.cookies.transaction():
                second.cookies.clear()
                raise RuntimeError("the block failed")
        assert second.cookies.export() == saved


def test_the_netscape_file_leaves_partitioned_cookies_out(tmp_path):
    with primed() as s:
        text = s.cookies.to_netscape()
        s.cookies.save_netscape(tmp_path / "cookies.txt")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("# ")]
    assert len(lines) == 1 and lines[0].endswith("\tu\t1"), text
    assert (tmp_path / "cookies.txt").read_text(encoding="utf-8") == text
    # The same from records given by hand.
    assert "\tp\t" not in format_netscape([{"name": "p", "value": "1", "domain": "b.example",
                                            "partition": SITE_A}])


def test_a_malformed_partition_is_refused():
    with curlpro.Session("chrome-154-windows") as s:
        with pytest.raises(curlpro.CurlProError, match="partition"):
            s.cookies.set("x", "1", domain="b.example", partition="a.test")
        with pytest.raises(curlpro.CurlProError, match="partition"):
            s.cookies.load([{"name": "x", "value": "1", "domain": "b.example",
                             "partition": "ftp://a.test/"}])
        assert s.cookies.export() == [], "nothing landed in the ordinary jar"


def test_capabilities_name_the_partitioning():
    assert curlpro.capabilities("chrome-154-windows")["cookies"]["partitioning"] == "partitioned"
    assert curlpro.capabilities("firefox-156-windows")["cookies"]["partitioning"] == "third-party"
    assert not curlpro.capabilities("safari-26-ios")["cookies"].get("partitioning")
