"""High-entropy client hints and device selection.

Chrome cut the model and the OS version out of the User-Agent: every phone
"reports Android 10; K" there. Phones differ through the sec-ch-ua-model and
sec-ch-ua-platform-version hints, which the browser sends only after Accept-CH.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
CERT_DIR = REPO / "capture" / "certs"


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


class HintServer:
    """A server that asks for hints and records the raw headers."""

    def __init__(self, accept_ch: str, critical: bool = False):
        self.accept_ch = accept_ch
        self.critical = critical
        self.requests: list[list[str]] = []

        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(CERT_DIR / "tls.crt", CERT_DIR / "tls.key")
        self._ctx.set_alpn_protocols(["http/1.1"])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as conn:
                    while self._handle(conn):
                        pass
            except (ssl.SSLError, OSError):
                pass

    def _handle(self, conn: ssl.SSLSocket) -> bool:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        self.requests.append([ln for ln in head[1:] if ":" in ln])

        body = b"ok"
        extra = f"Accept-CH: {self.accept_ch}\r\n"
        if self.critical:
            extra += f"Critical-CH: {self.accept_ch}\r\n"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + extra.encode()
            + b"Connection: keep-alive\r\n\r\n"
            + body
        )
        return True

    def names(self, i: int) -> list[str]:
        return [ln.split(":", 1)[0] for ln in self.requests[i]]

    def value(self, i: int, name: str) -> str | None:
        for ln in self.requests[i]:
            k, _, v = ln.partition(":")
            if k.strip().lower() == name:
                return v.strip()
        return None

    def __enter__(self) -> "HintServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)



import json as _json
from pathlib import Path as _Path

_SEED = {d["name"]: d for d in _json.loads(
    (_Path(__file__).resolve().parents[2] / "scripts" / "android-devices.json")
    .read_text(encoding="utf-8"))}


def _pv(name: str) -> str:
    """The Android version the seed assigns a device — so a regenerated pool
    does not break tests that only care that the value flows through intact."""
    return _SEED[name]["platform_version"]


def _model(name: str) -> str:
    return _SEED[name]["model"]


ALL_HINTS = (
    "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-form-factors, "
    "sec-ch-ua-full-version, sec-ch-ua-full-version-list, sec-ch-ua-model, "
    "sec-ch-ua-platform-version, sec-ch-ua-wow64"
)


def test_hints_appear_only_after_accept_ch():
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 8") as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(0, "sec-ch-ua-model") is None, "the hint went out before Accept-CH"
    assert srv.value(1, "sec-ch-ua-model") == '"Pixel 8"'
    assert srv.value(1, "sec-ch-ua-platform-version") == f'"{_pv("Pixel 8")}"'


def test_critical_ch_makes_the_client_repeat_at_once():
    with HintServer("sec-ch-ua-model", critical=True) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
    assert len(srv.requests) == 2, "Critical-CH must trigger an immediate repeat"
    assert srv.value(1, "sec-ch-ua-model") == '"Pixel 7"'


def test_only_requested_hints_are_sent():
    with HintServer("sec-ch-ua-model") as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    names = [n.lower() for n in srv.names(1)]
    assert "sec-ch-ua-model" in names
    assert "sec-ch-ua-platform-version" not in names, "the site did not ask for this hint"
    assert "sec-ch-ua-full-version-list" not in names


def test_hint_order_matches_measured_template():
    """The order of the cluster with hints was captured from Chrome 152 on a Pixel 7."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    got = [n for n in srv.names(1) if n.lower().startswith("sec-ch-ua")]
    assert got == [
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
        "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model",
        "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-full-version-list",
        "sec-ch-ua-form-factors",
    ], got


def test_random_device_differs_between_sessions():
    seen = set()
    with HintServer("sec-ch-ua-model") as srv:
        for _ in range(12):
            with curlpro.Session("chrome-152-android", verify=False,
                                 force_http1=True, device="random") as s:
                s.get(srv.url)
                s.get(srv.url)
            seen.add(srv.value(len(srv.requests) - 1, "sec-ch-ua-model"))
    assert len(seen) > 1, f"the device never changed over twelve sessions: {seen}"


def test_own_device_list_overrides_the_profile():
    devices = [{"name": "mine", "model": "SM-X999", "platform_version": "13.0.0"}]
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False, force_http1=True,
                             device="mine", devices=devices) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(1, "sec-ch-ua-model") == '"SM-X999"'
    assert srv.value(1, "sec-ch-ua-platform-version") == '"13.0.0"'


def test_unknown_device_is_an_error():
    with pytest.raises(curlpro.CurlProError, match="device"):
        curlpro.Session("chrome-152-android", device="Nokia 3310")


def test_a_chosen_device_goes_into_the_chrome_user_agent_too():
    """The owner's decision, against what Chrome does: a stock Chrome ≥110 sends
    the reduced "Android 10; K" for every phone and discloses the model only in
    the hints. Here a chosen device is written into the string as well, so the
    46 phones are 46 User-Agent strings on Chrome the way they are on Yandex.
    The string and the hints must still say the same phone and the same Android."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False,
                             force_http1=True, device="Galaxy S23") as s:
            s.get(srv.url)
            s.get(srv.url)
    m, v = _model("Galaxy S23"), _pv("Galaxy S23")
    ua = srv.value(1, "user-agent")
    assert f"Android {v.split('.')[0]}; {m})" in ua, ua
    assert "Android 10; K" not in ua
    assert "Chrome/152.0.0.0 Mobile Safari/537.36" in ua
    assert srv.value(1, "sec-ch-ua-model") == f'"{m}"'
    assert srv.value(1, "sec-ch-ua-platform-version") == f'"{v}"'


def test_without_a_device_chrome_keeps_the_reduced_user_agent():
    """No device chosen: the profile goes out as captured, reduced string included."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False, force_http1=True) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert "Android 10; K" in srv.value(1, "user-agent")
    assert srv.value(1, "sec-ch-ua-model") is None


def test_random_devices_are_visible_in_the_chrome_user_agent():
    seen = set()
    for _ in range(30):
        with curlpro.Session("chrome-152-android", device="random") as s:
            seen.add(s.fingerprint().user_agent)
    assert len(seen) >= 10, f"random reached only {len(seen)} User-Agent strings"


def test_yandex_puts_the_device_into_the_user_agent():
    """Yandex puts the model and the Android version into the string itself — so we substitute there."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False,
                             force_http1=True, device="Galaxy S23") as s:
            s.get(srv.url)
            s.get(srv.url)
    m, v = _model("Galaxy S23"), _pv("Galaxy S23")
    major = v.split(".")[0]
    ua = srv.value(1, "user-agent")
    assert f"Android {major}; {m}" in ua, ua
    assert "Pixel 7" not in ua
    # The hint and the string must say the same thing.
    assert srv.value(1, "sec-ch-ua-model") == f'"{m}"'
    assert srv.value(1, "sec-ch-ua-platform-version") == f'"{v}"'


def test_yandex_full_version_is_its_own():
    """Yandex has its own full version, not Chrome's — measured on a phone."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False,
                             force_http1=True, device="Pixel 7") as s:
            s.get(srv.url)
            s.get(srv.url)
    assert srv.value(1, "sec-ch-ua-full-version") == '"26.8.2.121"'
    assert "Yandex" in srv.value(1, "sec-ch-ua-full-version-list")


def test_without_device_nothing_is_substituted():
    """Without device the profile stays exactly as it was captured."""
    with HintServer(ALL_HINTS) as srv:
        with curlpro.Session("yandex-26.8-android", verify=False, force_http1=True) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert "Pixel 7" in srv.value(1, "user-agent")
    assert srv.value(1, "sec-ch-ua-model") is None, "no model is substituted without a chosen device"


# The machine, network and preference hints (STAGE45): what a site such as a
# search engine asks for besides the User-Agent ones. Measured on Chrome 155
# and 156 with all of them asked for (capture/hints).
MACHINE_HINTS = (
    "device-memory, sec-ch-device-memory, dpr, sec-ch-dpr, viewport-width, "
    "sec-ch-viewport-width, sec-ch-viewport-height, rtt, downlink, ect, "
    "sec-ch-prefers-color-scheme, sec-ch-prefers-reduced-motion, "
    "sec-ch-prefers-reduced-transparency, " + ALL_HINTS
)
HINT_NAMES = {n.strip() for n in MACHINE_HINTS.split(",")} | {
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}


def _hints_in(names: list[str]) -> list[str]:
    return [n.lower() for n in names if n.lower() in HINT_NAMES]


def test_a_navigation_lays_every_hint_out_as_chromium_does():
    """The browser process adds them in one fixed sequence: the machine's and
    the network's before sec-ch-ua, the preferences after the last UA hint."""
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert _hints_in(srv.names(1)) == [
        "device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr", "viewport-width",
        "sec-ch-viewport-width", "sec-ch-viewport-height", "rtt", "downlink", "ect",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
        "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model",
        "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-full-version-list",
        "sec-ch-ua-form-factors", "sec-ch-prefers-color-scheme",
        "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
    ], srv.names(1)
    assert _hints_in(srv.names(0)) == ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"], (
        "the first request carried hints the site had not asked for yet")


def test_the_default_machine_is_the_capture_machine():
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True) as s:
            s.get(srv.url)
            s.get(srv.url)
    v = lambda n: srv.value(1, n)  # noqa: E731
    assert (v("device-memory"), v("sec-ch-device-memory")) == ("16", "16")
    assert (v("dpr"), v("sec-ch-dpr")) == ("1", "1")
    assert (v("viewport-width"), v("sec-ch-viewport-width"), v("sec-ch-viewport-height")) == ("1920", "1920", "969")
    assert v("ect") == "4g"
    assert v("sec-ch-prefers-color-scheme") == "dark"
    assert v("sec-ch-prefers-reduced-motion") == "no-preference"
    assert v("sec-ch-prefers-reduced-transparency") == "no-preference"


def test_network_hints_are_rounded_and_noised_like_chromium():
    """rtt in steps of 50 ms, downlink in steps of 50 kbps, around Chromium's
    default for Ethernet (90 ms, 1456 kbps): it multiplies by 0.90-1.10 per
    site, so 90 ms always reads 100."""
    with HintServer("rtt, downlink") as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True) as s:
            for _ in range(3):
                s.get(srv.url)
    rtts = {srv.value(i, "rtt") for i in (1, 2)}
    downs = {srv.value(i, "downlink") for i in (1, 2)}
    assert rtts == {"100"}, rtts
    assert len(downs) == 1, f"the value moved within one session and site: {downs}"
    d = float(downs.pop())
    assert 1.3 <= d <= 1.6 and round(d * 1000) % 50 == 0, d


def test_critical_ch_for_the_colour_scheme_repeats_at_once():
    """What a search engine asks: Critical-CH on sec-ch-prefers-color-scheme."""
    with HintServer("sec-ch-prefers-color-scheme", critical=True) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True) as s:
            s.get(srv.url)
    assert len(srv.requests) == 2, "Critical-CH must trigger an immediate repeat"
    assert srv.value(0, "sec-ch-prefers-color-scheme") is None
    assert srv.value(1, "sec-ch-prefers-color-scheme") == "dark"


def test_own_device_names_the_machine():
    devices = [{"name": "laptop", "full_version": "156.0.8078.73", "platform_version": "15.0.0",
                "hint_arch": "x86", "bitness": "64", "wow64": "?0", "form_factors": "Desktop",
                "device_memory": "8", "dpr": "1.5", "viewport": "1280x601", "color_scheme": "light",
                "rtt": "250", "downlink": "10", "ect": "3g"}]
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True,
                             device="laptop", devices=devices) as s:
            s.get(srv.url)
            s.get(srv.url)
    v = lambda n: srv.value(1, n)  # noqa: E731
    assert (v("device-memory"), v("dpr"), v("sec-ch-dpr")) == ("8", "1.5", "1.5")
    assert (v("viewport-width"), v("sec-ch-viewport-height")) == ("1280", "601")
    assert v("sec-ch-prefers-color-scheme") == "light"
    assert v("ect") == "3g"
    assert int(v("rtt")) in range(200, 301, 50)
    assert 9.0 <= float(v("downlink")) <= 10.0, v("downlink")  # 10 Mbps, capped at 10
    assert v("sec-ch-ua-platform-version") == '"15.0.0"'


def test_a_fetch_lays_its_cluster_out_as_chrome_156_did():
    """Blink keeps a page's headers, the hints and User-Agent in one hash map
    and the wire follows its buckets: the same names come out in Chrome's
    order — here against the fetch Chrome 156 made with all hints asked for."""
    capture = _json.loads((REPO / "capture" / "hints" / "chrome-156-all.json").read_text(encoding="utf-8"))
    chrome = next(r for r in capture if r["path"] == "/f-get-b")
    want = [h.split(": ", 1)[0] for h in chrome["headers"] if not h.startswith(":")]
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True, mode="fetch",
                             page=srv.url) as s:
            s.get(srv.url, mode="navigate")
            s.get(srv.url + "f-get-b")
    got = [n.lower() for n in srv.names(1)]
    cluster = HINT_NAMES | {"user-agent"}
    assert [n for n in got if n in cluster] == [n for n in want if n in cluster], got


def test_a_fetch_puts_the_pages_own_header_where_chrome_does():
    """X-Api-Key goes into the same map: bucket 13, before sec-ch-ua-mobile."""
    capture = _json.loads((REPO / "capture" / "hints" / "chrome-156-all.json").read_text(encoding="utf-8"))
    chrome = next(r for r in capture if r["path"] == "/f-key-b")
    want = [h.split(": ", 1)[0] for h in chrome["headers"] if not h.startswith(":")]
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True, mode="fetch",
                             page=srv.url) as s:
            s.get(srv.url, mode="navigate")
            s.get(srv.url + "f-key-b", headers={"X-Api-Key": "v1"})
    got = [n.lower() for n in srv.names(1)]
    cluster = HINT_NAMES | {"user-agent", "x-api-key"}
    assert [n for n in got if n in cluster] == [n for n in want if n in cluster], got


def test_accept_ch_on_a_fetch_switches_nothing_on():
    """Chromium persists the hints a top-level page asks for; an API that
    answers a fetch with Accept-CH changes nothing."""
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-156-windows", verify=False, force_http1=True, mode="fetch",
                             page=srv.url) as s:
            s.get(srv.url)
            s.get(srv.url)
    assert _hints_in(srv.names(1)) == ["sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile"], srv.names(1)


def test_a_phone_sends_its_own_screen():
    """A Galaxy S24 Ultra is not a Pixel: its scale factor, its viewport — 980
    wide in a navigation, as Chrome on Android scales it — its memory."""
    with HintServer(MACHINE_HINTS) as srv:
        with curlpro.Session("chrome-152-android", verify=False, force_http1=True,
                             device="Galaxy S24 Ultra") as s:
            s.get(srv.url)
            s.get(srv.url)
            s.get(srv.url + "api", mode="fetch", page=srv.url)
    nav = lambda n: srv.value(1, n)  # noqa: E731
    page = lambda n: srv.value(2, n)  # noqa: E731
    assert nav("sec-ch-ua-model") == '"SM-S928B"'
    assert (nav("dpr"), nav("device-memory")) == ("3.5", "8")
    assert (nav("viewport-width"), nav("sec-ch-viewport-height")) == ("980", str(round(787 * 980 / 412)))
    assert (page("sec-ch-viewport-width"), page("sec-ch-viewport-height")) == ("412", "787")
    assert nav("sec-ch-prefers-color-scheme") in ("light", "dark")


def test_a_mac_and_a_linux_box_have_screens_of_their_own():
    with HintServer(MACHINE_HINTS) as srv:
        for name in ("chrome-156-macos", "chrome-156-linux"):
            with curlpro.Session(name, verify=False, force_http1=True) as s:
                s.get(srv.url)
                s.get(srv.url)
    mac, linux = 1, 3
    assert (srv.value(mac, "dpr"), srv.value(mac, "viewport-width")) == ("2", "1470")
    assert srv.value(mac, "sec-ch-ua-arch") == '"arm"'
    assert (srv.value(linux, "dpr"), srv.value(linux, "sec-ch-viewport-height")) == ("1", "977")
