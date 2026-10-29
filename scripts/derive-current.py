"""Write the presets for the browser versions current on 2026-09-26 and
2026-10-10 that this project could not capture yet, as deltas on captured
twins, marked.

Every profile written here carries ``source.kind = "derived"``: its ClientHello,
HTTP/2 frames and header sets are a captured twin's, and only what published
facts establish is changed — the User-Agent, the brand list (computed as
Chromium computes it, scripts/chromium_brands.py), and for Chrome the identity
pool (scripts/gen-identities.py, run afterwards). ``capabilities()["measured"]``
is False for them and the audit says so; ``list_profiles(measured=True)``
leaves them out. Each is to be replaced by a live capture the day its browser
is on the stand (docs/CAPTURE.md).

The evidence, read on 2026-09-26:

- Chrome 154 went stable on 2026-09-22 (chromiumdash: 154.0.8037.57/.58 for
  Windows and Mac, .57 for Linux). Its TLS is not measured: Chrome 153 added an
  extension (0xca34) where 152 had none, so a major can change the hello. The
  installed Chrome here is 153.0.8010.54.
- Edge 154 stable is 154.0.4258.37 (edgeupdates.microsoft.com, 2026-09-24),
  built on Chromium 154; it stands on the derived Chrome 154, as edge-153 does
  on chrome-153.
- Opera 136.0.6008.52 (2026-09-24) is built on Chromium 152.0.7977.130
  (blogs.opera.com/desktop/2026/09/opera-136-0-6008-52-stable-update/): it
  stands on the captured Chrome 152.
- Safari 27 shipped with iOS 27.0 and macOS 27.0 on 2026-09-14. A real iOS 27.0
  Safari string (github.com/openwrt/uhttpd/issues/42, 2026-09-21) keeps the OS
  token frozen at 18_7 with Version/27.0. The macOS string is assumed in the
  form every Safari since 14 sends (Intel Mac OS X 10_15_7), not seen.

Added on 2026-10-10:

- Chrome 155 for Windows is captured (155.0.8059.39, ``curlpro capture``):
  its ClientHello, HTTP/2 frames and header order are Chrome 153's, the
  User-Agent and the brands aside, and the brands it sent are exactly what
  scripts/chromium_brands.py computes for 155. So Chrome 155 for macOS and
  Linux stand on their 153 twins with 155's User-Agent and brands.
- Chrome 156 went stable on 2026-10-07 (chromiumdash: 156.0.8078.12, Windows)
  while the Chrome here is 155: it stands on the captured chrome-155-windows,
  and its macOS and Linux twins on the 153 ones. Three majors in a row kept
  the hello; that is evidence, not a measurement of 156.

Revised on 2026-10-26:

- Chrome 155 turned JPEG XL on (kJXLImageFormat, enabled by default from 155):
  image/jxl leads the Accept of every navigation, frame and image, as the
  captured Chrome 155 shows (capture/subres/chrome-155-*). Chrome 155 and 156
  for macOS and Linux therefore stand on the captured chrome-155-windows rather
  than on their 153 twins, with their own platform, User-Agent and brands —
  what a twin changes (the hello, the frames and the header sets come from
  BoringSSL and the network stack, not from the OS: every Chrome/Edge and
  Linux/macOS pair the corpus holds agrees).

Run: ``python scripts/derive-current.py`` then ``python scripts/gen-identities.py``
and ``python scripts/gen-safari-fetch.py``.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ROOT / "profiles"
sys.path.insert(0, str(ROOT / "scripts"))
from chromium_brands import sec_ch_ua  # noqa: E402

DATE = "2026-09-26"
DATE_1010 = "2026-10-10"
DATE_1026 = "2026-10-26"
DATE_1029 = "2026-10-29"
PLATFORM = {"windows": '"Windows"', "macos": '"macOS"', "linux": '"Linux"'}

WIN = "Windows NT 10.0; Win64; x64"
MAC = "Macintosh; Intel Mac OS X 10_15_7"
LINUX = "X11; Linux x86_64"


def chrome_ua(platform: str, major: int, extra: str = "") -> str:
    return (f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36{extra}")


CHROME_155_NOTE = ("Derived, not captured: Chrome 155 was captured on Windows (155.0.8059.39 and .40, "
                   "2026-10-10 and 2026-10-26), and this {os} twin stands on that capture — its "
                   "ClientHello, HTTP/2 frames, header sets and resources, image/jxl in Accept included — "
                   "with {os}'s sec-ch-ua-platform and User-Agent and 155's brands, computed as Chromium "
                   "computes them. Replace with a capture from {os}.")
CHROME_156_NOTE = ("Derived, not captured: Chrome 156 was captured on Windows (156.0.8078.73, "
                   "2026-10-29: the same hello, frames, header sets and resources as 155), and this {os} "
                   "twin stands on that capture with {os}'s sec-ch-ua-platform and User-Agent and 156's "
                   "brands, computed as Chromium computes them. Replace with a capture from {os}.")
CHROME_157_NOTE = ("Derived, not captured: Chrome 157 went stable on 2026-10-22 (chromiumdash, Stable: "
                   "157.0.8103.15), and the stand's Chrome is 156 — its updater rolls 157 out to this "
                   "machine later. The ClientHello, HTTP/2 frames, header sets and resources are the "
                   "captured chrome-156-windows's{os}; the User-Agent and the brand list are 157's, the "
                   "brands computed as Chromium computes them. Chrome 153 to 156 sent the same hello, which "
                   "is evidence, not a measurement: replace with a capture when Chrome 157 is on the stand.")

CHROME_NOTE = ("Derived, not captured: Chrome 154 went stable on 2026-09-22 (chromiumdash, Stable: "
               "154.0.8037.57/.58), and the Chrome on this project's stand is still 153. The ClientHello, "
               "HTTP/2 frames and header sets are {base}'s; the User-Agent and the brand list are 154's, the "
               "brands computed as Chromium computes them. Chrome 153 added a TLS extension 152 lacked, so a "
               "major can change the hello: replace with a capture when Chrome 154 is on the stand.")

PLAN = [
    # (name, based_on, user agent, sec-ch-ua or None, source from, note)
    ("chrome-154-windows", "chrome-153-windows", chrome_ua(WIN, 154), sec_ch_ua(154, "Google Chrome", 154),
     "https://chromiumdash.appspot.com/releases?platform=Windows", CHROME_NOTE.format(base="chrome-153-windows")),
    ("chrome-154-macos", "chrome-153-macos", chrome_ua(MAC, 154), sec_ch_ua(154, "Google Chrome", 154),
     "https://chromiumdash.appspot.com/releases?platform=Mac", CHROME_NOTE.format(base="chrome-153-macos")),
    ("chrome-154-linux", "chrome-153-linux", chrome_ua(LINUX, 154), sec_ch_ua(154, "Google Chrome", 154),
     "https://chromiumdash.appspot.com/releases?platform=Linux", CHROME_NOTE.format(base="chrome-153-linux")),
    ("edge-154-windows", "chrome-154-windows", chrome_ua(WIN, 154, " Edg/154.0.0.0"),
     sec_ch_ua(154, "Microsoft Edge", 154), "https://edgeupdates.microsoft.com/api/products",
     "Derived, not captured: Edge 154.0.4258.37 is the stable release of 2026-09-24, on Chromium 154. "
     "It stands on the derived chrome-154-windows as edge-153-windows stands on chrome-153-windows: "
     "Chrome's hello and frames, Edge's User-Agent and brands. No identity pool: Edge writes its own "
     "build next to Chromium's in the full-version list, and Chromium's is not published."),
    ("opera-136-windows", "chrome-152-windows", chrome_ua(WIN, 152, " OPR/136.0.0.0"),
     sec_ch_ua(152, "Opera", 136), "https://blogs.opera.com/desktop/2026/09/opera-136-0-6008-52-stable-update/",
     "Derived, not captured: Opera 136.0.6008.52 (2026-09-24) is built on Chromium 152.0.7977.130, so "
     "it stands on the captured Chrome 152 — its hello, frames and header sets — with Opera's "
     "User-Agent and brands. That Opera's TLS equals its Chromium's is what wreq-util claims for "
     "every Opera it describes; it was not measured here."),
    ("opera-136-macos", "chrome-152-macos", chrome_ua(MAC, 152, " OPR/136.0.0.0"),
     sec_ch_ua(152, "Opera", 136), "https://blogs.opera.com/desktop/2026/09/opera-136-0-6008-52-stable-update/",
     "Derived, not captured: Opera 136.0.6008.52 (2026-09-24) on Chromium 152.0.7977.130, standing on "
     "Chrome 152 for macOS with Opera's User-Agent and brands; Opera's own TLS was not measured."),
    ("chrome-155-macos", "chrome-155-windows", chrome_ua(MAC, 155), sec_ch_ua(155, "Google Chrome", 155),
     "https://chromiumdash.appspot.com/releases?platform=Mac",
     CHROME_155_NOTE.format(os="macOS"), DATE_1026),
    ("chrome-155-linux", "chrome-155-windows", chrome_ua(LINUX, 155), sec_ch_ua(155, "Google Chrome", 155),
     "https://chromiumdash.appspot.com/releases?platform=Linux",
     CHROME_155_NOTE.format(os="Linux"), DATE_1026),
    ("chrome-156-macos", "chrome-156-windows", chrome_ua(MAC, 156), sec_ch_ua(156, "Google Chrome", 156),
     "https://chromiumdash.appspot.com/releases?platform=Mac",
     CHROME_156_NOTE.format(os="macOS"), DATE_1029),
    ("chrome-156-linux", "chrome-156-windows", chrome_ua(LINUX, 156), sec_ch_ua(156, "Google Chrome", 156),
     "https://chromiumdash.appspot.com/releases?platform=Linux",
     CHROME_156_NOTE.format(os="Linux"), DATE_1029),
    ("chrome-157-windows", "chrome-156-windows", chrome_ua(WIN, 157), sec_ch_ua(157, "Google Chrome", 157),
     "https://chromiumdash.appspot.com/releases?platform=Windows",
     CHROME_157_NOTE.format(os=""), DATE_1029),
    ("chrome-157-macos", "chrome-156-windows", chrome_ua(MAC, 157), sec_ch_ua(157, "Google Chrome", 157),
     "https://chromiumdash.appspot.com/releases?platform=Mac",
     CHROME_157_NOTE.format(os=", with macOS's sec-ch-ua-platform"), DATE_1029),
    ("chrome-157-linux", "chrome-156-windows", chrome_ua(LINUX, 157), sec_ch_ua(157, "Google Chrome", 157),
     "https://chromiumdash.appspot.com/releases?platform=Linux",
     CHROME_157_NOTE.format(os=", with Linux's sec-ch-ua-platform"), DATE_1029),
    ("edge-156-windows", "chrome-156-windows", chrome_ua(WIN, 156, " Edg/156.0.0.0"),
     sec_ch_ua(156, "Microsoft Edge", 156), "https://edgeupdates.microsoft.com/api/products",
     "Derived, not captured: Edge 156.0.4314.50 is the stable release of 2026-10-28, on Chromium 156. "
     "It stands on the captured chrome-156-windows as edge-153-windows stands on chrome-153-windows: "
     "Chrome's hello and frames, Edge's User-Agent and brands. The stand's Edge is 139 and its updates "
     "are switched off on that machine by policy. No identity pool: Edge writes its own build next to "
     "Chromium's in the full-version list.", DATE_1029),
    ("opera-139-macos", "chrome-155-macos", chrome_ua(MAC, 155, " OPR/139.0.0.0"),
     sec_ch_ua(155, "Opera", 139), "https://get.geo.opera.com/pub/opera/desktop/139.0.6053.15/",
     "Derived, not captured: Opera 139.0.6053.15 (2026-10-27) was captured on Windows "
     "(opera-139-windows, 2026-10-29) and sent Chrome 155's hello, frames, header sets and resources "
     "to the byte but for its User-Agent and brands; this macOS twin stands on Chrome 155 for macOS "
     "with Opera's User-Agent and brands.", DATE_1029),
    ("safari-27-ios", "safari-26-ios",
     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/27.0 Mobile/15E148 Safari/604.1", None, "https://github.com/openwrt/uhttpd/issues/42",
     "Derived, not captured: Safari 27 shipped with iOS 27.0 on 2026-09-14. The User-Agent is a real "
     "iOS 27.0 Safari string (OS token frozen at 18_7, Version/27.0); the ClientHello, HTTP/2 frames "
     "and header sets are the captured safari-26-ios's. Whether Safari 27 changed its TLS or HTTP/2 "
     "is not known here: replace with a capture from an iPhone on iOS 27."),
    ("safari-27-macos", "safari-26.0-macos",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/27.0 Safari/605.1.15", None, "https://support.apple.com/en-us/100100",
     "Derived, not captured: Safari 27 shipped for macOS 27, 26 and 15 on 2026-09-14. The User-Agent "
     "takes the form every Safari since 14 sends on a Mac (the OS frozen at Intel Mac OS X 10_15_7) "
     "with Version/27.0 — assumed, not seen; the ClientHello, HTTP/2 frames and header sets are the "
     "captured safari-26.0-macos's."),
]


def load(name: str) -> dict:
    return json.loads((PROFILES / f"{name}.json").read_text(encoding="utf-8"))


def resolved_order(name: str) -> list[dict]:
    while name:
        d = load(name)
        order = (d.get("headers") or {}).get("order")
        if order:
            return [dict(h) for h in order]
        name = d.get("based_on")
    raise SystemExit(f"no header order in the chain of {name}")


def resolved_trust_anchors(name: str) -> list[str] | None:
    while name:
        d = load(name)
        ids = (d.get("tls") or {}).get("trust_anchors")
        if ids:
            return list(ids)
        name = d.get("based_on")
    return None


def relative_oid(s: str) -> bytes:
    out = bytearray()
    for arc in (int(a) for a in s.split(".")):
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


def chrome_major(name: str) -> int | None:
    m = re.match(r"chrome-(\d+)-", name)
    return int(m.group(1)) if m else None


# From 154 Chromium sorts the trust_anchors list bytewise before encoding it
# (942bda4, "Sort TAI list", first in 154.0.8031.0); up to 153 it went out in
# an order drawn once per browser process (an absl::flat_hash_set). A Chrome 154+ derived on a 153 capture
# therefore carries the capture's list sorted — Chrome 155's capture shows
# exactly that order.
TAI_SORTED_NOTE = (" The trust_anchors list goes out sorted bytewise, as Chromium sends it from 154 "
                   "(942bda4); the set is the capture's, Chrome's root store being unchanged since 153.")


def main() -> int:
    check = "--check" in sys.argv
    drift = False
    for name, base, ua, brands, src, note, *date in PLAN:
        order = resolved_order(base)
        platform = PLATFORM.get(name.rsplit("-", 1)[-1]) if name.startswith("chrome-") else None
        for h in order:
            k = h["key"].lower()
            if k == "sec-ch-ua" and brands:
                h["value"] = brands
            elif k == "user-agent" and h.get("value"):
                h["value"] = ua
            elif k == "sec-ch-ua-platform" and platform and h.get("value"):
                h["value"] = platform
        want = {
            "name": name,
            "based_on": base,
            "source": {"kind": "derived", "from": src, "date": date[0] if date else DATE,
                       "path": "scripts/derive-current.py",
                       "note": note},
            "headers": {"user_agent": ua, "order": order},
        }
        major, base_major = chrome_major(name), chrome_major(base)
        if major and base_major and major >= 154 > base_major:
            ids = resolved_trust_anchors(base)
            if ids:
                want["tls"] = {"trust_anchors": sorted(ids, key=relative_oid)}
                want["source"]["note"] += TAI_SORTED_NOTE
                want = {k: want[k] for k in ("name", "based_on", "source", "tls", "headers")}
        path = PROFILES / f"{name}.json"
        if path.exists():
            have = load(name)
            # The generators own devices, client hints and fetch sets.
            kept = {k: v for k, v in have.items() if k in ("devices", "device_kind", "client_hints", "fetch")}
            want.update(kept)
            if have == want:
                continue
            if check:
                print(f"{name}: differs from the plan", file=sys.stderr)
                drift = True
                continue
        elif check:
            print(f"{name}: missing", file=sys.stderr)
            drift = True
            continue
        path.write_text(json.dumps(want, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"{name}: written on {base}")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
