"""Write the presets for the browser versions current on 2026-09-26 that this
project could not capture yet, as deltas on captured twins, marked.

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

Run: ``python scripts/derive-current.py`` then ``python scripts/gen-identities.py``
and ``python scripts/gen-safari-fetch.py``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ROOT / "profiles"
sys.path.insert(0, str(ROOT / "scripts"))
from chromium_brands import sec_ch_ua  # noqa: E402

DATE = "2026-09-26"

WIN = "Windows NT 10.0; Win64; x64"
MAC = "Macintosh; Intel Mac OS X 10_15_7"
LINUX = "X11; Linux x86_64"


def chrome_ua(platform: str, major: int, extra: str = "") -> str:
    return (f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36{extra}")


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


def main() -> int:
    check = "--check" in sys.argv
    drift = False
    for name, base, ua, brands, src, note in PLAN:
        order = resolved_order(base)
        for h in order:
            k = h["key"].lower()
            if k == "sec-ch-ua" and brands:
                h["value"] = brands
            elif k == "user-agent" and h.get("value"):
                h["value"] = ua
        want = {
            "name": name,
            "based_on": base,
            "source": {"kind": "derived", "from": src, "date": DATE, "path": "scripts/derive-current.py",
                       "note": note},
            "headers": {"user_agent": ua, "order": order},
        }
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
