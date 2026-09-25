"""Write the identity pools — what varies between real users of one browser
version besides the phone model — into the profiles.

The Android pool (``gen-devices.py``) answered one question: which phone. This
one answers the rest, per family, from the committed seed
``scripts/identities.json``, which names its sources:

- Chromium on Windows: the Windows release (``sec-ch-ua-platform-version``:
  the UniversalApiContract version, 10.0.0 for Windows 10 22H2 as measured on
  the capture machine, 14/15/19 for Windows 11), the exact Chrome build
  (``sec-ch-ua-full-version`` and the versions inside ``-full-version-list``,
  from chromiumdash) and whether the browser is a 32-bit process on 64-bit
  Windows (``sec-ch-ua-wow64``). Arch ``x86``, bitness ``64``, form factor
  ``Desktop`` — Chromium reports those for every Windows desktop.
- Chromium on macOS: the macOS version and the CPU (``arm`` on Apple
  silicon, ``x86`` on Intel), and the build.
- Chromium on Linux: only the build — Chromium sends an empty platform
  version there (``user_agent_utils.cc``), and the architecture is x86-64.
- Safari on iOS: the iOS version. Safari 18 writes it into the User-Agent
  twice — ``iPhone OS 18_1_1`` and ``Version/18.1.1``; Safari 26 froze the OS
  token at ``18_7`` and writes the real version only in ``Version/26.0.1``
  (every 26.x seen in real traffic says so) — so the pool needs a template.
  Each captured iOS profile takes the versions of its own Safari line.
- Firefox on Linux: the distribution token some builds carry (``Ubuntu; ``).

Desktop Chromium profiles also receive the ``client_hints`` section they
lacked: the header order after ``Accept-CH``/``Critical-CH`` as measured on
Chrome 153 / Windows 10 (STAGE19) — the navigation order from the stand's
second page, the fetch order from the Pixel 7 capture of Chrome 152, which the
desktop capture matched wherever no custom header disturbed the cluster — and
the default values of the capture machine, so that a session without a device
chosen still answers a site the way that machine does.

Without ``device=`` a session sends the defaults, a real machine; with
``device="random"`` it draws one identity from the pool for its lifetime, as
``chrome-152-android`` draws a phone. The TLS never changes: that is the point.

Run: ``python scripts/gen-identities.py`` (``--check`` in CI fails on drift).
"""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "scripts" / "identities.json"
PROFILES = ROOT / "profiles"

# Measured on Chrome 153 / Windows 10 22H2, 2026-09-22 (STAGE19): the hints
# the capture machine sends once a site asked, and the order it sends them in.
MACHINE = {
    "sec-ch-ua-full-version": '"153.0.8010.52"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-ch-ua-model": '""',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-wow64": "?1",
    "sec-ch-ua-form-factors": '"Desktop"',
}
NAV_ORDER = [
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model",
    "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-full-version-list",
    "sec-ch-ua-form-factors", "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
FETCH_ORDER = [
    "content-length", "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "sec-ch-ua",
    "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-mobile", "sec-ch-ua-form-factors",
    "sec-ch-ua-wow64", "sec-ch-ua-arch", "sec-ch-ua-full-version", "user-agent",
    "content-type", "sec-ch-ua-platform-version", "accept", "origin", "sec-fetch-site",
    "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language",
    "cookie", "priority",
]

# Which desktop Chromium profiles carry a pool: (profile, os, chrome major).
DESKTOP = [
    ("chrome-151-windows", "windows", "151"), ("chrome-151-macos", "macos", "151"), ("chrome-151-linux", "linux", "151"),
    ("chrome-152-windows", "windows", "152"), ("chrome-152-macos", "macos", "152"), ("chrome-152-linux", "linux", "152"),
    ("chrome-153-windows", "windows", "153"), ("chrome-153-macos", "macos", "153"), ("chrome-153-linux", "linux", "153"),
    # Derived, not captured (scripts/derive-current.py): the pool is Chrome 154's
    # builds on the 153 capture's hints order.
    ("chrome-154-windows", "windows", "154"), ("chrome-154-macos", "macos", "154"), ("chrome-154-linux", "linux", "154"),
]
# Not edge-153-windows: Edge writes its own build into "Microsoft Edge";v= and
# sec-ch-ua-full-version (153.0.3xxx.xx) next to Chromium's in the list, and
# neither the Edge builds nor which Chromium build each carries is known here
# without a real Edge on the stand. It keeps the pre-0.11 behaviour: no pool,
# no high-entropy hints.

IOS_TEMPLATE = ("Mozilla/5.0 (iPhone; CPU iPhone OS {os_version} like Mac OS X) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/{version} Mobile/15E148 Safari/604.1")


def seed() -> dict:
    return json.loads(SEED.read_text(encoding="utf-8"))


def full_version_list(brands: str, full: str) -> str:
    major = full.split(".")[0]
    parts = []
    for part in brands.split(", "):
        name, _, v = part.partition(";v=")
        v = v.strip('"')
        parts.append(f'{name};v="{full}"' if v == major else f'{name};v="{v}.0.0.0"')
    return ", ".join(parts)


def desktop_devices(os_: str, major: str, s: dict) -> list[dict]:
    builds = s["chrome_builds"][major]
    out = []
    if os_ == "windows":
        for w in s["windows"]:
            for b in builds:
                out.append({"name": f"{w['name']}, Chrome {b}", "platform_version": w["platform_version"],
                            "full_version": b, "hint_arch": "x86", "bitness": "64", "wow64": w["wow64"],
                            "form_factors": "Desktop"})
    elif os_ == "macos":
        for m in s["macos"]:
            for b in builds:
                out.append({"name": f"{m['name']} ({'Apple silicon' if m['arch'] == 'arm' else 'Intel'}), Chrome {b}",
                            "platform_version": m["platform_version"], "full_version": b, "hint_arch": m["arch"],
                            "bitness": "64", "wow64": "?0", "form_factors": "Desktop"})
    else:
        for b in builds:
            out.append({"name": f"Linux, Chrome {b}", "full_version": b, "hint_arch": "x86", "bitness": "64",
                        "wow64": "?0", "form_factors": "Desktop"})
    return out


def desktop_values(os_: str, major: str, brands: str, s: dict) -> dict:
    """The hints a session sends without a device: the capture machine's on
    chrome-153-windows, the pool's first identity elsewhere."""
    if os_ == "windows" and major == "153":
        v = dict(MACHINE)
    else:
        d = desktop_devices(os_, major, s)[0]
        v = {"sec-ch-ua-full-version": f'"{d["full_version"]}"', "sec-ch-ua-arch": f'"{d["hint_arch"]}"',
             "sec-ch-ua-platform-version": f'"{d.get("platform_version", "")}"', "sec-ch-ua-model": '""',
             "sec-ch-ua-bitness": '"64"', "sec-ch-ua-wow64": d["wow64"], "sec-ch-ua-form-factors": '"Desktop"'}
    v["sec-ch-ua-full-version-list"] = full_version_list(brands, v["sec-ch-ua-full-version"].strip('"'))
    return v


def resolved_header(name: str, key: str) -> str:
    """A navigation header's value as the chain resolves it."""
    seen = set()
    while name and name not in seen:
        seen.add(name)
        d = json.loads((PROFILES / f"{name}.json").read_text(encoding="utf-8"))
        for h in (d.get("headers") or {}).get("order", []):
            if h["key"].lower() == key and h["value"]:
                return h["value"]
        name = d.get("based_on")
    return ""


def ios_devices(spec: dict) -> list[dict]:
    """One identity per iOS version of the line; ``frozen_os`` is the OS token
    Safari 26 pins the string to while ``Version/`` keeps the real one."""
    frozen = spec.get("frozen_os")
    by_version = spec.get("frozen_os_by_version") or {}
    return [{"name": f"iPhone, iOS {v}", "os_version": by_version.get(v) or frozen or v.replace(".", "_"),
             "version": v}
            for v in spec["versions"]]


def wanted() -> dict[str, dict]:
    """profile name -> the fields the generator owns and their wanted content."""
    s = seed()
    out: dict[str, dict] = {}
    for name, os_, major in DESKTOP:
        brands = resolved_header(name, "sec-ch-ua")
        out[name] = {
            "client_hints": {
                "values": desktop_values(os_, major, brands, s),
                "order": [{"key": k, "value": ""} for k in NAV_ORDER],
                "fetch_order": [{"key": k, "value": ""} for k in FETCH_ORDER],
            },
            "devices": desktop_devices(os_, major, s),
            "device_kind": "desktop",
        }
    for name, spec in s["ios"].items():
        out[name] = {"devices": ios_devices(spec), "device_kind": "iphone",
                     "user_agent_template": IOS_TEMPLATE}
    for p in sorted(PROFILES.glob("firefox-*-linux.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        ua = d["headers"]["user_agent"]
        # The profile's own string may already carry the Ubuntu token (wreq-util's
        # Firefox strings do); the template takes either shape.
        tpl = re.sub(r"\(X11; (?:Ubuntu; )?Linux x86_64;", "(X11; {distro}Linux x86_64;", ua)
        out[p.stem] = {"devices": list(s["firefox_linux"]), "device_kind": "distro",
                       "user_agent_template": tpl}
    # A delta inherits its parent's pool, and most deltas on a pooled profile
    # must not have one: the macOS Safari profiles stand on the iOS captures,
    # edge-153-windows on chrome-153-windows (Edge writes its own build into the
    # list, unknown here), the transcribed iOS and iPadOS deltas on the iOS
    # captures. Each gets an explicit empty pool — and, under a desktop parent,
    # an empty hints section, because the inherited values would carry the
    # parent's brands and build.
    desktop = {name for name, _, _ in DESKTOP}
    for p in sorted(PROFILES.glob("*.json")):
        if p.stem in out or json.loads(p.read_text(encoding="utf-8")).get("devices"):
            continue  # pooled here, or by gen-devices.py (the Android phones)
        pooled = [a for a in chain(p.stem) if a in out]
        if not pooled:
            continue
        want = {"devices": []}
        if any(a in desktop for a in pooled):
            want["client_hints"] = {"values": {}, "order": [], "fetch_order": []}
        out[p.stem] = want
    return out


def chain(name: str) -> list[str]:
    """The ancestors of a profile, nearest first."""
    out, seen = [], {name}
    while True:
        d = json.loads((PROFILES / f"{name}.json").read_text(encoding="utf-8"))
        name = d.get("based_on")
        if not name or name in seen:
            return out
        seen.add(name)
        out.append(name)


def main() -> int:
    check = "--check" in sys.argv
    drift = False
    for name, want in wanted().items():
        path = PROFILES / f"{name}.json"
        if not path.exists():
            print(f"{name}: no such profile", file=sys.stderr)
            drift = True
            continue
        raw = path.read_bytes()
        nl = "\r\n" if b"\r\n" in raw else "\n"
        profile = json.loads(raw.decode("utf-8"))
        changed = False
        for key, value in want.items():
            if key == "user_agent_template":
                if profile.setdefault("headers", {}).get("user_agent_template") != value:
                    profile["headers"]["user_agent_template"] = value
                    changed = True
            elif profile.get(key) != value:
                profile[key] = value
                changed = True
        if not changed:
            continue
        if check:
            print(f"{name}: differs from the seed", file=sys.stderr)
            drift = True
            continue
        text = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
        io.open(path, "wb").write(text.replace("\n", nl).encode("utf-8"))
        n = len(want.get("devices", []))
        print(f"{name}: wrote {n} identities" if n else f"{name}: no pool of its own")
    return 1 if (check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
