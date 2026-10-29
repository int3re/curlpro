"""Write the shared Android device pool into the Android profiles.

The pool is data, not a decision: a phone contributes its exact
``ro.product.model`` — the string Chrome reports in ``sec-ch-ua-model`` and
Yandex writes into the User-Agent — plus a plausible Android version. A big
pool means ``device="random"`` draws from many real phones while the TLS stays
one, which is the whole point: one fingerprint, many believable identities.

Source of the models: Google's public Play "supported devices" catalogue
(``storage.googleapis.com/play_public/supported_devices.csv``), the same list
Play Console shows. The global variant is chosen — Samsung's ``…B``/``…E``, not
the US ``…U`` — because the library is aimed at Russian sites. The verified
result is committed as ``scripts/android-devices.json`` so the repository need
not carry the 4.7 MB CSV; anyone can re-verify a model against that public file.

The Android version is the running OS a device plausibly reports, spread across
13–16 rather than pinned to one: a pool where every phone runs the same Android
would itself be a tell.

Two profiles carry the pool. ``chrome-152-android`` gets model and version —
modern Chrome froze the model out of the User-Agent, so it travels only in the
hints. ``yandex-26.8-android`` gets ``arch`` too and writes the model into the
User-Agent through its template, so there the pool is 46 distinct UA strings.

Each phone also carries its screen and memory, for the hints a site may ask
for besides the model (STAGE45): ``dpr``, ``screen`` (CSS pixels), ``panel``
(the maker's resolution) and ``ram_gb``, with ``screen_source`` saying where
the screen comes from — Chromium DevTools' emulated devices, the public
viewport table at yesviz.com (read 2026-10-29), the same maker's row with the
same panel, or the table's density for the panel's width (2.625 at 1080 px,
1.875 at 720, 3 at 1200-1280; Xiaomi's 2.75, Samsung's 3 and 3.5 on the S
line). From those the generator writes the device fields: ``device_memory``
as Chromium rounds the RAM a phone reports (about 7% under the nominal, the
nearest power of two, 1 to 8 on Android), ``viewport`` — the CSS screen less a
32 dp status bar, Chrome's 56 dp toolbar and a 16 dp gesture bar; a
navigation reports it scaled to 980 wide, as Chrome on Android does — the
colour scheme, alternating, and the network: Chromium's own default estimate
for Wi-Fi (116 ms, 2658 kbps) or a 4G cellular link (137 ms, 1708 kbps),
alternating (network_quality_estimator_params.cc). The profiles' defaults are
the Pixel 7 the Android capture was made on (STAGE16), on Wi-Fi.

Run: ``python scripts/gen-devices.py`` (after editing the seed). The test
``python/tests/test_devices.py`` fails if a profile drifts from the seed.
"""
import io
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "scripts" / "android-devices.json"

# profile name -> whether its devices carry arch (Yandex writes it into the UA)
TARGETS = {
    "chrome-152-android": False,
    "yandex-26.8-android": True,
}


# Chromium's default network estimate per connection type
# (net/nqe/network_quality_estimator_params.cc): http RTT ms, downlink kbps.
NETWORK = {"wifi": (116, 2658), "4g": (137, 1708)}
BARS_DP = 32 + 56 + 16  # status bar, Chrome's toolbar, gesture bar


def css_screen(d: dict) -> tuple[int, int]:
    if d.get("screen"):
        w, h = d["screen"].split("x")
        return int(w), int(h)
    pw, ph = (int(x) for x in d["panel"].split("x"))
    dpr = float(d["dpr"])
    return math.ceil(pw / dpr - 1e-9), math.ceil(ph / dpr - 1e-9)


def device_memory(ram_gb: int) -> str:
    """approximated_device_memory.cc on what Android reports (~7% under)."""
    mb = int(ram_gb * 1024 * 0.93)
    power = mb.bit_length() - 1
    lower, upper = 1 << power, 1 << (power + 1)
    gb = (lower if mb - lower <= upper - mb else upper) / 1024
    gb = min(max(gb, 1), 8)
    return str(int(gb)) if gb == int(gb) else str(gb)


def machine(d: dict, i: int) -> dict:
    w, h = css_screen(d)
    rtt, kbps = NETWORK["wifi" if i % 2 == 0 else "4g"]
    return {"device_memory": device_memory(d["ram_gb"]), "dpr": d["dpr"],
            "viewport": f"{w}x{h - BARS_DP}", "color_scheme": "light" if i % 2 == 0 else "dark",
            "rtt": str(rtt), "downlink": str(kbps / 1000), "ect": "4g"}


def defaults() -> dict:
    """The new hints' values without a device: the Pixel 7 of STAGE16, Wi-Fi."""
    pool = json.loads(SEED.read_text(encoding="utf-8"))
    m = machine(next(d for d in pool if d["name"] == "Pixel 7"), 0)
    w, h = m["viewport"].split("x")
    return {"device-memory": m["device_memory"], "sec-ch-device-memory": m["device_memory"],
            "dpr": m["dpr"], "sec-ch-dpr": m["dpr"], "viewport-width": w, "sec-ch-viewport-width": w,
            "sec-ch-viewport-height": h, "rtt": m["rtt"], "downlink": m["downlink"], "ect": m["ect"],
            "sec-ch-prefers-color-scheme": "light", "sec-ch-prefers-reduced-motion": "no-preference",
            "sec-ch-prefers-reduced-transparency": "no-preference"}


def devices(with_arch: bool) -> list[dict]:
    pool = json.loads(SEED.read_text(encoding="utf-8"))
    out = []
    for i, d in enumerate(pool):
        entry = {"name": d["name"], "model": d["model"],
                 "platform_version": d["platform_version"]}
        if with_arch:
            # Every phone in the pool is arm64; that is what a modern Android
            # device puts in ro.product.cpu.abilist, and Yandex writes arm_64.
            entry["arch"] = "arm_64"
        entry.update(machine(d, i))
        out.append(entry)
    return out


def main() -> int:
    check = "--check" in sys.argv
    changed = False
    for name, with_arch in TARGETS.items():
        path = ROOT / "profiles" / f"{name}.json"
        raw = path.read_bytes()
        nl = "\r\n" if b"\r\n" in raw else "\n"
        profile = json.loads(raw.decode("utf-8"))
        want = devices(with_arch)
        values = dict((profile.get("client_hints") or {}).get("values") or {})
        values.update(defaults())
        if (profile.get("devices") == want and profile.get("device_kind") == "phone"
                and (profile.get("client_hints") or {}).get("values") == values):
            continue
        if check:
            print(f"{name}: devices differ from the seed", file=sys.stderr)
            changed = True
            continue
        profile["devices"] = want
        profile["device_kind"] = "phone"
        profile.setdefault("client_hints", {})["values"] = values
        text = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
        io.open(path, "wb").write(text.replace("\n", nl).encode("utf-8"))
        print(f"{name}: wrote {len(want)} devices")
    if check and changed:
        return 1
    if not check:
        print(f"seed: {len(json.loads(SEED.read_text(encoding='utf-8')))} devices")
    return 0


if __name__ == "__main__":
    sys.exit(main())
