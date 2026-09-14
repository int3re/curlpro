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

Run: ``python scripts/gen-devices.py`` (after editing the seed). The test
``python/tests/test_devices.py`` fails if a profile drifts from the seed.
"""
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "scripts" / "android-devices.json"

# profile name -> whether its devices carry arch (Yandex writes it into the UA)
TARGETS = {
    "chrome-152-android": False,
    "yandex-26.8-android": True,
}


def devices(with_arch: bool) -> list[dict]:
    pool = json.loads(SEED.read_text(encoding="utf-8"))
    out = []
    for d in pool:
        entry = {"name": d["name"], "model": d["model"],
                 "platform_version": d["platform_version"]}
        if with_arch:
            # Every phone in the pool is arm64; that is what a modern Android
            # device puts in ro.product.cpu.abilist, and Yandex writes arm_64.
            entry["arch"] = "arm_64"
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
        if profile.get("devices") == want:
            continue
        if check:
            print(f"{name}: devices differ from the seed", file=sys.stderr)
            changed = True
            continue
        profile["devices"] = want
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
