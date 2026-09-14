"""The Android device pool: shared, in sync with the seed, and real.

The pool exists so that ``device="random"`` on a mobile profile draws from many
believable phones while the TLS fingerprint stays one — one identity axis that
varies without touching the one anti-bots score. These tests guard three things:
the profiles have not drifted from the seed that owns them, the pool is large,
and each entry is a real device rather than a plausible-looking invention.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
SEED = json.loads((REPO / "scripts" / "android-devices.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def _profile(name: str) -> dict:
    return json.loads((REPO / "profiles" / f"{name}.json").read_text(encoding="utf-8"))


def test_the_pool_is_large():
    """The point of the change: many phones, not eight."""
    assert len(SEED) >= 40


def test_chrome_android_matches_the_seed():
    """gen-devices.py owns the list; a hand edit to the profile must be caught."""
    want = [{"name": d["name"], "model": d["model"],
             "platform_version": d["platform_version"]} for d in SEED]
    assert _profile("chrome-152-android")["devices"] == want


def test_yandex_android_matches_the_seed_with_arch():
    """Yandex writes the model into the User-Agent and carries arch; every
    modern phone in the pool is arm64."""
    want = [{"name": d["name"], "model": d["model"],
             "platform_version": d["platform_version"], "arch": "arm_64"} for d in SEED]
    assert _profile("yandex-26.8-android")["devices"] == want


def test_models_look_like_real_ro_product_model():
    """No blanks, no duplicates, and each model is a shape a real device reports —
    a Samsung SM-…, a Pixel, a Xiaomi/Redmi numeric code, a Tecno/Infinix string.
    An invented marketing name like "Galaxy Ultra Max" would fail this."""
    models = [d["model"] for d in SEED]
    assert len(models) == len(set(models)), "duplicate models in the pool"
    # ro.product.model shapes: Samsung SM-…, Pixel, Xiaomi/Redmi/POCO numeric
    # codes (two digits then alphanumerics), realme RMX…, OnePlus CPH…, vivo
    # V…, Honor's two, and Tecno/Infinix which carry the brand in the string.
    shape = re.compile(
        r"^(SM-[A-Z0-9]+|Pixel [0-9A-Za-z ]+|RMX\d+|CPH\d+|V\d{4}|"
        r"REA-NX9|BVL-N49|TECNO [A-Z0-9]+|Infinix X\d+[A-Za-z]?|"
        r"\d{2}[0-9A-Z]{5,})$")
    for m in models:
        assert m and not m.isspace(), "blank model"
        assert shape.match(m), f"model does not look real: {m!r}"


def test_platform_versions_are_plausible_and_varied():
    """A pool where every phone runs the same Android is itself a signal;
    the versions must span a real range."""
    versions = {d["platform_version"] for d in SEED}
    assert versions <= {"13.0.0", "14.0.0", "15.0.0", "16.0.0"}
    assert len(versions) >= 3, "the pool needs a spread of Android versions"


def test_random_draws_across_the_pool():
    """device="random" must reach many phones, not a favourite few. Yandex is
    the observable path: it writes the model into the User-Agent, so the wire
    itself shows which phone was drawn (Chrome emits it only after Accept-CH)."""
    seen = set()
    for _ in range(200):
        with curlpro.Session("yandex-26.8-android", device="random") as s:
            ua = s.fingerprint("https://example.com").user_agent
            m = re.search(r"Android [0-9.]+; ([^)]+)\)", ua)
            if m:
                seen.add(m.group(1))
    # 200 draws over ~46 phones: the coupon-collector expectation covers the
    # pool many times over, so a bound well below the size still catches a
    # generator that collapsed to a handful.
    assert len(seen) >= 20, f"random reached only {len(seen)} of {len(SEED)} phones"
