"""sec-ch-ua on every Chromium-family profile is what the browser sends.

From Chromium 105 the brand list is a function of the Chromium major
(scripts/chromium_brands.py mirrors user_agent_utils.cc). The captured
profiles are the ground truth for that function; the transcribed ones must
agree with it. wreq-util's strings did not, for 41 profiles: copied between
versions, unterminated, or with the pre-105 GREASE brand's leading space lost.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
from chromium_brands import FIRST_GREASED, sec_ch_ua  # noqa: E402

PRODUCT = {"chrome": ("Google Chrome", r"Chrome/(\d+)"), "edge": ("Microsoft Edge", r"Edg/(\d+)"),
           "opera": ("Opera", r"OPR/(\d+)")}


def _chain(name):
    while name:
        d = json.loads((REPO / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
        yield d
        name = d.get("based_on")


def _header(name, key):
    for d in _chain(name):
        if key == "user-agent" and (d.get("headers") or {}).get("user_agent"):
            return d["headers"]["user_agent"]
        for h in (d.get("headers") or {}).get("order", []):
            if h["key"].lower() == key and h.get("value"):
                return h["value"]
    return ""


def _chromium_profiles():
    for p in sorted((REPO / "profiles").glob("*.json")):
        fam = p.stem.split("-")[0]
        if fam in PRODUCT and _header(p.stem, "sec-ch-ua"):
            yield p.stem, fam


def test_the_algorithm_matches_every_capture():
    """If this fails, the algorithm is wrong, not the capture."""
    checked = 0
    for name, fam in _chromium_profiles():
        src = next(_chain(name)).get("source")
        if src and not src.get("covers"):
            continue
        ua = _header(name, "user-agent")
        chromium = int(re.search(r"Chrome/(\d+)\.", ua).group(1))
        if chromium < FIRST_GREASED:
            continue
        product, pattern = PRODUCT[fam]
        assert _header(name, "sec-ch-ua") == sec_ch_ua(chromium, product, re.search(pattern, ua).group(1)), name
        checked += 1
    assert checked >= 20, checked


@pytest.mark.parametrize("name,fam", list(_chromium_profiles()))
def test_every_brand_list_is_the_browser_s(name, fam):
    ua = _header(name, "user-agent")
    brands = _header(name, "sec-ch-ua")
    assert brands.count('"') % 2 == 0, f"{name}: unterminated {brands!r}"
    chromium = int(re.search(r"Chrome/(\d+)\.", ua).group(1))
    product, pattern = PRODUCT[fam]
    major = re.search(pattern, ua).group(1)
    if chromium >= FIRST_GREASED:
        assert brands == sec_ch_ua(chromium, product, major), name
    else:
        # Before the GREASE algorithm: whatever the captured twin of the
        # same version sends, on every platform.
        twin = f"{fam}-{major}-windows"
        assert brands == _header(twin, "sec-ch-ua"), (name, twin)
