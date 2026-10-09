"""The device profile the patched Chromium reads (chromium/DESIGN.md).

Three things that must hold without a browser built: the driver encodes a
profile byte for byte as scripts/fpcapture.py does, the brand a profile names
is found the way Chromium writes its GREASE entry, and that one brand is all
the patch needs -- Chromium's own seeding by the major version then gives the
measured Chrome's whole list, order and GREASE included
(chromium/patches/0003).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
from chromium_brands import CHARS, sec_ch_ua  # noqa: E402
from fpcapture import switch_value, vendor_brand  # noqa: E402

from curlpro.browser.chrome import fingerprint_switch  # noqa: E402

PROFILE = {
    "source": "a test device",
    "webgl": {"unmasked_vendor": "Google Inc. (NVIDIA)",
              "unmasked_renderer": "ANGLE (NVIDIA, Ünïcödé)",
              "parameters": [{"name": "MAX_VERTEX_UNIFORM_VECTORS", "enum": 36347, "value": 4095}],
              "webgl2_parameters": []},
    "fonts": {"present": ["Arial", "Segoe UI"]},
    "ua": {"brand": "Google Chrome"},
}


def test_the_driver_encodes_a_profile_as_fpcapture_does(tmp_path):
    path = tmp_path / "device.profile.json"
    path.write_text(json.dumps(PROFILE, ensure_ascii=False, indent=1), encoding="utf-8")
    # From the dict and from the file alike: the build decodes one form.
    assert fingerprint_switch(PROFILE) == switch_value(PROFILE)
    assert fingerprint_switch(path) == switch_value(PROFILE)


def test_the_vendor_brand_is_whatever_is_neither_chromium_nor_grease():
    # Measured on Chrome 154 (the RTX 4050 record).
    assert vendor_brand(["Chromium;154", "Google Chrome;154", "Not A(Brand;99"]) == "Google Chrome"
    assert vendor_brand(["Not)A;Brand;8", "Chromium;150", "Microsoft Edge;150"]) == "Microsoft Edge"
    # Chromium itself names no third brand, and nothing is invented for it.
    assert vendor_brand(["Chromium;154", "Not A(Brand;99"]) == ""
    assert vendor_brand([]) == ""
    # Every GREASE spelling Chromium can produce is recognised as GREASE.
    for a in CHARS:
        for b in CHARS:
            assert vendor_brand([f"Not{a}A{b}Brand;99", "Chromium;154", "Opera;136"]) == "Opera"


def test_one_brand_reproduces_the_measured_list_in_order():
    """What patch 0003 relies on: given only "Google Chrome", Chromium's own
    GenerateBrandVersionList at major 154 yields exactly what the real Chrome
    154 sent, in its order."""
    measured = ["Chromium;154", "Google Chrome;154", "Not A(Brand;99"]
    header = sec_ch_ua(154, vendor_brand(measured), 154)
    computed = [f"{name};{ver}" for name, ver in
                (entry.split('";v="') for entry in
                 (e.strip().strip('"') for e in header.split(", ")))]
    assert computed == measured
