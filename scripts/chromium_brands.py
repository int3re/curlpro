"""Chromium's sec-ch-ua, computed as the browser computes it.

From Chromium 105 the brand list is a function of the Chromium major alone
(components/embedder_support/user_agent_utils.cc, GenerateBrandVersionList and
GetGreasedUserAgentBrandVersion): the seed is the major; the GREASE brand is
"Not" + c[s % 11] + "A" + c[(s + 1) % 11] + "Brand" with version v[s % 3];
the three entries are laid out by the permutation orders[s % 6]. Before 105 it
was a fixed " Not A;Brand" in a per-version place, which only a capture shows.

Every captured Chromium profile from 105 up matches this (tests/test_brands.py),
so it is safe to write for a version nobody captured here.
"""
from __future__ import annotations

CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
VERSIONS = ["8", "99", "24"]
ORDERS = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
FIRST_GREASED = 105


def sec_ch_ua(chromium_major: int, product: str, product_major: int | str) -> str:
    """The header as Chromium >= 105 sends it; product is "Google Chrome",
    "Microsoft Edge", "Opera" and the like, with its own major."""
    if chromium_major < FIRST_GREASED:
        raise ValueError(f"Chromium {chromium_major} predates the GREASE algorithm; take a capture")
    s = chromium_major
    grease = f'"Not{CHARS[s % 11]}A{CHARS[(s + 1) % 11]}Brand";v="{VERSIONS[s % 3]}"'
    entries = [None, None, None]
    order = ORDERS[s % 6]
    entries[order[0]] = grease
    entries[order[1]] = f'"Chromium";v="{s}"'
    entries[order[2]] = f'"{product}";v="{product_major}"'
    return ", ".join(entries)
