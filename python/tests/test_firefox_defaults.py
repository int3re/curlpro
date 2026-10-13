"""Every desktop Firefox profile sends what that Firefox release sends by default.

The rule is Firefox's own, read from its source at each FIREFOX_N_0_RELEASE
tag (modules/libpref/init/StaticPrefList.yaml and
security/manager/ssl/nsNSSIOLayer.cpp), and the captures agree with it:

- 0xc009 (ECDHE-ECDSA-AES128-SHA): on up to 150, off from 151
  (security.ssl3.ecdhe_ecdsa_aes_128_sha);
- 0xc00a (ECDHE-ECDSA-AES256-SHA): on up to 153, off from 154
  (security.ssl3.ecdhe_ecdsa_aes_256_sha);
- the FFDHE groups 0x0100 and 0x0101 in supported_groups: up to 155; from 156
  only when a DHE suite is on, and none is by default.

From 154 Firefox therefore offers Chrome's fifteen ciphers, and JA4's sorted
cipher hash is Chrome's (8daaf6152771) while the order on the wire stays
Gecko's: TLS_AES_128_GCM, TLS_CHACHA20, TLS_AES_256_GCM. A report on 0.17.0
took that for a hello no browser sends; Firefox 157.0.1 sent exactly it to a
bare socket, field for field (2026-10-14). The same reading found the real
fault: the transcribed firefox-151 profiles carried 150's seventeen ciphers.
"""

from __future__ import annotations

import re
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
C009, C00A = "c009", "c00a"
FFDHE = {"0100", "0101"}


def firefox_desktops() -> list[tuple[str, int]]:
    out = []
    for n in (p.stem for p in (REPO / "profiles").glob("firefox-*.json")):
        m = re.fullmatch(r"firefox-(\d+)(?:\.\d+)*-(windows|macos|linux)", n)
        if m:
            out.append((n, int(m.group(1))))
    return sorted(out, key=lambda x: (x[1], x[0]))


def test_the_corpus_has_firefox_on_both_sides_of_every_change():
    majors = {v for _, v in firefox_desktops()}
    assert min(majors) <= 150 and 151 in majors and max(majors) >= 156


@pytest.mark.parametrize("name,major", firefox_desktops())
def test_a_firefox_profile_sends_its_release_defaults(name, major):
    with curlpro.Session(name) as s:
        fp = s.fingerprint()
    ciphers, groups = list(fp.ciphers), set(fp.curves)
    assert (C009 in ciphers) == (major <= 150), f"{name}: 0xc009 is {'on' if major <= 150 else 'off'} in Firefox {major}"
    assert (C00A in ciphers) == (major <= 153), f"{name}: 0xc00a is {'on' if major <= 153 else 'off'} in Firefox {major}"
    assert bool(FFDHE & groups) == (major <= 155), f"{name}: FFDHE groups in Firefox {major}: {sorted(groups)}"
    # Gecko's order of the TLS 1.3 suites, whatever the hash says.
    assert ciphers[:3] == ["1301", "1303", "1302"], ciphers[:3]


def test_from_154_the_cipher_hash_is_chromes_and_the_order_is_not():
    with curlpro.Session("firefox-157-windows") as ff, curlpro.Session("chrome-155-windows") as ch:
        f, c = ff.fingerprint(), ch.fingerprint()
    assert f.ja4.split("_")[1] == c.ja4.split("_")[1] == "8daaf6152771"
    assert sorted(f.ciphers) == sorted(c.ciphers) and f.ciphers != c.ciphers
    assert f.ja4.split("_")[2] != c.ja4.split("_")[2]  # extensions and signatures stay apart


def test_firefox_151_says_where_its_ciphers_come_from():
    note = curlpro.get_profile("firefox-151-windows").data["source"]["note"]
    assert "0xc009" in note and "FIREFOX_151_0_RELEASE" in note
