"""Transcribed profiles: another project's description of a browser, taken
on trust and marked as such at every level a caller can see."""
import json
from pathlib import Path

import curlpro

REPO = Path(__file__).resolve().parents[2]


def test_a_transcribed_profile_says_so_everywhere():
    caps = curlpro.capabilities("chrome-145-windows")
    assert caps["measured"] is False
    assert caps["source"]["kind"] == "transcribed" and "wreq-util" in caps["source"]["from"]
    assert caps["source"]["ref"] and caps["source"]["note"]
    with curlpro.Session("chrome-145-windows") as s:
        fp = s.fingerprint()
        assert fp.measured is False and fp.source["from"] == caps["source"]["from"]
        assert [f.code for f in s.audit()] == ["transcribed_profile"]
        assert "wreq-util" in str(s.audit()[0])
    assert curlpro.capabilities("chrome-142-macos")["measured"] is True
    assert "source" not in curlpro.capabilities("chrome-142-macos")
    with curlpro.Session("chrome-142-macos") as s:
        assert s.fingerprint().measured and s.fingerprint().source is None


def test_a_transcribed_profile_replays_its_captured_base():
    for name in ("chrome-145-windows", "edge-148-macos", "opera-131-windows", "firefox-150-linux",
                 "safari-26.2-macos", "safari-18-ipados", "chrome-106-linux"):
        base = curlpro.get_profile(name).based_on
        assert curlpro.capabilities(base)["measured"], f"{name} stands on {base}, which is not captured"
        with curlpro.Session(name) as s, curlpro.Session(base) as b:
            fp, bfp = s.fingerprint(), b.fingerprint()
            assert (fp.ja4, fp.ja3n) == (bfp.ja4, bfp.ja3n), name
            assert fp.user_agent != bfp.user_agent


def test_every_transcribed_profile_is_a_delta_with_a_note():
    seen = 0
    for p in (REPO / "profiles").glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        if "source" not in d:
            continue
        seen += 1
        assert d["based_on"], p.name
        assert d["source"]["note"] and d["source"]["ref"], p.name
        # devices and client_hints are what gen-identities.py adds on top (an
        # empty pool, on a delta of a pooled profile); fetch is the derived
        # Safari set gen-safari-fetch.py writes from the delta's own navigation order.
        assert set(d) <= {"name", "based_on", "source", "headers", "http2", "devices", "client_hints", "fetch"}, \
            f"{p.name}: a transcribed delta carries {set(d)}"
        if "fetch" in d:
            assert p.name.startswith("safari-") and d["fetch"]["derived"] is True, p.name
    assert seen > 200


def test_list_profiles_can_leave_the_transcribed_ones_out():
    every = curlpro.list_profiles()
    measured = curlpro.list_profiles(measured=True)
    transcribed = curlpro.list_profiles(measured=False)
    assert set(measured) | set(transcribed) == set(every) and not set(measured) & set(transcribed)
    assert "chrome-142-macos" in measured and "chrome-145-windows" in transcribed
    assert all(curlpro.capabilities(n)["measured"] for n in measured)
