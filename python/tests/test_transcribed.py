"""Transcribed profiles: another project's description of a browser, taken
on trust and marked as such at every level a caller can see."""
import json
import re
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
        caps = curlpro.capabilities(base)
        # A base whose SETTINGS alone are transcribed (source.covers) is a capture.
        assert caps["measured"] or (caps.get("source") or {}).get("covers"),             f"{name} stands on {base}, which is not captured"
        with curlpro.Session(name) as s, curlpro.Session(base) as b:
            fp, bfp = s.fingerprint(), b.fingerprint()
            assert (fp.ja4, fp.ja3n) == (bfp.ja4, bfp.ja3n), name
            assert fp.user_agent != bfp.user_agent


def test_every_transcribed_profile_is_a_delta_with_a_note():
    seen = 0
    for p in (REPO / "profiles").glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        if "source" not in d or d["source"].get("covers"):
            continue  # captured, or captured with one part (its SETTINGS) transcribed
        seen += 1
        assert d["based_on"], p.name
        # A transcription names the commit it read; a derived profile names
        # the published fact it rests on (source.from) instead.
        assert d["source"]["note"] and (d["source"].get("ref") or d["source"]["kind"] == "derived"), p.name
        tlsclient = d["source"].get("from") == "github.com/bogdanfinn/tls-client"
        # devices and client_hints are what gen-identities.py adds on top (an
        # empty pool, on a delta of a pooled profile); fetch is the derived
        # Safari set gen-safari-fetch.py writes from the delta's own navigation order.
        allowed = {"name", "based_on", "source", "headers", "http2", "devices", "device_kind", "client_hints",
                   "fetch", "tls"}
        if p.stem == "brave-1.88-windows":
            # Sec-GPC, which Brave sends on every request, in the HTTP/1.1
            # and fetch orders of the Chrome 146 it stands beside.
            allowed |= {"http1"}
        assert set(d) <= allowed, f"{p.name}: a transcribed delta carries {set(d)}"
        if "fetch" in d and p.stem != "brave-1.88-windows":
            assert p.name.startswith("safari-") and d["fetch"]["derived"] is True, p.name
        # The one TLS a transcription may carry: Firefox 151 to 153 without 0xc009,
        # which Firefox itself turned off in 151 while wreq-util declares 150's
        # list (test_firefox_defaults.py). Everything else of the hello is captured.
        # And a derived Chrome 154+ on a 153 capture: the capture's trust_anchors
        # list sorted bytewise, as Chromium sends it from 154.
        # tls-client's hellos have no captured twin and are written field for
        # field, with their HTTP/2; Brave 1.88's is Chrome 146's and replayed.
        if tlsclient:
            if p.stem == "brave-1.88-windows":
                assert "tls" not in d and "http2" not in d, p.name
            else:
                assert set(d["tls"]) <= {"cipher_suites", "compression_methods", "extensions",
                                         "permute_extensions", "signature_algorithms"}, p.name
                assert d["tls"]["extensions"] and d["http2"]["settings"], p.name
                assert "tls-client's" in d["source"]["note"], p.name
        elif "tls" in d and p.name.startswith("firefox-"):
            assert re.fullmatch(r"firefox-15[123]-\w+\.json", p.name) and set(d["tls"]) == {"cipher_suites"}, p.name
            assert 0xC009 not in d["tls"]["cipher_suites"] and "FIREFOX_151_0_RELEASE" in d["source"]["note"], p.name
        elif "tls" in d:
            assert d["source"]["kind"] == "derived" and set(d["tls"]) == {"trust_anchors"}, p.name
            assert int(p.name.split("-")[1]) >= 154 and "sorted bytewise" in d["source"]["note"], p.name
    assert seen > 200


def test_list_profiles_can_leave_the_transcribed_ones_out():
    every = curlpro.list_profiles()
    measured = curlpro.list_profiles(measured=True)
    transcribed = curlpro.list_profiles(measured=False)
    assert set(measured) | set(transcribed) == set(every) and not set(measured) & set(transcribed)
    assert "chrome-142-macos" in measured and "chrome-145-windows" in transcribed
    assert all(curlpro.capabilities(n)["measured"] for n in measured)
