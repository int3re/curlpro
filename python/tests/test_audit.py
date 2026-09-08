"""Contradictions inside an identity.

The audit is only worth having if it is quiet when nothing is wrong. A check
that cries wolf on a correct setup teaches people to skip the output, and then
the one real finding goes unread with the rest. So half of these tests are
about silence.
"""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def codes(findings) -> set[str]:
    return {f.code for f in findings}


# --- silence --------------------------------------------------------------

def test_a_plain_session_has_nothing_to_report():
    with curlpro.Session("chrome-151-windows") as s:
        assert s.audit() == []


def test_every_desktop_profile_is_quiet():
    """A stock profile must not accuse itself.

    Whatever the audit says has to be about the caller's setup; a profile that
    complains out of the box would make the whole thing noise.
    """
    noisy = {}
    for name in curlpro.list_profiles():
        with curlpro.Session(name) as s:
            found = s.audit()
        if found:
            noisy[name] = codes(found)

    # The only expected ones are phone profiles that offer devices and have
    # none chosen — a real thing to tell the caller about.
    assert all(c == {"mobile_no_device"} for c in noisy.values()), noisy


def test_safari_on_ios_is_not_asked_for_a_device():
    """Client hints are Chromium's; Safari sends none, so there is nothing to fill."""
    with curlpro.Session("safari-18.4-ios") as s:
        assert "mobile_no_device" not in codes(s.audit())


def test_tor_and_yandex_versions_are_not_flagged():
    """Their own version is not the engine version, and that is normal.

    Tor Browser 14 is built on Firefox 128 and Yandex 26.8 on Chromium 150.
    Comparing the name with the User-Agent there would report the profiles
    rather than the caller.
    """
    for name in ("tor-14-macos", "yandex-26.8-android"):
        with curlpro.Session(name) as s:
            assert "ua_version" not in codes(s.audit()), name


# --- what it must catch ---------------------------------------------------

def test_tor_with_another_language_is_a_high_finding():
    """The one the maintainer nearly shipped by hand."""
    with curlpro.Session("tor-14-macos") as s:
        s.headers["Accept-Language"] = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
        found = s.audit()

    assert "tor_language" in codes(found)
    tell = next(f for f in found if f.code == "tor_language")
    assert tell.level == "high"
    assert "en-US" in tell.fix


def test_a_user_agent_from_another_version():
    with curlpro.Session("chrome-151-windows") as s:
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        found = s.audit()

    assert "ua_version" in codes(found)
    assert next(f for f in found if f.code == "ua_version").level == "high"


def test_a_platform_hint_that_contradicts_the_user_agent():
    with curlpro.Session("chrome-151-windows") as s:
        s.headers["sec-ch-ua-platform"] = '"macOS"'
        found = s.audit()
    assert "platform" in codes(found)


def test_a_phone_profile_without_a_device():
    p = curlpro.Persona.new("chrome-152-android")
    assert "mobile_no_device" in codes(p.audit())

    chosen = curlpro.Persona.new("chrome-152-android", device="Pixel 8")
    assert "mobile_no_device" not in codes(chosen.audit())


def test_the_q_ladder_is_no_longer_read_as_a_signature():
    """Firefox 155 steps by 0.1, the same as Chrome — measured 2026-09-08.

    The check that read the ladder shape was removed with the measurement that
    disproved it; see the note in audit.py. Both shapes now have to be silent
    on both browsers, or the module would be reporting a browser for behaving
    the way it actually behaves.
    """
    ladders = ("ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
               "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
    for profile in ("chrome-151-windows", "firefox-144-macos"):
        for ladder in ladders:
            with curlpro.Session(profile) as s:
                s.headers["Accept-Language"] = ladder
                assert "language_shape" not in codes(s.audit())


# --- shape of the output --------------------------------------------------

def test_findings_are_sorted_by_severity_and_readable():
    with curlpro.Session("tor-14-macos") as s:
        s.headers["Accept-Language"] = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
        found = s.audit()

    order = ("high", "medium", "low")
    levels = [f.level for f in found]
    assert levels == sorted(levels, key=order.index)
    text = str(found[0])
    # Every finding says what, why and what to do: a finding without a reason
    # is an instruction to obey rather than a thing to understand.
    assert "why:" in text and "fix:" in text


def test_a_persona_audits_without_being_opened_by_the_caller():
    p = curlpro.Persona.new("chrome-151-windows")
    assert p.audit() == []


# ---------------------------------------------------------------- ua_family
#
# Added after a real mistake: `capture --name firefox-154-windows` launched
# Chrome, because the name never selected the browser. The profile that came
# out had Chrome's TLS under a Firefox name, and the audit said nothing — the
# version check bailed out silently when the family's token was missing from
# the User-Agent, which is the strongest form of the disagreement rather than
# a reason to skip it.

_CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")
_FIREFOX_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) "
               "Gecko/20100101 Firefox/154.0")


def _codes(profile, ua=None):
    with curlpro.Session(impersonate=profile) as s:
        if ua is not None:
            s.headers["user-agent"] = ua
        return [(f.code, f.level) for f in s.audit()]


def test_firefox_profile_with_a_chrome_user_agent():
    assert ("ua_family", "high") in _codes("firefox-144-macos", _CHROME_UA)


def test_chrome_profile_with_a_firefox_user_agent():
    assert ("ua_family", "high") in _codes("chrome-152-windows", _FIREFOX_UA)


def test_user_agent_naming_no_browser_is_softer():
    """Not the same thing: a custom string may be deliberate, a wrong browser is not."""
    assert ("ua_family", "medium") in _codes("firefox-144-macos", "MyBot/1.0")


def test_agreeing_profile_and_user_agent_are_silent():
    assert not [c for c in _codes("chrome-152-windows", _CHROME_UA)
                if c[0] == "ua_family"]


def test_tor_and_safari_stay_silent():
    """Tor 14 rides on Firefox 128 and Safari carries no engine token: both
    would be false alarms, which is why neither family is checked."""
    for profile in ("tor-14-macos", "safari-26.0-macos"):
        assert not [c for c in _codes(profile) if c[0] == "ua_family"]
