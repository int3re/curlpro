"""Asking a profile what it can do, and telling a permanent failure from a
passing one.

Both come from one field report. A worker handed a Safari profile got the same
``CurlProError`` for "this profile cannot do mode=fetch" as for a blinked
connection: it retried three times and dropped the task, forty-eight of them
before anyone noticed. And the only way to filter such profiles in advance was
to open a session, aim a request at a closed port and look for the words
"fetch header" in the error text — a string the versioning policy explicitly
refuses to keep stable.
"""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


# --- capabilities ---------------------------------------------------------

def test_capabilities_answers_what_a_probe_used_to():
    chrome = curlpro.capabilities("chrome-152-android")
    assert chrome["modes"] == ["navigate", "fetch"]
    assert chrome["protocols"] == ["http1", "h2", "h3"]
    assert len(chrome["devices"]) == 46 and "Pixel 8" in chrome["devices"]
    assert chrome["client_hints"] and chrome["websocket"] and chrome["http1_set"]
    assert chrome["user_agent_varies"], "a chosen device reaches the string"
    assert chrome["family"] == "chrome"

    okhttp = curlpro.capabilities("okhttp-5.5-jvm")
    assert okhttp["modes"] == ["navigate"], "a library has no fetch set, and should not"
    assert okhttp["devices"] == [] and not okhttp["websocket"]


def test_capabilities_matches_what_a_session_actually_accepts():
    """The claim and the behaviour, on every profile: the point of the API is
    that a caller can trust it instead of probing."""
    for name in sorted(p.stem for p in (REPO / "profiles").glob("*.json")):
        caps = curlpro.capabilities(name)
        if "fetch" in caps["modes"]:
            curlpro.Session(name, mode="fetch").close()
        else:
            with pytest.raises(curlpro.ProfileCapabilityError):
                curlpro.Session(name, mode="fetch")
        if "h3" in caps["protocols"]:
            curlpro.Session(name, http3=True).close()
        else:
            with pytest.raises(curlpro.ProfileCapabilityError):
                curlpro.Session(name, http3=True)
        if caps["devices"]:
            curlpro.Session(name, device="random").close()
        else:
            with pytest.raises(curlpro.ProfileCapabilityError):
                curlpro.Session(name, device="random")


def test_capabilities_and_get_profile_refuse_an_unknown_name():
    for call in (lambda: curlpro.capabilities("netscape-4"),
                 lambda: curlpro.get_profile("netscape-4")):
        with pytest.raises(curlpro.ConfigurationError, match="netscape-4"):
            call()


def test_get_profile_returns_the_resolved_profile():
    """A delta arrives whole: reading site-packages was the only way before."""
    p = curlpro.get_profile("chrome-152-android")
    assert isinstance(p, curlpro.Profile)
    assert p.name == "chrome-152-android"
    assert p.based_on == "chrome-152-windows"
    # Inherited from the chain, not present in the file itself.
    assert p.data["http1"]["order"][0] == "Host"
    assert len(p.data["devices"]) == 46
    assert p.data["tls"]["raw_client_hello"]


def test_library_version_is_public():
    v = curlpro.library_version()
    assert v.count(".") == 2 and v.split(".")[0].isdigit()


# --- permanent versus passing --------------------------------------------

def test_a_profile_that_cannot_is_told_apart_from_a_network_that_blinked():
    permanent = [
        # okhttp is a library: it has no fetch concept, and never will.
        ("no fetch set", lambda: curlpro.Session("okhttp-5.5-jvm", mode="fetch"),
         curlpro.ProfileCapabilityError),
        # chrome-150-macos carries no identity pool; the 151–153 desktops do since 0.11.
        ("no devices", lambda: curlpro.Session("chrome-150-macos", device="random"),
         curlpro.ProfileCapabilityError),
        ("no http3", lambda: curlpro.Session("firefox-155-windows", http3=True),
         curlpro.ProfileCapabilityError),
        ("unknown profile", lambda: curlpro.Session("netscape-4"),
         curlpro.ConfigurationError),
        ("unknown device", lambda: curlpro.Session("chrome-152-android", device="Nokia 3310"),
         curlpro.ConfigurationError),
        ("page is not a URL", lambda: curlpro.Session("chrome-151-windows", page="nope"),
         curlpro.ConfigurationError),
        ("a name listed twice", lambda: curlpro.Session("chrome-151-windows",
                                                        header_order=["accept", "Accept"]),
         curlpro.ConfigurationError),
    ]
    for what, call, want in permanent:
        with pytest.raises(want) as info:
            call()
        assert isinstance(info.value, curlpro.PermanentError), what
        assert info.value.code in ("profile_capability", "configuration"), what

    # The one that must stay retryable, and must not be a PermanentError.
    with pytest.raises(curlpro.CurlProError) as info:
        with curlpro.Session("chrome-151-windows", timeout=(0.3, 0.3), retries=0) as s:
            s.get("http://127.0.0.1:1/")
    assert not isinstance(info.value, curlpro.PermanentError)


def test_every_permanent_error_is_still_a_curlproerror():
    """Existing code catches CurlProError; the new classes must not escape it."""
    for cls in (curlpro.PermanentError, curlpro.ProfileCapabilityError,
                curlpro.ConfigurationError):
        assert issubclass(cls, curlpro.CurlProError)
        assert issubclass(cls, RuntimeError)
    assert issubclass(curlpro.ProfileCapabilityError, curlpro.PermanentError)
    assert issubclass(curlpro.ConfigurationError, curlpro.PermanentError)
    assert not issubclass(curlpro.Timeout, curlpro.PermanentError), "a timeout is retried"


def test_the_message_is_still_the_good_one():
    """The code is for programs, the message for people: neither replaces the
    other, and the message that explained the fix must survive."""
    with pytest.raises(curlpro.ProfileCapabilityError) as info:
        curlpro.Session("okhttp-5.5-jvm", mode="fetch")
    text = str(info.value)
    assert "okhttp-5.5-jvm" in text and "fetch header set" in text


# --- the derived Safari fetch set ----------------------------------------

def test_safari_can_now_fetch_and_says_the_set_is_derived():
    """Eleven profiles could not make an XHR at all. They can now, and the
    one thing in the corpus that was not measured announces itself."""
    for name in ("safari-26.0-macos", "safari-18.4-ios", "safari-15.5-macos"):
        caps = curlpro.capabilities(name)
        assert caps["modes"] == ["navigate", "fetch"], name
        assert caps["derived_fetch"] is True, name
        with curlpro.Session(name, mode="fetch") as s:
            h = s.headers_for("POST", "https://a.test/api", page="https://b.test/app")
            assert h["accept"] == "*/*"
            assert "upgrade-insecure-requests" not in h and "sec-fetch-user" not in h
            assert h["origin"] == "https://b.test" and h["referer"] == "https://b.test/"
            assert {f.code for f in s.audit()} >= {"derived_fetch_set"}


def test_safari_15_gets_no_fetch_metadata_it_never_sent():
    """WebKit shipped Fetch Metadata in 16.4. Inventing sec-fetch-* for the
    15.x profiles would be a worse tell than the missing set was."""
    with curlpro.Session("safari-15.5-macos", mode="fetch") as s:
        h = s.headers_for(url="https://a.test/api")
    assert not [n for n in h if n.startswith("sec-fetch")], h
    with curlpro.Session("safari-26.0-macos", mode="fetch") as s:
        h = s.headers_for(url="https://a.test/api")
    assert h["sec-fetch-mode"] == "cors" and h["sec-fetch-dest"] == "empty"


def test_a_measured_fetch_set_is_not_marked_derived():
    for name in ("chrome-152-windows", "firefox-155-windows", "yandex-26.8-android"):
        assert curlpro.capabilities(name).get("derived_fetch", False) is False, name
        with curlpro.Session(name, mode="fetch") as s:
            assert "derived_fetch_set" not in {f.code for f in s.audit()}, name
