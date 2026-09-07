"""A network identity that survives between runs.

The point of a persona is that the second run looks like the first one to the
site: same fingerprint, same exit, same cookies. So that is what is checked —
not that the fields round-trip, but that the identity does.
"""

from __future__ import annotations

import json
from pathlib import Path

import curlpro
import pytest

from flakyserver import FlakyServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_a_persona_round_trips_through_a_file(tmp_path):
    p = curlpro.Persona.new("chrome-151-windows", name="user42",
                            headers={"Accept-Language": "de-DE,de;q=0.9"},
                            notes={"account": "user42@example.com"})
    path = p.save(tmp_path / "user42.json")

    back = curlpro.Persona.load(path)
    assert back.name == "user42"
    assert back.profile == "chrome-151-windows"
    assert back.headers["Accept-Language"] == "de-DE,de;q=0.9"
    assert back.notes["account"] == "user42@example.com"


def test_the_identity_survives_the_round_trip():
    """The thing that actually matters: the wire looks the same."""
    a = curlpro.Persona.new("chrome-151-windows")
    restored = curlpro.Persona.from_dict(a.to_dict())
    assert a.fingerprint() == restored.fingerprint()


def test_cookies_are_carried_between_runs(tmp_path):
    with FlakyServer() as srv:
        url = srv.scenario("/login", [{
            "status": 200, "body": "ok",
            "headers": {"Set-Cookie": "sid=abc123; Path=/"},
        }])

        p = curlpro.Persona.new("chrome-151-windows")
        with p.session(verify=False, force_http1=True) as s:
            s.get(url)
        path = p.save(tmp_path / "acc.json")

        # A different process, as far as the library is concerned.
        again = curlpro.Persona.load(path)
        assert any(c["name"] == "sid" and c["value"] == "abc123" for c in again.cookies)

        with again.session(verify=False, force_http1=True) as s:
            assert s.cookies["sid"] == "abc123"


def test_cookies_are_kept_even_when_the_block_raises(tmp_path):
    """A half-finished login is still state.

    Throwing it away would make the next run start further back than it needs
    to — and a login that failed on the second step is exactly when the cookies
    matter most.
    """
    with FlakyServer() as srv:
        url = srv.scenario("/step1", [{
            "status": 200, "body": "ok",
            "headers": {"Set-Cookie": "step=1; Path=/"},
        }])
        p = curlpro.Persona.new("chrome-151-windows")
        with pytest.raises(RuntimeError):
            with p.session(verify=False, force_http1=True) as s:
                s.get(url)
                raise RuntimeError("the second step failed")

    assert any(c["name"] == "step" for c in p.cookies)


def test_the_device_reaches_the_wire():
    """The device is observable in the client hints, not in the User-Agent.

    Chrome on Android reports the reduced "Android 10; K" for every phone, and
    the model moved to sec-ch-ua-model — which a server only receives after it
    asks with Accept-CH. So that is the exchange the persona has to survive:
    ask, then look.
    """
    from test_client_hints import ALL_HINTS, HintServer

    with HintServer(ALL_HINTS) as srv:
        p = curlpro.Persona.new("chrome-152-android", device="Pixel 8")
        with p.session(verify=False, force_http1=True) as s:
            assert s.impersonate == "chrome-152-android"
            s.get(srv.url)
            s.get(srv.url)

    assert srv.value(0, "sec-ch-ua-model") is None, "the hint went out before Accept-CH"
    assert srv.value(1, "sec-ch-ua-model") == '"Pixel 8"'
    assert srv.value(1, "sec-ch-ua-platform-version") == '"16.0.0"'


def test_an_unknown_device_is_refused_by_name():
    """A typo in a device must not quietly become "some other phone"."""
    p = curlpro.Persona.new("chrome-152-android", device="pixel-7")
    with pytest.raises(curlpro.CurlProError, match='device "pixel-7" not found'):
        p.open()


def test_two_personas_of_one_profile_look_the_same_and_two_profiles_do_not():
    a = curlpro.Persona.new("chrome-151-windows")
    b = curlpro.Persona.new("chrome-151-windows")
    c = curlpro.Persona.new("firefox-133-macos")

    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()


def test_save_is_atomic(tmp_path):
    """A persona is rewritten on every run; a truncated file is a lost account."""
    p = curlpro.Persona.new("chrome-151-windows")
    path = p.save(tmp_path / "acc.json")
    p.notes["run"] = 2
    p.save()

    assert json.loads(path.read_text("utf-8"))["notes"]["run"] == 2
    assert not list(tmp_path.glob("*.tmp")), "a temporary file was left behind"


def test_save_without_a_path_the_first_time_is_an_error():
    p = curlpro.Persona.new("chrome-151-windows")
    with pytest.raises(ValueError, match="needs a path"):
        p.save()


def test_a_missing_file_says_what_to_do(tmp_path):
    with pytest.raises(FileNotFoundError, match="no persona at"):
        curlpro.Persona.load(tmp_path / "nope.json")


def test_a_truncated_file_is_refused_rather_than_guessed(tmp_path):
    bad = tmp_path / "half.json"
    bad.write_text('{"version": 1, "profile": "chrome-151-win', "utf-8")
    with pytest.raises(ValueError, match="not a persona file"):
        curlpro.Persona.load(bad)


def test_a_future_format_is_refused(tmp_path):
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"version": 99, "profile": "chrome-151-windows"}), "utf-8")
    with pytest.raises(ValueError, match="format 99"):
        curlpro.Persona.load(path)


def test_load_all_reads_a_directory(tmp_path):
    for i in range(3):
        curlpro.Persona.new("chrome-151-windows", name=f"acc{i}").save(tmp_path / f"acc{i}.json")
    names = [p.name for p in curlpro.load_all(tmp_path)]
    assert names == ["acc0", "acc1", "acc2"]
