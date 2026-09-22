"""The identity pools: what varies between real users of one browser
version besides the phone model, and how a session draws from them."""
import json
import re
from pathlib import Path

import curlpro
import pytest
from echo_stand import EchoStand

REPO = Path(__file__).resolve().parents[2]
SEED = json.loads((REPO / "scripts" / "identities.json").read_text("utf-8"))


def _profile(name: str) -> dict:
    return json.loads((REPO / "profiles" / f"{name}.json").read_text("utf-8"))


def test_the_pools_match_the_seed():
    # The generator's own check: a profile that drifted from the seed fails here.
    import subprocess, sys
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "gen-identities.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_windows_pool_covers_releases_and_builds():
    devs = _profile("chrome-153-windows")["devices"]
    assert len(devs) == len(SEED["windows"]) * len(SEED["chrome_builds"]["153"])
    assert {d["platform_version"] for d in devs} == {w["platform_version"] for w in SEED["windows"]}
    assert {d["full_version"] for d in devs} == set(SEED["chrome_builds"]["153"])
    assert all(d["hint_arch"] == "x86" and d["bitness"] == "64" and d["form_factors"] == "Desktop" for d in devs)
    assert {d["wow64"] for d in devs} == {"?0", "?1"}
    # The capture machine's own hints are the defaults, measured (STAGE19).
    values = _profile("chrome-153-windows")["client_hints"]["values"]
    assert values["sec-ch-ua-platform-version"] == '"10.0.0"' and values["sec-ch-ua-full-version"] == '"153.0.8010.52"'
    assert values["sec-ch-ua-full-version-list"] == \
        '"Google Chrome";v="153.0.8010.52", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.52"'


def test_a_desktop_device_reaches_the_hints_after_accept_ch():
    # A site asks with Accept-CH; the second request carries the identity's
    # build, Windows release and wow64, with the full-version list rebuilt
    # from the brand list — the rule measured on Chrome 153 and Chrome 152.
    with EchoStand() as st:
        st.routes["/x"] = (200, [("Accept-CH", "sec-ch-ua-full-version-list, sec-ch-ua-platform-version, sec-ch-ua-wow64, sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-model, sec-ch-ua-form-factors, sec-ch-ua-full-version")], b"{}")
        with curlpro.Session("chrome-153-windows", device="Windows 11 24H2, Chrome 153.0.8010.53") as s:
            s.get(st.url + "/x")
            s.get(st.url + "/x")
            sent = st.last()
            assert sent["sec-ch-ua-platform-version"] == '"19.0.0"'
            assert sent["sec-ch-ua-full-version"] == '"153.0.8010.53"'
            assert sent["sec-ch-ua-full-version-list"] == \
                '"Google Chrome";v="153.0.8010.53", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53"'
            assert sent["sec-ch-ua-wow64"] == "?0" and sent["sec-ch-ua-arch"] == '"x86"'
            assert sent["sec-ch-ua-bitness"] == '"64"' and sent["sec-ch-ua-model"] == '""'
            assert sent["sec-ch-ua-form-factors"] == '"Desktop"'
            assert s.fingerprint().device == "Windows 11 24H2, Chrome 153.0.8010.53"
            # The User-Agent does not move: Chromium's is frozen on the desktop.
            assert "Chrome/153.0.0.0" in sent["user-agent"]
        # Without a device the machine's defaults go out, and no finding fires:
        # a desktop that names no device is a real desktop.
        with curlpro.Session("chrome-153-windows") as s:
            s.get(st.url + "/x")
            s.get(st.url + "/x")
            assert st.last()["sec-ch-ua-wow64"] == "?1" and st.last()["sec-ch-ua-platform-version"] == '"10.0.0"'
            assert s.audit() == []


def test_random_draws_a_desktop_identity_and_the_tls_stays():
    seen, ja4 = set(), set()
    for _ in range(40):
        with curlpro.Session("chrome-153-macos", device="random") as s:
            fp = s.fingerprint()
            seen.add(fp.device)
            ja4.add(fp.ja4)
    assert len(seen) >= 15 and len(ja4) == 1


def test_ios_identity_rewrites_the_user_agent():
    with curlpro.Session("safari-26-ios", device="iPhone, iOS 26.4.1") as s:
        ua = s.fingerprint().user_agent
        # Safari 26 froze the OS token at 18_7; the real version is in Version/ only.
        assert "iPhone OS 18_7 like Mac OS X" in ua and "Version/26.4.1 " in ua
        assert s.fingerprint().device == "iPhone, iOS 26.4.1"
    uas = set()
    for _ in range(30):
        with curlpro.Session("safari-26-ios", device="random") as s:
            uas.add(s.fingerprint().user_agent)
    assert len(uas) >= 8
    with curlpro.Session("safari-26-ios") as s:
        assert "iPhone OS 26_0 like" in s.fingerprint().user_agent  # the captured string, untouched
        assert s.audit() == []  # Safari names no phone: nothing to ask for


def test_ios_pools_follow_each_safari_line():
    for name, spec in SEED["ios"].items():
        devs = _profile(name)["devices"]
        assert [d["version"] for d in devs] == spec["versions"]
        major = name.split("-")[1].split(".")[0]
        assert all(v.startswith(major + ".") for v in spec["versions"]), name
        # Safari 18 wrote the OS version into the string; Safari 26 pins it at
        # 18_7 (every 26.x seen in real traffic) and keeps the real one in Version/.
        frozen = spec.get("frozen_os")
        for d in devs:
            assert d["os_version"] == (frozen or d["version"].replace(".", "_")), (name, d)
    assert SEED["ios"]["safari-26-ios"]["frozen_os"] == "18_7"
    assert "frozen_os" not in SEED["ios"]["safari-18.4-ios"]


def test_firefox_on_linux_may_carry_the_ubuntu_token():
    with curlpro.Session("firefox-150-linux", device="Linux, Ubuntu build") as s:
        assert "(X11; Ubuntu; Linux x86_64; rv:150.0)" in s.fingerprint().user_agent
    with curlpro.Session("firefox-150-linux", device="Linux, generic build") as s:
        assert "(X11; Linux x86_64; rv:150.0)" in s.fingerprint().user_agent


def test_a_delta_on_a_pooled_profile_has_no_pool_unless_it_says_so():
    """The macOS Safari profiles stand on the iOS captures, Edge on Chrome 153,
    the transcribed iOS and iPadOS deltas on the iOS captures: none of them may
    inherit a pool, a template or the parent's hint values."""
    pooled = {f"chrome-{v}-{o}" for v in (151, 152, 153) for o in ("windows", "macos", "linux")} | set(SEED["ios"]) | {
        p.stem for p in (REPO / "profiles").glob("firefox-*-linux.json")}
    pooled |= {"chrome-152-android", "yandex-26.8-android"}
    # The files on disk, not the registry: another test may register a delta on
    # a pooled profile, and that one inherits the pool by design.
    for name in sorted(p.stem for p in (REPO / "profiles").glob("*.json")):
        caps = curlpro.capabilities(name)
        if name in pooled:
            assert caps["devices"], name
            continue
        assert caps["devices"] == [] and not caps["user_agent_varies"], name
        if name.startswith(("chrome-", "edge-", "opera-")) and caps.get("based_on") in pooled:
            assert not caps["client_hints"], name
    with pytest.raises(curlpro.ProfileCapabilityError):
        curlpro.Session("safari-18.0-macos", device="random")
    with curlpro.Session("edge-153-windows") as s:
        assert "sec-ch-ua-full-version-list" not in s.headers_for("GET", "https://a.test/")


def test_capabilities_list_the_identities():
    caps = curlpro.capabilities("chrome-153-windows")
    assert len(caps["devices"]) == 48 and "Windows 11 24H2, Chrome 153.0.8010.53" in caps["devices"]
    assert caps["client_hints"] is True
    assert curlpro.capabilities("safari-26-ios")["user_agent_varies"] is True
    assert curlpro.capabilities("chrome-153-windows")["user_agent_varies"] is False


def test_windows_platform_versions_are_the_documented_contract_versions():
    # 10.0.0 measured on the capture machine (Windows 10 22H2); 13–19 are the
    # Windows 11 contract versions Microsoft documents and Chromium knows.
    assert {w["platform_version"] for w in SEED["windows"]} <= {"10.0.0", "13.0.0", "14.0.0", "15.0.0", "19.0.0"}
    assert all(re.fullmatch(r"\d+\.0\.0", w["platform_version"]) for w in SEED["windows"])
