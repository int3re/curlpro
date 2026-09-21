"""The guide's claims, checked against the code.

docs/GUIDE.md was written to be the verified description of the library — the
document an AI assistant reads before touching code that uses it. A document
like that is only worth having while it stays true, and numbers drift first:
a profile is added, a code is introduced, a name is exported. So the claims
that can be counted are counted here, and the guide fails with the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]
GUIDE = (REPO / "docs" / "GUIDE.md").read_text(encoding="utf-8")
LLMS = (REPO / "llms.txt").read_text(encoding="utf-8")
# Prose wraps at 80 columns; a phrase is looked for across line breaks.
TEXT = re.sub(r"\s+", " ", GUIDE)
# The shipped profiles are the files: the native registry is shared by the
# whole test run, and other tests register profiles of their own into it.
NAMES = sorted(p.stem for p in (REPO / "profiles").glob("*.json"))


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_the_profile_count_and_families():
    names = NAMES
    assert len(names) == 50
    assert set(names) <= set(curlpro.list_profiles())
    families = {}
    for n in names:
        families[n.split("-")[0]] = families.get(n.split("-")[0], 0) + 1
    assert families == {"chrome": 25, "edge": 6, "firefox": 4, "safari": 11,
                        "tor": 1, "yandex": 1, "okhttp": 2}
    assert "50 profiles" in TEXT and "25 Chrome" in TEXT


def test_the_number_of_distinct_ja4_values():
    # Other tests re-register shipped names with altered TLS into the shared
    # native registry; the files are re-loaded so the claim is about the wheel.
    curlpro.load_profiles(REPO / "profiles")
    # The last Chromium hellos before the post-quantum key share sit near 512
    # bytes, and their padding extension appears or not with the random size
    # of the ECH GREASE payload — so that group has two JA4 spellings, as the
    # browsers do, and the baselines list both. The count folds the pair.
    flip = {"t13d1517h2_8daaf6152771_b1ff8ab2d16f": "t13d1516h2_8daaf6152771_02713d6af862"}
    pre_kyber = {"chrome-119-linux", "chrome-119-macos", "chrome-120-linux", "chrome-120-macos",
                 "chrome-123-macos", "chrome-124-macos", "chrome-131-android", "chrome-131-macos",
                 "edge-119-linux", "edge-120-linux"}
    groups: dict[str, list[str]] = {}
    for n in NAMES:
        with curlpro.Session(n) as s:
            ja4 = s.fingerprint().ja4
        if ja4 in flip:
            assert n in pre_kyber, f"{n} showed the padding variant {ja4}"
            ja4 = flip[ja4]
        groups.setdefault(ja4, []).append(n)
    assert len(groups) == 17, "\n".join(f"{k}: {v}" for k, v in sorted(groups.items()))
    assert "17 distinct JA4" in TEXT and "17 distinct JA4" in LLMS


def test_which_profiles_have_http3_and_fetch_sets():
    curlpro.load_profiles(REPO / "profiles")
    with_h3 = {"chrome-151-windows", "chrome-152-windows", "chrome-152-android", "yandex-26.8-android"}
    for n in with_h3:
        with curlpro.Session(n, http3=True) as s:
            assert s.impersonate == n
    for n in ("firefox-155-windows", "safari-26.0-macos"):
        with pytest.raises(curlpro.CurlProError):
            curlpro.Session(n, http3=True)
    for n in NAMES:
        # Every browser profile has a fetch set; okhttp, a library, has none.
        has_fetch = not n.startswith("okhttp-")
        if has_fetch:
            curlpro.Session(n, mode="fetch").close()
        else:
            with pytest.raises(curlpro.CurlProError):
                curlpro.Session(n, mode="fetch")
    for n in sorted(with_h3):
        assert n in GUIDE and n in LLMS


def test_the_device_pool_size():
    import json
    for n in ("chrome-152-android", "yandex-26.8-android"):
        p = json.loads((REPO / "profiles" / f"{n}.json").read_text(encoding="utf-8"))
        assert len(p["devices"]) == 46
    assert "46 real phones" in TEXT


def test_the_error_codes_named_are_the_ones_the_native_side_knows():
    go = (REPO / "internal" / "client" / "errors.go").read_text(encoding="utf-8")
    native = set(re.findall(r'ErrorCode = "([a-z_]+)"', go))
    assert native == {"session_closed", "timeout", "ws_closed", "ws_too_big",
                      "ws_protocol", "too_large", "proxy_closed",
                      "profile_capability", "configuration",
                      "proxy", "proxy_auth", "cors"}
    for code in native | {"expectation"}:
        assert f"`{code}`" in GUIDE, code
        assert code in LLMS, code
    assert curlpro.ExpectationFailed("x").code == "expectation"


def test_every_name_in_the_api_index_exists():
    index = GUIDE.split("## 17. API index", 1)[1].split("## 18.", 1)[0]
    names = set()
    for m in re.finditer(r"^\| ((?:`[^`]+`(?:, )?)+) \|", index, re.M):
        for n in re.findall(r"`([^`]+)`", m.group(1)):
            names.add(n.split("(")[0])
    assert "Session" in names and "request" in names, names
    # A row may name a method rather than a module-level name: s.headers_for.
    methods = {n[2:] for n in names if n.startswith("s.")}
    missing = [n for n in methods if not hasattr(curlpro.Session, n)]
    assert missing == [], f"Session has no {missing}"
    names -= {n for n in names if n.startswith("s.")}
    missing = [n for n in names if n != "curlpro.requests" and not hasattr(curlpro, n)]
    assert missing == [], missing
    import curlpro.requests as rq
    assert hasattr(rq, "get") and hasattr(rq, "Session")


def test_the_session_parameters_in_the_guide_are_the_constructor_s():
    import inspect
    params = set(inspect.signature(curlpro.Session.__init__).parameters) - {"self"}
    section = GUIDE.split("## 4. Sessions", 1)[1].split("## 5.", 1)[0]
    documented = set(re.findall(r"^\| `([a-z_0-9]+)`", section, re.M))
    documented |= {n for row in re.findall(r"^\| ((?:`[a-z_0-9]+`, )+`[a-z_0-9]+`)", section, re.M)
                   for n in re.findall(r"`([a-z_0-9]+)`", row)}
    assert params - documented == set(), params - documented
    assert documented - params == set(), documented - params


def test_the_request_parameters_in_the_guide_are_the_method_s():
    import inspect
    params = set(inspect.signature(curlpro.Session.request).parameters) - {"self", "method", "url"}
    section = GUIDE.split("## 5. Requests", 1)[1].split("The response:", 1)[0]
    documented = set()
    for row in re.findall(r"^\| ((?:`[a-z_0-9*]+`(?:, )?)+) \|", section, re.M):
        documented |= set(re.findall(r"`([a-z_0-9]+)`", row))
    # retry_* stands for the five retry overrides.
    documented |= {p for p in params if p.startswith("retry_")} if "retry_*" in section else set()
    assert params - documented == set(), params - documented
    assert documented - params == set(), documented - params
