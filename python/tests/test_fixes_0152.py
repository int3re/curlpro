"""The fixes of 0.15.2, from the Qrator field report (2026-10-06): a solver
for ``login.mts.ru`` moved from curl_cffi to curlpro 0.15.1.

1. ``list_profiles()`` answered ``[]`` in a fresh process, where
   ``get_profile()`` and ``capabilities()`` load the bundled profiles first.
   The report's ``name if name in list_profiles() else default`` sent every
   User-Agent to the default.
2. ``Response.challenge`` did not know Qrator. The rules are the report's,
   measured on the wire, a browser's answers beside the library's — including
   the one that cost it half a day: a 403 *with* ``X-Qrator-Validate-Result``
   is a verdict, a bare 403 is "what you sent could not be read".
3. ``r.headers.get(name) == "captcha"`` was false for ever: the value is a
   list. It still is — and now also equal to, and printed as, the string
   ``curlpro.requests`` gives for the same header.
4. ``AsyncSession(proxies=...)`` raised a TypeError naming ``Session``.

Qrator's own site is not used: the rules are replayed on the local stand and
against :func:`curlpro.challenge.detect`, as the report gave them.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import curlpro
import pytest
from curlpro.challenge import detect
from echo_stand import EchoStand

REPO = Path(__file__).resolve().parents[2]

#: What login.mts.ru answered, as the report quotes it: the page carries the
#: vendor's script, and the cookie comes with the 401.
QRATOR_PAGE = (b'<!doctype html><html><head><script src="/__qrator/qauth_utm_v2_bd3c4e.js">'
               b"</script></head><body></body></html>")


# --- 1. list_profiles in a fresh process -----------------------------------

def test_list_profiles_loads_the_bundled_set_first():
    # The report's own reproduction: four functions in a cold process. The
    # bundled directory is pointed at the repository's profiles, which is
    # what a wheel carries next to the package.
    code = (
        "import pathlib, curlpro, curlpro.profiles as p\n"
        f"p._BUNDLED = pathlib.Path({str(REPO / 'profiles')!r})\n"
        "first = len(curlpro.list_profiles())\n"
        "curlpro.get_profile('chrome-151-windows')\n"
        "print(first, len(curlpro.list_profiles()))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO / "python", capture_output=True,
                         text=True, timeout=120, env={**os.environ, "PYTHONPATH": str(REPO / "python")})
    assert out.returncode == 0, out.stderr
    first, after = map(int, out.stdout.split())
    assert first > 0, "list_profiles() answered [] before anything else had loaded the set"
    assert first == after


# --- 2. Qrator, by the report's rules ---------------------------------------

def _qrator(status, extra=(), body=b"", url="https://login.mts.ru/amserver/NUI/"):
    headers = {"Server": ["QRATOR"]}
    for k, v in extra:
        headers.setdefault(k, []).append(v)
    return detect(status, headers, body, url)


def test_the_401_with_its_cookie_and_script_is_a_challenge():
    c = _qrator(401, [("Set-Cookie", "qrator_jsr=v2.1.1759.abc; path=/")], QRATOR_PAGE)
    assert (c.vendor, c.kind, c.solvable) == ("qrator", "challenge", True)
    assert "set-cookie: qrator_jsr" in c.evidence and "/__qrator/ script" in c.evidence


def test_the_401_is_known_from_its_headers_alone():
    # A stream sees the headers and not yet the page: the cookie is enough.
    c = _qrator(401, [("Set-Cookie", "qrator_jsr=x; path=/")])
    assert (c.vendor, c.kind) == ("qrator", "challenge")


def test_server_qrator_alone_is_not_a_gate():
    # On ordinary 200s as well, the report says.
    assert _qrator(200) is None
    assert _qrator(401) is None   # a 401 of the site's own, behind Qrator


def test_a_verdict_of_captcha_is_the_picture():
    c = _qrator(403, [("X-Qrator-Validate-Result", "captcha"), ("X-Qrator-Token", "t0k3n")],
                url="https://login.mts.ru/__qrator/validate?pow=1")
    assert (c.vendor, c.kind, c.solvable) == ("qrator", "captcha", True)
    assert "x-qrator-validate-result: captcha" in c.evidence and "x-qrator-token" in c.evidence


@pytest.mark.parametrize("status, extra", [
    (403, [("X-Qrator-Validate-Result", "base")]),
    (418, []),
    (420, []),
])
def test_the_checkbox_branch(status, extra):
    c = _qrator(status, extra, url="https://login.mts.ru/__qrator/validate")
    assert (c.vendor, c.kind) == ("qrator", "captcha")


def test_a_bare_403_from_validate_is_no_verdict_at_all():
    # The half day: the browser's 403 carried the verdict, the library's came
    # back empty. One is a judgement, the other is not.
    c = _qrator(403, [("Content-Length", "0")], url="https://login.mts.ru/__qrator/validate")
    assert (c.vendor, c.kind, c.solvable) == ("qrator", "no-verdict", False)
    assert "403 without x-qrator-validate-result" in c.evidence
    judged = _qrator(403, [("X-Qrator-Validate-Result", "captcha")],
                     url="https://login.mts.ru/__qrator/validate")
    assert judged.kind != c.kind


def test_the_endpoint_names_the_vendor_when_the_server_header_does_not():
    # A proxy in between may rewrite Server; the path is Qrator's by itself.
    c = detect(403, {"Server": ["nginx"]}, b"", "https://login.mts.ru/__qrator/validate")
    assert (c.vendor, c.kind) == ("qrator", "no-verdict")


@pytest.mark.parametrize("status, headers, url", [
    (401, {"WWW-Authenticate": ["Basic realm=x"]}, "https://a.test/"),   # HTTP auth
    (418, {}, "https://a.test/teapot"),                                   # a teapot
    (403, {"Server": ["QRATOR"]}, "https://a.test/private"),              # the site's own 403
])
def test_lookalikes_are_left_alone(status, headers, url):
    assert detect(status, headers, b"", url) is None


def test_a_session_sees_qrator_and_hands_it_to_a_solver():
    class Solver:
        calls = 0

        def solve(self, req):
            Solver.calls += 1
            assert req.challenge.vendor == "qrator"
            c = {"name": "qrator_jsid", "value": "ok", "domain": "127.0.0.1", "path": "/", "host_only": True}
            return curlpro.Solution([c], req.user_agent, "t") if req.verify([c]) else None

    def gate(rec):
        if "qrator_jsid=ok" in rec.get("cookie", ""):
            return 200, [], b"welcome"
        return 401, [("Set-Cookie", "qrator_jsr=v2; path=/")], QRATOR_PAGE

    with EchoStand() as st:
        st.routes["/login"] = gate
        st.routes["/__qrator/validate"] = (403, [], b"")
        with curlpro.Session("chrome-154-windows") as s:
            r = s.get(st.url + "/login")
            assert (r.status, r.challenge.vendor, r.challenge.kind) == (401, "qrator", "challenge")
            with pytest.raises(curlpro.ChallengeError):
                r.raise_for_challenge()
            bare = s.post(st.url + "/__qrator/validate")
            assert bare.challenge.kind == "no-verdict"
        with curlpro.Session("chrome-154-windows", solver=Solver()) as s:
            assert s.get(st.url + "/login").status == 200
    assert Solver.calls == 1


# --- 3. a header value that is also its string ------------------------------

def _answered(headers):
    with EchoStand() as st, curlpro.Session("chrome-154-windows") as s:
        st.routes["/h"] = (403, headers, b"")
        return s.get(st.url + "/h")


def test_the_ported_comparison_is_true_when_it_should_be():
    r = _answered([("X-Qrator-Validate-Result", "captcha")])
    v = r.headers.get("x-qrator-validate-result")
    assert v == "captcha" and "captcha" == v and not (v != "captcha")
    assert f"verdict={v}" == "verdict=captcha" and str(v) == "captcha"
    assert v in ("captcha", "base")
    assert v == ["captcha"] and repr(v) == "['captcha']"   # still the list it was


def test_a_repeated_header_is_still_walked_and_equals_the_shims_string():
    r = _answered([("Set-Cookie", "a=1; path=/"), ("Set-Cookie", "b=2; path=/")])
    lines = r.headers.get("set-cookie")
    assert [line.split("=")[0] for line in lines] == ["a", "b"]     # the loop 0.12 kept
    assert lines[0] == "a=1; path=/" and len(lines) == 2
    assert lines == "a=1; path=/, b=2; path=/"
    import json
    assert json.loads(json.dumps(dict(r.headers)))["Set-Cookie"] == ["a=1; path=/", "b=2; path=/"]
    with EchoStand() as st:
        st.routes["/h"] = (200, [("Set-Cookie", "a=1; path=/"), ("Set-Cookie", "b=2; path=/")], b"")
        import curlpro.requests as creq
        assert lines == creq.get(st.url + "/h", impersonate="chrome-154-windows").headers.get("set-cookie")


def test_an_empty_header_is_falsy_but_present():
    r = _answered([("X-Empty", "")])
    v = r.headers.get("x-empty")
    assert v is not None and not v and "x-empty" in r.headers   # requests: "" — present, falsy
    assert r.headers.first("x-empty") == "" and r.header("x-empty") == ""
    assert r.headers.get("x-absent") is None and r.headers.first("x-absent", "d") == "d"


def test_what_wants_a_string_still_fails_loudly():
    v = _answered([("Retry-After", "120")]).headers.get("retry-after")
    with pytest.raises(AttributeError):
        v.lower()
    with pytest.raises(TypeError):
        int(v)
    with pytest.raises(TypeError):
        hash(v)                               # unhashable, as a list is


def test_every_way_of_reading_hands_out_the_string_like_value():
    # Values are converted on first read, so each read path must convert:
    # a loop over items() of fresh headers is where a bare list would slip out.
    for read in (lambda h: dict(h.items())["X-V"], lambda h: list(h.values())[0],
                 lambda h: h["x-v"], lambda h: h.get("X-V"), lambda h: h.pop("x-v"),
                 lambda h: h.setdefault("x-v", []), lambda h: h.popitem()[1]):
        h = curlpro.Headers({"X-V": ["captcha"]})
        assert read(h) == "captcha", read


def test_get_list_and_the_value_object_itself():
    import pickle
    r = _answered([("X-A", "1"), ("X-A", "2")])
    assert r.headers.get_list("x-a") == ["1", "2"] and type(r.headers.get_list("x-a")) is list
    assert r.headers.get_list("x-none") == []
    r.headers["x-a"].append("3")                       # the stored object, not a copy
    assert r.headers["X-A"] == ["1", "2", "3"]
    back = pickle.loads(pickle.dumps(r.headers))
    assert back.get("x-a") == "1, 2, 3" and type(back.get("x-a")).__name__ == "HeaderValues"


# --- 4. the class AsyncSession names ----------------------------------------

def test_async_session_names_itself_for_an_unknown_argument():
    async def make():
        return curlpro.AsyncSession("chrome-151-windows", proxies={"https": "http://127.0.0.1:9"})

    with pytest.raises(TypeError, match=r"^AsyncSession\(\) got an unexpected keyword argument 'proxies'"):
        asyncio.run(make())


def test_async_session_still_takes_every_session_argument():
    async def go():
        async with curlpro.AsyncSession("chrome-151-windows", proxy="http://127.0.0.1:9", timeout=5,
                                        verify=False, http3=False) as s:
            return s.impersonate
    assert asyncio.run(go()) == "chrome-151-windows"
