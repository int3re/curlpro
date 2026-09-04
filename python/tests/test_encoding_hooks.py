"""Кодировка ответа, перехватчики и объект профиля."""

from __future__ import annotations

from pathlib import Path

import curlpro
import pytest
from curlpro.session import Response

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def make(content: bytes, content_type: str | None = None) -> Response:
    headers = {"Content-Type": [content_type]} if content_type else {}
    return Response(200, "HTTP/1.1", headers, content, "https://example.com/")


# --- кодировка ---------------------------------------------------------------

def test_charset_from_header_wins():
    r = make("Привет".encode("cp1251"), "text/html; charset=windows-1251")
    assert r.encoding == "windows-1251"
    assert r.text == "Привет"


def test_charset_from_document_when_header_is_silent():
    body = '<meta charset="windows-1251">Привет'.encode("cp1251")
    r = make(body, "text/html")
    assert r.encoding == "windows-1251"
    assert r.text.endswith("Привет")


def test_old_style_meta_is_understood():
    body = (b'<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">'
            + "Привет".encode("cp1251"))
    assert make(body, "text/html").text.endswith("Привет")


def test_bom_beats_the_document():
    r = make("﻿Привет".encode("utf-8-sig"), "text/html")
    assert r.encoding == "utf-8"


def test_latin1_is_read_as_windows_1252():
    """Так требует HTML5 и так делают браузеры: в этих страницах живут
    байты 0x80–0x9F, которых в настоящем latin-1 нет."""
    r = make(b"caf\xe9 \x93\x94", "text/html; charset=iso-8859-1")
    assert r.encoding == "windows-1252"
    assert r.text == "café “”"


def test_unknown_charset_falls_back_to_utf8():
    r = make("Привет".encode("utf-8"), "text/html; charset=выдуманная-1")
    assert r.encoding == "utf-8"
    assert r.text == "Привет"


def test_encoding_can_be_overridden():
    r = make("Привет".encode("cp1251"), "text/html; charset=utf-8")
    assert r.text != "Привет", "сайт объявил кодировку неверно"
    r.encoding = "windows-1251"
    assert r.text == "Привет"


def test_json_ignores_the_declared_charset():
    """Тело JSON — UTF-8 по RFC 8259, что бы ни стояло в заголовке."""
    r = make('{"город": "Москва"}'.encode("utf-8"), "application/json; charset=iso-8859-1")
    assert r.json()["город"] == "Москва"


# --- перехватчики ------------------------------------------------------------

def test_request_hook_sees_and_changes_the_request():
    seen = []

    def add_marker(meta):
        seen.append(meta["url"])
        meta.setdefault("headers", {})["X-Marker"] = "1"

    with curlpro.Session(verify=False) as s:
        s.on_request(add_marker)
        assert s.hooks["request"] == [add_marker]
        # Отправлять некуда: важно, что перехватчик вызван до обращения к сети.
        with pytest.raises(curlpro.CurlProError):
            s.get("https://127.0.0.1:9/")
    assert seen == ["https://127.0.0.1:9/"]


def test_response_hook_can_replace_the_answer():
    def swap(resp):
        return make(b"replaced")

    s = curlpro.Session(verify=False)
    s.on_response(swap)
    assert s._after(make(b"original")).content == b"replaced"
    s.close()


def test_hooks_can_be_given_at_construction():
    calls = []
    s = curlpro.Session(verify=False, hooks={"response": [calls.append]})
    s._after(make(b"x"))
    s.close()
    assert len(calls) == 1


def test_unknown_hook_event_is_rejected():
    with pytest.raises(ValueError, match="request and response"):
        curlpro.Session(verify=False, hooks={"before": [print]})


# --- объект профиля ----------------------------------------------------------

def test_profile_derives_and_registers():
    base = curlpro.Profile.from_file(REPO / "profiles" / "chrome-152-windows.json")
    assert base.name == "chrome-152-windows"
    child = base.derive("chrome-199-windows",
                        headers={"user_agent": "Mozilla/5.0 ... Chrome/199.0.0.0 Safari/537.36"})
    assert child.based_on == "chrome-152-windows"
    assert "chrome-199-windows" in child.register()

    with curlpro.Session("chrome-199-windows", verify=False) as s:
        assert s.impersonate == "chrome-199-windows"


def test_profile_saves_to_file(tmp_path):
    base = curlpro.Profile.from_file(REPO / "profiles" / "chrome-152-android.json")
    path = tmp_path / "p.json"
    base.derive("chrome-198-android").save(path)
    assert '"based_on": "chrome-152-android"' in path.read_text(encoding="utf-8")


def test_profile_without_name_cannot_be_a_parent():
    with pytest.raises(ValueError, match="delta"):
        curlpro.Profile({"headers": {}}).derive("x")
