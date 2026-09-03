"""Проверка отпечатка HTTP/1.1.

В HTTP/2 имена заголовков обязаны быть строчными, а в HTTP/1.1 регистр
произволен — и браузеры им пользуются. Публичные оракулы имена нормализуют,
поэтому проверка идёт против локального сервера, отдающего сырые строки.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import curlpro
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]

# Порядок и регистр навигационного запроса по HTTP/1.1.
#
# Замер Chrome 152 и Firefox 154 (docs/STAGE15-RESULTS.md): на HTTP/1.1 Chrome
# не шлёт priority, а Firefox — TE, хотя в HTTP/2 оба присутствуют. Поэтому
# http1.order задаёт не только порядок, но и набор.
CHROME_H1 = [
    "Host", "Connection",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests", "User-Agent", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language",
]

FIREFOX_H1 = [
    "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
    "Connection", "Upgrade-Insecure-Requests",
    "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
    "Priority",
]

# Кластер, в который Chrome ставит кастомные заголовки запроса fetch/XHR.
CHROME_FETCH_H1 = [
    "Host", "Connection", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua",
    "X-Api-Key", "sec-ch-ua-mobile", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language",
]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def raw():
    with RawHeaderServer() as srv:
        yield srv


def fetch(srv, profile: str, **kw) -> dict:
    with curlpro.Session(profile, force_http1=True, verify=False, **kw) as s:
        return s.get(srv.url).json()


def test_chrome_header_order_and_case(raw):
    assert fetch(raw, "chrome-151-windows")["headers"] == CHROME_H1


def test_firefox_header_order_and_case(raw):
    assert fetch(raw, "firefox-144-macos")["headers"] == FIREFOX_H1


def test_case_is_not_canonicalized(raw):
    """sec-ch-* остаются строчными, хотя Go по умолчанию канонизирует имена."""
    names = fetch(raw, "chrome-151-windows")["headers"]
    assert "sec-ch-ua" in names and "Sec-Ch-Ua" not in names
    assert "sec-ch-ua-platform" in names and "Sec-Ch-Ua-Platform" not in names
    # А эти, наоборот, должны быть в Title-Case.
    assert "User-Agent" in names and "user-agent" not in names


def test_host_and_connection_present(raw):
    """Их нет в HTTP/2, но в HTTP/1.1 браузер шлёт оба, и Host — первым."""
    d = fetch(raw, "chrome-151-windows")
    assert d["headers"][0] == "Host"
    assert d["headers"][1] == "Connection"
    assert any(line.startswith("Connection: keep-alive") for line in d["raw"])


def test_request_line(raw):
    assert fetch(raw, "chrome-151-windows")["request_line"] == "GET / HTTP/1.1"


def test_profiles_differ(raw):
    chrome = fetch(raw, "chrome-151-windows")["headers"]
    firefox = fetch(raw, "firefox-144-macos")["headers"]
    assert chrome != firefox
    # У Firefox есть Priority, у Chrome на HTTP/1.1 его нет вовсе.
    assert "Priority" in firefox and not any(h.lower() == "priority" for h in chrome)
    # sec-ch-* — только у Chromium.
    assert "sec-ch-ua" in chrome and "sec-ch-ua" not in firefox


def test_custom_header_switches_to_fetch_set(raw):
    """Кастомный заголовок бывает только у fetch/XHR, и набор у них другой.

    Навигационный набор плюс X-Api-Key аномален при любом якоре: у fetch нет
    upgrade-insecure-requests и sec-fetch-user, accept — */*, а sec-ch-*
    стоят в кластере рендерера (замер Chrome 152).
    """
    with curlpro.Session("chrome-151-windows", force_http1=True, verify=False) as s:
        s.headers["X-Api-Key"] = "secret"
        d = s.get(raw.url).json()
    assert d["headers"] == CHROME_FETCH_H1
    assert any(line.startswith("Accept: */*") for line in d["raw"])


def test_mode_navigate_keeps_navigation_set(raw):
    """Явный режим navigate оставляет навигационный набор."""
    with curlpro.Session("chrome-151-windows", force_http1=True, verify=False,
                         mode="navigate") as s:
        s.headers["X-Api-Key"] = "secret"
        names = s.get(raw.url).json()["headers"]
    assert [h for h in names if h != "X-Api-Key"] == CHROME_H1
    assert names.index("X-Api-Key") == names.index("Accept") - 1
