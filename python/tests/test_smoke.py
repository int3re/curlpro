"""Проверка биндинга против локального fingerproxy echo-server.

Стенд поднимается отдельно (см. docs/CAPTURE.md):

    tools/echo-server_windows_amd64.exe -listen-addr localhost:8443 \
        -cert-filename capture/certs/tls.crt -certkey-filename capture/certs/tls.key

Без него тесты пропускаются, а не падают.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

import curlpro

STAND = "https://localhost:8443/json"
REPO = Path(__file__).resolve().parents[2]
REFERENCE = REPO / "reference" / "chrome-151-windows.json"


def _stand_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _stand_up(), reason="echo-server на :8443 не запущен")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    names = curlpro.load_profiles(REPO / "profiles")
    assert "chrome-151-windows" in names
    return names


def _fetch(profile: str) -> dict:
    with curlpro.Session(profile, verify=False) as s:
        return s.get(STAND).json()


def test_fingerprint_matches_reference():
    """JA4 должен совпасть с эталоном, снятым с настоящего Chrome 151."""
    want = json.loads(REFERENCE.read_text(encoding="utf-8"))["captured"]["ja4"][0]
    assert _fetch("chrome-151-windows")["ja4"] == want


def test_ja3_varies_between_connections():
    """Chrome >=110 перемешивает расширения: постоянный JA3 — сам по себе признак."""
    seen = set()
    for _ in range(5):
        # Каждая сессия — новое TLS-соединение и новая перестановка расширений.
        with curlpro.Session("chrome-151-windows", verify=False) as s:
            seen.add(s.get(STAND).json()["ja3"])
    assert len(seen) > 1, f"JA3 не меняется между соединениями: {seen}"


def test_profiles_differ():
    """Разные браузеры должны давать разные отпечатки на всех слоях."""
    chrome = _fetch("chrome-151-windows")
    firefox = _fetch("firefox-144-macos")
    assert chrome["ja4"] != firefox["ja4"]
    # Firefox отличается и на уровне HTTP/2: своё окно и порядок псевдо-заголовков.
    assert chrome["http2"] != firefox["http2"]
    assert firefox["http2"].endswith("m,p,a,s")


def test_register_profile_at_runtime():
    """Профиль, добавленный в рантайме, сразу пригоден для запросов."""
    base = json.loads((REPO / "profiles" / "chrome-151-windows.json").read_text(encoding="utf-8"))
    delta = {
        "name": "chrome-152-test",
        "based_on": "chrome-151-windows",
        "headers": {"user_agent": base["headers"]["user_agent"].replace("151", "152")},
    }
    assert "chrome-152-test" in curlpro.register_profile(delta)

    with curlpro.Session("chrome-152-test", verify=False) as s:
        body = s.get(STAND).json()
    # Отпечаток TLS унаследован от родителя — менялся только User-Agent.
    assert body["ja4"] == _fetch("chrome-151-windows")["ja4"]


def test_error_surfaces_from_native():
    with pytest.raises(curlpro.CurlProError, match="не найден"):
        curlpro.Session("no-such-profile")
