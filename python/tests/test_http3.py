"""Проверка HTTP/3.

Отпечаток сверяется с настоящим Chrome: quic.browserleaks.com отдаёт h3_text,
который у Chrome 144 выглядит ровно так, как записано в CHROME_H3.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]
ORACLE = "https://quic.browserleaks.com/fp"

# Эталон, снятый с настоящего Chrome 144.
CHROME_H3 = "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p"


def _quic_reachable() -> bool:
    # Проверяем TCP-порт: если хост недоступен, UDP тем более.
    try:
        with socket.create_connection(("quic.browserleaks.com", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _quic_reachable(), reason="нет доступа к quic.browserleaks.com")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_http3_negotiated():
    with curlpro.Session(http3=True) as s:
        r = s.get(ORACLE)
    assert r.status == 200
    assert r.proto.startswith("HTTP/3")


def test_http3_fingerprint_matches_chrome():
    with curlpro.Session(http3=True) as s:
        body = s.get(ORACLE).json()
    assert body["h3_text"] == CHROME_H3


def test_http3_fingerprint_is_stable():
    """Отпечаток не должен меняться от запроса к запросу.

    Ловит две гонки, которые уже случались: управляющий поток, уходящий
    параллельно запросу, и PRIORITY_UPDATE, отправленный один раз вместо
    каждого запроса.
    """
    with curlpro.Session(http3=True) as s:
        seen = {s.get(ORACLE).json()["h3_text"] for _ in range(4)}
    assert seen == {CHROME_H3}, f"отпечаток нестабилен: {seen}"


def test_ja4_marks_quic_transport():
    """JA4 над QUIC начинается с 'q', над TCP — с 't'."""
    with curlpro.Session(http3=True) as s:
        quic_ja4 = s.get(ORACLE).json()["ja4"]
    assert quic_ja4.startswith("q13d"), quic_ja4


def test_http3_requires_profile_support():
    """Профиль без секции http3 не должен молча уходить на TCP."""
    with pytest.raises(curlpro.CurlProError, match="no http3 section"):
        curlpro.Session("firefox-144-macos", http3=True)


def test_brotli_response_is_decompressed():
    """Профиль объявляет br и zstd — значит ответ надо уметь распаковать.

    До появления распаковки этот запрос возвращал сжатые байты, и разбор JSON
    падал на первом символе.
    """
    with curlpro.Session(http3=True) as s:
        r = s.get(ORACLE)
    assert r.json()["h3_text"]  # разобралось, значит распаковано
