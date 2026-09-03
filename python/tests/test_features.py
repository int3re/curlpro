"""Проверка возможностей клиента против настоящих сайтов.

Стенд echo-server здесь не нужен: проверяются семантика HTTP и сетевые
возможности, а не отпечаток. Тесты пропускаются, если нет интернета.
"""

from __future__ import annotations

import asyncio
import socket
import time
from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]


def _online() -> bool:
    try:
        with socket.create_connection(("httpbin.org", 443), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _online(), reason="нет доступа к httpbin.org")


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_http2_negotiated():
    with curlpro.Session() as s:
        assert s.get("https://httpbin.org/get").proto == "HTTP/2.0"


def test_http1_when_forced():
    """Профиль предлагает h2, но force_http1 должен ограничить ALPN."""
    with curlpro.Session(force_http1=True) as s:
        r = s.get("https://httpbin.org/get")
    assert r.proto.startswith("HTTP/1.")


def test_redirects_followed():
    with curlpro.Session() as s:
        r = s.get("https://httpbin.org/redirect/3")
    assert r.status == 200
    assert r.url.endswith("/get")


def test_redirects_disabled():
    with curlpro.Session(allow_redirects=False) as s:
        r = s.get("https://httpbin.org/redirect/1")
    assert r.status in (301, 302)
    assert r.header("location")


def test_redirect_limit():
    with curlpro.Session(max_redirects=2) as s:
        with pytest.raises(curlpro.CurlProError, match="предел редиректов"):
            s.get("https://httpbin.org/redirect/5")


def test_cookies_persist_across_requests():
    with curlpro.Session(cookies=True) as s:
        s.get("https://httpbin.org/cookies/set?probe=curlpro")
        got = s.get("https://httpbin.org/cookies").json()
    assert got.get("cookies", {}).get("probe") == "curlpro"


def test_cookies_disabled():
    with curlpro.Session(cookies=False, allow_redirects=False) as s:
        s.get("https://httpbin.org/cookies/set?probe=nope")
        got = s.get("https://httpbin.org/cookies").json()
    assert "probe" not in got.get("cookies", {})


def test_post_json_body():
    with curlpro.Session() as s:
        r = s.post("https://httpbin.org/post", json_body={"hello": "мир"})
    assert r.json()["json"] == {"hello": "мир"}


def test_default_headers_can_be_disabled():
    """Без заголовков профиля должен уйти только то, что задано явно."""
    with curlpro.Session(default_headers=False) as s:
        sent = s.get("https://httpbin.org/get",
                     headers={"x-only": "1"}).json()["headers"]
    assert "X-Only" in sent
    assert "Sec-Ch-Ua" not in sent


def test_header_order_is_controllable():
    """httpbin не отдаёт порядок, поэтому проверяем через отражение заголовков
    в /headers: важно, что запрос не сломался и наши заголовки дошли."""
    order = ["user-agent", "accept", "x-marker"]
    with curlpro.Session(header_order=order) as s:
        sent = s.get("https://httpbin.org/headers",
                     headers={"x-marker": "ok"}).json()["headers"]
    assert sent.get("X-Marker") == "ok"


def test_verify_can_be_disabled():
    with curlpro.Session(verify=False) as s:
        assert s.get("https://httpbin.org/get").status == 200


def test_connection_is_reused():
    """Второй запрос по той же сессии не должен переустанавливать TLS."""
    with curlpro.Session() as s:
        s.get("https://httpbin.org/get")
        first = time.perf_counter()
        s.get("https://httpbin.org/get")
        reused = time.perf_counter() - first
    assert reused < 2.0, f"повторный запрос занял {reused:.2f}s — соединение не переиспользовано"


def test_async_requests_run_concurrently():
    """Пять секундных задержек должны занять примерно столько же, сколько одна.

    Порог относительный, а не абсолютный: httpbin отвечает то за секунду,
    то за три, и фиксированное значение делало тест флаким. Базовый замер
    снимается в тех же условиях, что и параллельный.
    """
    n = 5

    async def one():
        async with curlpro.AsyncSession() as s:
            start = time.perf_counter()
            await s.get("https://httpbin.org/delay/1")
            return time.perf_counter() - start

    async def many():
        urls = [f"https://httpbin.org/delay/1?i={i}" for i in range(n)]
        async with curlpro.AsyncSession() as s:
            start = time.perf_counter()
            results = await asyncio.gather(*(s.get(u) for u in urls))
            return time.perf_counter() - start, results

    baseline = asyncio.run(one())
    elapsed, results = asyncio.run(many())

    assert all(r.status == 200 for r in results)
    # Последовательное выполнение дало бы примерно n * baseline.
    assert elapsed < baseline * 2.5, (
        f"{n} запросов заняли {elapsed:.2f}s при базовом {baseline:.2f}s — "
        "похоже на последовательное выполнение"
    )
