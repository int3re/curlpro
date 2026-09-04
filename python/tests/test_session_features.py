"""Повторы, переопределения на запрос и заголовки сессии.

Проверяется против локального сервера со сценариями: важно точно знать,
сколько попыток дошло, а публичные сервисы этого не показывают.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

import curlpro
from flakyserver import FlakyServer
from proxyserver import HTTPProxy
from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def srv():
    with FlakyServer() as s:
        yield s


def session(**kw):
    kw.setdefault("verify", False)
    kw.setdefault("force_http1", True)
    return curlpro.Session(**kw)


# --- повторы -------------------------------------------------------------


def test_retry_until_success(srv):
    url = srv.scenario("/flaky", [{"status": 503}, {"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.get(url).status == 200
    assert srv.hits["/flaky"] == 3, "должно быть ровно три попытки"


def test_exhausted_retries_return_last_response(srv):
    """Исчерпав попытки, клиент отдаёт последний ответ, а не ошибку.

    Ответ сервера — это результат, а не сбой клиента: так ведут себя curl
    и urllib3, и это согласуется с тем, что raise_for_status здесь добровольный.
    """
    url = srv.scenario("/always", [{"status": 500, "body": {"why": "busy"}}])
    with session(retries=2, retry_backoff=0.01) as s:
        r = s.get(url)
    assert r.status == 500
    assert r.json() == {"why": "busy"}, "тело последнего ответа потеряно"
    assert srv.hits["/always"] == 3, "первая попытка плюс два повтора"


def test_post_not_retried_returns_response(srv):
    """POST не повторяется, но ответ сервера всё равно доходит."""
    url = srv.scenario("/post503", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        r = s.post(url, data=b"x")
    assert r.status == 503
    assert srv.hits["/post503"] == 1


def test_no_retry_by_default(srv):
    url = srv.scenario("/once", [{"status": 503}, {"status": 200}])
    with session() as s:
        assert s.get(url).status == 503
    assert srv.hits["/once"] == 1


def test_retry_respects_retry_after(srv):
    url = srv.scenario(
        "/after",
        [{"status": 429, "headers": {"Retry-After": "1"}}, {"status": 200}],
    )
    with session(retries=2, retry_backoff=0.01) as s:
        start = time.perf_counter()
        assert s.get(url).status == 200
        elapsed = time.perf_counter() - start
    # Сервер попросил секунду — формула backoff дала бы 0.01 с.
    assert elapsed >= 0.9, f"Retry-After проигнорирован: {elapsed:.2f}s"


def test_post_not_retried_by_default(srv):
    """Повтор POST может создать второй заказ: сервер мог обработать запрос
    и не успеть ответить, и клиент этого не различает."""
    url = srv.scenario("/post", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.post(url, data=b"x").status == 503
    assert srv.hits["/post"] == 1


def test_post_retried_when_allowed(srv):
    url = srv.scenario("/post-ok", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01, retry_methods=["POST"]) as s:
        assert s.post(url, data=b"x").status == 200
    assert srv.hits["/post-ok"] == 2


def test_retry_status_list_is_configurable(srv):
    url = srv.scenario("/notfound", [{"status": 404}, {"status": 200}])
    with session(retries=2, retry_backoff=0.01, retry_statuses=[404]) as s:
        assert s.get(url).status == 200
    assert srv.hits["/notfound"] == 2


def test_per_request_retry_override(srv):
    url = srv.scenario("/req", [{"status": 503}, {"status": 200}])
    with session() as s:  # у сессии повторов нет
        assert s.get(url, retries=2, retry_backoff=0.01).status == 200
    assert srv.hits["/req"] == 2


# --- переопределения на запрос ------------------------------------------


def test_per_request_timeout(srv):
    url = srv.scenario("/slow", [{"status": 200, "delay": 3}])
    with session(timeout=30) as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError):
            s.get(url, timeout=0.6)
        assert time.perf_counter() - start < 1.5


def test_timeout_covers_whole_redirect_chain(srv):
    """Дедлайн общий на цепочку, а не свой у каждого шага.

    Иначе четыре редиректа растянулись бы на четыре таймаута.
    """
    for i in range(3):
        srv.scenario(f"/c{i}", [{"status": 302, "headers": {"Location": srv.url(f"/c{i+1}")}}])
    srv.scenario("/c3", [{"status": 200, "delay": 3}])

    with session() as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError):
            s.get(srv.url("/c0"), timeout=1.0)
        assert time.perf_counter() - start < 2.0


def test_zero_timeout_rejected(srv):
    with session() as s:
        with pytest.raises(curlpro.CurlProError, match="must be positive"):
            s.get(srv.url("/ok"), timeout=0)


def test_per_request_redirect_block(srv):
    srv.scenario("/redir", [{"status": 302, "headers": {"Location": srv.url("/dest")}}])
    srv.scenario("/dest", [{"status": 200}])
    with session(allow_redirects=True) as s:
        assert s.get(srv.url("/redir")).status == 200
        assert s.get(srv.url("/redir"), allow_redirects=False).status == 302


def test_body_survives_307_redirect(srv):
    """307 обязан сохранить метод и тело. Раньше BodyFile терялся при копии
    запроса, и на сервер уходил пустой POST."""
    srv.scenario("/r307", [{"status": 307, "headers": {"Location": srv.url("/land")}}])
    srv.scenario("/land", [{"status": 200}])

    path = Path(tempfile.mkdtemp()) / "body.bin"
    path.write_bytes(b"A" * 4096)

    with session() as s:
        s.post(srv.url("/r307"), body_file=str(path))

    landed = [r for r in srv.requests if r["path"] == "/land"][0]
    assert landed["method"] == "POST"
    assert landed["body_len"] == 4096


def test_body_dropped_on_303(srv):
    """303 наоборот: метод становится GET, тело отбрасывается."""
    srv.scenario("/r303", [{"status": 303, "headers": {"Location": srv.url("/land303")}}])
    srv.scenario("/land303", [{"status": 200}])
    with session() as s:
        s.post(srv.url("/r303"), data=b"payload")
    landed = [r for r in srv.requests if r["path"] == "/land303"][0]
    assert landed["method"] == "GET"
    assert landed["body_len"] == 0


# --- прокси --------------------------------------------------------------


def test_proxy_can_be_bypassed_per_request(srv):
    url = srv.scenario("/ok", [{"status": 200}])
    with HTTPProxy() as proxy:
        with session(proxy=f"http://{proxy.url_host}") as s:
            assert s.get(url).status == 200
            assert len(proxy.tunnels) == 1
            # proxy=False должен пойти напрямую
            assert s.get(url, proxy=False).status == 200
            assert len(proxy.tunnels) == 1, "запрос всё же ушёл через прокси"


def test_proxy_can_be_overridden_per_request(srv):
    url = srv.scenario("/ok2", [{"status": 200}])
    with HTTPProxy() as first, HTTPProxy() as second:
        with session(proxy=f"http://{first.url_host}") as s:
            s.get(url, proxy=f"http://{second.url_host}")
            assert len(second.tunnels) == 1
            assert len(first.tunnels) == 0


def test_proxy_true_rejected():
    with session() as s:
        with pytest.raises(ValueError, match="meaningless"):
            s.get("https://example.com", proxy=True)


# --- заголовки сессии ----------------------------------------------------


@pytest.fixture
def raw():
    with RawHeaderServer() as srv:
        yield srv


def headers_of(srv, s) -> list[str]:
    return s.get(srv.url).json()["headers"]


def test_session_header_added_before_anchor(raw):
    """Кастомный заголовок встаёт перед якорем профиля, а не в конец.

    Служебный хвост (accept-encoding, cookie) браузер дописывает последним,
    поэтому заголовок после него — заметная аномалия. Режим задан явно:
    без него кастомное имя переключает набор на fetch (см. test_http1.py).
    """
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        s.headers["X-Api-Key"] = "secret"
        after = headers_of(raw, s)

    assert "X-Api-Key" in after
    assert after.index("X-Api-Key") < after.index("Accept-Encoding")
    # Порядок профильных заголовков не изменился.
    assert [h for h in after if h != "X-Api-Key"] == base


def test_cookie_takes_profile_position(raw):
    """cookie объявлен в профиле слотом и встаёт на свою позицию — после
    accept-language, а не туда, куда его положил бы порядок добавления.

    На HTTP/1.1 Chrome не шлёт priority (замер Chrome 152), поэтому cookie
    здесь последний; в HTTP/2 за ним идёт priority.
    """
    with session(cookies=True) as s:
        s.headers["Cookie"] = "sid=abc"
        names = [h.lower() for h in headers_of(raw, s)]
    assert "cookie" in names
    assert names.index("accept-language") < names.index("cookie")
    assert names.index("cookie") == len(names) - 1


def test_session_header_removed_by_name(raw):
    with session(mode="navigate") as s:
        s.headers["X-One"] = "1"
        s.headers["X-Two"] = "2"
        del s.headers["X-One"]
        names = headers_of(raw, s)
        assert "X-Two" in names and "X-One" not in names


def test_removing_unknown_header_raises(raw):
    with session() as s:
        with pytest.raises(KeyError):
            del s.headers["X-Never-Set"]


def test_reset_keeps_profile_headers(raw):
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        s.headers["X-A"] = "1"
        s.headers["X-B"] = "2"
        assert s.headers.clear() == 2
        assert headers_of(raw, s) == base


def test_overriding_profile_header_keeps_its_position(raw):
    """Значение меняется, позиция остаётся: перенос в конец сломал бы
    отпечаток."""
    with session(mode="navigate") as s:
        base = headers_of(raw, s)
        position = base.index("User-Agent")
        s.headers["User-Agent"] = "custom/1.0"
        after = s.get(raw.url).json()
        assert after["headers"].index("User-Agent") == position
        assert any(l == "User-Agent: custom/1.0" for l in after["raw"])


# --- добавлено по итогам аудита (STAGE14) ---------------------------------


def test_per_request_zero_retries_overrides_session(srv):
    """retries=0 у запроса выключает повторы сессии, а не наследует их.

    Раньше ноль схлопывался в «не задано», и отключить повторы на один
    запрос было нельзя.
    """
    url = srv.scenario("/zero", [{"status": 503}, {"status": 200}])
    with session(retries=3, retry_backoff=0.01) as s:
        assert s.get(url, retries=0).status == 503
    assert srv.hits["/zero"] == 1


def test_stream_accepts_request_overrides(srv):
    """stream() принимает те же переопределения, что и request()."""
    url = srv.scenario("/slow-stream", [{"status": 200, "delay": 3}])
    with session(timeout=30) as s:
        start = time.perf_counter()
        with pytest.raises(curlpro.CurlProError) as info:
            s.stream("GET", url, timeout=0.6)
        assert time.perf_counter() - start < 1.5
        assert info.value.code == "timeout"


def test_stream_early_close_keeps_session_usable(srv):
    """Закрытие потока с недочитанным телом не портит следующий запрос."""
    srv.scenario("/big", [{"status": 200, "body": {"n": "z" * 200_000}}])
    srv.scenario("/after", [{"status": 200}])
    with session() as s:
        stream = s.stream("GET", srv.url("/big"))
        next(stream.iter_content(64))
        stream.close()
        assert s.get(srv.url("/after")).status == 200
