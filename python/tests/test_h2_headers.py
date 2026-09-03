"""Порядок обычных заголовков в HTTP/2 — на проводе, а не в сборке.

Между сборкой заголовков и проводом лежит HPACK, и до сих пор порядок в HTTP/2
не проверялся ничем: Python-тесты заголовков гоняют с force_http1=True, а
Go-тесты видят только результат сборки. Из-за этого прожил незамеченным баг,
при котором якорь пользовательских заголовков работал лишь на HTTP/1.1.

Стенд `echo-server` из fingerproxy отдаёт HEADERS-кадр в порядке провода
(`/json/detail` → detail.metadata.HTTP2Frames.Headers), чем здесь и пользуемся.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

import curlpro

STAND = "https://localhost:8443/json/detail"
REPO = Path(__file__).resolve().parents[2]


def _stand_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _stand_up(), reason="стенд на :8443 не поднят")


@pytest.fixture(scope="module", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture
def sess():
    with curlpro.Session("chrome-151-windows", verify=False) as s:
        yield s


def wire_order(s: curlpro.Session) -> list[str]:
    """Имена полей HEADERS в порядке отправки, включая псевдо-заголовки."""
    detail = s.get(STAND).json()["detail"]
    return [h["Name"] for h in detail["metadata"]["HTTP2Frames"]["Headers"]]


def test_pseudo_headers_come_first_in_chrome_order(sess):
    assert wire_order(sess)[:4] == [":method", ":authority", ":scheme", ":path"]


def test_profile_order_reaches_the_wire(sess):
    names = [n for n in wire_order(sess) if not n.startswith(":")]
    assert names[0] == "sec-ch-ua", f"порядок профиля не дошёл: {names}"
    # Служебный хвост Chrome дописывает последним.
    assert names[-1] == "priority"
    assert names.index("accept-encoding") < names.index("accept-language")


def test_custom_header_lands_before_anchor():
    """Якорь обязан работать и в HTTP/2, а не только в HTTP/1.1.

    Именно этот случай был сломан: reorder вызывался лишь при явном порядке,
    который есть только у http1.order. Режим задан явно: без него кастомное
    имя переключает набор на fetch.
    """
    with curlpro.Session("chrome-151-windows", verify=False, mode="navigate") as sess:
        before = wire_order(sess)
        sess.headers["X-Api-Key"] = "secret"
        after = wire_order(sess)

    assert "x-api-key" in after, "заголовок сессии не дошёл до провода"
    assert after.index("x-api-key") < after.index("accept-encoding"), (
        f"кастомный заголовок после служебного хвоста: {after}"
    )
    # Порядок профильных заголовков не изменился.
    assert [n for n in after if n != "x-api-key"] == before


def test_custom_header_switches_to_fetch_set(sess):
    """Без явного режима кастомный заголовок означает fetch: у него другой
    набор и другой кластер (замер Chrome 152)."""
    navigation = wire_order(sess)
    sess.headers["X-Api-Key"] = "secret"
    after = wire_order(sess)

    assert "x-api-key" in after
    assert "upgrade-insecure-requests" not in after, "у fetch этого заголовка нет"
    assert "sec-fetch-user" not in after
    assert after.index("x-api-key") < after.index("sec-ch-ua-mobile")
    assert after != navigation


def test_profile_header_override_keeps_position(sess):
    """Переопределение профильного имени не меняет ни набор, ни позицию:
    user-agent есть и в навигационном наборе, значит это не признак fetch."""
    before = wire_order(sess)
    position = before.index("user-agent")
    sess.headers["User-Agent"] = "custom/1.0"

    after = wire_order(sess)
    assert after.index("user-agent") == position, f"позиция сдвинулась: {after}"
    assert after == before, "переопределение значения изменило порядок"
