"""Разбор значения ``timeout``.

Отдельный модуль, потому что пара нужна и запросу, и потоку, и сокету:
живи она в session.py, websocket.py импортировал бы его в обратную сторону
и замкнул круг импортов.
"""

from __future__ import annotations


def split_timeout(
    value: float | tuple[float, float] | None,
) -> tuple[float | None, float | None]:
    """Разбирает timeout: число или пара (соединение, всего).

    Пара пришла из requests, где второй элемент — предел молчания между
    байтами. У нас он ограничивает запрос целиком: это строже, а не мягче,
    поэтому привычное значение подставлять безопасно. Разница названа
    в документации прямо, чтобы никто не рассчитывал на обратное.
    """
    if value is None:
        return None, None
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("timeout как пара — это (соединение, всего)")
        connect, total = value
        return (
            float(connect) if connect else None,
            float(total) if total else None,
        )
    return None, float(value)
