"""Parsing of the ``timeout`` value.

A separate module because the pair is needed by requests, streams and
sockets alike: living in session.py it would make websocket.py import that
module back and close an import cycle.
"""

from __future__ import annotations


def split_timeout(
    value: float | tuple[float, float] | None,
) -> tuple[float | None, float | None]:
    """Splits timeout: a number, or a (connect, total) pair.

    The pair comes from requests, where the second element caps the silence
    between bytes. Here it caps the whole request instead: stricter rather
    than looser, so the familiar number is safe to keep. The difference is
    spelled out in the docs so that nobody counts on the other meaning.
    """
    if value is None:
        return None, None
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("timeout as a pair is (connect, total)")
        connect, total = value
        _not_bool(connect)
        _not_bool(total)
        return (
            float(connect) if connect else None,
            float(total) if total else None,
        )
    _not_bool(value)
    return None, float(value)


def _not_bool(value: object) -> None:
    """``timeout=True`` is a mistake, not one second.

    bool is an int in Python, so float(True) is 1.0 and the request would
    quietly get a one-second limit. Refused before the conversion, where the
    intent — "yes, use a timeout" — can still be named.
    """
    if isinstance(value, bool):
        raise TypeError(f"timeout must be a number of seconds, not {value!r}")
