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
        return (
            float(connect) if connect else None,
            float(total) if total else None,
        )
    return None, float(value)
