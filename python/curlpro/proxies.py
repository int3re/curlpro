"""Прокси из переменных окружения.

Разбор живёт здесь, а не только в нативной части, по неочевидной причине:
на Linux Go читает окружение таким, каким оно было при старте процесса, и
``os.environ[...] = ...`` из Python его уже не меняет. На Windows меняет.
Пользователь Python вправе выставить переменную в рантайме и ожидать, что она
подействует, поэтому адрес прокси выбирается здесь и передаётся вниз явно.

Правила те же, что у curl и requests: HTTPS_PROXY, затем ALL_PROXY; NO_PROXY
отменяет прокси для перечисленных узлов, «*» — для всех.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")


def proxy_for(url: str) -> str | None:
    """Прокси для адреса или None, если идти напрямую."""
    host = urlsplit(url).hostname or ""
    if not host or no_proxy(host):
        return None
    for name in _PROXY_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def no_proxy(host: str) -> bool:
    """Исключён ли узел из проксирования по NO_PROXY."""
    rules = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    if not rules:
        return False
    host = host.lower().rstrip(".")
    for rule in rules.split(","):
        rule = rule.strip().lower()
        if not rule:
            continue
        if rule == "*":
            return True
        # «.example.com» и «example.com» одинаково покрывают сам домен
        # и его поддомены — так это понимают curl и requests.
        rule = rule.lstrip(".")
        if host == rule or host.endswith("." + rule):
            return True
    return False
