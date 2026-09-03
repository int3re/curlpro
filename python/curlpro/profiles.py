"""Управление профилями браузеров."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ._ffi import _call, encode


_BUNDLED = Path(__file__).resolve().parent / "profiles"
_autoloaded = False


def load_profiles(directory: str | Path) -> list[str]:
    """Загружает все *.json из каталога. Возвращает имена всех известных профилей."""
    data = _call("curlpro_profiles_load_dir", str(directory).encode("utf-8"))
    return data["profiles"]


def ensure_loaded() -> list[str]:
    """Подгружает профили, вложенные в пакет, если их ещё не грузили.

    Нужно, чтобы после ``pip install`` библиотека работала без дополнительных
    шагов: колесо содержит и нативную часть, и профили. При запуске из
    репозитория каталога рядом с пакетом нет — тогда профили загружает
    вызывающий, как раньше.
    """
    global _autoloaded
    if _autoloaded:
        return list_profiles()
    _autoloaded = True
    if _BUNDLED.is_dir():
        return load_profiles(_BUNDLED)
    return list_profiles()


def register_profile(profile: dict[str, Any] | str | bytes) -> list[str]:
    """Регистрирует профиль в рантайме.

    Принимает словарь, строку JSON или байты. Это способ подключить новую
    версию браузера, не дожидаясь релиза библиотеки и не пересобирая
    нативную часть — ради него всё и затевалось.
    """
    if isinstance(profile, dict):
        payload = encode(profile)
    elif isinstance(profile, str):
        payload = profile.encode("utf-8")
    else:
        payload = profile
    # Проверяем разбор на стороне Python, чтобы ошибка указывала на строку,
    # а не приходила из Go общим сообщением.
    json.loads(payload)
    data = _call("curlpro_profile_register", payload)
    return data["profiles"]


def list_profiles() -> list[str]:
    """Имена зарегистрированных профилей."""
    return _call("curlpro_profiles_list")["profiles"]
