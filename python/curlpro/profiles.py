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


class Profile:
    """Профиль браузера как объект.

    Профиль — это данные, а не код: под новую версию браузера правится JSON,
    и пересобирать нативную часть не нужно. Класс добавляет к этим данным
    привычные операции, не пряча их: :attr:`data` остаётся обычным словарём.

        base = Profile.from_file("profiles/chrome-152-windows.json")
        my = base.derive("chrome-153-windows",
                         headers={"user_agent": "...Chrome/153..."})
        my.register()
    """

    __slots__ = ("data",)

    def __init__(self, data: dict[str, Any]):
        if not isinstance(data, dict):
            raise TypeError("a profile is a dict of JSON fields")
        self.data = data

    @classmethod
    def from_file(cls, path: str | Path) -> "Profile":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @property
    def name(self) -> str:
        return self.data.get("name", "")

    @property
    def based_on(self) -> str:
        return self.data.get("based_on", "")

    def derive(self, name: str, **overrides: Any) -> "Profile":
        """Новый профиль дельтой над этим.

        Наследование живёт в ядре: дельта хранит только отличия, остальное
        берётся у предка. Так весь профиль Chrome 110 — это одна строка
        про перемешивание расширений.
        """
        if not self.name:
            raise ValueError("the parent profile has no name, so a delta has nothing to build on")
        data: dict[str, Any] = {"name": name, "based_on": self.name}
        data.update(overrides)
        return Profile(data)

    def register(self) -> list[str]:
        """Регистрирует профиль в рантайме и возвращает имена всех известных."""
        return register_profile(self.data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def __repr__(self) -> str:
        base = f" based on {self.based_on}" if self.based_on else ""
        return f"<Profile {self.name or 'unnamed'}{base}>"
