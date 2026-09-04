"""Browser profile management."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ._ffi import _call, encode


_BUNDLED = Path(__file__).resolve().parent / "profiles"
_autoloaded = False


def load_profiles(directory: str | Path) -> list[str]:
    """Loads every *.json in a directory. Returns the names of all known profiles."""
    data = _call("curlpro_profiles_load_dir", str(directory).encode("utf-8"))
    return data["profiles"]


def ensure_loaded() -> list[str]:
    """Loads the profiles bundled with the package, once.

    This is what makes the library work right after ``pip install``: the
    wheel carries both the native part and the profiles. When running from
    the repository there is no such directory next to the package, and the
    caller loads the profiles itself, as before.
    """
    global _autoloaded
    if _autoloaded:
        return list_profiles()
    _autoloaded = True
    if _BUNDLED.is_dir():
        return load_profiles(_BUNDLED)
    return list_profiles()


def register_profile(profile: dict[str, Any] | str | bytes) -> list[str]:
    """Registers a profile at runtime.

    Accepts a dict, a JSON string or bytes. This is how a new browser
    version is added without waiting for a library release and without
    rebuilding the native part — the whole point of the project.
    """
    if isinstance(profile, dict):
        payload = encode(profile)
    elif isinstance(profile, str):
        payload = profile.encode("utf-8")
    else:
        payload = profile
    # Parse on the Python side so a syntax error points at the line
    # instead of arriving from Go as a generic message.
    json.loads(payload)
    data = _call("curlpro_profile_register", payload)
    return data["profiles"]


def list_profiles() -> list[str]:
    """Names of the registered profiles."""
    return _call("curlpro_profiles_list")["profiles"]


class Profile:
    """A browser profile as an object.

    A profile is data, not code: a new browser version means editing JSON,
    not rebuilding the native part. This class adds the usual operations on
    top without hiding anything: :attr:`data` stays a plain dict.

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
        """A new profile as a delta over this one.

        Inheritance lives in the core: a delta stores only the differences
        and the rest comes from the parent. That is how the entire Chrome
        110 profile boils down to one line about extension shuffling.
        """
        if not self.name:
            raise ValueError("the parent profile has no name, so a delta has nothing to build on")
        data: dict[str, Any] = {"name": name, "based_on": self.name}
        data.update(overrides)
        return Profile(data)

    def register(self) -> list[str]:
        """Registers the profile at runtime and returns every known name."""
        return register_profile(self.data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def __repr__(self) -> str:
        base = f" based on {self.based_on}" if self.based_on else ""
        return f"<Profile {self.name or 'unnamed'}{base}>"
