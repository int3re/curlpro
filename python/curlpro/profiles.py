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
    if not Path(directory).is_dir():
        # The native side opens the directory as a filesystem root and reports
        # its failure as "open .", which names nothing the caller typed.
        raise FileNotFoundError(f"profile directory not found: {directory}")
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
    try:
        json.loads(payload)
    except json.JSONDecodeError as e:
        raise ValueError(f"profile is not valid JSON: {e}") from None
    data = _call("curlpro_profile_register", payload)
    return data["profiles"]


def list_profiles() -> list[str]:
    """Names of the registered profiles."""
    return _call("curlpro_profiles_list")["profiles"]


def capabilities(name: str) -> dict[str, Any]:
    """What a profile can do, without opening a session or sending anything.

        caps = curlpro.capabilities("safari-26.0-macos")
        if "fetch" in caps["modes"]:
            ...

    | Key | Meaning |
    |---|---|
    | ``modes`` | the header sets it carries: ``navigate`` always, ``fetch`` with a fetch section |
    | ``protocols`` | ``http1`` and ``h2`` always, ``h3`` with an ``http3`` section |
    | ``devices`` | the phones it offers, empty for a desktop profile |
    | ``client_hints``, ``websocket``, ``http1_set`` | whether it answers ``Accept-CH``, carries a handshake template, has a measured HTTP/1.1 order |
    | ``user_agent``, ``user_agent_varies`` | the string without a device, and whether a device changes it |
    | ``derived_fetch`` | the fetch set was worked out rather than captured (see the guide) |
    | ``name``, ``based_on``, ``family`` | identity, after inheritance is resolved |

    This exists because the only way to learn any of it used to be to try: a
    caller filtering profiles had to open a session, aim a request at a closed
    port and read the words "fetch header" out of the error text — and the
    wording of an error is explicitly not part of the API.
    """
    ensure_loaded()
    return _call("curlpro_profile_capabilities", name.encode("utf-8"))


def get_profile(name: str) -> "Profile":
    """A registered profile as an object, with its inheritance resolved.

        p = curlpro.get_profile("chrome-152-windows")
        p.data["headers"]["order"]          # what it actually sends

    What comes back is the profile as it behaves, not the delta as it is
    stored: a child that carries three lines over ``based_on`` arrives whole.
    Reading the JSON out of ``site-packages`` was the only way before this.
    """
    ensure_loaded()
    return Profile(_call("curlpro_profile_get", name.encode("utf-8")))


def library_version() -> str:
    """The version of the native library, beside ``curlpro.__version__``.

    They are different numbers on purpose (``docs/VERSIONING.md``), and a bug
    report wants both: a wheel always carries a matching pair, a source build
    need not.
    """
    return _call("curlpro_version")["version"]


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
