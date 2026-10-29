"""Browser profile management."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.request
import warnings
from pathlib import Path
from typing import Any

from ._ffi import _call, encode


_BUNDLED = Path(__file__).resolve().parent / "profiles"
_autoloaded = False
_load_lock = threading.Lock()

#: Where the project publishes its signed profile bundle between releases: a
#: GitHub release whose assets are replaced as profiles are captured.
PROFILES_URL = "https://github.com/int3re/curlpro/releases/download/profiles/profiles.json.gz"
_BUNDLE_FILE = "profiles.json.gz"


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

    Safe from any number of threads at once. The flag used to be set before
    the load: a second thread saw it, went on, and opened its session
    against an empty registry while the first was still loading — the
    native call releases the GIL, so it took no free-threaded build to lose
    that race, only two threads starting together.
    """
    global _autoloaded
    if _autoloaded:
        return _registered()
    with _load_lock:
        if not _autoloaded:
            if _BUNDLED.is_dir():
                load_profiles(_BUNDLED)
                _load_cached_bundle()
            _autoloaded = True
    return _registered()


def _cache_dir() -> Path:
    """Where update_profiles keeps the bundle: CURLPRO_CACHE_DIR, or the
    platform's user cache directory."""
    if os.environ.get("CURLPRO_CACHE_DIR"):
        return Path(os.environ["CURLPRO_CACHE_DIR"])
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "curlpro"


def _version_tuple(v: str) -> tuple[int, ...]:
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def _bundle_package(path: Path) -> str:
    """The curlpro version a bundle was built from, read without trusting it:
    only to decide whether to offer it to the library, which checks the
    signature before anything is registered."""
    with gzip.open(path, "rb") as f:
        return str(json.load(f).get("package", ""))


def _not_older_than_installed(path: Path) -> bool:
    from . import __version__
    return _version_tuple(_bundle_package(path)) >= _version_tuple(__version__)


def _load_cached_bundle() -> None:
    """The bundle update_profiles fetched, over the wheel's profiles — unless
    CURLPRO_PROFILE_UPDATES=0, or the bundle is older than the installed
    package (a newer wheel carries newer profiles than an old bundle)."""
    if os.environ.get("CURLPRO_PROFILE_UPDATES", "1").lower() in ("0", "off", "false", "no"):
        return
    path = _cache_dir() / _BUNDLE_FILE
    if not path.is_file():
        return
    try:
        if _not_older_than_installed(path):
            load_profile_bundle(path)
    except Exception as e:  # a bad cache must not cost the bundled profiles
        warnings.warn(f"curlpro: the cached profile bundle {path} was not loaded: {e}", stacklevel=3)


def load_profile_bundle(path: str | Path) -> dict[str, Any]:
    """Loads a signed profile bundle: ``path`` and ``path + ".sig"``.

    The native library checks the Ed25519 signature against the project's key
    — or a key in ``CURLPRO_BUNDLE_KEYS`` (base64, comma-separated), for a
    channel of one's own — and that no profile asks for a newer library, then
    registers every profile of it, or none. Returns what it loaded:
    ``profiles`` (every registered name), ``loaded``, ``package``, ``commit``,
    ``built``, ``min_abi``.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"profile bundle not found: {p}")
    keys = os.environ.get("CURLPRO_BUNDLE_KEYS", "")
    return _call("curlpro_profiles_load_bundle", str(p).encode("utf-8"), keys.encode("utf-8"))


def _fetch(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "curlpro-update"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — https only, below
        return r.read()


def update_profiles(url: str | None = None, *, timeout: float = 30.0) -> dict[str, Any]:
    """Fetches the newest signed profile bundle and loads it.

        info = curlpro.update_profiles()
        info["new"]          # profiles the installed package did not have

    Browsers ship every two weeks, a release of this package less often: the
    project publishes the profile corpus between releases as a bundle signed
    with Ed25519, and this fetches it (``url``, default :data:`PROFILES_URL`;
    ``url + ".sig"`` beside it), lets the native library check the signature
    and load it, and keeps it in the user cache directory
    (``CURLPRO_CACHE_DIR`` overrides), from where every later import loads it
    over the wheel's profiles. A bundle older than the installed package is
    refused — a newer wheel carries newer profiles — and nothing is kept
    unless it verified and loaded. ``CURLPRO_PROFILE_UPDATES=0`` turns the
    loading at import off.
    """
    url = url or PROFILES_URL
    if not url.startswith("https://"):
        raise ValueError(f"the profile bundle is fetched over https only: {url}")
    before = set(ensure_loaded())
    dest = _cache_dir()
    dest.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="bundle-", dir=dest))
    try:
        data = _fetch(url, timeout)
        sig = _fetch(url + ".sig", timeout)
        staged = tmp / _BUNDLE_FILE
        staged.write_bytes(data)
        (tmp / (_BUNDLE_FILE + ".sig")).write_bytes(sig)
        if not _not_older_than_installed(staged):
            from . import __version__
            raise ValueError(f"the published bundle ({_bundle_package(staged)}) is older than "
                             f"the installed curlpro {__version__}: nothing to update")
        info = load_profile_bundle(staged)
        os.replace(tmp / (_BUNDLE_FILE + ".sig"), dest / (_BUNDLE_FILE + ".sig"))
        os.replace(staged, dest / _BUNDLE_FILE)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    info["new"] = sorted(set(info["profiles"]) - before)
    info["path"] = str(dest / _BUNDLE_FILE)
    return info


def _registered() -> list[str]:
    """What the native registry holds right now, loaded or not."""
    return _call("curlpro_profiles_list")["profiles"]


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


def list_profiles(*, measured: bool | None = None) -> list[str]:
    """Names of the registered profiles.

    ``measured=True`` keeps only the profiles captured from a browser — by
    this project or by the signatures it imported; ``measured=False`` only
    the transcribed ones, taken from another project's description and
    marked so (see :func:`capabilities`). A scraper that draws a random
    profile should draw from ``measured=True``: a transcribed profile
    replays a captured version's hello under another version's User-Agent,
    which is what its source claims and nothing this project has seen.

    Loads the bundled profiles first, as :func:`get_profile`,
    :func:`capabilities` and a new session do. Until 0.15.2 it was the one
    function that did not: in a fresh process it answered ``[]``, which reads
    exactly like "no such profiles", and a field report's
    ``name if name in list_profiles() else default`` sent every User-Agent to
    the default — a ClientHello of the wrong version, chosen by the very
    function written to prevent one.
    """
    names = ensure_loaded()
    if measured is None:
        return names
    return [n for n in names if capabilities(n)["measured"] is measured]


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
    | ``resources`` | the resource kinds a request can name with ``resource=``, empty without a ``resources`` section |
    | ``cookies`` | the family's cookie policy, absent for a non-browser: ``lax_by_default``, ``third_party``, ``schemeful``, ... and ``partitioning`` — ``"partitioned"`` (Chromium keeps ``Partitioned`` cookies per top-level site), ``"third-party"`` (Firefox keeps every cookie a third party sets that way), absent for one jar |
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
