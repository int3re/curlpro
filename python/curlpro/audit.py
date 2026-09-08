"""Contradictions inside an identity — the reason a correct fingerprint still fails.

Every client of this kind answers one question: how do I send a request that
looks like Chrome. The question people actually lose days to is the second one —
I did everything right and I am still being caught.

Usually the answer is not a wrong fingerprint but a **disagreement**: the TLS
says Chrome 151 while the User-Agent says 120, the profile is a phone while no
device is set so the client hints go out empty, the profile is the Tor Browser
while the language says Russian. Each part is defensible alone; together they
describe a client that does not exist.

Nothing here needs a network. Everything is read from what the session would
actually send — :meth:`curlpro.Session.fingerprint` — rather than from our own
configuration: a check against internal state would happily pass while the wire
said something else.

    for f in persona.audit():
        print(f)

The checks are conservative on purpose. A false alarm costs more than a missed
one here: someone who is told about three problems and finds two of them
imaginary stops reading the third.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

#: How much a finding matters. "high" means a server can single this client out
#: on that basis alone; "medium" means it narrows the crowd; "low" is worth
#: knowing but rarely decisive.
LEVELS = ("high", "medium", "low")


class Finding:
    """One contradiction, with the reason it matters and what to do."""

    __slots__ = ("code", "level", "what", "why", "fix")

    def __init__(self, code: str, level: str, what: str, why: str, fix: str):
        self.code = code
        self.level = level
        self.what = what
        self.why = why
        self.fix = fix

    def __repr__(self) -> str:
        return f"<Finding {self.level} {self.code}>"

    def __str__(self) -> str:
        mark = {"high": "!!", "medium": " !", "low": "  "}[self.level]
        return f"{mark} {self.what}\n     why: {self.why}\n     fix: {self.fix}"


_VERSION_IN_NAME = re.compile(r"^([a-z]+)-(\d+)")

#: Families whose own version *is* the engine version in the User-Agent, and
#: the token to read it from.
#:
#: Tor and Yandex are absent on purpose: Tor Browser 14 is built on Firefox 128
#: and Yandex 26.8 on Chromium 150, so their names and their User-Agents
#: legitimately disagree. Checking them would report the profiles rather than
#: the caller's override — and a check that cries wolf on a correct setup is
#: worse than no check. Safari carries no such token at all.
_ENGINE_VERSION = {
    "chrome": re.compile(r"Chrome/(\d+)"),
    "edge": re.compile(r"Edg/(\d+)"),
    "firefox": re.compile(r"Firefox/(\d+)"),
}


def _header(pairs: Iterable[dict], name: str) -> str | None:
    lowered = name.lower()
    for h in pairs:
        if h.get("name", "").lower() == lowered:
            return h.get("value", "")
    return None


def audit(target: Any) -> list[Finding]:
    """Looks for contradictions in what this session or persona would send.

    Accepts a :class:`~curlpro.Session` or a :class:`~curlpro.Persona`.
    """
    persona = None
    if hasattr(target, "open") and hasattr(target, "profile"):
        persona = target
        with target.open() as session:
            return _audit(session.fingerprint(), persona)
    return _audit(target.fingerprint(), persona)


def _audit(fp: Any, persona: Any) -> list[Finding]:
    data = fp.to_dict()
    pairs = data.get("header_values") or []
    profile = data.get("profile", "")
    ua = data.get("user_agent", "")
    out: list[Finding] = []

    out += _check_tor_language(profile, pairs)
    out += _check_user_agent_version(profile, ua)
    out += _check_platform(profile, pairs, ua)
    out += _check_mobile_device(profile, data)
    out += _check_language_pair(pairs, ua)

    order = {level: i for i, level in enumerate(LEVELS)}
    out.sort(key=lambda f: order[f.level])
    return out


def _check_tor_language(profile: str, pairs: list) -> list[Finding]:
    """The Tor Browser sends one language to everybody. Any other is a tell."""
    if not profile.startswith("tor-"):
        return []
    lang = _header(pairs, "accept-language") or ""
    if lang.lower().startswith("en-us"):
        return []
    return [Finding(
        code="tor_language",
        level="high",
        what=f"profile {profile} sends accept-language {lang!r}",
        why="the Tor Browser sends en-US,en;q=0.5 to everyone always, and "
            "that is the point: all of its users are meant to look alike. "
            "Any other language says \"this is not the Tor Browser\" and "
            "singles the client out of the very crowd Tor is chosen for",
        fix="restore en-US,en;q=0.5, or use a non-Tor profile")]


def _check_user_agent_version(profile: str, ua: str) -> list[Finding]:
    """A User-Agent that disagrees with the profile it rides on.

    Aimed at a caller's override, not at the profiles: only families whose own
    version is the engine version are compared, so a Tor or a Yandex profile —
    where the two differ by design — is left alone.
    """
    m = _VERSION_IN_NAME.match(profile)
    if not m:
        return []
    family, want = m.group(1), int(m.group(2))
    pattern = _ENGINE_VERSION.get(family)
    if pattern is None:
        return []
    got = pattern.search(ua)
    if not got:
        return _family_mismatch(profile, family, ua)
    have = int(got.group(1))
    if have == want:
        return []
    return [Finding(
        code="ua_version",
        level="high",
        what=f"profile {profile}, but the User-Agent promises version {have}",
        why="the TLS fingerprint and the client hints are built from the "
            "profile and say one version while the User-Agent says another. "
            "A server sees both and compares them for free",
        fix=f"drop the User-Agent override, or use a version {have} profile")]


#: How to recognise the browser a User-Agent claims to be. Order matters: an
#: Edge string carries "Chrome/" as well, and a Yandex one carries both, so the
#: more specific token has to be tried first.
_UA_FAMILY = (
    ("edge", re.compile(r"Edg/")),
    ("yandex", re.compile(r"YaBrowser/")),
    ("firefox", re.compile(r"Firefox/")),
    ("chrome", re.compile(r"Chrome/")),
)


def _family_mismatch(profile: str, family: str, ua: str) -> list[Finding]:
    """The profile is one browser and the User-Agent is another one entirely.

    Reached when the family's own token is missing from the User-Agent — a
    stronger disagreement than a wrong version, and the one a mislabelled
    capture produces: a profile named firefox-154 built from a Chrome
    connection carries Chrome's TLS under a Firefox name.
    """
    for other, pattern in _UA_FAMILY:
        if other != family and pattern.search(ua):
            return [Finding(
                code="ua_family",
                level="high",
                what=f"profile {profile} is {family}, but the User-Agent is {other}",
                why="this is not a version disagreement but a different browser: "
                    "the TLS fingerprint, the client hints and the header order "
                    "all come from the profile and describe "
                    f"{family}, while the User-Agent announces {other}. "
                    "The two are compared for free by anything that reads both",
                fix=f"use a {other} profile, or drop the User-Agent override")]
    return [Finding(
        code="ua_family",
        level="medium",
        what=f"profile {profile} is {family}, but the User-Agent names no browser",
        why=f"a {family} profile is expected to carry a {family} User-Agent; this "
            "one carries no recognisable browser at all, so the string does not "
            "back up what the TLS layer says",
        fix=f"restore the profile's User-Agent, or use a profile matching it")]


_PLATFORMS = {
    "windows": ('"Windows"', "Windows NT"),
    "macos": ('"macOS"', "Macintosh"),
    "linux": ('"Linux"', "X11; Linux"),
    "android": ('"Android"', "Android"),
    "ios": ('"iOS"', "iPhone"),
}


def _check_platform(profile: str, pairs: list, ua: str) -> list[Finding]:
    """sec-ch-ua-platform against the platform the User-Agent claims."""
    hint = _header(pairs, "sec-ch-ua-platform")
    if not hint:
        return []
    for want_hint, ua_mark in _PLATFORMS.values():
        if hint.strip() == want_hint:
            if ua and ua_mark not in ua:
                return [Finding(
                    code="platform",
                    level="high",
                    what=f"sec-ch-ua-platform says {hint}, the User-Agent does not",
                    why="the client hints and the User-Agent describe one "
                        "machine, and a disagreement between them is never "
                        "accidental",
                    fix="remove one of the two overrides")]
            return []
    return []


def _check_mobile_device(profile: str, data: dict) -> list[Finding]:
    """A phone profile with a device list and none of them chosen.

    Only fires when there is something to choose. Safari on iOS sends no client
    hints at all — they are a Chromium feature — and two older Chrome profiles
    carry the hints but no device list of their own, so telling either to "set
    a device" would be advice that cannot be followed. A check that suggests
    the impossible teaches people to skip the output.
    """
    if data.get("device"):
        return []
    if not data.get("devices"):
        return []
    return [Finding(
        code="mobile_no_device",
        level="medium",
        what=f"phone profile {profile} with no device chosen",
        why="a real phone, once the server asks with Accept-CH, names its "
            "model and platform version in sec-ch-ua-model and "
            "sec-ch-ua-platform-version. Without a device those hints go out "
            "empty — a phone that does not know which phone it is",
        fix='set device="Pixel 8" (or "random") on the session or the persona')]


def _check_language_pair(pairs: list, ua: str) -> list[Finding]:
    """A language list whose shape belongs to another browser.

    Chrome builds its q ladder in steps of 0.1, Firefox uses 0.8/0.5/0.3. One
    shape on the wrong browser is the sort of detail nobody sets by hand and a
    detector gets for free.
    """
    lang = _header(pairs, "accept-language") or ""
    if not lang or ";q=" not in lang:
        return []
    steps = re.findall(r";q=([\d.]+)", lang)
    if not steps:
        return []
    firefox_shape = "0.5" in steps or "0.3" in steps
    is_firefox = "Firefox/" in ua
    if firefox_shape and not is_firefox:
        return [Finding(
            code="language_shape",
            level="medium",
            what=f"accept-language is shaped like Firefox's: {lang!r}",
            why="the q ladder is the browser's own signature: Chrome steps by "
                "0.1, Firefox uses 0.8/0.5/0.3. A shape from another browser "
                "stands out exactly as a foreign header order does",
            fix="rewrite the value in this browser's own shape")]
    if not firefox_shape and is_firefox:
        return [Finding(
            code="language_shape",
            level="medium",
            what=f"Firefox with a non-Firefox accept-language: {lang!r}",
            why="Firefox builds its q ladder as 0.8/0.5/0.3; stepping by 0.1 "
                "is Chrome's",
            fix="rewrite the value in Firefox's shape")]
    return []
