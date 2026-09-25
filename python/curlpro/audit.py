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


def audit(target: Any, mode: str | None = None) -> list[Finding]:
    """Looks for contradictions in what this session or persona would send.

    Accepts a :class:`~curlpro.Session` or a :class:`~curlpro.Persona`.
    ``mode`` names a header set to judge as if it were in use —
    ``audit(mode="fetch")`` on a session that will send fetch requests it has
    not sent yet. Without it the session is judged by the sets its requests
    have actually gone out with, plus the one it was constructed with.
    """
    persona = None
    if hasattr(target, "open") and hasattr(target, "profile"):
        persona = target
        with target.open() as session:
            return _audit(session.fingerprint(), persona, mode)
    return _audit(target.fingerprint(), persona, mode)


def _audit(fp: Any, persona: Any, mode: str | None = None) -> list[Finding]:
    data = fp.to_dict()
    pairs = data.get("header_values") or []
    # The profile's own request, before anything the caller added or removed:
    # the reference the real preview is measured against.
    profile_pairs = data.get("profile_header_values") or []
    profile = data.get("profile", "")
    ua = data.get("user_agent", "")
    out: list[Finding] = []

    out += _check_tor_language(profile, pairs)
    out += _check_no_user_agent(profile, ua)
    out += _check_user_agent_version(profile, ua)
    out += _check_platform(profile, pairs, ua)
    out += _check_mobile_device(profile, data)
    out += _check_fetch_metadata(pairs)
    out += _check_accept_encoding(pairs, profile_pairs)
    out += _check_referer(pairs, data.get("url", ""))
    out += _check_derived_fetch(profile, data, mode)
    out += _check_transcribed(profile, data)

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
    if not ua:
        return []  # reported once, by _check_no_user_agent
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
        fix="restore the profile's User-Agent, or use a profile matching it")]


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
    # A desktop profile with a pool (Windows builds, macOS versions, Chrome
    # builds) is complete without a choice: the captured machine's own hints
    # go out, a real desktop. Only a phone that names no phone contradicts itself.
    if (_header(data.get("header_values") or [], "sec-ch-ua-mobile") or "?0") != "?1":
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


def _check_no_user_agent(profile: str, ua: str) -> list[Finding]:
    """A request with no User-Agent at all.

    The shape ``default_headers=False`` produces when the caller supplies no
    User-Agent of their own: the transport's default is suppressed on purpose,
    so nothing Go-shaped goes out in its place — and nothing else does either.
    """
    if ua:
        return []
    return [Finding(
        code="no_user_agent",
        level="high",
        what=f"profile {profile}, and the request carries no User-Agent at all",
        why="every browser sends one, so a request without it is not a "
            "browser's whatever the TLS says. This is what default_headers="
            "False leaves behind unless a User-Agent is passed by hand",
        fix="keep the profile headers on and remove single ones with None "
            "(headers={\"Sec-Fetch-User\": None}), or pass a User-Agent")]


#: sec-fetch-dest values a navigation can carry; anything else is a fetch or a
#: subresource, and neither sends the navigation set.
_NAVIGATION_DEST = ("document", "iframe", "frame")


def _check_fetch_metadata(pairs: list) -> list[Finding]:
    """Navigation-only headers on a request whose fetch metadata says fetch.

    ``sec-fetch-user`` and ``upgrade-insecure-requests`` exist only on a
    navigation; a ``fetch()`` or XHR never carries them. A request that says
    ``sec-fetch-mode: cors`` and carries them describes a request no browser
    makes — the pair that sent a client into a captcha on every attempt.
    """
    mode = (_header(pairs, "sec-fetch-mode") or "").strip().lower()
    dest = (_header(pairs, "sec-fetch-dest") or "").strip().lower()
    if (not mode or mode == "navigate") and (not dest or dest in _NAVIGATION_DEST):
        return []
    carried = [n for n in ("sec-fetch-user", "upgrade-insecure-requests")
               if _header(pairs, n) is not None]
    if not carried:
        return []
    return [Finding(
        code="navigation_headers_on_fetch",
        level="high",
        what=f"sec-fetch-mode {mode or '-'} / sec-fetch-dest {dest or '-'} "
             f"next to {' and '.join(carried)}",
        why="those two headers exist only on a page load — a browser's fetch() "
            "and XHR never send them. Fetch metadata that says one thing beside "
            "headers that say another is a request no browser makes, and it is "
            "read for free by anything that reads both",
        fix="let the set switch itself (mode=\"auto\") or set mode=\"fetch\"; on "
            "a profile without a fetch set, remove the two with None")]


def _check_accept_encoding(pairs: list, profile_pairs: list) -> list[Finding]:
    """accept-encoding that is not the profile's.

    The value is part of the header fingerprint and a browser sends the same
    one every time; ``gzip`` alone is the mark of a library. The client decodes
    gzip, deflate, br and zstd, so the profile's value costs nothing to keep.
    """
    want = _header(profile_pairs, "accept-encoding")
    if want is None:
        return []
    got = _header(pairs, "accept-encoding")
    if got is None:
        if not _header(pairs, "user-agent"):
            return []  # the whole set is off; reported once, by no_user_agent
        return [Finding(
            code="accept_encoding",
            level="medium",
            what=f"no accept-encoding, where the profile sends {want!r}",
            why="every browser advertises what it can decode, and a request "
                "without the header is not one this browser makes",
            fix="drop the None on Accept-Encoding; the client decodes the "
                "profile's value itself")]
    if got.strip().lower() == want.strip().lower():
        return []
    return [Finding(
        code="accept_encoding",
        level="medium",
        what=f"accept-encoding {got!r}, where the profile sends {want!r}",
        why="the value is part of the header fingerprint (JA4H hashes it) and "
            "a browser sends the same one every time; gzip alone is the mark "
            "of a library. The client decodes gzip, deflate, br and zstd, so "
            "the profile's value costs nothing",
        fix="drop the Accept-Encoding override; the profile's value is "
            "decoded by the client")]


def _check_derived_fetch(profile: str, data: dict, mode: str | None = None) -> list[Finding]:
    """A fetch set that was worked out rather than captured.

    Fires only when such a set is actually in use — the session was built in
    fetch mode, a request of it went out in fetch mode, or the caller asks
    about fetch — because on a navigation the derived data never reaches the
    wire. Everything else in a profile was seen from a real browser; this
    one part was not, and a caller weighing a detection deserves to know
    which of the two they are looking at.

    The sets requests actually went out with count as much as the
    constructor's: a session built without a mode whose every request says
    ``mode="fetch"`` is a fetch session, and a check keyed on the constructor
    alone stayed silent for exactly the caller it was written for.
    """
    if not data.get("derived_fetch"):
        return []
    in_use = data.get("mode") == "fetch" or "fetch" in (data.get("modes_used") or [])
    if not in_use and mode != "fetch":
        return []
    return [Finding(
        code="derived_fetch_set",
        level="medium",
        what=f"profile {profile} is sending a derived fetch set, not a captured one",
        why="the names and values follow the Fetch standard and the profile's "
            "own navigation set, but the order was not measured from Safari — "
            "and order is part of the header fingerprint. It is better than "
            "the outright refusal it replaced and weaker than everything else "
            "in this profile",
        fix="use a Chromium or Firefox profile where the fetch set is measured, "
            "or capture Safari's own with curlpro capture on a Mac or iPhone")]


def _check_transcribed(profile: str, data: dict) -> list[Finding]:
    """A profile taken from another project's description, not captured.

    Every other profile in the corpus was seen on the wire — by this project
    or by the signatures it imported, which carry the hashes to prove it. A
    transcribed one carries what wreq-util (or another library) believes the
    browser sends: its ClientHello and HTTP/2 come from the nearest captured
    version the source claims to be identical, its User-Agent and brand list
    from the source, and nothing of it was checked against a browser here.
    Fires whatever the mode, because all of it is on trust.
    """
    src = data.get("source")
    if not src:
        return []
    kind = src.get("kind") or "transcribed"
    covers = src.get("covers") or []
    if covers:
        what = f"profile {profile}: {', '.join(covers)} {kind} from {src.get('from', '?')}, not captured"
    else:
        what = f"profile {profile} is {kind} from {src.get('from', '?')}, not captured"
    return [Finding(
        code="transcribed_profile",
        level="medium",
        what=what,
        why=(src.get("note") or "another project's description of the browser, taken on "
             "trust: nothing this profile sends was seen on the wire by this project"),
        fix="prefer a captured profile of the same family — capabilities(name)['measured'] "
            "is True for those — or capture this version with curlpro capture")]


def _origin_of(url: str) -> str:
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return f"{p.scheme.lower()}://{p.netloc.lower()}"


def _check_referer(pairs: list, url: str) -> list[Finding]:
    """A Referer that disagrees with the fetch metadata or the Origin beside it.

    A browser derives all three from one thing — the page the request is made
    from — so they cannot disagree. A hand-written Referer beside the
    profile's ``sec-fetch-site: none`` is the commonest shape: a request that
    claims to come from a page and, in the same breath, from nowhere.
    """
    referer = _header(pairs, "referer")
    if not referer:
        return []
    site = (_header(pairs, "sec-fetch-site") or "").strip().lower()
    origin = _header(pairs, "origin")
    fix = 'set page="<the URL of the page>" on the session or the request and drop the hand-written Referer'
    if site == "none":
        return [Finding(
            code="referer_site",
            level="high",
            what=f"Referer {referer!r} next to sec-fetch-site: none",
            why="a browser sends sec-fetch-site: none only for a navigation it "
                "started itself — a typed URL, a bookmark — and such a request "
                "has no page to send a Referer from. The pair describes a request "
                "no browser makes",
            fix=fix)]
    try:
        ro, uo = _origin_of(referer), _origin_of(url)
    except ValueError:
        return []
    if site == "same-origin" and ro != uo:
        return [Finding(
            code="referer_site", level="high",
            what=f"sec-fetch-site: same-origin, but the Referer is from {ro}",
            why="same-origin says the page is on the request's own origin, and "
                "the Referer says it is not",
            fix=fix)]
    if site == "cross-site" and ro == uo:
        return [Finding(
            code="referer_site", level="high",
            what=f"sec-fetch-site: cross-site, but the Referer is from the request's own origin {ro}",
            why="cross-site says the page is on another site, and the Referer "
                "says it is this very origin",
            fix=fix)]
    if origin and _origin_of(origin) != ro:
        return [Finding(
            code="referer_site", level="high",
            what=f"Origin {origin!r} and Referer {referer!r} name different origins",
            why="both are the page's origin in a browser; two values mean two "
                "pages, which one request cannot come from",
            fix=fix)]
    return []


# The q-ladder check that used to live here has been removed.
#
# It read the shape of accept-language as a browser signature: Chrome steps by
# 0.1, Firefox uses 0.8/0.5/0.3. The Firefox half was inferred from the formula
# 1 - i/n, never measured — and a measurement of Firefox 155 on 2026-09-08 says
# it is wrong. Asked with intl.accept_languages set explicitly, it answered:
#
#     ru-RU, ru, en-US, en  ->  ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
#     ru-RU, ru, en-US      ->  ru-RU,ru;q=0.9,en-US;q=0.8
#     ru-RU, ru             ->  ru-RU,ru;q=0.9
#     ru                    ->  ru
#
# A flat 0.1 step, the same as Chrome's. So the shape no longer separates the
# two, and the check fired on the only Firefox profile ever captured live.
#
# The other half went with it rather than being kept: "a ladder containing 0.5
# or 0.3 is Firefox's" holds only for short lists. Chrome with six languages
# reaches 0.5 by stepping, and would have been reported for behaving normally.
#
# What is not known is when Firefox changed, so the inferred values in the
# 133/135/144 profiles are left alone — replacing one guess with another buys
# nothing. Recorded in ROADMAP.md as a debt to close by measurement.
