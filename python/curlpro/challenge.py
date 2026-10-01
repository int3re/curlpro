"""Telling an anti-bot's challenge from an ordinary answer.

A 403 from a site says nothing by itself: an expired session, a missing
permission and a bot check all answer it. A challenge says more if one looks:
Cloudflare marks every challenge response with ``cf-mitigated: challenge`` (its
documented way for a client to tell, developers.cloudflare.com, "Detect a
challenge page response"), and the other vendors leave their names in a header,
a cookie or the page. :func:`detect` reads those marks; a response carries the
result as :attr:`~curlpro.Response.challenge`.

What is a challenge and what is a block matters to the caller. A challenge is
passed by a browser that runs it — :mod:`curlpro.solvers` hands it to one. A
block (Cloudflare's 1020, an Akamai "Access Denied") is a decision already
made: no browser changes it, only another address or another request does.

The Cloudflare marks are the vendor's documented ones. The others are the
marks their challenge and block pages are known to carry; they were not
measured on this project's stand, and each Challenge says what it matched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

#: Statuses a gate answers with. A 200 with a captcha widget on it is a page
#: that asks for one in its own form, not a gate in front of the page.
_GATE_STATUSES = frozenset({403, 429, 503})

#: How much of a body is read for the marks: every challenge page names its
#: vendor in its head, and a large 403 is not worth scanning whole.
_SCAN = 64 * 1024


@dataclass(frozen=True)
class Challenge:
    """An anti-bot's challenge or block, as :func:`detect` recognised it.

    ``vendor`` is ``"cloudflare"``, ``"datadome"``, ``"akamai"``, ``"human"``
    (PerimeterX), ``"imperva"`` or ``"kasada"``. ``kind`` is ``"challenge"`` —
    a check a browser runs and passes (Cloudflare's managed and JS
    challenges, Turnstile in front of a page); ``"captcha"`` — one that may
    ask a person to act (DataDome's slider, HUMAN's press-and-hold);
    ``"block"`` — a refusal no browser changes; ``"rate-limit"``. ``solvable``
    says whether a solver can help. ``ray`` is Cloudflare's request id, the
    one its support asks for; ``evidence`` names the marks that matched.
    """

    vendor: str
    kind: str
    status: int
    url: str = ""
    ray: str = ""
    evidence: tuple = ()

    @property
    def solvable(self) -> bool:
        return self.kind in ("challenge", "captcha")

    def __str__(self) -> str:
        ray = f", ray {self.ray}" if self.ray else ""
        return f"{self.vendor} {self.kind} (HTTP {self.status}{ray}) at {self.url or '?'}"


def _header(headers: Mapping[str, Any], name: str) -> str:
    """The first value of a header by any case; the native side hands lists."""
    for key, value in headers.items():
        if key.lower() == name:
            if isinstance(value, (list, tuple)):
                return str(value[0]) if value else ""
            return str(value)
    return ""


def _cookie_names(headers: Mapping[str, Any]) -> set:
    names = set()
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        for line in value if isinstance(value, (list, tuple)) else [value]:
            names.add(str(line).split("=", 1)[0].strip().lower())
    return names


def detect(status: int, headers: Mapping[str, Any], body: bytes = b"", url: str = "") -> Challenge | None:
    """The challenge or block a response is, or None for an ordinary one.

    ``headers`` may map a name to a value or to a list of values, in any case;
    ``body`` may be cut short (a stream's first chunk) or empty — a header
    alone is enough for Cloudflare, whose every challenge carries
    ``cf-mitigated``.
    """
    mitigated = _header(headers, "cf-mitigated").lower()
    server = _header(headers, "server").lower()
    ray = _header(headers, "cf-ray")
    # Cloudflare's own word comes first and needs no body: a challenge on a
    # fetch is a 403 with the header and nothing a browser would render.
    if mitigated == "challenge":
        return Challenge("cloudflare", "challenge", status, url, ray, ("cf-mitigated: challenge",))
    if status not in _GATE_STATUSES:
        return None
    text = body[:_SCAN].decode("latin-1", "replace").lower()
    cookies = _cookie_names(headers)

    if server == "cloudflare" or ray:
        if "/cdn-cgi/challenge-platform/" in text or "_cf_chl_opt" in text:
            return Challenge("cloudflare", "challenge", status, url, ray, ("challenge-platform script",))
        if "error code: 1015" in text or (status == 429 and "cloudflare" in text):
            return Challenge("cloudflare", "rate-limit", status, url, ray, ("error 1015",))
        if "cf-error-details" in text or "sorry, you have been blocked" in text or "error code: 10" in text:
            return Challenge("cloudflare", "block", status, url, ray, ("block page",))
    if _header(headers, "x-datadome") or "x-datadome-cid" in {k.lower() for k in headers}:
        kind = "captcha" if "captcha-delivery.com" in text else "block"
        return Challenge("datadome", kind, status, url, "", ("x-datadome",))
    if "captcha-delivery.com" in text and "datadome" in cookies:
        return Challenge("datadome", "captcha", status, url, "", ("captcha-delivery.com",))
    if "_pxappid" in text or "px-captcha" in text:
        return Challenge("human", "captcha", status, url, "", ("_pxAppId / px-captcha",))
    if "sec-if-cpt-container" in text or "/_sec/cp_challenge/" in text:
        return Challenge("akamai", "challenge", status, url, "", ("sec-cpt interstitial",))
    if "akamaighost" in server and "access denied" in text:
        return Challenge("akamai", "block", status, url, "", ("AkamaiGHost access denied",))
    if "_incapsula_resource" in text or "incapsula incident id" in text:
        kind = "block" if "incapsula incident id" in text else "challenge"
        return Challenge("imperva", kind, status, url, "", ("_Incapsula_Resource",))
    if status == 429 and any(k.lower().startswith("x-kpsdk-") for k in headers):
        return Challenge("kasada", "challenge", status, url, "", ("x-kpsdk-*",))
    return None
