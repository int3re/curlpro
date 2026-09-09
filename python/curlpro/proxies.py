"""Proxy settings taken from the environment.

The parsing lives here rather than only in the native side for a subtle
reason: on Linux Go sees the environment as it was when the process started,
so ``os.environ[...] = ...`` from Python no longer changes it. On Windows it
does. A Python user may set the variable at runtime and expect it to take
effect, so the proxy address is picked here and passed down explicitly.

The rules are the ones curl and requests use: the variable follows the
request's scheme — HTTPS_PROXY for https://, HTTP_PROXY for http:// — and
ALL_PROXY covers both. NO_PROXY excludes the hosts it lists, and "*" excludes
everything.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

_HTTPS_VARS = ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
_HTTP_VARS = ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def proxy_for(url: str) -> str | None:
    """Proxy for this address, or None to go directly.

    Until cleartext ``http://`` was supported there was nothing to read
    HTTP_PROXY for, and only the HTTPS variables were consulted. A plain
    request then went out direct while HTTP_PROXY sat in the environment
    saying otherwise — silently, which is the worst way for a proxy setting
    to be wrong.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or no_proxy(host):
        return None
    names = _HTTP_VARS if parts.scheme == "http" else _HTTPS_VARS
    # httpoxy (CVE-2016-5385): under CGI a client's "Proxy:" header arrives as
    # HTTP_PROXY, so it is not trusted there. REQUEST_METHOD marks a CGI
    # environment. The same guard is in the native side.
    cgi = bool(os.environ.get("REQUEST_METHOD"))
    for name in names:
        if cgi and name.upper() == "HTTP_PROXY":
            continue
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def no_proxy(host: str) -> bool:
    """Whether NO_PROXY excludes this host from proxying."""
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
        # ".example.com" and "example.com" both cover the domain itself
        # and its subdomains — that is how curl and requests read them.
        rule = rule.lstrip(".")
        if host == rule or host.endswith("." + rule):
            return True
    return False
