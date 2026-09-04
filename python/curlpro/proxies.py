"""Proxy settings taken from the environment.

The parsing lives here rather than only in the native side for a subtle
reason: on Linux Go sees the environment as it was when the process started,
so ``os.environ[...] = ...`` from Python no longer changes it. On Windows it
does. A Python user may set the variable at runtime and expect it to take
effect, so the proxy address is picked here and passed down explicitly.

The rules are the ones curl and requests use: HTTPS_PROXY, then ALL_PROXY;
NO_PROXY excludes the hosts it lists, and "*" excludes everything.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")


def proxy_for(url: str) -> str | None:
    """Proxy for this address, or None to go directly."""
    host = urlsplit(url).hostname or ""
    if not host or no_proxy(host):
        return None
    for name in _PROXY_VARS:
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
