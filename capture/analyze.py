#!/usr/bin/env python3
"""Turns a fingerproxy echo-server log (-verbose) into a set of reference samples.

Checks the central assumption of stage 0: Chrome >=110 shuffles its TLS
extensions on every connection, so JA3 is unstable while JA4 — which sorts them —
is not. If that holds, the stand is capturing a real browser rather than an
artefact of its own.

Usage: python analyze.py <server.log> [--out samples/]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

LINE = re.compile(r"\[client (?P<client>[\d.:]+)\] (?P<key>ja3|ja4|detail): (?P<val>.*)")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def request_path(detail: dict) -> str:
    frames = detail.get("metadata", {}).get("HTTP2Frames") or {}
    for h in frames.get("Headers") or []:
        if h["Name"] == ":path":
            return h["Value"]
    return ""


def parse(log_path: Path, want_path: str = "") -> dict[str, dict]:
    """Groups the records by client address. One address is one TLS connection.

    A browser sends several requests over one h2 connection (the navigation,
    then /favicon.ico), and each produces its own detail record. Their headers
    differ: the favicon has no upgrade-insecure-requests and other sec-fetch-*
    values. So the details accumulate and the right one is chosen by :path.
    """
    conns: dict[str, dict] = {}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE.search(line)
        if not m:
            continue
        conn = conns.setdefault(m["client"], {})
        val = m["val"].strip()
        if m["key"] == "detail":
            try:
                conn.setdefault("details", []).append(json.loads(val))
            except json.JSONDecodeError:
                pass
        else:
            conn[m["key"]] = val

    for conn in conns.values():
        details = conn.get("details") or []
        chosen = next((d for d in details if request_path(d) == want_path), None) if want_path else None
        conn["detail"] = chosen or (details[0] if details else {})
    return conns


def summarize(conns: dict[str, dict]) -> int:
    browser = {
        c: d for c, d in conns.items()
        if (ua := d.get("detail", {}).get("user_agent", "")) and "curl" not in ua.lower()
    }
    if not browser:
        print("no browser connections in the log", file=sys.stderr)
        return 1

    ja3s = [d["ja3"] for d in browser.values() if "ja3" in d]
    ja4s = [d["ja4"] for d in browser.values() if "ja4" in d]

    print(f"browser connections: {len(browser)}")
    ua = next(iter(browser.values())).get("detail", {}).get("user_agent", "?")
    print(f"User-Agent: {ua}\n")

    print(f"distinct JA3: {len(set(ja3s))} of {len(ja3s)}")
    for h, n in Counter(ja3s).most_common():
        print(f"   {h}  x{n}")
    print(f"\ndistinct JA4: {len(set(ja4s))} of {len(ja4s)}")
    for h, n in Counter(ja4s).most_common():
        print(f"   {h}  x{n}")

    ok = len(set(ja3s)) > 1 and len(set(ja4s)) == 1
    print()
    if ok:
        print("OK: JA3 unstable, JA4 stable — the extension shuffling is confirmed.")
    elif len(set(ja4s)) > 1:
        print("WARNING: JA4 is unstable. Different clients or versions are mixed in.")
    else:
        print("WARNING: JA3 is stable. Too few samples, or the connection was reused.")

    akamai = Counter()
    for d in browser.values():
        fp = akamai_fingerprint(d.get("detail", {}))
        if fp:
            akamai[fp] += 1
    if akamai:
        print("\nAkamai HTTP/2:")
        for fp, n in akamai.most_common():
            print(f"   {fp}  x{n}")

    return 0 if ok else 2


def akamai_fingerprint(detail: dict) -> str | None:
    """SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER.

    Two traps other implementations fall into: the PRIORITY weight on the wire
    is one less than the real one (RFC 7540), and an absent WINDOW_UPDATE
    serialises as "00" rather than "0".
    """
    frames = detail.get("metadata", {}).get("HTTP2Frames") or {}
    settings = frames.get("Settings")
    if not settings:
        return None

    s = ";".join(f"{x['Id']}:{x['Val']}" for x in settings)
    wu = frames.get("WindowUpdateIncrement") or 0
    wu_s = f"{wu:02d}"

    prio = frames.get("Priorities") or []
    p_s = ",".join(
        f"{p['StreamId']}:{int(p['Exclusive'])}:{p['StreamDep']}:{p['Weight'] + 1}"
        for p in prio
    ) or "0"

    pseudo = ",".join(
        h["Name"][1] for h in (frames.get("Headers") or []) if h["Name"].startswith(":")
    )
    return f"{s}|{wu_s}|{p_s}|{pseudo}"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    log = Path(sys.argv[1])
    want = sys.argv[sys.argv.index("--path") + 1] if "--path" in sys.argv else ""
    conns = parse(log, want)

    if "--out" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--out") + 1])
        out.mkdir(parents=True, exist_ok=True)
        n = 0
        for d in conns.values():
            ua = d.get("detail", {}).get("user_agent", "")
            if not ua or "curl" in ua.lower():
                continue
            n += 1
            # the ja3/ja4 lines arrive as separate log lines, not inside the detail
            payload = dict(d["detail"], _ja3_hash=d.get("ja3"), _ja4=d.get("ja4"))
            (out / f"sample-{n:02d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        print(f"samples saved: {n} -> {out}\n")

    return summarize(conns)


if __name__ == "__main__":
    sys.exit(main())
